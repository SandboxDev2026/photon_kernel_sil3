#include "photon_kernel/sandbox/sandboxed_executor.hpp"
#include "photon_kernel/sandbox/sandbox_policy.hpp"
#include "photon_kernel/sandbox/audit_logger.hpp"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <fcntl.h>

#include <chrono>
#include <thread>
#include <sstream>
#include <iomanip>
#include <future>
#include <cstring>
#include <iostream>
#include <ctime>

#ifndef PR_SET_PDEATHSIG
#define PR_SET_PDEATHSIG 1
#endif

namespace photon_kernel {
namespace sandbox {

SandboxedExecutor::SandboxedExecutor(const SandboxConfig& config)
    : config_(config) {
    if (!config_.validate()) {
        throw SandboxException(SandboxErrorCode::CONFIG_INVALID,
            "Sandbox config validation failed.");
    }
}

// ---- 安全：关闭子进程中所有非必要文件描述符 ----
// 沙盒子进程不应继承父进程的 fd（可通过 /proc/self/fd 访问父进程文件）。
// 只保留 stdin(0)/stdout(1)/stderr(2) 和通信 pipe。
static void close_unneeded_fds(int keep_fd) {
    // 优先用 close_range（Linux 5.9+），高效批量关闭
#if defined(__linux__) && defined(SYS_close_range)
    // 关闭 3 到 keep_fd-1，以及 keep_fd+1 到 UINT_MAX
    // 分两段：先关 3..keep_fd-1，再关 keep_fd+1..~0U
    if (keep_fd > 3) {
        syscall(SYS_close_range, 3, static_cast<unsigned>(keep_fd) - 1, 0);
    }
    syscall(SYS_close_range, static_cast<unsigned>(keep_fd) + 1, ~0U, 0);
    return;
#endif
    // fallback：遍历 /proc/self/fd
    DIR* dir = opendir("/proc/self/fd");
    if (!dir) return;
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        int fd = std::atoi(entry->d_name);
        if (fd >= 3 && fd != keep_fd) {
            close(fd);
        }
    }
    closedir(dir);
}

// ---- 子进程入口（参考 NsJail child.cpp） ----
static void child_process_entry(const SandboxedTask& task,
                                const SandboxConfig& config,
                                int write_fd) {
    try {
        // 0. 安全：关闭所有继承的非必要 fd（防止沙盒逃逸访问父进程文件）
        close_unneeded_fds(write_fd);
        // 0b. stdin 重定向到 /dev/null（防止用户代码读取父进程输入）
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            close(devnull);
        }
        // 1. 应用资源限制（rlimit）
        SandboxPolicy::apply_rlimits(config);

        // 2. 获取系统调用白名单
        auto base = SandboxPolicy::get_whitelist_for_risk(config.risk_level);
        auto whitelist = SandboxPolicy::merge_with_extra(base, config.extra_allowed_syscalls);

        // 3. 安装 seccomp 过滤器
        SandboxPolicy::install_seccomp_filter(whitelist);

        // 4. 通知父进程就绪
        const char* ready_msg = "READY";
        if (write(write_fd, ready_msg, strlen(ready_msg)) != static_cast<ssize_t>(strlen(ready_msg))) {
            _exit(1);
        }

        // 5. 执行任务
        task.func();

        // 6. 完成
        const char* done_msg = "DONE";
        ssize_t _w = write(write_fd, done_msg, strlen(done_msg));

        if (_w < 0) { /* 子进程中无法上报写入失败 */ }
        _exit(0);

    } catch (const std::exception& e) {
        std::string err = "EXCEPTION: " + std::string(e.what());
        ssize_t _w = write(write_fd, err.c_str(), err.size());

        if (_w < 0) { /* 子进程中无法上报写入失败 */ }
        _exit(1);
    } catch (...) {
        const char* msg = "UNKNOWN_EXCEPTION";
        ssize_t _w = write(write_fd, msg, strlen(msg));

        if (_w < 0) { /* 子进程中无法上报写入失败 */ }
        _exit(1);
    }
}

// ---- 沙盒执行主逻辑（参考 NsJail 进程管理 + JudgeServer 资源统计） ----
SandboxResult SandboxedExecutor::run_in_sandbox(const SandboxedTask& task) {
    SandboxResult result;

    // 任务一经提交即计入统计（并发下 pipe/fork 失败也必须计入，保证 total 口径一致）
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        total_tasks_++;
    }

    // ---- 管道通信（参考 JudgeServer 管道处理） ----
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        result.error_code = SandboxErrorCode::INTERNAL_PIPE_ERROR;
        result.error_message = "pipe() failed";
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            total_failures_++;
        }
        return result;
    }

    // ---- fork（参考 NsJail） ----
    pid_t pid = fork();
    if (pid < 0) {
        result.error_code = SandboxErrorCode::FORK_FAILED;
        result.error_message = "fork() failed: " + std::string(strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            total_failures_++;
        }
        return result;
    }

    if (pid == 0) {
        // 子进程
        close(pipefd[0]);
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        child_process_entry(task, config_, pipefd[1]);
        _exit(1);  // 不应到达
    }

    // ---- 父进程 ----
    close(pipefd[1]);

    // ---- 读取就绪消息 ----
    // 修复：子进程写入 READY 后若任务执行极快，READY 与 DONE 可能被管道一次合并读出
    // （如 "READYDONE"）。因此第一次 read 必须精确读取 READY 的固定长度，
    // 剩余内容（DONE/EXCEPTION）留给后续 read。
    constexpr char kReady[] = "READY";
    constexpr size_t kReadyLen = sizeof(kReady) - 1;  // 5
    char rbuf[64];
    size_t got = 0;
    while (got < kReadyLen) {
        ssize_t nr = read(pipefd[0], rbuf + got, kReadyLen - got);
        if (nr <= 0) break;
        got += static_cast<size_t>(nr);
    }

    if (got != kReadyLen || strncmp(rbuf, kReady, kReadyLen) != 0) {
        result.error_code = SandboxErrorCode::TASK_CRASHED;
        if (got == 0) {
            result.error_message = "Child failed to start";
        } else {
            rbuf[got < sizeof(rbuf) ? got : sizeof(rbuf) - 1] = '\0';
            result.error_message = "Child init failed: " + std::string(rbuf);
        }
        close(pipefd[0]);
        waitpid(pid, nullptr, 0);
        total_failures_++;
        return result;
    }

    // ---- 看门狗超时（参考 JudgeServer 定时器） ----
    // 修复：将 cpu_time_limit（秒）正确换算为毫秒，避免原实现 *1000 放大 1000 倍导致超时失效
    std::chrono::milliseconds timeout_ms =
        task.timeout.count() > 0
            ? task.timeout
            : std::chrono::duration_cast<std::chrono::milliseconds>(config_.cpu_time_limit);

    auto deadline = std::chrono::steady_clock::now() + timeout_ms;
    int status = 0;
    bool timed_out = false;

    while (true) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            timed_out = true;
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            break;
        }
        pid_t ret = waitpid(pid, &status, WNOHANG);
        if (ret == pid) {
            break;
        } else if (ret < 0) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    if (!timed_out) {
        waitpid(pid, &status, 0);
    }

    // 读取最终消息
    char buffer[4096];
    ssize_t n = read(pipefd[0], buffer, sizeof(buffer) - 1);
    close(pipefd[0]);

    // ---- 收集资源统计（参考 JudgeServer 的 getrusage） ----
    struct rusage usage;
    if (getrusage(RUSAGE_CHILDREN, &usage) == 0) {
        result.cpu_time_us = (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) * 1000000LL +
                             usage.ru_utime.tv_usec + usage.ru_stime.tv_usec;
        result.memory_peak_bytes = static_cast<int64_t>(usage.ru_maxrss) * 1024LL;
    }

    // ---- 解析退出状态（参考 NsJail 信号处理） ----
    if (timed_out) {
        result.success = false;
        result.error_code = SandboxErrorCode::TIMEOUT_EXPIRED;
        result.error_message = "Task timed out after " + std::to_string(timeout_ms.count()) + "ms";
        total_failures_++;
    } else if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        result.exit_status = exit_code;
        if (exit_code == 0) {
            if (n > 0) {
                buffer[n] = '\0';
                std::string final_msg(buffer);
                if (final_msg == "DONE" || final_msg == "READY") {
                    result.success = true;
                    result.error_code = SandboxErrorCode::OK;
                } else {
                    result.success = false;
                    result.error_code = SandboxErrorCode::TASK_CRASHED;
                    result.error_message = "Child error: " + final_msg;
                    total_failures_++;
                }
            } else {
                result.success = true;
            }
        } else {
            result.success = false;
            result.error_code = SandboxErrorCode::TASK_CRASHED;
            result.error_message = "Child exited with code " + std::to_string(exit_code);
            total_failures_++;
        }
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        result.success = false;
        result.error_code = SandboxErrorCode::TASK_CRASHED;
        result.error_message = "Child killed by signal " + std::to_string(sig);
        result.exit_signal = sig;

        // 映射常见信号
        if (sig == SIGXCPU) {
            result.error_code = SandboxErrorCode::TIMEOUT_EXPIRED;
        } else if (sig == SIGSYS) {
            result.error_code = SandboxErrorCode::ILLEGAL_SYSCALL;
        } else if (sig == SIGKILL) {
            // 可能是 OOM，但无法精确区分
        }
        total_failures_++;
    } else {
        result.success = false;
        result.error_code = SandboxErrorCode::TASK_CRASHED;
        result.error_message = "Child terminated abnormally";
        total_failures_++;
    }

    // ---- 审计日志（参考 Z-Jail JSON Lines 格式） ----
    append_audit_entry(result, task.name);

    return result;
}

// ---- 同步执行 ----
SandboxResult SandboxedExecutor::execute_sync(const SandboxedTask& task) {
    return run_in_sandbox(task);
}

// ---- 异步执行 ----
std::future<SandboxResult> SandboxedExecutor::execute_async(const SandboxedTask& task) {
    return std::async(std::launch::async, &SandboxedExecutor::run_in_sandbox, this, task);
}

// ---- 批量执行（隔离） ----
std::vector<SandboxResult> SandboxedExecutor::execute_batch(const std::vector<SandboxedTask>& tasks) {
    std::vector<SandboxResult> results;
    results.reserve(tasks.size());
    for (const auto& task : tasks) {
        results.push_back(run_in_sandbox(task));
    }
    return results;
}

// ---- 统计 ----
size_t SandboxedExecutor::get_total_tasks_executed() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return total_tasks_;
}

size_t SandboxedExecutor::get_total_failures() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return total_failures_;
}

double SandboxedExecutor::get_failure_rate() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    if (total_tasks_ == 0) return 0.0;
    return static_cast<double>(total_failures_) / static_cast<double>(total_tasks_);
}

// ---- JSON 审计日志（参考 Z-Jail 审计架构） ----
std::string SandboxedExecutor::get_iso_timestamp() const {
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) % 1000;
    std::tm tm_buf;
    std::tm* tm = gmtime_r(&tt, &tm_buf);
    if (!tm) return "1970-01-01T00:00:00.000Z";
    std::ostringstream oss;
    oss << std::put_time(tm, "%Y-%m-%dT%H:%M:%S")
        << "." << std::setfill('0') << std::setw(3) << ms.count() << "Z";
    return oss.str();
}

std::string SandboxedExecutor::escape_json(const std::string& s) const {
    std::ostringstream oss;
    for (char c : s) {
        switch (c) {
            case '"': oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default: oss << c; break;
        }
    }
    return oss.str();
}

void SandboxedExecutor::append_audit_entry(const SandboxResult& result,
                                           const std::string& task_name) {
    std::ostringstream oss;
    oss << "{\"ts\":\"" << get_iso_timestamp() << "\""
        << ",\"task\":\"" << escape_json(task_name) << "\""
        << ",\"risk\":\"" << risk_level_to_string(config_.risk_level) << "\""
        << ",\"ok\":" << (result.success ? "true" : "false")
        << ",\"code\":" << static_cast<int>(result.error_code)
        << ",\"cpu_us\":" << result.cpu_time_us
        << ",\"mem_bytes\":" << result.memory_peak_bytes
        << ",\"signal\":" << result.exit_signal
        << ",\"status\":" << result.exit_status
        << ",\"err\":\"" << escape_json(result.error_message) << "\""
        << "}";

    // 生产级审计：写入日志文件（AuditLogger 未初始化时自动降级 stderr）
    AuditLogger::instance().log_json(oss.str());
}

} // namespace sandbox
} // namespace photon_kernel
