#include "photon_kernel/sandbox/code_runner.hpp"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <cstring>
#include <cstdio>
#include <ctime>

namespace photon_kernel {
namespace sandbox {

std::string code_runner_to_string(CodeRunner r) {
    switch (r) {
        case CodeRunner::PYTHON3: return "PYTHON3";
        case CodeRunner::NODE:    return "NODE";
        case CodeRunner::SHELL:   return "SHELL";
        default:                  return "UNKNOWN";
    }
}

const char* interpreter_path(CodeRunner r) {
    switch (r) {
        case CodeRunner::PYTHON3: return "/usr/bin/python3";
        case CodeRunner::NODE:    return "/usr/bin/node";
        case CodeRunner::SHELL:   return "/bin/sh";
        default:                  return nullptr;
    }
}

// ---- 低层 I/O 辅助（在 seccomp 环境内仅使用白名单内 syscall）----
static bool write_all(int fd, const char* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, data + off, len - off);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

static std::string read_fd_all(int fd, size_t limit) {
    std::string out;
    out.reserve(limit < 4096 ? limit : 4096);
    char buf[4096];
    while (out.size() < limit) {
        size_t want = limit - out.size();
        if (want > sizeof(buf)) want = sizeof(buf);
        ssize_t n = read(fd, buf, want);
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
    }
    return out;
}

// ---- 核心执行逻辑 ----
CodeRunResult run_user_code(const CodeRunRequest& req, size_t process_limit) {
    CodeRunResult r;
    auto t0 = std::chrono::steady_clock::now();

    const char* path = interpreter_path(req.runner);
    if (path == nullptr) {
        r.error = "unsupported runner";
        return r;
    }

    // 1. 临时输出文件（任务进程 stdout/stderr 捕获）
    char tmpl[] = "/tmp/photon_sb_out_XXXXXX";
    int out_fd = mkstemp(tmpl);
    if (out_fd < 0) {
        r.error = "mkstemp failed";
        return r;
    }

    // 2. 代码输入管道（stdin → 解释器）
    int in_pipe[2];
    if (pipe(in_pipe) != 0) {
        r.error = "pipe failed";
        close(out_fd);
        unlink(tmpl);
        return r;
    }

    // 3. fork 任务进程（继承父进程已就绪的 seccomp / rlimit）
    pid_t pid = fork();
    if (pid < 0) {
        r.error = "fork failed: " + std::string(std::strerror(errno));
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_fd); unlink(tmpl);
        return r;
    }

    if (pid == 0) {
        // ---- 任务进程 ----
        close(in_pipe[1]);
        // 防 fork 炸弹：在任务进程内单独收紧 RLIMIT_NPROC
        // （worker 进程自身不收紧，以保持持续 fork 任务的能力）
        struct rlimit nproc{static_cast<rlim_t>(process_limit),
                            static_cast<rlim_t>(process_limit)};
        (void)setrlimit(RLIMIT_NPROC, &nproc);
        dup2(in_pipe[0], 0);          // stdin = 代码管道
        dup2(out_fd, 1);              // stdout → 文件
        dup2(out_fd, 2);              // stderr → 文件
        // 安全加固：禁止 setuid 提权 + 禁止 ptrace/dump
        (void)prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        // 解释器路径白名单（硬编码；生产环境建议用 Landlock LANDLOCK_ACCESS_FS_EXECUTE 内核强制）
        execl(path, path, "-", static_cast<char*>(nullptr));
        _exit(127);
    }

    // ---- 沙箱进程（worker）----
    close(in_pipe[0]);
    write_all(in_pipe[1], req.code.data(), req.code.size());
    close(in_pipe[1]);

    // 4. 看门狗超时 + wait4 收集单个任务的资源统计
    int status = 0;
    struct rusage usage;
    bool timed_out = false;
    auto deadline = std::chrono::steady_clock::now() + req.timeout;

    while (true) {
        pid_t ret = wait4(pid, &status, WNOHANG, &usage);
        if (ret == pid) break;
        if (ret < 0) break;
        if (std::chrono::steady_clock::now() >= deadline) {
            timed_out = true;
            kill(pid, SIGKILL);
            wait4(pid, &status, 0, &usage);
            break;
        }
        struct timespec ts{0, 50'000};   // 50us 细粒度轮询：快任务命中延迟 <2ms 的关键
        nanosleep(&ts, nullptr);
    }

    // 5. 读取输出
    lseek(out_fd, 0, SEEK_SET);
    r.output = read_fd_all(out_fd, req.max_output_bytes);
    close(out_fd);
    unlink(tmpl);

    auto t1 = std::chrono::steady_clock::now();
    r.elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();

    // 6. 资源统计（wait4 的 rusage 只针对该任务进程）
    r.cpu_time_us = (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) * 1000000LL +
                    usage.ru_utime.tv_usec + usage.ru_stime.tv_usec;
    r.memory_peak_bytes = static_cast<int64_t>(usage.ru_maxrss) * 1024LL;

    // 7. 结果解析
    if (timed_out) {
        r.success = false;
        r.error = "task timed out after " + std::to_string(req.timeout.count()) + "ms";
        r.exit_signal = SIGKILL;
    } else if (WIFEXITED(status)) {
        r.exit_code = WEXITSTATUS(status);
        r.success = (r.exit_code == 0);
        if (!r.success) {
            r.error = "exited with code " + std::to_string(r.exit_code);
        }
    } else if (WIFSIGNALED(status)) {
        r.exit_signal = WTERMSIG(status);
        r.success = false;
        r.error = "killed by signal " + std::to_string(r.exit_signal);
    } else {
        r.success = false;
        r.error = "abnormal termination";
    }

    return r;
}

} // namespace sandbox
} // namespace photon_kernel
