#include "photon_kernel/sandbox/prewarmed_worker.hpp"
#include "photon_kernel/sandbox/sandbox_policy.hpp"
#include "photon_kernel/sandbox/sandbox_exception.hpp"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

#include <cstring>
#include <cstdio>
#include <sstream>
#include <iostream>

namespace photon_kernel {
namespace sandbox {

// ======================= worker 子进程侧 =======================

namespace {

bool w_write_all(int fd, const char* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, data + off, len - off);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

// 读取一行（以 '\n' 结尾）
bool w_read_line(int fd, std::string& out) {
    out.clear();
    char c;
    while (true) {
        ssize_t n = read(fd, &c, 1);
        if (n <= 0) return false;
        if (c == '\n') return true;
        out.push_back(c);
    }
}

bool w_read_exact(int fd, char* buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

// 简单 JSON 转义
std::string w_json_escape(const std::string& s) {
    std::ostringstream oss;
    for (char ch : s) {
        switch (ch) {
            case '"':  oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:   oss << ch; break;
        }
    }
    return oss.str();
}

std::string w_result_to_json(const CodeRunResult& r) {
    std::ostringstream oss;
    oss << "{\"success\":" << (r.success ? "true" : "false")
        << ",\"exit_code\":" << r.exit_code
        << ",\"exit_signal\":" << r.exit_signal
        << ",\"cpu_us\":" << r.cpu_time_us
        << ",\"mem_bytes\":" << r.memory_peak_bytes
        << ",\"elapsed_us\":" << r.elapsed_us
        << ",\"output\":\"" << w_json_escape(r.output) << "\""
        << ",\"error\":\"" << w_json_escape(r.error) << "\""
        << "}";
    return oss.str();
}

// worker 主循环：一次性完成沙箱初始化，然后循环处理任务
void worker_main(int cmd_fd, int res_fd, const SandboxConfig& cfg) {
    // ---- 一次性沙箱初始化（重活只做一次）----
    try {
        // worker 不收紧 RLIMIT_NPROC（需持续 fork 任务进程）；
        // 防 fork 炸弹的 NPROC 限制由 run_user_code 在任务进程内单独设置
        SandboxPolicy::apply_rlimits(cfg, /*apply_nproc=*/false);
        auto whitelist = SandboxPolicy::get_whitelist_for_code_runner();
        SandboxPolicy::install_seccomp_filter(whitelist);
    } catch (...) {
        static const char* fail = "INIT_FAIL\n";
        (void)w_write_all(res_fd, fail, strlen(fail));
        _exit(1);
    }

    static const char* ready = "READY\n";
    if (!w_write_all(res_fd, ready, strlen(ready))) _exit(1);

    // ---- 任务循环 ----
    while (true) {
        std::string header;
        if (!w_read_line(cmd_fd, header)) break;   // 父进程关闭
        if (header == "QUIT") break;

        // 协议：RUN:<runner>:<timeout_ms>:<code_len>
        if (header.rfind("RUN:", 0) == 0) {
            int runner = 0;
            long timeout_ms = 0;
            long code_len = 0;
            if (std::sscanf(header.c_str(), "RUN:%d:%ld:%ld", &runner, &timeout_ms, &code_len) != 3) {
                static const char* e = "ERR:BAD_CMD\n";
                (void)w_write_all(res_fd, e, strlen(e));
                continue;
            }
            if (code_len < 0 || code_len > 16 * 1024 * 1024) {
                static const char* e = "ERR:BAD_LEN\n";
                (void)w_write_all(res_fd, e, strlen(e));
                continue;
            }
            std::string code(static_cast<size_t>(code_len), '\0');
            if (!w_read_exact(cmd_fd, &code[0], static_cast<size_t>(code_len))) break;

            CodeRunRequest req;
            req.runner = static_cast<CodeRunner>(runner);
            req.code = std::move(code);
            req.timeout = std::chrono::milliseconds(timeout_ms);

            CodeRunResult r = run_user_code(req, cfg.process_limit);

            std::string json = w_result_to_json(r);
            std::string hdr = "RESULT:" + std::to_string(json.size()) + "\n";
            // 合并 header + JSON 为单次 write（减少 syscall，降低命中延迟）
            std::string out = hdr + json;
            if (!w_write_all(res_fd, out.data(), out.size())) break;
        } else {
            static const char* e = "ERR:UNKNOWN\n";
            (void)w_write_all(res_fd, e, strlen(e));
        }
    }
    _exit(0);
}

// 解析 worker 返回的 JSON（字段已知，简单解析）
CodeRunResult w_parse_result(const std::string& json) {
    CodeRunResult r;
    auto get = [&](const std::string& key, std::string& val) -> bool {
        auto p = json.find("\"" + key + "\":");
        if (p == std::string::npos) return false;
        p = json.find(':', p);
        p++;  // 跳过 ':'
        while (p < json.size() && (json[p] == ' ' || json[p] == '\t')) p++;
        if (json[p] == '"') {
            p++;
            std::string s;
            while (p < json.size() && json[p] != '"') {
                if (json[p] == '\\' && p + 1 < json.size()) {
                    if (json[p + 1] == 'n') { s.push_back('\n'); p += 2; continue; }
                    if (json[p + 1] == 'r') { s.push_back('\r'); p += 2; continue; }
                    if (json[p + 1] == 't') { s.push_back('\t'); p += 2; continue; }
                    if (json[p + 1] == '"' || json[p + 1] == '\\') { s.push_back(json[p + 1]); p += 2; continue; }
                }
                s.push_back(json[p++]);
            }
            val = s;
            return true;
        }
        // 数字/布尔：取到逗号或 '}'
        size_t e = json.find_first_of(",}", p);
        if (e == std::string::npos) e = json.size();
        val = json.substr(p, e - p);
        return true;
    };

    std::string tmp;
    if (get("success", tmp)) r.success = (tmp == "true");
    if (get("exit_code", tmp)) r.exit_code = std::atoi(tmp.c_str());
    if (get("exit_signal", tmp)) r.exit_signal = std::atoi(tmp.c_str());
    if (get("cpu_us", tmp)) r.cpu_time_us = std::atoll(tmp.c_str());
    if (get("mem_bytes", tmp)) r.memory_peak_bytes = std::atoll(tmp.c_str());
    if (get("elapsed_us", tmp)) r.elapsed_us = std::atoll(tmp.c_str());
    if (get("output", tmp)) r.output = tmp;
    if (get("error", tmp)) r.error = tmp;
    return r;
}

} // namespace

// ======================= 父进程侧 =======================

PrewarmedWorker::PrewarmedWorker(const SandboxConfig& cfg) {
    static std::atomic<int> counter{0};
    id_ = "pw-" + std::to_string(++counter);

    int cmd_pipe[2] = {-1, -1};
    int res_pipe[2] = {-1, -1};
    if (pipe(cmd_pipe) != 0 || pipe(res_pipe) != 0) {
        throw SandboxException(SandboxErrorCode::INTERNAL_PIPE_ERROR,
                               "prewarmed worker pipe() failed");
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(cmd_pipe[0]); close(cmd_pipe[1]);
        close(res_pipe[0]); close(res_pipe[1]);
        throw SandboxException(SandboxErrorCode::FORK_FAILED,
                               "prewarmed worker fork() failed");
    }

    if (pid == 0) {
        // worker 子进程
        close(cmd_pipe[1]);
        close(res_pipe[0]);
        worker_main(cmd_pipe[0], res_pipe[1], cfg);
        _exit(1);  // 不应到达
    }

    // 父进程
    close(cmd_pipe[0]);
    close(res_pipe[1]);
    worker_pid_ = pid;
    cmd_fd_ = cmd_pipe[1];
    res_fd_ = res_pipe[0];

    // 等待 worker 就绪（阻塞读一行）
    std::string ack;
    if (!w_read_line(res_fd_, ack)) {
        close_pipes();
        waitpid(worker_pid_, nullptr, 0);
        throw SandboxException(SandboxErrorCode::TASK_CRASHED,
                               "prewarmed worker did not become ready");
    }
    if (ack != "READY") {
        close_pipes();
        kill(worker_pid_, SIGKILL);
        waitpid(worker_pid_, nullptr, 0);
        throw SandboxException(SandboxErrorCode::SECCOMP_INSTALL_FAILED,
                               "prewarmed worker init failed: " + ack);
    }
    ready_ = true;
}

PrewarmedWorker::~PrewarmedWorker() {
    shutdown();
}

void PrewarmedWorker::close_pipes() {
    if (cmd_fd_ >= 0) { close(cmd_fd_); cmd_fd_ = -1; }
    if (res_fd_ >= 0) { close(res_fd_); res_fd_ = -1; }
}

CodeRunResult PrewarmedWorker::run(const CodeRunRequest& req) {
    CodeRunResult fail;
    if (!ready_.load() || !healthy_.load()) {
        fail.error = "worker not ready";
        return fail;
    }

    // 1. 发送命令（合并 header + code 为单次 write，减少 syscall）
    std::string hdr = "RUN:" + std::to_string(static_cast<int>(req.runner)) + ":"
                    + std::to_string(req.timeout.count()) + ":"
                    + std::to_string(req.code.size()) + "\n";
    std::string cmd = hdr + req.code;
    if (!w_write_all(cmd_fd_, cmd.data(), cmd.size())) {
        healthy_ = false;
        fail.error = "write to worker failed";
        return fail;
    }

    // 2. 读结果头
    std::string rh;
    if (!w_read_line(res_fd_, rh)) {
        healthy_ = false;
        fail.error = "worker closed";
        return fail;
    }
    if (rh.rfind("RESULT:", 0) == 0) {
        long json_len = std::atol(rh.c_str() + 7);
        if (json_len < 0 || json_len > 64 * 1024 * 1024) {
            healthy_ = false;
            fail.error = "bad result length";
            return fail;
        }
        std::string json(static_cast<size_t>(json_len), '\0');
        if (!w_read_exact(res_fd_, &json[0], static_cast<size_t>(json_len))) {
            healthy_ = false;
            fail.error = "read result failed";
            return fail;
        }
        return w_parse_result(json);
    }
    // ERR 行
    fail.error = rh;
    return fail;
}

void PrewarmedWorker::shutdown() {
    if (worker_pid_ > 0) {
        if (healthy_.load() && ready_.load() && cmd_fd_ >= 0) {
            static const char* quit = "QUIT\n";
            (void)w_write_all(cmd_fd_, quit, strlen(quit));
        }
        close_pipes();
        waitpid(worker_pid_, nullptr, 0);
        worker_pid_ = -1;
    }
    ready_ = false;
    healthy_ = false;
}

} // namespace sandbox
} // namespace photon_kernel
