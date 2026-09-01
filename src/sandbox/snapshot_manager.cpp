#include "photon_kernel/sandbox/snapshot_manager.hpp"
#include "photon_kernel/sandbox/sandbox_policy.hpp"
#include "photon_kernel/sandbox/sandbox_config.hpp"
#include "photon_kernel/sandbox/sandbox_exception.hpp"
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <cstring>
#include <iostream>
namespace photon_kernel {
namespace sandbox {
namespace {
// 母进程主循环：已装好 seccomp+rlimit，等待 fork 指令
void snapshot_parent_main(int cmd_fd, int res_fd, const SandboxConfig& cfg) {
    // 一次性完成沙箱初始化（重活只做一次）
    try {
        // 母进程不收紧 RLIMIT_NPROC（需持续 fork 子进程）
        SandboxPolicy::apply_rlimits(cfg, /*apply_nproc=*/false);
        auto whitelist = SandboxPolicy::get_whitelist_for_code_runner();
        SandboxPolicy::install_seccomp_filter(whitelist);
    } catch (...) {
        static const char fail = 'X';
        (void)write(res_fd, &fail, 1);
        _exit(1);
    }
    // 通知父进程就绪
    static const char ready = 'R';
    if (write(res_fd, &ready, 1) != 1) _exit(1);
    // 任务循环：等待 fork 指令
    while (true) {
        char cmd = 0;
        ssize_t n = read(cmd_fd, &cmd, 1);
        if (n <= 0) break;  // 父进程关闭管道
        if (cmd == 'F') {
            pid_t child = fork();
            if (child == 0) {
                // 克隆出的子进程：继承已装好的 seccomp+rlimit
                // 立即退出（调用方可通过信号/管道进一步控制；此处用于极致延迟测量）
                _exit(0);
            }
            if (child < 0) {
                // fork 失败，返回 -1
                pid_t neg = -1;
                (void)write(res_fd, &neg, sizeof(pid_t));
                continue;
            }
            // 返回子进程 PID 给父进程
            if (write(res_fd, &child, sizeof(pid_t)) != sizeof(pid_t)) break;
        } else if (cmd == 'Q') {
            // 退出指令
            break;
        }
    }
    _exit(0);
}
} // namespace
SnapshotManager::~SnapshotManager() {
    shutdown();
}
SnapshotManager& SnapshotManager::instance() {
    static SnapshotManager mgr;
    return mgr;
}
void SnapshotManager::init(size_t pool_size, int risk_level) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_) return;
    RiskLevel level = static_cast<RiskLevel>(risk_level);
    SandboxConfig cfg = SandboxConfig::for_code_runner();
    for (size_t i = 0; i < pool_size; ++i) {
        int cmd_pipe[2] = {-1, -1};
        int res_pipe[2] = {-1, -1};
        if (pipe(cmd_pipe) != 0 || pipe(res_pipe) != 0) {
            std::cerr << "[SnapshotManager] pipe() failed\n";
            continue;
        }
        pid_t pid = fork();
        if (pid < 0) {
            close(cmd_pipe[0]); close(cmd_pipe[1]);
            close(res_pipe[0]); close(res_pipe[1]);
            std::cerr << "[SnapshotManager] fork() failed\n";
            continue;
        }
        if (pid == 0) {
            // 母进程
            close(cmd_pipe[1]);
            close(res_pipe[0]);
            snapshot_parent_main(cmd_pipe[0], res_pipe[1], cfg);
            _exit(1);  // 不应到达
        }
        // 父进程
        close(cmd_pipe[0]);
        close(res_pipe[1]);
        // 等待母进程就绪
        char ack = 0;
        if (read(res_pipe[0], &ack, 1) != 1 || ack != 'R') {
            std::cerr << "[SnapshotManager] snapshot " << i << " did not become ready\n";
            close(cmd_pipe[1]);
            close(res_pipe[0]);
            kill(pid, SIGKILL);
            waitpid(pid, nullptr, 0);
            continue;
        }
        SnapshotState state;
        state.parent_pid = pid;
        state.cmd_fd = cmd_pipe[1];
        state.res_fd = res_pipe[0];
        state.created_at = std::chrono::steady_clock::now();
        state.is_ready = true;
        snapshots_.push_back(std::move(state));
    }
    if (!snapshots_.empty()) {
        initialized_ = true;
        std::cout << "[SnapshotManager] Initialized " << snapshots_.size()
                  << " pre-forked snapshots (seccomp-ready)\n";
    } else {
        std::cerr << "[SnapshotManager] No snapshots initialized\n";
    }
}
pid_t SnapshotManager::clone_sandbox() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (snapshots_.empty()) return -1;
    // 轮询选择一个母进程
    size_t idx = round_robin_ % snapshots_.size();
    round_robin_++;
    auto& snap = snapshots_[idx];
    if (!snap.is_ready) return -1;
    // 发送 fork 指令
    char cmd = 'F';
    if (write(snap.cmd_fd, &cmd, 1) != 1) {
        snap.is_ready = false;
        return -1;
    }
    // 读取子进程 PID
    pid_t child_pid = -1;
    if (read(snap.res_fd, &child_pid, sizeof(pid_t)) != sizeof(pid_t)) {
        snap.is_ready = false;
        return -1;
    }
    if (child_pid > 0) {
        clone_count_++;
    }
    return child_pid;
}
void SnapshotManager::recycle(pid_t child_pid) {
    if (child_pid <= 0) return;
    int status = 0;
    waitpid(child_pid, &status, 0);
}
void SnapshotManager::shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& snap : snapshots_) {
        if (snap.cmd_fd >= 0) {
            char quit = 'Q';
            (void)write(snap.cmd_fd, &quit, 1);
            close(snap.cmd_fd);
            snap.cmd_fd = -1;
        }
        if (snap.res_fd >= 0) {
            close(snap.res_fd);
            snap.res_fd = -1;
        }
        if (snap.parent_pid > 0) {
            kill(snap.parent_pid, SIGTERM);
            waitpid(snap.parent_pid, nullptr, 0);
            snap.parent_pid = -1;
        }
        snap.is_ready = false;
    }
    snapshots_.clear();
    initialized_ = false;
}
size_t SnapshotManager::snapshot_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return snapshots_.size();
}
} // namespace sandbox
} // namespace photon_kernel
