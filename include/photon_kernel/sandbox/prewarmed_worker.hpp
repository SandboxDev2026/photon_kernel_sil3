#ifndef PHOTON_KERNEL_SANDBOX_PREWARMED_WORKER_HPP
#define PHOTON_KERNEL_SANDBOX_PREWARMED_WORKER_HPP

#include <string>
#include <atomic>
#include <chrono>

#include "sandbox_config.hpp"
#include "code_runner.hpp"

namespace photon_kernel {
namespace sandbox {

// ---- 预 fork 沙盒 worker（任务1 核心）----
// 初始化时 fork 一个子进程，并在其中一次性完成 rlimit + seccomp 安装，
// 之后该 worker 以“就绪模板”状态长驻。任务执行时：
//   - 不再重新 fork + 装 seccomp（避免 ~50ms 的冷启动）
//   - worker 内部 fork 任务进程（继承已装 seccomp），通过 stdin 执行用户代码
// 从而将任务延迟降到毫秒级，worker 可反复复用。
class PrewarmedWorker {
public:
    // 预 fork 并完成沙箱初始化；初始化失败抛 SandboxException
    explicit PrewarmedWorker(const SandboxConfig& cfg);
    ~PrewarmedWorker();

    PrewarmedWorker(const PrewarmedWorker&) = delete;
    PrewarmedWorker& operator=(const PrewarmedWorker&) = delete;

    // 执行用户代码；worker 保持可复用
    [[nodiscard]] CodeRunResult run(const CodeRunRequest& req);

    [[nodiscard]] bool is_ready() const { return ready_.load(); }
    [[nodiscard]] bool is_healthy() const { return healthy_.load(); }
    [[nodiscard]] std::string id() const { return id_; }

    // 优雅关闭（发送 QUIT 并回收子进程）
    void shutdown();

private:
    void close_pipes();

    pid_t worker_pid_ = -1;
    int cmd_fd_ = -1;   // 父进程写 → worker 读
    int res_fd_ = -1;   // worker 写 → 父进程读
    std::string id_;
    std::atomic<bool> ready_{false};
    std::atomic<bool> healthy_{true};
};

} // namespace sandbox
} // namespace photon_kernel

#endif
