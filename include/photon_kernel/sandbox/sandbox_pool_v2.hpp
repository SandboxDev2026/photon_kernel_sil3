#ifndef PHOTON_KERNEL_SANDBOX_POOL_V2_HPP
#define PHOTON_KERNEL_SANDBOX_POOL_V2_HPP

#include <memory>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <queue>
#include <set>
#include <vector>
#include <chrono>

#include "prewarmed_worker.hpp"
#include "code_runner.hpp"
#include "sandbox_config.hpp"

namespace photon_kernel {
namespace sandbox {

struct PoolV2Config {
    size_t min_size = 4;              // 启动时预 fork 的 worker 数
    size_t max_size = 50;             // 动态扩容上限
    RiskLevel risk_level = RiskLevel::LOW;
    std::chrono::milliseconds task_timeout{5000};
};

// ---- 预 fork 预热池（任务1）----
// 初始化时真正预 fork 子进程并完成 seccomp 安装；
// 任务执行直接从池中获取已就绪 worker，延迟从冷启动 ~50ms 降至毫秒级。
class SandboxPoolV2 {
public:
    explicit SandboxPoolV2(const PoolV2Config& config);
    ~SandboxPoolV2();

    SandboxPoolV2(const SandboxPoolV2&) = delete;
    SandboxPoolV2& operator=(const SandboxPoolV2&) = delete;

    // 预 fork min_size 个 worker（阻塞直到全部就绪）
    void initialize();

    // 从池获取 worker 执行用户代码并归还
    [[nodiscard]] CodeRunResult execute(const CodeRunRequest& req);

    struct PoolStatus {
        size_t total;
        size_t idle;
        size_t busy;
        size_t failed;
    };
    [[nodiscard]] PoolStatus get_status() const;

    void shutdown();

private:
    std::shared_ptr<PrewarmedWorker> create_worker();
    std::shared_ptr<PrewarmedWorker> acquire(std::chrono::milliseconds timeout);
    void release(std::shared_ptr<PrewarmedWorker> worker);

    PoolV2Config config_;
    mutable std::mutex mtx_;
    std::condition_variable cv_;
    std::vector<std::shared_ptr<PrewarmedWorker>> all_;
    std::queue<std::shared_ptr<PrewarmedWorker>> idle_;
    std::set<std::shared_ptr<PrewarmedWorker>> busy_;
    std::atomic<bool> running_{true};
    std::atomic<size_t> failures_{0};
};

} // namespace sandbox
} // namespace photon_kernel

#endif
