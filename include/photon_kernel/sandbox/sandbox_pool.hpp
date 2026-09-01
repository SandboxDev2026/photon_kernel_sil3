#ifndef PHOTON_KERNEL_SANDBOX_POOL_HPP
#define PHOTON_KERNEL_SANDBOX_POOL_HPP

#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <memory>
#include <vector>
#include <chrono>
#include <thread>
#include <functional>
#include <future>
#include <unordered_map>

#include "sandboxed_executor.hpp"
#include "sandbox_config.hpp"

namespace photon_kernel {
namespace sandbox {

// ---- 池配置（参考 OpenSandbox BatchSandbox Pool） ----
struct PoolConfig {
    size_t min_size = 5;            // 最小实例数
    size_t max_size = 50;           // 最大实例数
    size_t idle_timeout_sec = 300;  // 空闲超时回收（秒）
    int health_check_interval_sec = 60; // 健康检查间隔
    RiskLevel risk_level = RiskLevel::MEDIUM;
    std::chrono::milliseconds task_timeout{5000};
};

// ---- 沙盒实例（封装执行器 + 状态） ----
struct SandboxInstance {
    std::unique_ptr<SandboxedExecutor> executor;
    std::atomic<bool> in_use{false};
    std::chrono::steady_clock::time_point last_used;
    std::string id;
    bool healthy = true;

    SandboxInstance(const SandboxConfig& cfg, const std::string& id)
        : executor(std::make_unique<SandboxedExecutor>(cfg)),
          id(id),
          last_used(std::chrono::steady_clock::now()) {}
};

// ---- 预热池（参考 OpenSandbox poolRef 机制） ----
class SandboxPool {
public:
    explicit SandboxPool(const PoolConfig& config);
    ~SandboxPool();

    SandboxPool(const SandboxPool&) = delete;
    SandboxPool& operator=(const SandboxPool&) = delete;

    // 初始化池（预热创建 min_size 个实例）
    void initialize();

    // 获取一个空闲沙盒（阻塞，超时抛出异常）
    std::shared_ptr<SandboxInstance> acquire(
        std::chrono::milliseconds timeout = std::chrono::milliseconds(100));

    // 归还沙盒到池中
    void release(std::shared_ptr<SandboxInstance> instance);

    // 执行任务（从池获取 → 执行 → 自动归还）
    SandboxResult execute(const SandboxedTask& task);

    // 获取池状态
    struct PoolStatus {
        size_t total;
        size_t idle;
        size_t busy;
        size_t failed;
    };
    PoolStatus get_status() const;

    // 关闭池（回收所有实例）
    void shutdown();

private:
    // ---- 内部方法 ----
    std::shared_ptr<SandboxInstance> create_instance();
    void recycle_idle_instances();
    void health_check();
    void expand_pool(size_t count);

    // ---- 成员变量 ----
    PoolConfig config_;
    std::vector<std::shared_ptr<SandboxInstance>> instances_;
    std::queue<std::shared_ptr<SandboxInstance>> idle_queue_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> running_{true};
    std::thread health_thread_;
    std::atomic<size_t> total_failures_{0};
};

} // namespace sandbox
} // namespace photon_kernel

#endif
