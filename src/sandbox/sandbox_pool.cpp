#include "photon_kernel/sandbox/sandbox_pool.hpp"
#include "photon_kernel/sandbox/sandbox_exception.hpp"

#include <iostream>
#include <algorithm>

namespace photon_kernel {
namespace sandbox {

SandboxPool::SandboxPool(const PoolConfig& config) : config_(config) {
    // 创建健康检查线程
    health_thread_ = std::thread(&SandboxPool::health_check, this);
}

SandboxPool::~SandboxPool() {
    shutdown();
}

void SandboxPool::initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (size_t i = 0; i < config_.min_size; ++i) {
        auto instance = create_instance();
        instances_.push_back(instance);
        idle_queue_.push(instance);
        std::cout << "[SandboxPool] Created instance " << instance->id
                  << " (" << (i + 1) << "/" << config_.min_size << ")\n";
    }
    std::cout << "[SandboxPool] Initialized with " << config_.min_size << " instances\n";
}

std::shared_ptr<SandboxInstance> SandboxPool::create_instance() {
    static std::atomic<int> counter{0};
    std::string id = "sb-" + std::to_string(++counter);

    SandboxConfig cfg = SandboxConfig::for_risk_level(config_.risk_level);
    // 调整超时匹配池配置
    cfg.cpu_time_limit = std::chrono::duration_cast<std::chrono::seconds>(config_.task_timeout);

    auto instance = std::make_shared<SandboxInstance>(cfg, id);
    instance->last_used = std::chrono::steady_clock::now();
    return instance;
}

std::shared_ptr<SandboxInstance> SandboxPool::acquire(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    auto start = std::chrono::steady_clock::now();

    while (running_) {
        // 检查空闲队列
        if (!idle_queue_.empty()) {
            auto instance = idle_queue_.front();
            idle_queue_.pop();

            // 检查实例健康
            if (!instance->healthy) {
                // 淘汰不健康实例
                auto it = std::find(instances_.begin(), instances_.end(), instance);
                if (it != instances_.end()) {
                    instances_.erase(it);
                }
                continue;
            }

            instance->in_use = true;
            instance->last_used = std::chrono::steady_clock::now();
            return instance;
        }

        // 池已满且无空闲：等待或扩容
        if (instances_.size() < config_.max_size) {
            // 动态扩容
            lock.unlock();
            expand_pool(1);
            lock.lock();
            continue;
        }

        // 等待空闲实例
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start);
        if (elapsed >= timeout) {
            throw SandboxException(SandboxErrorCode::TIMEOUT_EXPIRED,
                "Pool acquire timeout");
        }
        cv_.wait_for(lock, timeout - elapsed);
    }

    throw SandboxException(SandboxErrorCode::TASK_CRASHED, "Pool is shutting down");
}

void SandboxPool::release(std::shared_ptr<SandboxInstance> instance) {
    std::lock_guard<std::mutex> lock(mutex_);

    instance->in_use = false;
    instance->last_used = std::chrono::steady_clock::now();

    // 检查实例是否仍然健康（通过快速测试）
    if (instance->executor) {
        // 简单的健康探测：执行空任务
        try {
            SandboxedTask probe_task;
            probe_task.name = "__health_probe__";
            probe_task.timeout = std::chrono::milliseconds(100);
            probe_task.func = []() { /* 空操作 */ };
            auto result = instance->executor->execute_sync(probe_task);

            if (!result.success) {
                instance->healthy = false;
                total_failures_++;
                std::cerr << "[SandboxPool] Instance " << instance->id
                          << " marked unhealthy after probe failure\n";
                return;
            }
        } catch (...) {
            instance->healthy = false;
            total_failures_++;
            return;
        }
    }

    // 放回空闲队列
    idle_queue_.push(instance);
    cv_.notify_one();
}

SandboxResult SandboxPool::execute(const SandboxedTask& task) {
    auto start = std::chrono::steady_clock::now();

    // 1. 获取沙盒实例（带超时）
    auto instance = acquire(std::chrono::milliseconds(500));
    SandboxResult result;
    try {
        // 2. 执行任务
        result = instance->executor->execute_sync(task);

        // 3. 记录执行时间
        auto end = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        result.cpu_time_us = elapsed.count();
    } catch (const std::exception& e) {
        result.success = false;
        result.error_message = e.what();
        result.error_code = SandboxErrorCode::TASK_CRASHED;
    }

    // 4. 归还沙盒
    release(instance);

    return result;
}

void SandboxPool::expand_pool(size_t count) {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t to_create = std::min(count, config_.max_size - instances_.size());
    for (size_t i = 0; i < to_create; ++i) {
        auto instance = create_instance();
        instances_.push_back(instance);
        idle_queue_.push(instance);
        std::cout << "[SandboxPool] Expanded: created " << instance->id << "\n";
    }
}

SandboxPool::PoolStatus SandboxPool::get_status() const {
    std::lock_guard<std::mutex> lock(mutex_);
    PoolStatus status;
    status.total = instances_.size();
    status.idle = idle_queue_.size();
    status.busy = status.total - status.idle;
    status.failed = total_failures_.load();
    return status;
}

void SandboxPool::health_check() {
    while (running_) {
        // 用条件变量等待：既支持周期执行，也支持 shutdown 立即唤醒
        std::unique_lock<std::mutex> lock(mutex_);
        bool woken = cv_.wait_for(
            lock, std::chrono::seconds(config_.health_check_interval_sec),
            [this]() { return !running_.load(); });
        if (!running_ || woken) {
            break;  // 被 shutdown 唤醒
        }
        lock.unlock();

        // 检查空闲实例是否超时未使用（回收）
        recycle_idle_instances();

        // 确保最小实例数
        size_t current_idle = 0;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            current_idle = idle_queue_.size();
        }
        if (current_idle < config_.min_size / 2) {
            expand_pool(config_.min_size - current_idle);
        }
    }
}

void SandboxPool::recycle_idle_instances() {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    std::queue<std::shared_ptr<SandboxInstance>> new_queue;

    while (!idle_queue_.empty()) {
        auto instance = idle_queue_.front();
        idle_queue_.pop();

        auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(
                             now - instance->last_used).count();

        if (idle_time > static_cast<long long>(config_.idle_timeout_sec) &&
            instances_.size() > config_.min_size) {
            // 回收空闲超时的实例
            auto it = std::find(instances_.begin(), instances_.end(), instance);
            if (it != instances_.end()) {
                instances_.erase(it);
                std::cout << "[SandboxPool] Reclaimed idle instance " << instance->id << "\n";
            }
        } else {
            new_queue.push(instance);
        }
    }
    idle_queue_ = std::move(new_queue);
}

void SandboxPool::shutdown() {
    running_ = false;
    cv_.notify_all();

    if (health_thread_.joinable()) {
        health_thread_.join();
    }

    std::lock_guard<std::mutex> lock(mutex_);
    instances_.clear();
    while (!idle_queue_.empty()) idle_queue_.pop();
}

} // namespace sandbox
} // namespace photon_kernel
