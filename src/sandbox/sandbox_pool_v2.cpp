#include "photon_kernel/sandbox/sandbox_pool_v2.hpp"
#include "photon_kernel/sandbox/sandbox_exception.hpp"

#include <iostream>
#include <algorithm>

namespace photon_kernel {
namespace sandbox {

SandboxPoolV2::SandboxPoolV2(const PoolV2Config& config) : config_(config) {}

SandboxPoolV2::~SandboxPoolV2() {
    shutdown();
}

std::shared_ptr<PrewarmedWorker> SandboxPoolV2::create_worker() {
    SandboxConfig cfg = SandboxConfig::for_code_runner();
    cfg.cpu_time_limit = std::chrono::duration_cast<std::chrono::seconds>(config_.task_timeout);
    return std::make_shared<PrewarmedWorker>(cfg);
}

void SandboxPoolV2::initialize() {
    std::lock_guard<std::mutex> lock(mtx_);
    for (size_t i = 0; i < config_.min_size; ++i) {
        auto w = create_worker();
        all_.push_back(w);
        idle_.push(w);
        std::cout << "[PoolV2] Pre-forked worker " << w->id()
                  << " (" << (i + 1) << "/" << config_.min_size << "), seccomp ready\n";
    }
    std::cout << "[PoolV2] Initialized with " << config_.min_size
              << " pre-forked (seccomp-ready) workers\n";
}

std::shared_ptr<PrewarmedWorker> SandboxPoolV2::acquire(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mtx_);
    auto start = std::chrono::steady_clock::now();

    while (running_) {
        if (!idle_.empty()) {
            auto w = idle_.front();
            idle_.pop();
            if (!w->is_healthy()) {
                // 淘汰不健康 worker，动态补充
                auto it = std::find(all_.begin(), all_.end(), w);
                if (it != all_.end()) all_.erase(it);
                failures_++;
                continue;
            }
            busy_.insert(w);
            return w;
        }
        // 池耗尽且未达上限：动态扩容
        if (all_.size() < config_.max_size) {
            lock.unlock();
            auto w = create_worker();
            lock.lock();
            all_.push_back(w);
            idle_.push(w);
            continue;
        }
        // 等待空闲
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        if (elapsed >= timeout) {
            throw SandboxException(SandboxErrorCode::TIMEOUT_EXPIRED, "pool acquire timeout");
        }
        cv_.wait_for(lock, timeout - elapsed);
    }
    throw SandboxException(SandboxErrorCode::TASK_CRASHED, "pool is shutting down");
}

void SandboxPoolV2::release(std::shared_ptr<PrewarmedWorker> worker) {
    std::lock_guard<std::mutex> lock(mtx_);
    busy_.erase(worker);
    if (worker->is_healthy()) {
        idle_.push(worker);
    } else {
        failures_++;
        auto it = std::find(all_.begin(), all_.end(), worker);
        if (it != all_.end()) all_.erase(it);
    }
    cv_.notify_one();
}

CodeRunResult SandboxPoolV2::execute(const CodeRunRequest& req) {
    auto t0 = std::chrono::steady_clock::now();
    auto w = acquire(std::chrono::milliseconds(500));
    CodeRunResult r;
    try {
        r = w->run(req);
    } catch (const std::exception& e) {
        r.success = false;
        r.error = e.what();
    }
    release(w);
    r.elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
                       std::chrono::steady_clock::now() - t0).count();
    return r;
}

SandboxPoolV2::PoolStatus SandboxPoolV2::get_status() const {
    std::lock_guard<std::mutex> lock(mtx_);
    PoolStatus s;
    s.total = all_.size();
    s.idle = idle_.size();
    s.busy = busy_.size();
    s.failed = failures_.load();
    return s;
}

void SandboxPoolV2::shutdown() {
    std::vector<std::shared_ptr<PrewarmedWorker>> workers;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (!running_.exchange(false)) return;
        workers = all_;
        all_.clear();
        while (!idle_.empty()) idle_.pop();
        busy_.clear();
    }
    cv_.notify_all();
    for (auto& w : workers) {
        w->shutdown();
    }
}

} // namespace sandbox
} // namespace photon_kernel
