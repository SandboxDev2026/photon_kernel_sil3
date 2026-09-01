#ifndef PHOTON_KERNEL_SANDBOXED_EXECUTOR_HPP
#define PHOTON_KERNEL_SANDBOXED_EXECUTOR_HPP

#include <functional>
#include <future>
#include <vector>
#include <mutex>
#include <string>
#include <chrono>

#include "sandbox_config.hpp"
#include "sandbox_exception.hpp"

namespace photon_kernel {
namespace sandbox {

struct SandboxedTask {
    std::function<void()> func;
    std::string name;
    std::chrono::milliseconds timeout{0};
};

struct SandboxResult {
    bool success = false;
    std::string error_message;
    SandboxErrorCode error_code = SandboxErrorCode::OK;
    int64_t cpu_time_us = 0;          // 微秒
    int64_t memory_peak_bytes = 0;    // 字节
    int exit_signal = 0;
    int exit_status = 0;
};

// ---- 沙盒执行器（参考 NsJail 进程管理 + JudgeServer 资源统计） ----
class SandboxedExecutor {
public:
    explicit SandboxedExecutor(const SandboxConfig& config =
                                   SandboxConfig::for_risk_level(RiskLevel::MEDIUM));
    ~SandboxedExecutor() = default;

    SandboxedExecutor(const SandboxedExecutor&) = delete;
    SandboxedExecutor& operator=(const SandboxedExecutor&) = delete;

    // ---- 同步执行 ----
    SandboxResult execute_sync(const SandboxedTask& task);

    // ---- 异步执行 ----
    std::future<SandboxResult> execute_async(const SandboxedTask& task);

    // ---- 批量执行（隔离） ----
    std::vector<SandboxResult> execute_batch(const std::vector<SandboxedTask>& tasks);

    // ---- 统计 ----
    size_t get_total_tasks_executed() const;
    size_t get_total_failures() const;
    double get_failure_rate() const;

private:
    SandboxResult run_in_sandbox(const SandboxedTask& task);
    void append_audit_entry(const SandboxResult& result, const std::string& task_name);

    // 辅助函数
    std::string get_iso_timestamp() const;
    std::string escape_json(const std::string& s) const;

    SandboxConfig config_;
    size_t total_tasks_ = 0;
    size_t total_failures_ = 0;
    mutable std::mutex stats_mutex_;
};

} // namespace sandbox
} // namespace photon_kernel

#endif
