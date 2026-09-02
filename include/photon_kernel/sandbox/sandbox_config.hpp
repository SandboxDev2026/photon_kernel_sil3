#ifndef PHOTON_KERNEL_SANDBOX_CONFIG_HPP
#define PHOTON_KERNEL_SANDBOX_CONFIG_HPP

#include <cstddef>
#include <chrono>
#include <string>
#include "risk_level.hpp"
#include <vector>

namespace photon_kernel {
namespace sandbox {

// 参考：NsJail 多级安全策略（google/nsjail）

std::string risk_level_to_string(RiskLevel level);

struct SandboxConfig {
    // ---- 资源限制（参考 NsJail rlimit 参数） ----
    size_t memory_limit_bytes = 256 * 1024 * 1024;   // RLIMIT_AS
    std::chrono::seconds cpu_time_limit{2};          // RLIMIT_CPU
    size_t process_limit = 32;                       // RLIMIT_NPROC
    size_t file_size_limit = 10 * 1024 * 1024;       // RLIMIT_FSIZE
    size_t nofile_limit = 64;                           // RLIMIT_NOFILE（防 fd 耗尽）
    size_t sigpending_limit = 32;                       // RLIMIT_SIGPENDING
    size_t msgqueue_limit = 64 * 1024;                 // RLIMIT_MSGQUEUE（64KB）

    // ---- 网络与文件权限 ----
    bool allow_network = false;
    bool allow_filesystem_write = false;
    bool allow_filesystem_read = false;

    std::vector<std::string> read_whitelist;         // 仅允许这些路径

    // ---- 额外系统调用 ----
    std::vector<int> extra_allowed_syscalls;

    // ---- 看门狗 ----
    bool enable_watchdog = true;
    std::chrono::milliseconds watchdog_grace_period{100};

    // ---- 审计前缀 ----
    std::string audit_prefix = "sandbox";

    // ---- 风险等级 ----
    RiskLevel risk_level = RiskLevel::MEDIUM;

    // ---- 工厂方法：参考 NsJail 的分级配置思想 ----
    static SandboxConfig for_risk_level(RiskLevel level);

    // ---- 代码执行场景配置（配合 get_whitelist_for_code_runner 使用）----
    // 用于预 fork 沙盒 worker 中执行用户代码（Python/Node/Shell）
    static SandboxConfig for_code_runner();

    // ---- 验证配置 ----
    bool validate() const;
};

} // namespace sandbox
} // namespace photon_kernel

#endif
