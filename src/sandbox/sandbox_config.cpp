#include "photon_kernel/sandbox/sandbox_config.hpp"

namespace photon_kernel {
namespace sandbox {

std::string risk_level_to_string(RiskLevel level) {
    switch (level) {
        case RiskLevel::LOW:   return "LOW";
        case RiskLevel::MEDIUM: return "MEDIUM";
        case RiskLevel::HIGH:  return "HIGH";
        default: return "UNKNOWN";
    }
}

// 参考：NsJail 不同安全等级的资源阈值（google/nsjail）
SandboxConfig SandboxConfig::for_risk_level(RiskLevel level) {
    SandboxConfig cfg;
    cfg.risk_level = level;

    switch (level) {
        case RiskLevel::LOW:
            cfg.memory_limit_bytes = 512 * 1024 * 1024;   // 512MB
            cfg.cpu_time_limit = std::chrono::seconds(5);
            cfg.process_limit = 64;
            cfg.file_size_limit = 20 * 1024 * 1024;       // 20MB
            cfg.allow_network = true;
            cfg.allow_filesystem_read = true;
            cfg.read_whitelist = {"/etc/", "/usr/share/", "/usr/local/"};
            cfg.audit_prefix = "sandbox_low";
            break;

        case RiskLevel::MEDIUM:
            cfg.memory_limit_bytes = 256 * 1024 * 1024;
            cfg.cpu_time_limit = std::chrono::seconds(3);
            cfg.process_limit = 32;
            cfg.file_size_limit = 10 * 1024 * 1024;
            cfg.allow_network = false;
            cfg.allow_filesystem_read = true;
            cfg.read_whitelist = {"/etc/ssl/certs/", "/usr/share/zoneinfo/"};
            cfg.audit_prefix = "sandbox_medium";
            break;

        case RiskLevel::HIGH:
            cfg.memory_limit_bytes = 128 * 1024 * 1024;
            cfg.cpu_time_limit = std::chrono::seconds(1);
            cfg.process_limit = 16;
            cfg.file_size_limit = 5 * 1024 * 1024;
            cfg.allow_network = false;
            cfg.allow_filesystem_read = false;
            cfg.read_whitelist.clear();
            cfg.audit_prefix = "sandbox_high";
            break;
    }

    return cfg;
}

// 代码执行场景配置：基于 LOW（允许网络 + 文件读），配合 code_runner 白名单使用。
// 用于预 fork 沙盒 worker 中通过 stdin 执行用户代码（解释器路径由调用方硬编码白名单）。
SandboxConfig SandboxConfig::for_code_runner() {
    SandboxConfig cfg = for_risk_level(RiskLevel::LOW);
    cfg.memory_limit_bytes = 256 * 1024 * 1024;
    cfg.cpu_time_limit = std::chrono::seconds(5);
    // 任务进程内 NPROC 限制：需留足余量供多线程解释器（node/V8）启动，
    // 同时仍能约束 fork 炸弹（配合 RLIMIT_CPU + 看门狗双重防护）
    cfg.process_limit = 256;
    cfg.allow_network = true;
    cfg.allow_filesystem_read = true;
    cfg.read_whitelist = {"/usr/", "/etc/", "/lib/", "/lib64/", "/bin/", "/tmp/"};
    cfg.audit_prefix = "sandbox_coderunner";
    return cfg;
}

// 参考：Z-Jail 配置验证（Division-36/Z-Jail）
bool SandboxConfig::validate() const {
    if (memory_limit_bytes < 1024 * 1024) return false;
    if (cpu_time_limit.count() <= 0) return false;
    if (allow_filesystem_read && read_whitelist.empty()) return false;
    if (process_limit == 0) return false;
    return true;
}

} // namespace sandbox
} // namespace photon_kernel
