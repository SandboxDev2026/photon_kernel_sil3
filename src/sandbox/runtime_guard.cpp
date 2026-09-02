// runtime_guard.cpp - 运行时安全守卫实现
#include "photon_kernel/sandbox/runtime_guard.hpp"

#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>

namespace photon_kernel::sandbox {

RuntimeGuard::RuntimeGuard() = default;
RuntimeGuard::~RuntimeGuard() = default;

GuardResult RuntimeGuard::verify_before_execution(const TaskSecurityContext& ctx) {
    total_checks_++;
    GuardResult result;
    result.allowed = true;

    // 规则1: 不可信输入必须使用StrongPool
    if (ctx.is_untrusted_input && ctx.assigned_backend != RuntimeBackend::STRONG) {
        result.allowed = false;
        result.reason = "Untrusted input assigned to non-StrongPool backend "
                        "(backend=" + std::to_string(static_cast<int>(ctx.assigned_backend)) + ")";
        result.trigger_alert = true;
        result.alert_level = "P0";
        blocked_count_++;
        alert_count_++;
        log_security_event(ctx, result);
        return result;
    }

    // 规则2: HIGH/CRITICAL风险等级必须使用StrongPool
    if ((ctx.risk_level == RiskLevel::HIGH || ctx.risk_level == RiskLevel::CRITICAL) &&
        ctx.assigned_backend != RuntimeBackend::STRONG) {
        result.allowed = false;
        result.reason = "High/Critical risk task assigned to non-StrongPool backend "
                        "(risk=" + std::to_string(static_cast<int>(ctx.risk_level)) +
                        ", backend=" + std::to_string(static_cast<int>(ctx.assigned_backend)) + ")";
        result.trigger_alert = true;
        result.alert_level = "P0";
        blocked_count_++;
        alert_count_++;
        log_security_event(ctx, result);
        return result;
    }

    // 规则3: MEDIUM风险等级不允许使用LightPool(除非管理员覆盖)
    if (ctx.risk_level == RiskLevel::MEDIUM &&
        ctx.assigned_backend == RuntimeBackend::LIGHT &&
        !allow_admin_override_) {
        result.allowed = false;
        result.reason = "Medium risk task assigned to LightPool (admin override disabled)";
        result.trigger_alert = true;
        result.alert_level = "P1";
        blocked_count_++;
        alert_count_++;
        log_security_event(ctx, result);
        return result;
    }

    // 规则4: 需要网络访问的不可信任务必须StrongPool
    if (ctx.is_untrusted_input && ctx.requires_network &&
        ctx.assigned_backend != RuntimeBackend::STRONG) {
        result.allowed = false;
        result.reason = "Untrusted task requiring network assigned to non-StrongPool backend";
        result.trigger_alert = true;
        result.alert_level = "P0";
        blocked_count_++;
        alert_count_++;
        log_security_event(ctx, result);
        return result;
    }

    // 规则5: CRITICAL风险任务需要额外审计(允许执行但告警)
    if (ctx.risk_level == RiskLevel::CRITICAL) {
        result.trigger_alert = true;
        result.alert_level = "P1";
        alert_count_++;
        log_security_event(ctx, result);
    }

    return result;
}

bool RuntimeGuard::is_lightpool_allowed(const TaskSecurityContext& ctx) const {
    // 不可信输入不允许LightPool
    if (ctx.is_untrusted_input) return false;
    // HIGH/CRITICAL不允许LightPool
    if (ctx.risk_level == RiskLevel::HIGH || ctx.risk_level == RiskLevel::CRITICAL) return false;
    // MEDIUM需要管理员覆盖
    if (ctx.risk_level == RiskLevel::MEDIUM && !allow_admin_override_) return false;
    return true;
}

bool RuntimeGuard::is_gvisor_allowed(const TaskSecurityContext& ctx) const {
    // gVisor不适合CRITICAL风险(可能有syscall兼容问题)
    if (ctx.risk_level == RiskLevel::CRITICAL) return false;
    // gVisor适合HIGH(比LightPool安全, 比StrongPool轻量)
    return true;
}

RuntimeBackend RuntimeGuard::mandatory_backend(RiskLevel level) const {
    switch (level) {
        case RiskLevel::LOW:
            return RuntimeBackend::LIGHT;  // 低风险可用LightPool
        case RiskLevel::MEDIUM:
            return allow_admin_override_ ? RuntimeBackend::LIGHT : RuntimeBackend::GVISOR;
        case RiskLevel::HIGH:
        case RiskLevel::CRITICAL:
            return RuntimeBackend::STRONG;  // 高风险必须StrongPool
    }
    return RuntimeBackend::STRONG;  // 默认安全选择
}

void RuntimeGuard::log_security_event(const TaskSecurityContext& ctx, const GuardResult& result) {
    // 获取时间戳
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    char time_buf[64];
    std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", std::localtime(&time_t_now));

    // 输出到stderr(生产环境应写入审计日志)
    std::cerr << "[RUNTIME_GUARD][" << time_buf << "]"
              << " alert=" << (result.trigger_alert ? "YES" : "NO")
              << " level=" << result.alert_level
              << " allowed=" << (result.allowed ? "YES" : "NO")
              << " task_id=" << ctx.task_id
              << " risk=" << static_cast<int>(ctx.risk_level)
              << " backend=" << static_cast<int>(ctx.assigned_backend)
              << " untrusted=" << (ctx.is_untrusted_input ? "YES" : "NO")
              << " reason=" << result.reason
              << std::endl;
}

} // namespace photon_kernel::sandbox
