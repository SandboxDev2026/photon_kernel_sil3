// risk_enforcer.cpp — 风险强制配置与后端二次校验实现
#include "photon_kernel/sandbox/risk_enforcer.hpp"
#include <iostream>
#include <sstream>
namespace photon_kernel {
namespace sandbox {
RiskEnforcer::RiskEnforcer(const RiskEnforcerConfig& config)
    : config_(config) {}
bool RiskEnforcer::is_trusted_source(TaskSource source) const {
    switch (source) {
        case TaskSource::INTERNAL_AGENT:
        case TaskSource::INTERNAL_SERVICE:
            return true;
        case TaskSource::EXTERNAL_USER:
        case TaskSource::EXTERNAL_API:
        case TaskSource::UNTRUSTED_CODE:
            return false;
        case TaskSource::UNKNOWN:
            return !config_.unknown_source_as_untrusted;
    }
    return false;
}
bool RiskEnforcer::is_trusted_tenant(const std::string& tenant_id) const {
    return config_.trusted_tenants.count(tenant_id) > 0;
}
bool RiskEnforcer::is_trusted_principal(const std::string& principal) const {
    return config_.trusted_principals.count(principal) > 0;
}
TaskSource RiskEnforcer::infer_source_from_spec(const TaskSpec& spec) const {
    // 检查 labels 中的 source 标记
    auto it = spec.labels.find("source");
    if (it != spec.labels.end()) {
        const std::string& src = it->second;
        if (src == "internal_agent") return TaskSource::INTERNAL_AGENT;
        if (src == "internal_service") return TaskSource::INTERNAL_SERVICE;
        if (src == "external_user") return TaskSource::EXTERNAL_USER;
        if (src == "external_api") return TaskSource::EXTERNAL_API;
        if (src == "untrusted_code") return TaskSource::UNTRUSTED_CODE;
    }
    // 检查 tenant 是否可信
    if (is_trusted_tenant(spec.identity.tenant_id)) {
        return TaskSource::INTERNAL_AGENT;
    }
    // 检查 principal 是否可信
    if (is_trusted_principal(spec.identity.principal)) {
        return TaskSource::INTERNAL_SERVICE;
    }
    // 检查是否有明确的不可信标记
    auto untrusted_it = spec.labels.find("untrusted");
    if (untrusted_it != spec.labels.end() && untrusted_it->second == "true") {
        return TaskSource::UNTRUSTED_CODE;
    }
    return TaskSource::UNKNOWN;
}
EnforcementDecision RiskEnforcer::enforce(const std::string& task_id,
                                            TaskSource source,
                                            int risk_score,
                                            bool kvm_available) {
    std::lock_guard<std::mutex> lock(mtx_);
    EnforcementDecision decision;
    stats_.total_decisions++;
    // 1. 确定风险等级
    if (risk_score >= config_.critical_risk_threshold) {
        decision.risk_level = RiskLevel::CRITICAL;
    } else if (risk_score >= config_.high_risk_threshold) {
        decision.risk_level = RiskLevel::HIGH;
    } else if (risk_score >= 30) {
        decision.risk_level = RiskLevel::MEDIUM;
    } else {
        decision.risk_level = RiskLevel::LOW;
    }
    // 2. 不可信来源强制 StrongPool（不依赖风险打分）
    bool source_untrusted = !is_trusted_source(source);
    if (source_untrusted && config_.untrusted_source_force_strong) {
        decision.force_strong_pool = true;
        decision.reject_if_no_kvm = true;
        decision.reason = "untrusted source (" + std::string(task_source_name(source)) +
                           ") forces StrongPool (risk score not trusted)";
        decision.warnings.push_back("RiskScorer result ignored for untrusted source");
    }
    // 3. 高风险分数强制 StrongPool
    if (decision.risk_level == RiskLevel::HIGH || decision.risk_level == RiskLevel::CRITICAL) {
        decision.force_strong_pool = true;
        decision.reject_if_no_kvm = true;
        if (decision.reason.empty()) {
            decision.reason = "high risk score (" + std::to_string(risk_score) +
                               ") requires StrongPool";
        } else {
            decision.reason += "; high risk score (" + std::to_string(risk_score) + ")";
        }
    }
    // 4. 严重风险使用一次性沙盒
    if (decision.risk_level == RiskLevel::CRITICAL) {
        decision.required_backend = BackendType::ONCE_SANDBOX;
        stats_.forced_once_sandbox++;
    } else if (decision.force_strong_pool) {
        decision.required_backend = BackendType::STRONG_POOL;
        stats_.forced_strong_pool++;
    } else {
        decision.required_backend = BackendType::LIGHT_POOL;
    }
    // 5. 无 KVM 时的处理
    if (decision.force_strong_pool && !kvm_available) {
        if (config_.reject_high_risk_without_kvm) {
            decision.required_backend = BackendType::REJECTED;
            decision.reason += "; KVM unavailable, task REJECTED (no silent downgrade)";
            stats_.rejected_no_kvm++;
            // 触发告警
            std::ostringstream alert_msg;
            alert_msg << "HIGH RISK task rejected: no KVM available. "
                      << "task_id=" << task_id
                      << " source=" << task_source_name(source)
                      << " risk_score=" << risk_score;
            trigger_alert(alert_msg.str(), decision);
        } else {
            // 不推荐：降级到 LightPool
            decision.required_backend = BackendType::LIGHT_POOL;
            decision.warnings.push_back("KVM unavailable, downgraded to LightPool (NOT RECOMMENDED)");
            decision.reason += "; KVM unavailable, downgraded to LightPool";
        }
    }
    // 6. 永远不允许静默降级
    decision.allow_silent_downgrade = false;
    // 7. 记录审计
    record_audit(task_id, decision);
    return decision;
}
EnforcementDecision RiskEnforcer::enforce_from_spec(const TaskSpec& spec,
                                                      int risk_score,
                                                      bool kvm_available) {
    TaskSource source = infer_source_from_spec(spec);
    return enforce(spec.task_id, source, risk_score, kvm_available);
}
RiskEnforcer::BackendCheckResult RiskEnforcer::verify_backend(
        const std::string& task_id,
        BackendType actual_backend,
        const EnforcementDecision& decision) {
    std::lock_guard<std::mutex> lock(mtx_);
    BackendCheckResult result;
    result.actual_backend = actual_backend;
    result.required_backend = decision.required_backend;
    if (!config_.enable_backend_double_check) {
        result.passed = true;
        result.reason = "backend double check disabled";
        stats_.backend_check_passed++;
        return result;
    }
    // 被拒绝的任务不应该执行
    if (decision.required_backend == BackendType::REJECTED) {
        result.passed = false;
        result.reason = "task was rejected, should not execute";
        stats_.backend_check_failed++;
        trigger_alert("REJECTED task attempted to execute: task_id=" + task_id, decision);
        return result;
    }
    // 后端类型必须匹配
    if (actual_backend != decision.required_backend) {
        result.passed = false;
        std::ostringstream reason;
        reason << "backend mismatch: required=" << backend_type_name(decision.required_backend)
               << ", actual=" << backend_type_name(actual_backend);
        result.reason = reason.str();
        stats_.backend_check_failed++;
        // 高风险任务分配到 LightPool 是严重问题
        if (decision.force_strong_pool && actual_backend == BackendType::LIGHT_POOL) {
            trigger_alert("CRITICAL: high-risk task assigned to LightPool! "
                          "task_id=" + task_id + " " + reason.str(), decision);
        }
        return result;
    }
    result.passed = true;
    result.reason = "backend matches requirement";
    stats_.backend_check_passed++;
    return result;
}
void RiskEnforcer::trigger_alert(const std::string& message, const EnforcementDecision& decision) {
    stats_.alerts_triggered++;
    std::cerr << "[RiskEnforcer] ALERT: " << message << "\n";
    if (config_.alert_callback) {
        config_.alert_callback(message, decision);
    }
}
void RiskEnforcer::record_audit(const std::string& task_id, const EnforcementDecision& decision) {
    stats_.audit_records++;
    if (config_.audit_callback) {
        config_.audit_callback(task_id, decision);
    }
}
void RiskEnforcer::add_trusted_tenant(const std::string& tenant_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    config_.trusted_tenants.insert(tenant_id);
}
void RiskEnforcer::remove_trusted_tenant(const std::string& tenant_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    config_.trusted_tenants.erase(tenant_id);
}
void RiskEnforcer::add_trusted_principal(const std::string& principal) {
    std::lock_guard<std::mutex> lock(mtx_);
    config_.trusted_principals.insert(principal);
}
void RiskEnforcer::remove_trusted_principal(const std::string& principal) {
    std::lock_guard<std::mutex> lock(mtx_);
    config_.trusted_principals.erase(principal);
}
RiskEnforcer::Stats RiskEnforcer::get_stats() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return stats_;
}
} // namespace sandbox
} // namespace photon_kernel
