// risk_enforcer.hpp — 风险强制配置与后端二次校验
//
// 用途：解决 RISK_ASSESSMENT.md 第 4.1/4.2 项风险
//   4.1 风险分数信任问题：RiskScorer 静态扫描可被混淆绕过
//   4.2 高风险任务静默降级：KVM 消失时高风险任务可能降级到 LightPool
//
// 功能：
//   1. 不可信输入强制 StrongPool：用户直接提交的代码/输入，不依赖 RiskScorer 打分，直接强制 MicroVM
//   2. 业务层二次校验后端类型：任务执行前再次确认后端与风险等级匹配
//   3. 高风险任务拒绝降级：无 KVM 时高风险任务直接拒绝，不静默降级到 LightPool
//   4. 后端类型审计：所有任务的后端选择记入审计链
//   5. 告警：高风险任务被分配 LightPool 时触发告警
//   6. 可信来源白名单：内网可信 Agent 可使用 LightPool，外部用户输入强制 StrongPool
#ifndef PHOTON_KERNEL_SANDBOX_RISK_ENFORCER_HPP
#define PHOTON_KERNEL_SANDBOX_RISK_ENFORCER_HPP
#include <string>
#include <vector>
#include <unordered_set>
#include <atomic>
#include <mutex>
#include <functional>
#include "photon_kernel/sandbox/task_spec.hpp"
#include "photon_kernel/sandbox/risk_level.hpp"
namespace photon_kernel {
namespace sandbox {
// 任务来源类型
enum class TaskSource {
    INTERNAL_AGENT = 0,    // 内网可信 Agent（可使用 LightPool）
    INTERNAL_SERVICE = 1,   // 内网服务（可使用 LightPool）
    EXTERNAL_USER = 2,      // 外部用户输入（强制 StrongPool）
    EXTERNAL_API = 3,       // 外部 API 调用（强制 StrongPool）
    UNTRUSTED_CODE = 4,     // 明确标记为不可信代码（强制 StrongPool）
    UNKNOWN = 5,             // 未知来源（默认按不可信处理）
};
inline const char* task_source_name(TaskSource source) {
    switch (source) {
        case TaskSource::INTERNAL_AGENT: return "internal_agent";
        case TaskSource::INTERNAL_SERVICE: return "internal_service";
        case TaskSource::EXTERNAL_USER: return "external_user";
        case TaskSource::EXTERNAL_API: return "external_api";
        case TaskSource::UNTRUSTED_CODE: return "untrusted_code";
        case TaskSource::UNKNOWN: return "unknown";
    }
    return "unknown";
}
// 后端类型
enum class BackendType {
    LIGHT_POOL = 0,   // 进程沙盒（fork + seccomp）
    STRONG_POOL = 1,  // MicroVM（Firecracker）
    ONCE_SANDBOX = 2, // 一次性沙盒（执行完销毁）
    REJECTED = 3,      // 任务被拒绝（无可用后端）
};
inline const char* backend_type_name(BackendType type) {
    switch (type) {
        case BackendType::LIGHT_POOL: return "light_pool";
        case BackendType::STRONG_POOL: return "strong_pool";
        case BackendType::ONCE_SANDBOX: return "once_sandbox";
        case BackendType::REJECTED: return "rejected";
    }
    return "unknown";
}
// 强制决策结果
struct EnforcementDecision {
    BackendType required_backend = BackendType::LIGHT_POOL;  // 要求的后端
    RiskLevel risk_level = RiskLevel::LOW;                     // 风险等级
    bool force_strong_pool = false;                              // 是否强制 StrongPool
    bool reject_if_no_kvm = false;                               // 无 KVM 时是否拒绝
    bool allow_silent_downgrade = false;                        // 是否允许静默降级（永远 false）
    std::string reason;                                          // 决策原因
    std::vector<std::string> warnings;                           // 警告列表
    bool is_valid() const { return required_backend != BackendType::REJECTED; }
};
// 风险强制配置
struct RiskEnforcerConfig {
    // 高风险阈值（超过此分数强制 StrongPool）
    int high_risk_threshold = 70;
    // 严重风险阈值（超过此分数使用一次性沙盒）
    int critical_risk_threshold = 90;
    // 不可信来源是否强制 StrongPool
    bool untrusted_source_force_strong = true;
    // 未知来源是否按不可信处理
    bool unknown_source_as_untrusted = true;
    // 内网可信来源白名单（tenant_id）
    std::unordered_set<std::string> trusted_tenants;
    // 内网可信来源白名单（principal）
    std::unordered_set<std::string> trusted_principals;
    // 无 KVM 时高风险任务的行为：true=拒绝, false=降级到 LightPool（不推荐）
    bool reject_high_risk_without_kvm = true;
    // 是否启用后端二次校验
    bool enable_backend_double_check = true;
    // 高风险任务分配 LightPool 时是否告警
    bool alert_on_high_risk_light_pool = true;
    // 告警回调
    using AlertCallback = std::function<void(const std::string&, const EnforcementDecision&)>;
    AlertCallback alert_callback = nullptr;
    // 审计回调
    using AuditCallback = std::function<void(const std::string&, const EnforcementDecision&)>;
    AuditCallback audit_callback = nullptr;
};
// 风险强制器
class RiskEnforcer {
public:
    explicit RiskEnforcer(const RiskEnforcerConfig& config);
    ~RiskEnforcer() = default;
    RiskEnforcer(const RiskEnforcer&) = delete;
    RiskEnforcer& operator=(const RiskEnforcer&) = delete;
    // 核心方法：根据任务来源和风险分数，强制决策后端类型
    // task_id: 任务 ID（用于审计/告警）
    // source: 任务来源
    // risk_score: RiskScorer 给出的风险分数（0-100）
    // kvm_available: 当前环境是否有 KVM
    EnforcementDecision enforce(const std::string& task_id,
                                TaskSource source,
                                int risk_score,
                                bool kvm_available);
    // 便捷方法：从 TaskSpec 推断来源并强制
    EnforcementDecision enforce_from_spec(const TaskSpec& spec,
                                           int risk_score,
                                           bool kvm_available);
    // 业务层二次校验：任务执行前再次确认后端与风险等级匹配
    // 返回 true 表示校验通过，false 表示后端不匹配（应拒绝执行或重新调度）
    struct BackendCheckResult {
        bool passed = false;
        std::string reason;
        BackendType required_backend;
        BackendType actual_backend;
    };
    BackendCheckResult verify_backend(const std::string& task_id,
                                       BackendType actual_backend,
                                       const EnforcementDecision& decision);
    // 判断来源是否可信
    bool is_trusted_source(TaskSource source) const;
    // 判断 tenant 是否在可信白名单中
    bool is_trusted_tenant(const std::string& tenant_id) const;
    // 判断 principal 是否在可信白名单中
    bool is_trusted_principal(const std::string& principal) const;
    // 从 TaskSpec 推断任务来源
    TaskSource infer_source_from_spec(const TaskSpec& spec) const;
    // 添加可信 tenant
    void add_trusted_tenant(const std::string& tenant_id);
    // 移除可信 tenant
    void remove_trusted_tenant(const std::string& tenant_id);
    // 添加可信 principal
    void add_trusted_principal(const std::string& principal);
    // 移除可信 principal
    void remove_trusted_principal(const std::string& principal);
    // 统计信息
    struct Stats {
        uint64_t total_decisions = 0;
        uint64_t forced_strong_pool = 0;
        uint64_t forced_once_sandbox = 0;
        uint64_t rejected_no_kvm = 0;
        uint64_t backend_check_passed = 0;
        uint64_t backend_check_failed = 0;
        uint64_t alerts_triggered = 0;
        uint64_t audit_records = 0;
    };
    Stats get_stats() const;
private:
    // 触发告警
    void trigger_alert(const std::string& message, const EnforcementDecision& decision);
    // 记录审计
    void record_audit(const std::string& task_id, const EnforcementDecision& decision);
    RiskEnforcerConfig config_;
    mutable std::mutex mtx_;
    Stats stats_;
};
} // namespace sandbox
} // namespace photon_kernel
#endif // PHOTON_KERNEL_SANDBOX_RISK_ENFORCER_HPP
