// runtime_guard.hpp - 运行时安全守卫
// 执行前二次校验, 防止不可信任务因配置错误/bug被送到LightPool
// 这是风险4(LightPool根本安全风险)的纵深防御第2层
#pragma once

#include <string>
#include <cstdint>
#include <optional>

namespace photon_kernel::sandbox {

// 任务风险等级
enum class RiskLevel : uint8_t {
    LOW = 0,       // 内网可信代码
    MEDIUM = 1,    // 半可信代码
    HIGH = 2,      // 不可信代码, 必须StrongPool
    CRITICAL = 3   // 高危代码, 必须StrongPool+额外审计
};

// 运行时后端类型
enum class RuntimeBackend : uint8_t {
    LIGHT = 0,     // LightPool: fork+seccomp, 共享内核
    STRONG = 1,    // StrongPool: Firecracker MicroVM, 独立内核
    GVISOR = 2,    // gVisor: 用户态内核
    WASM = 3       // Wasm: 沙箱化执行
};

// 任务安全上下文
struct TaskSecurityContext {
    uint64_t task_id = 0;
    RiskLevel risk_level = RiskLevel::LOW;
    RuntimeBackend assigned_backend = RuntimeBackend::LIGHT;
    bool is_untrusted_input = false;      // 是否为不可信用户输入
    bool requires_network = false;         // 是否需要网络访问
    bool requires_filesystem = false;      // 是否需要文件系统访问
    std::string source;                    // 任务来源(用于审计)
};

// 守卫验证结果
struct GuardResult {
    bool allowed = false;
    std::string reason;                    // 拒绝原因
    bool trigger_alert = false;            // 是否触发告警
    std::string alert_level;               // 告警级别(P0/P1/P2)
};

// 运行时安全守卫
class RuntimeGuard {
public:
    RuntimeGuard();
    ~RuntimeGuard();

    // 执行前校验: 检查任务分配是否符合安全策略
    // 这是防止RuntimeSelector bug/配置错误的第二层防线
    GuardResult verify_before_execution(const TaskSecurityContext& ctx);

    // 检查是否允许使用LightPool
    bool is_lightpool_allowed(const TaskSecurityContext& ctx) const;

    // 检查是否允许使用gVisor
    bool is_gvisor_allowed(const TaskSecurityContext& ctx) const;

    // 强制后端: 根据风险等级返回必须使用的后端
    RuntimeBackend mandatory_backend(RiskLevel level) const;

    // 配置: 是否允许管理员覆盖安全策略(生产环境应设为false)
    void set_allow_admin_override(bool allow) { allow_admin_override_ = allow; }
    bool allow_admin_override() const { return allow_admin_override_; }

    // 配置: 高风险任务无KVM时是否拒绝(生产环境应设为true)
    void set_reject_on_no_kvm(bool reject) { reject_on_no_kvm_ = reject; }
    bool reject_on_no_kvm() const { return reject_on_no_kvm_; }

    // 获取统计
    uint64_t total_checks() const { return total_checks_; }
    uint64_t blocked_count() const { return blocked_count_; }
    uint64_t alert_count() const { return alert_count_; }

private:
    bool allow_admin_override_ = false;    // 默认不允许管理员覆盖
    bool reject_on_no_kvm_ = true;         // 默认无KVM时拒绝
    uint64_t total_checks_ = 0;
    uint64_t blocked_count_ = 0;
    uint64_t alert_count_ = 0;

    // 记录安全事件(审计日志)
    void log_security_event(const TaskSecurityContext& ctx, const GuardResult& result);
};

} // namespace photon_kernel::sandbox
