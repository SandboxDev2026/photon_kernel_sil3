#ifndef PHOTON_KERNEL_ACT_AUDIT_EVENTS_HPP
#define PHOTON_KERNEL_ACT_AUDIT_EVENTS_HPP

// 第十五条 —— 审计日志
// 法案要求记录 6 类关键事件，原始数据保留前须脱敏。
// 本模块定义事件类型枚举，并将事件编码为 JSON 审计行写入 AuditLogger（经脱敏）。

#include <string>

namespace photon_kernel {
namespace act {

enum class AuditEventType {
    INFERENCE_REQUEST,            // 1. 推理请求与输出摘要（可脱敏）
    LIMITER_TRIGGERED,            // 2. 限幅触发事件
    BREAKER_STATE_CHANGE,         // 3. 熔断状态变更
    PERMISSION_OR_MODEL_CHANGE,   // 4. 权限变更与模型切换
    MANUAL_OVERRIDE,              // 5. 人工覆盖操作
    EXECUTOR_FEEDBACK_THRESHOLD   // 6. 执行器反馈超阈值事件
};

const char* audit_event_type_name(AuditEventType t);

// 审计事件记录器：把 6 类事件编码为 JSON 并写入 AuditLogger（开启脱敏）。
// 若审计系统未初始化则自动降级到 stderr（AuditLogger 行为），保证不丢。
class ActAuditRecorder {
public:
    // 记录一条法案审计事件；extra 字段以 "k":"v" 逗号分隔形式追加（可选）
    void record(AuditEventType type,
                const std::string& summary,
                const std::string& extra_kv = "") const;

    // 便捷方法：推理请求（输出摘要自动脱敏）
    void record_inference(const std::string& task_id,
                          const std::string& output_digest) const;

    // 便捷方法：人工覆盖操作（记录操作者与理由）
    void record_manual_override(const std::string& operator_name,
                                const std::string& reason) const;

    // 是否启用（审计系统已初始化）
    bool is_active() const;
};

} // namespace act
} // namespace photon_kernel

#endif
