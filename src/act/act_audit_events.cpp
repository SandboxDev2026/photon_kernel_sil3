#include "photon_kernel/act/act_audit_events.hpp"

#include <string>

#include "photon_kernel/sandbox/audit_logger.hpp"

namespace photon_kernel {
namespace act {

const char* audit_event_type_name(AuditEventType t) {
    switch (t) {
        case AuditEventType::INFERENCE_REQUEST:          return "inference_request";
        case AuditEventType::LIMITER_TRIGGERED:          return "limiter_triggered";
        case AuditEventType::BREAKER_STATE_CHANGE:       return "breaker_state_change";
        case AuditEventType::PERMISSION_OR_MODEL_CHANGE: return "permission_or_model_change";
        case AuditEventType::MANUAL_OVERRIDE:            return "manual_override";
        case AuditEventType::EXECUTOR_FEEDBACK_THRESHOLD: return "executor_feedback_threshold";
    }
    return "unknown";
}

static std::string esc(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

void ActAuditRecorder::record(AuditEventType type, const std::string& summary,
                              const std::string& extra_kv) const {
    auto& logger = sandbox::AuditLogger::instance();
    // 审计开启脱敏：原始数据保留前脱敏（summaries 中若含 code/path 等字段自动打码）
    std::string line =
        std::string("{\"act_event\":\"") + audit_event_type_name(type) +
        "\",\"summary\":\"" + esc(summary) + "\"";
    if (!extra_kv.empty()) {
        line += "," + extra_kv;
    }
    line += "}";
    logger.log_json(line);
}

void ActAuditRecorder::record_inference(const std::string& task_id,
                                        const std::string& output_digest) const {
    record(AuditEventType::INFERENCE_REQUEST,
           "inference request " + task_id,
           "\"output_digest\":\"" + esc(output_digest) + "\"");
}

void ActAuditRecorder::record_manual_override(const std::string& operator_name,
                                              const std::string& reason) const {
    record(AuditEventType::MANUAL_OVERRIDE,
           "manual override by " + operator_name,
           "\"reason\":\"" + esc(reason) + "\"");
}

bool ActAuditRecorder::is_active() const {
    return sandbox::AuditLogger::instance().is_initialized();
}

} // namespace act
} // namespace photon_kernel
