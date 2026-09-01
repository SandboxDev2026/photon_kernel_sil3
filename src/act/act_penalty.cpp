#include "photon_kernel/act/act_penalty.hpp"

#include "photon_kernel/act/act_audit_events.hpp"

namespace photon_kernel {
namespace act {

const char* violation_name(Violation v) {
    switch (v) {
        case Violation::RISK_DECLARATION_FALSE:    return "risk_declaration_false";
        case Violation::OUTPUT_LIMITER_MISSING:    return "output_limiter_missing";
        case Violation::HARDWARE_SELFDIAG_MISSING: return "hardware_selfdiag_missing";
        case Violation::LOGIC_BREAKER_MISSING:     return "logic_breaker_missing";
        case Violation::SAFETY_ASSESS_MISSING:     return "safety_assess_missing";
        case Violation::AUDIT_LOG_FORGED:          return "audit_log_forged";
        case Violation::REFUSE_INSPECTION:         return "refuse_inspection";
    }
    return "?";
}

Penalty penalty_for(Violation v) {
    switch (v) {
        case Violation::RISK_DECLARATION_FALSE:
            // 主动上报且24小时整改→观察期；隐瞒/伪造→暂停交付+公开通报
            return {v, "主动上报24h整改→观察期；隐瞒/伪造→暂停交付+公开通报",
                    "24h", true};
        case Violation::OUTPUT_LIMITER_MISSING:
            return {v, "限期整改", "30天", false};
        case Violation::HARDWARE_SELFDIAG_MISSING:
            return {v, "限期整改", "30天", false};
        case Violation::LOGIC_BREAKER_MISSING:
            return {v, "限期整改", "30天", false};
        case Violation::SAFETY_ASSESS_MISSING:
            return {v, "限期整改，暂停新功能上线", "60天", true};
        case Violation::AUDIT_LOG_FORGED:
            return {v, "公开通报，永久记档", "永久", true};
        case Violation::REFUSE_INSPECTION:
            return {v, "限期整改，逾期暂停交付", "30天", true};
    }
    return {v, "", "", false};
}

PenaltyDecision ActPenalty::issue(Violation v, const std::string& facts) {
    Penalty p = penalty_for(v);
    PenaltyDecision d{v, facts, 19, p.measure, p.deadline, false};
    decisions_.push_back(d);
    ActAuditRecorder().record(AuditEventType::MANUAL_OVERRIDE,
                              "penalty issued: " + std::string(violation_name(v)),
                              "\"facts\":\"" + facts + "\"");
    return d;
}

void ActPenalty::appeal(const std::string& decision_ref) {
    for (auto& d : decisions_) {
        if (d.measure == decision_ref) {
            d.appealed = true;
        }
    }
}

bool ActPenalty::self_check_pass() const {
    // 第十九条合规自检：无"审计造假/拒绝配合"类永久性严重违规
    for (const auto& d : decisions_) {
        if (d.violation == Violation::AUDIT_LOG_FORGED ||
            d.violation == Violation::REFUSE_INSPECTION) {
            return false;
        }
    }
    return true;
}

} // namespace act
} // namespace photon_kernel
