#include "photon_kernel/act/act_risk_grade.hpp"

#include "photon_kernel/act/act_audit_events.hpp"

namespace photon_kernel {
namespace act {

const char* risk_grade_name(ActRiskGrade g) {
    switch (g) {
        case ActRiskGrade::LOW:   return "LOW";
        case ActRiskGrade::MEDIUM: return "MEDIUM";
        case ActRiskGrade::HIGH:  return "HIGH";
    }
    return "?";
}

ActRiskGrade grade_by_impact(OutputImpact impact) {
    switch (impact) {
        case OutputImpact::INFORMATION_ONLY:  return ActRiskGrade::LOW;
        case OutputImpact::ASSISTED_DECISION: return ActRiskGrade::MEDIUM;
        case OutputImpact::PHYSICAL_EXECUTOR: return ActRiskGrade::HIGH;
    }
    return ActRiskGrade::LOW;
}

const char* exemption_reason_name(ExemptionReason r) {
    switch (r) {
        case ExemptionReason::PURE_RESEARCH:          return "pure_research";
        case ExemptionReason::INTERNAL_TEST:          return "internal_test";
        case ExemptionReason::OPEN_SOURCE_NONCOMMERCIAL: return "open_source_noncommercial";
        case ExemptionReason::EQUIVALENT_FRAMEWORK:   return "equivalent_framework";
    }
    return "?";
}

void RiskRegister::self_assess(OutputImpact impact) {
    grade_ = grade_by_impact(impact);
    confirmed_ = false;
}

void RiskRegister::committee_confirm(ActRiskGrade grade, const std::string& committee_ref) {
    if (grade != grade_) {
        // 等级变更：重新评估并备案（审计事件）
        ++changes_;
        ActAuditRecorder().record(AuditEventType::PERMISSION_OR_MODEL_CHANGE,
                                  "risk grade changed to " + std::string(risk_grade_name(grade)),
                                  "\"committee\":\"" + committee_ref + "\"");
    }
    grade_ = grade;
    confirmed_ = true;
    committee_ref_ = committee_ref;
}

void RiskRegister::change_grade(ActRiskGrade new_grade, const std::string& reason) {
    ++changes_;
    ActAuditRecorder().record(AuditEventType::PERMISSION_OR_MODEL_CHANGE,
                              "risk grade change to " + std::string(risk_grade_name(new_grade)),
                              "\"reason\":\"" + reason + "\"");
    grade_ = new_grade;
}

void RiskRegister::apply_exemption(ExemptionReason reason, const std::string& applicant) {
    exempt_ = true;
    exempt_reason_ = reason;
    ActAuditRecorder().record(AuditEventType::PERMISSION_OR_MODEL_CHANGE,
                              "exemption applied by " + applicant,
                              "\"reason\":\"" + std::string(exemption_reason_name(reason)) + "\"");
}

bool RiskRegister::self_check_pass() const {
    // 第七条要求：初始等级须经委员会确认（豁免情形除外）
    return exempt_ || confirmed_;
}

} // namespace act
} // namespace photon_kernel
