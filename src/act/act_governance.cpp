#include "photon_kernel/act/act_governance.hpp"

#include <algorithm>

namespace photon_kernel {
namespace act {

const char* responsible_role_name(ResponsibleRole r) {
    switch (r) {
        case ResponsibleRole::DEVELOPER:        return "developer";
        case ResponsibleRole::SAFETY_OFFICER:   return "safety_officer";
        case ResponsibleRole::DEPLOYER:         return "deployer";
        case ResponsibleRole::COMPLIANCE_AUDITOR: return "compliance_auditor";
    }
    return "?";
}

void ActGovernance::assign(ResponsibleRole role, const std::string& name) {
    assignees_.emplace_back(role, name);
}

bool ActGovernance::has_role(ResponsibleRole role) const {
    for (const auto& a : assignees_) {
        if (a.first == role) return true;
    }
    return false;
}

std::vector<std::string> ActGovernance::role_holders(ResponsibleRole role) const {
    std::vector<std::string> out;
    for (const auto& a : assignees_) {
        if (a.first == role) out.push_back(a.second);
    }
    return out;
}

void ActGovernance::add_committee_member(const std::string& name, const std::string& domain) {
    committee_.emplace_back(name, domain);
}

size_t ActGovernance::committee_size() const {
    return committee_.size();
}

bool ActGovernance::committee_quorum(size_t need) const {
    return committee_.size() >= need;
}

bool ActGovernance::submit_appeal(const std::string& from, const std::string& decision_ref) {
    if (appeal_pending_) return false;  // 已有一单待复核
    appeal_from_ = from;
    appeal_decision_ref_ = decision_ref;
    appeal_pending_ = true;
    review_done_ = false;
    return true;
}

bool ActGovernance::is_appeal_pending() const {
    return appeal_pending_;
}

bool ActGovernance::conclude_review(const std::string& decision) {
    if (!appeal_pending_) return false;
    (void)decision;
    appeal_pending_ = false;
    review_done_ = true;
    return true;
}

bool ActGovernance::review_concluded() const {
    return review_done_;
}

bool ActGovernance::self_check_pass() const {
    // 第四条：四种责任主体至少各一名（合规审计方独立于开发/运维）
    return has_role(ResponsibleRole::DEVELOPER) &&
           has_role(ResponsibleRole::SAFETY_OFFICER) &&
           has_role(ResponsibleRole::DEPLOYER) &&
           has_role(ResponsibleRole::COMPLIANCE_AUDITOR);
}

} // namespace act
} // namespace photon_kernel
