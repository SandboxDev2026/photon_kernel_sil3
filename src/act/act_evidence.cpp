#include "photon_kernel/act/act_evidence.hpp"

#include <algorithm>
#include <cstdlib>

namespace photon_kernel {
namespace act {

const char* evidence_stage_name(EvidenceStage s) {
    switch (s) {
        case EvidenceStage::REQUIREMENT: return "requirement";
        case EvidenceStage::DEVELOPMENT: return "development";
        case EvidenceStage::TESTING:     return "testing";
        case EvidenceStage::DEPLOYMENT:  return "deployment";
    }
    return "?";
}

void EvidenceLogger::add(EvidenceStage stage, const std::string& artifact,
                         const std::string& note, const std::string& id) {
    std::string rid = id.empty()
        ? std::string("EVID-") + std::to_string(++seq_)
        : id;
    records_.push_back({rid, stage, artifact, git_commit_, note});
}

void EvidenceLogger::set_git_commit(const std::string& sha) {
    git_commit_ = sha;
}

void EvidenceLogger::read_git_commit_from_env(const std::string& env_var) {
    const char* v = std::getenv(env_var.c_str());
    if (v && *v) git_commit_ = v;
}

bool EvidenceLogger::link(const std::string& from_id, const std::string& to_id) {
    // 校验两端证据存在
    auto has = [&](const std::string& rid) {
        return std::any_of(records_.begin(), records_.end(),
                           [&](const EvidenceRecord& r) { return r.id == rid; });
    };
    if (!has(from_id) || !has(to_id)) return false;
    links_.push_back({from_id, to_id});
    return true;
}

std::vector<EvidenceRecord> EvidenceLogger::records() const {
    return records_;
}

std::vector<EvidenceRecord> EvidenceLogger::records_of(EvidenceStage s) const {
    std::vector<EvidenceRecord> out;
    for (const auto& r : records_) {
        if (r.stage == s) out.push_back(r);
    }
    return out;
}

std::vector<TraceLink> EvidenceLogger::trace_links() const {
    return links_;
}

bool EvidenceLogger::has_git_commit() const {
    return !git_commit_.empty();
}

std::string EvidenceLogger::git_commit() const {
    return git_commit_;
}

bool EvidenceLogger::self_check_pass() const {
    // 可追溯性：需求/开发/测试三阶段均有证据，且证据链绑定 Git commit
    return !records_of(EvidenceStage::REQUIREMENT).empty() &&
           !records_of(EvidenceStage::DEVELOPMENT).empty() &&
           !records_of(EvidenceStage::TESTING).empty() &&
           !links_.empty() &&
           has_git_commit();
}

} // namespace act
} // namespace photon_kernel
