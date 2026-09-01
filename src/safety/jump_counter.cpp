#include "photon_kernel/safety/jump_counter.hpp"
#include <algorithm>
namespace photon_kernel::safety {
JumpCounter::JumpCounter()
    : review_needed_(false),
      last_review_time_(std::chrono::system_clock::now()) {}

bool JumpCounter::is_hop_zero() const {
    std::lock_guard<std::mutex> lock(mtx_);
    // V4.14: 仅当系统输出已规划实际部署或接口处于活跃通信状态时，视为跳数=0
    if (hop_chain_.empty()) {
        return false;
    }
    // 检查最顶层（最终执行器层）
    const auto& last_hop = hop_chain_.back();
    return last_hop.is_planned_deployment || last_hop.is_active_communication;
}

void JumpCounter::add_hop(const JumpHop& hop) {
    std::lock_guard<std::mutex> lock(mtx_);
    hop_chain_.push_back(hop);
}

void JumpCounter::reset() {
    std::lock_guard<std::mutex> lock(mtx_);
    hop_chain_.clear();
}

std::vector<JumpHop> JumpCounter::get_hop_chain() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return hop_chain_;
}

// ---- 第九条：跳数声明验证 ----
HopClaimVerification JumpCounter::verify_hop_zero_claim() const {
    std::lock_guard<std::mutex> lock(mtx_);
    HopClaimVerification v{};
    if (hop_chain_.empty()) {
        v.message = "empty hop chain";
        return v;
    }
    const auto& last = hop_chain_.back();
    if (!last.is_planned_deployment && !last.is_active_communication) {
        v.message = "final hop is not a hop-zero (deployment/active) claim";
        return v;
    }

    // 证据完整性：规则库版本 + 校验层摘要均非空
    v.evidence_complete = !last.rule_base_version.empty() &&
                          !last.verification_digest.empty();
    // 规则校验层存在性：该规则库版本已注册（已持有 mtx_，直接查，避免重入死锁）
    v.rule_layer_present = false;
    for (const auto& entry : rule_layers_) {
        if (entry.rfind(last.rule_base_version + "@", 0) == 0) {
            v.rule_layer_present = true;
            break;
        }
    }
    v.rule_base_version = last.rule_base_version;
    v.digest = last.verification_digest;

    v.verified = v.evidence_complete && v.rule_layer_present;
    if (!v.evidence_complete) {
        v.message = "hop-zero claim missing verification evidence "
                    "(rule_base_version / verification_digest)";
    } else if (!v.rule_layer_present) {
        v.message = "hop-zero claim references unregistered rule layer: " +
                    last.rule_base_version;
    } else {
        v.message = "hop-zero claim verified against rule layer " +
                    last.rule_base_version;
    }
    return v;
}

void JumpCounter::register_rule_layer(const std::string& rule_base_version,
                                      const std::string& layer_ref) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::string entry = rule_base_version + "@" + layer_ref;
    if (std::find(rule_layers_.begin(), rule_layers_.end(), entry) == rule_layers_.end()) {
        rule_layers_.push_back(entry);
    }
}

bool JumpCounter::has_rule_layer(const std::string& rule_base_version) const {
    std::lock_guard<std::mutex> lock(mtx_);
    for (const auto& entry : rule_layers_) {
        if (entry.rfind(rule_base_version + "@", 0) == 0) {
            return true;
        }
    }
    return false;
}

std::vector<std::string> JumpCounter::get_rule_layers() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return rule_layers_;
}

// ---- 增量合规 ----
void JumpCounter::mark_compliance_review_needed() {
    std::lock_guard<std::mutex> lock(mtx_);
    review_needed_ = true;
    last_review_time_ = std::chrono::system_clock::now();
}

bool JumpCounter::is_review_needed() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return review_needed_;
}

std::chrono::system_clock::time_point JumpCounter::get_last_review_time() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return last_review_time_;
}
} // namespace photon_kernel::safety
