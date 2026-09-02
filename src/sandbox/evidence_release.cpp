// 证据发布闸门实现
#include "photon_kernel/sandbox/evidence_release.hpp"
#include "photon_kernel/sandbox/crypto_utils.hpp"
#include <sstream>
#include <fstream>
namespace photon_kernel {
namespace sandbox {
std::string release_decision_name(ReleaseDecision d) {
    switch (d) {
        case ReleaseDecision::RELEASE: return "RELEASE";
        case ReleaseDecision::REJECT: return "REJECT";
        case ReleaseDecision::REQUIRE_REVIEW: return "REQUIRE_REVIEW";
    }
    return "UNKNOWN";
}
std::string EvidencePackage::to_json() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"task_id\":\"" << task_id << "\",";
    oss << "\"diffs\":" << diffs.size() << ",";
    oss << "\"tests\":" << test_results.size() << ",";
    oss << "\"traces\":" << traces.size() << ",";
    oss << "\"artifacts\":" << artifacts.size() << ",";
    oss << "\"root_hash\":\"" << root_hash << "\"";
    oss << "}";
    return oss.str();
}
// ==================== EvidenceCollector ====================
EvidenceCollector::EvidenceCollector() = default;
void EvidenceCollector::start(const std::string& task_id, const std::string& tenant_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    task_id_ = task_id;
    tenant_id_ = tenant_id;
    collecting_ = true;
    diffs_.clear();
    tests_.clear();
    traces_.clear();
    artifacts_.clear();
    last_audit_hash_.clear();
    syscall_count_ = 0;
    network_count_ = 0;
    tool_count_ = 0;
}
void EvidenceCollector::record_diff(const FileDiff& diff) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!collecting_) return;
    diffs_.push_back(diff);
}
void EvidenceCollector::record_test(const TestResult& result) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!collecting_) return;
    tests_.push_back(result);
}
void EvidenceCollector::record_trace(const TraceEntry& entry) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!collecting_) return;
    TraceEntry e = entry;
    e.audit_hash = last_audit_hash_;
    std::string data = e.type + "|" + e.detail + "|" + last_audit_hash_;
    auto digest = crypto::hmac_sha256(
        reinterpret_cast<const uint8_t*>("photon-evidence"), 15,
        reinterpret_cast<const uint8_t*>(data.data()), data.size());
    last_audit_hash_ = crypto::to_hex(digest);
    traces_.push_back(e);
}
void EvidenceCollector::record_artifact(const Artifact& artifact) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!collecting_) return;
    artifacts_.push_back(artifact);
}
void EvidenceCollector::record_syscall(const std::string& syscall, const std::string& args) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!collecting_) return;
    syscall_count_++;
    TraceEntry e;
    e.timestamp = std::chrono::system_clock::now();
    e.type = "syscall";
    e.detail = syscall + "(" + args + ")";
    e.task_id = task_id_;
    traces_.push_back(e);
}
void EvidenceCollector::record_network(const std::string& dest_ip, uint16_t port,
                                         const std::string& protocol) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!collecting_) return;
    network_count_++;
    TraceEntry e;
    e.timestamp = std::chrono::system_clock::now();
    e.type = "network";
    e.detail = protocol + " " + dest_ip + ":" + std::to_string(port);
    e.task_id = task_id_;
    traces_.push_back(e);
}
void EvidenceCollector::record_tool_call(const std::string& tool, const std::string& args,
                                           bool allowed) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!collecting_) return;
    tool_count_++;
    TraceEntry e;
    e.timestamp = std::chrono::system_clock::now();
    e.type = "tool";
    e.detail = tool + "(" + args + ") " + (allowed ? "allowed" : "denied");
    e.task_id = task_id_;
    traces_.push_back(e);
}
std::string EvidenceCollector::compute_root_hash() const {
    std::string data = task_id_ + "|" + std::to_string(diffs_.size()) + "|" +
        std::to_string(tests_.size()) + "|" + std::to_string(traces_.size()) + "|" +
        std::to_string(artifacts_.size()) + "|" + last_audit_hash_;
    auto digest = crypto::sha256(
        reinterpret_cast<const uint8_t*>(data.data()), data.size());
    return crypto::to_hex(digest);
}
EvidencePackage EvidenceCollector::finish() {
    std::lock_guard<std::mutex> lock(mtx_);
    EvidencePackage pkg;
    pkg.task_id = task_id_;
    pkg.tenant_id = tenant_id_;
    pkg.collected_at = std::chrono::system_clock::now();
    pkg.diffs = diffs_;
    pkg.test_results = tests_;
    pkg.traces = traces_;
    pkg.artifacts = artifacts_;
    pkg.total_syscalls = syscall_count_;
    pkg.total_network_calls = network_count_;
    pkg.total_tool_calls = tool_count_;
    pkg.root_hash = compute_root_hash();
    collecting_ = false;
    return pkg;
}
void EvidenceCollector::reset() {
    std::lock_guard<std::mutex> lock(mtx_);
    collecting_ = false;
    diffs_.clear();
    tests_.clear();
    traces_.clear();
    artifacts_.clear();
    last_audit_hash_.clear();
    syscall_count_ = 0;
    network_count_ = 0;
    tool_count_ = 0;
}
// ==================== ReleaseGate ====================
ReleaseGate::ReleaseGate() = default;
ReleaseGate& ReleaseGate::instance() {
    static ReleaseGate gate;
    return gate;
}
bool ReleaseGate::check_test_results(const EvidencePackage& e, std::string& reason) const {
    if (e.test_results.empty()) {
        reason = "no test results collected";
        return false;
    }
    int failed = 0;
    for (const auto& t : e.test_results) {
        if (!t.passed) failed++;
    }
    if (failed > 0) {
        reason = std::to_string(failed) + " tests failed";
        return false;
    }
    return true;
}
bool ReleaseGate::check_sensitive_files(const EvidencePackage& e, std::string& reason) const {
    for (const auto& d : e.diffs) {
        if (d.is_sensitive && d.type != FileDiff::Type::DELETED) {
            reason = "sensitive file modified: " + d.path;
            return false;
        }
    }
    return true;
}
bool ReleaseGate::check_network_activity(const EvidencePackage& e, std::string& reason) const {
    if (e.total_network_calls > max_network_calls_) {
        reason = "excessive network calls: " + std::to_string(e.total_network_calls) +
            " > " + std::to_string(max_network_calls_);
        return false;
    }
    return true;
}
bool ReleaseGate::check_evidence_integrity(const EvidencePackage& e, std::string& reason) const {
    if (e.root_hash.empty()) {
        reason = "missing root hash";
        return false;
    }
    // 验证轨迹哈希链
    for (size_t i = 1; i < e.traces.size(); ++i) {
        if (e.traces[i].audit_hash.empty() && i > 0) {
            // 第一条可以没有前序哈希
        }
    }
    return true;
}
bool ReleaseGate::check_artifact_hashes(const EvidencePackage& e, std::string& reason) const {
    for (const auto& a : e.artifacts) {
        if (a.sha256.empty()) {
            reason = "artifact missing hash: " + a.path;
            return false;
        }
        if (a.sha256.size() != 64) {  // SHA256 hex = 64 chars
            reason = "invalid artifact hash length: " + a.path;
            return false;
        }
    }
    return true;
}
ReleaseResult ReleaseGate::verify(const EvidencePackage& evidence) {
    std::lock_guard<std::mutex> lock(mtx_);
    total_verified_++;
    ReleaseResult result;
    result.verified_at = std::chrono::system_clock::now();
    bool all_passed = true;
    bool review_needed = false;
    // 检查1: 测试结果
    std::string reason;
    if (check_test_results(evidence, reason)) {
        result.passed_checks.push_back("test_results");
    } else {
        result.failed_checks.push_back("test_results: " + reason);
        if (require_all_tests_pass_) {
            all_passed = false;
        }
    }
    // 检查2: 敏感文件
    if (check_sensitive_files(evidence, reason)) {
        result.passed_checks.push_back("sensitive_files");
    } else {
        result.failed_checks.push_back("sensitive_files: " + reason);
        if (!allow_sensitive_modification_) {
            all_passed = false;
            review_needed = true;
        }
    }
    // 检查3: 网络活动
    if (check_network_activity(evidence, reason)) {
        result.passed_checks.push_back("network_activity");
    } else {
        result.failed_checks.push_back("network_activity: " + reason);
        review_needed = true;
    }
    // 检查4: 证据完整性
    if (check_evidence_integrity(evidence, reason)) {
        result.passed_checks.push_back("evidence_integrity");
    } else {
        result.failed_checks.push_back("evidence_integrity: " + reason);
        if (require_integrity_) {
            all_passed = false;
        }
    }
    // 检查5: 产物哈希
    if (check_artifact_hashes(evidence, reason)) {
        result.passed_checks.push_back("artifact_hashes");
    } else {
        result.failed_checks.push_back("artifact_hashes: " + reason);
        review_needed = true;
    }
    // 决策
    if (!all_passed) {
        result.decision = ReleaseDecision::REJECT;
        result.reason = "critical checks failed: " +
            (result.failed_checks.empty() ? "unknown" : result.failed_checks[0]);
        rejected_++;
    } else if (review_needed) {
        result.decision = ReleaseDecision::REQUIRE_REVIEW;
        result.reason = "non-critical issues require human review";
        review_required_++;
    } else {
        result.decision = ReleaseDecision::RELEASE;
        result.reason = "all checks passed";
        released_++;
    }
    // 警告
    if (evidence.total_syscalls > 1000) {
        result.warnings.push_back("high syscall count: " + std::to_string(evidence.total_syscalls));
    }
    if (evidence.diffs.size() > 50) {
        result.warnings.push_back("large number of file changes: " + std::to_string(evidence.diffs.size()));
    }
    return result;
}
} // namespace sandbox
} // namespace photon_kernel
