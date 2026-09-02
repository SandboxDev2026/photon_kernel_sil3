#ifndef PHOTON_KERNEL_SANDBOX_EVIDENCE_RELEASE_HPP
#define PHOTON_KERNEL_SANDBOX_EVIDENCE_RELEASE_HPP
// Evidence + Release —— 证据与发布平面
//
// 职责：把 diff、测试、轨迹和产物哈希交给独立发布闸门重新验证
//
// 核心流程：
//   1. EvidenceCollector: 收集执行过程中的所有证据
//      - 文件 diff（变更了哪些文件）
//      - 测试结果（通过/失败/覆盖率）
//      - 执行轨迹（syscall/网络/工具调用记录）
//      - 产物哈希（输出文件的 SHA256）
//   2. ReleaseGate: 独立发布闸门，重新验证证据
//      - 验证证据完整性（哈希链）
//      - 验证测试全部通过
//      - 验证无高危操作（未授权网络访问/敏感文件修改）
//      - 验证产物哈希匹配
//      - 决策：RELEASE / REJECT / REQUIRE_REVIEW
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <memory>
namespace photon_kernel {
namespace sandbox {
// 文件变更记录
struct FileDiff {
    std::string path;
    enum class Type { ADDED, MODIFIED, DELETED } type;
    std::string old_hash;
    std::string new_hash;
    size_t old_size = 0;
    size_t new_size = 0;
    bool is_sensitive = false;  // 是否敏感文件（/etc/passwd, ~/.ssh 等）
};
// 测试结果
struct TestResult {
    std::string name;
    bool passed = false;
    std::string output;
    std::chrono::milliseconds duration{0};
    int assertions = 0;
};
// 执行轨迹条目
struct TraceEntry {
    std::chrono::system_clock::time_point timestamp;
    std::string type;  // syscall/network/tool/exec/file
    std::string detail;
    std::string task_id;
    std::string audit_hash;  // 哈希链
};
// 产物记录
struct Artifact {
    std::string path;
    std::string sha256;
    size_t size = 0;
    std::string description;
};
// 证据包
struct EvidencePackage {
    std::string task_id;
    std::string tenant_id;
    std::chrono::system_clock::time_point collected_at;
    // 各类证据
    std::vector<FileDiff> diffs;
    std::vector<TestResult> test_results;
    std::vector<TraceEntry> traces;
    std::vector<Artifact> artifacts;
    // 元数据
    std::string runtime_type;
    std::string capability_token_id;
    size_t total_syscalls = 0;
    size_t total_network_calls = 0;
    size_t total_tool_calls = 0;
    // 证据哈希链（防篡改）
    std::string root_hash;
    std::string to_json() const;
};
// 发布决策
enum class ReleaseDecision {
    RELEASE,            // 发布
    REJECT,             // 拒绝
    REQUIRE_REVIEW,     // 需要人工审核
};
std::string release_decision_name(ReleaseDecision d);
// 发布结果
struct ReleaseResult {
    ReleaseDecision decision;
    std::string reason;
    std::vector<std::string> passed_checks;
    std::vector<std::string> failed_checks;
    std::vector<std::string> warnings;
    std::chrono::system_clock::time_point verified_at;
};
// 证据收集器
class EvidenceCollector {
public:
    EvidenceCollector();
    // 开始收集（绑定任务）
    void start(const std::string& task_id, const std::string& tenant_id);
    // 记录文件变更
    void record_diff(const FileDiff& diff);
    // 记录测试结果
    void record_test(const TestResult& result);
    // 记录轨迹
    void record_trace(const TraceEntry& entry);
    // 记录产物
    void record_artifact(const Artifact& artifact);
    // 记录 syscall
    void record_syscall(const std::string& syscall, const std::string& args);
    // 记录网络访问
    void record_network(const std::string& dest_ip, uint16_t port, const std::string& protocol);
    // 记录工具调用
    void record_tool_call(const std::string& tool, const std::string& args, bool allowed);
    // 完成收集，生成证据包
    EvidencePackage finish();
    // 重置
    void reset();
private:
    mutable std::mutex mtx_;
    std::string task_id_;
    std::string tenant_id_;
    bool collecting_ = false;
    std::vector<FileDiff> diffs_;
    std::vector<TestResult> tests_;
    std::vector<TraceEntry> traces_;
    std::vector<Artifact> artifacts_;
    std::string last_audit_hash_;
    size_t syscall_count_ = 0;
    size_t network_count_ = 0;
    size_t tool_count_ = 0;
    std::string compute_root_hash() const;
};
// 发布闸门（独立验证）
class ReleaseGate {
public:
    static ReleaseGate& instance();
    // 验证证据包，做出发布决策
    ReleaseResult verify(const EvidencePackage& evidence);
    // 配置验证规则
    void set_require_all_tests_pass(bool require) { require_all_tests_pass_ = require; }
    void set_allow_sensitive_file_modification(bool allow) { allow_sensitive_modification_ = allow; }
    void set_max_allowed_network_calls(size_t max) { max_network_calls_ = max; }
    void set_require_evidence_integrity(bool require) { require_integrity_ = require; }
    // 统计
    size_t total_verified() const { return total_verified_; }
    size_t released() const { return released_; }
    size_t rejected() const { return rejected_; }
    size_t review_required() const { return review_required_; }
private:
    ReleaseGate();
    ReleaseGate(const ReleaseGate&) = delete;
    ReleaseGate& operator=(const ReleaseGate&) = delete;
    bool require_all_tests_pass_ = true;
    bool allow_sensitive_modification_ = false;
    size_t max_network_calls_ = 100;
    bool require_integrity_ = true;
    mutable std::mutex mtx_;
    size_t total_verified_ = 0;
    size_t released_ = 0;
    size_t rejected_ = 0;
    size_t review_required_ = 0;
    // 验证检查
    bool check_test_results(const EvidencePackage& e, std::string& reason) const;
    bool check_sensitive_files(const EvidencePackage& e, std::string& reason) const;
    bool check_network_activity(const EvidencePackage& e, std::string& reason) const;
    bool check_evidence_integrity(const EvidencePackage& e, std::string& reason) const;
    bool check_artifact_hashes(const EvidencePackage& e, std::string& reason) const;
};
} // namespace sandbox
} // namespace photon_kernel
#endif
