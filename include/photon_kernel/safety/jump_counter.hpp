#ifndef PHOTON_KERNEL_SAFETY_JUMP_COUNTER_HPP
#define PHOTON_KERNEL_SAFETY_JUMP_COUNTER_HPP
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <mutex>
namespace photon_kernel::safety {
// ---- V4.14 跳数归零规则 ----
// 扩展（对接第九条）：跳数声明必须携带验证证据，
// 证明下游规则校验层存在（规则库版本 + 校验层日志摘要）。
struct JumpHop {
    std::string layer_name;
    bool is_active_communication;
    bool is_planned_deployment;
    uint32_t hop_index;
    // ---- 第九条：跳数声明的验证证据 ----
    std::string rule_base_version;    // 下游规则校验层使用的规则库版本
    std::string verification_digest;  // 校验层日志摘要 / 签名（可追溯证据）
};

// 跳数=1 声明的验证结果
struct HopClaimVerification {
    bool rule_layer_present;      // 下游规则校验层是否已注册（存在性）
    bool evidence_complete;       // 证据字段（规则库版本 + 摘要）是否完整
    bool verified;                // 综合判定：存在性 && 证据完整
    std::string rule_base_version;
    std::string digest;
    std::string message;
};

class JumpCounter {
public:
    JumpCounter();
    [[nodiscard]] bool is_hop_zero() const;
    void add_hop(const JumpHop& hop);
    void reset();
    [[nodiscard]] std::vector<JumpHop> get_hop_chain() const;

    // ---- 第九条：跳数声明验证 ----
    // 验证“跳数=1（归零）声明”：最终执行器层跳须已注册到下游规则校验层，
    // 且携带完整证据（rule_base_version + verification_digest）。
    [[nodiscard]] HopClaimVerification verify_hop_zero_claim() const;

    // 注册下游规则校验层（存在性登记，供 verify 判定）
    void register_rule_layer(const std::string& rule_base_version,
                             const std::string& layer_ref);
    [[nodiscard]] bool has_rule_layer(const std::string& rule_base_version) const;
    [[nodiscard]] std::vector<std::string> get_rule_layers() const;

    // 增量合规
    void mark_compliance_review_needed();
    [[nodiscard]] bool is_review_needed() const;
    [[nodiscard]] std::chrono::system_clock::time_point get_last_review_time() const;

private:
    std::vector<JumpHop> hop_chain_;
    std::vector<std::string> rule_layers_;  // 已注册的下游规则校验层引用（"version@ref"）
    mutable std::mutex mtx_;
    bool review_needed_;
    std::chrono::system_clock::time_point last_review_time_;
};
} // namespace photon_kernel::safety
#endif
