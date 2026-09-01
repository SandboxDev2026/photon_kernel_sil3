#ifndef PHOTON_KERNEL_SANDBOX_AUDIT_SECURITY_HPP
#define PHOTON_KERNEL_SANDBOX_AUDIT_SECURITY_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <set>

namespace photon_kernel {
namespace sandbox {

// ---- 审计防篡改：HMAC-SHA256 哈希链 ----
// 每条审计记录携带 (seq, prev_hash, hmac)：
//   hmac = HMAC_SHA256(secret_key, prev_hash + payload_json)
// 形成哈希链，任何一条记录被篡改（或中间插入/删除）都会导致后续校验失败。
// 用于审计记录的安全校验（防篡改）。

class AuditHasher {
public:
    // HMAC-SHA256，返回 64 位小写 hex
    [[nodiscard]] static std::string hmac_sha256_hex(const std::string& key,
                                                     const std::string& data);
    // SHA-256，返回 64 位小写 hex
    [[nodiscard]] static std::string sha256_hex(const std::string& data);
};

class AuditChain {
public:
    AuditChain() : AuditChain("photon-sandbox-audit-chain-default-key") {}
    explicit AuditChain(const std::string& secret_key);

    // 将一条 JSON 审计行（以 '}' 结尾的对象）封链：
    // 追加 ",\"seq\":N,\"prev_hash\":\"...\",\"hmac\":\"...\"}"
    [[nodiscard]] std::string seal(const std::string& payload_json);

    // 校验整个审计文件（逐行验证 hash 链完整性与连续性）
    static bool verify_chain_file(const std::string& path, const std::string& secret_key);
    static bool verify_chain_file(const std::string& path, const std::string& secret_key,
                                  uint64_t& out_last_seq);

    [[nodiscard]] uint64_t last_seq() const { return seq_; }
    [[nodiscard]] std::string last_hash() const { return prev_hash_; }
    void reset();

private:
    std::string key_;
    uint64_t seq_ = 0;
    std::string prev_hash_;  // 创世值 = SHA256("PHOTON_SANDBOX_CHAIN_GENESIS")
};

// ---- 审计脱敏 ----
// 对审计记录中的敏感字段（用户代码、密钥、路径等）做脱敏，避免明文落盘/上报。
class AuditSanitizer {
public:
    AuditSanitizer();

    // 对单字段值脱敏：保留首尾 keep 个字符，中间用 '*' 填充
    [[nodiscard]] static std::string mask(const std::string& value, size_t keep = 2);

    // 注册敏感 key（精确匹配 JSON key）
    void add_sensitive_key(const std::string& key);
    void clear_sensitive_keys();
    [[nodiscard]] bool has_sensitive_key(const std::string& key) const;

    // 对一条审计 JSON 行脱敏：命中敏感 key 的字符串值调用 mask
    [[nodiscard]] std::string sanitize_json(const std::string& json_line) const;

private:
    std::set<std::string> sensitive_keys_;
};

} // namespace sandbox
} // namespace photon_kernel

#endif
