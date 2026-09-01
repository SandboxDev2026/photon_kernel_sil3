#include "photon_kernel/sandbox/audit_security.hpp"
// 条件编译：有 OpenSSL 用 OpenSSL，否则用纯 C++ 自实现（crypto_utils）
#if __has_include(<openssl/evp.h>) && defined(PHOTON_HAVE_OPENSSL)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#define PHOTON_USE_OPENSSL 1
#else
#include "photon_kernel/sandbox/crypto_utils.hpp"
#endif

#include <cstdio>
#include <fstream>
#include <sstream>

namespace photon_kernel {
namespace sandbox {

namespace {

// 小写 hex 编码
std::string to_hex(const unsigned char* data, size_t len) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(hex[data[i] >> 4]);
        out.push_back(hex[data[i] & 0x0F]);
    }
    return out;
}

} // namespace

std::string AuditHasher::hmac_sha256_hex(const std::string& key, const std::string& data) {
#ifdef PHOTON_USE_OPENSSL
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(),
         digest, &len);
    return to_hex(digest, len);
#else
    auto digest = crypto::hmac_sha256(key, data);
    return crypto::to_hex(digest);
#endif
}

std::string AuditHasher::sha256_hex(const std::string& data) {
#ifdef PHOTON_USE_OPENSSL
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);
    return to_hex(digest, SHA256_DIGEST_LENGTH);
#else
    auto digest = crypto::sha256(data);
    return crypto::to_hex(digest);
#endif
}

// ======================= AuditChain =======================

AuditChain::AuditChain(const std::string& secret_key) : key_(secret_key) {
    reset();
}

void AuditChain::reset() {
    seq_ = 0;
    prev_hash_ = AuditHasher::sha256_hex("PHOTON_SANDBOX_CHAIN_GENESIS");
}

std::string AuditChain::seal(const std::string& payload_json) {
    // 计算 hmac = HMAC(key, prev_hash + payload)
    std::string mac_input = prev_hash_ + payload_json;
    std::string hmac = AuditHasher::hmac_sha256_hex(key_, mac_input);

    // 输出：payload(去掉尾部 '}') + 链字段 + '}'
    std::string body = payload_json;
    if (!body.empty() && body.back() == '}') {
        body.pop_back();
    }
    std::ostringstream oss;
    oss << body << ",\"__chain\":{\"seq\":" << seq_
        << ",\"prev_hash\":\"" << prev_hash_
        << "\",\"hmac\":\"" << hmac << "\"}}";

    // 更新链状态
    prev_hash_ = hmac;
    ++seq_;
    return oss.str();
}

bool AuditChain::verify_chain_file(const std::string& path, const std::string& secret_key,
                                   uint64_t& out_last_seq) {
    std::ifstream f(path);
    if (!f.is_open()) return false;

    std::string expect_prev = AuditHasher::sha256_hex("PHOTON_SANDBOX_CHAIN_GENESIS");
    uint64_t expect_seq = 0;
    std::string line;
    uint64_t last_seq = 0;
    bool ok = true;

    while (std::getline(f, line)) {
        if (line.empty()) continue;
        // 提取 __chain 字段
        auto pos = line.find("\"__chain\":{");
        if (pos == std::string::npos) { ok = false; break; }
        auto seq_pos = line.find("\"seq\":", pos);
        if (seq_pos == std::string::npos) { ok = false; break; }
        auto seq_start = seq_pos + 6;
        auto seq_end = line.find(',', seq_start);
        uint64_t seq = std::strtoull(line.substr(seq_start, seq_end - seq_start).c_str(), nullptr, 10);

        auto ph_pos = line.find("\"prev_hash\":\"", pos);
        if (ph_pos == std::string::npos) { ok = false; break; }
        auto ph_start = ph_pos + 13;
        auto ph_end = line.find('"', ph_start);
        std::string prev_hash = line.substr(ph_start, ph_end - ph_start);

        auto hm_pos = line.find("\"hmac\":\"", pos);
        if (hm_pos == std::string::npos) { ok = false; break; }
        auto hm_start = hm_pos + 8;
        auto hm_end = line.find('"', hm_start);
        std::string hmac = line.substr(hm_start, hm_end - hm_start);

        // 连续性校验：seq 必须递增，prev_hash 必须等于上一条 hmac
        if (seq != expect_seq) { ok = false; break; }
        if (prev_hash != expect_prev) { ok = false; break; }

        // 完整性校验：用"去链字段后的 payload"重算 hmac
        // payload = line 去掉末尾的 ,"__chain":{...}}
        auto chain_body_pos = line.rfind(",\"__chain\":{");
        if (chain_body_pos == std::string::npos) { ok = false; break; }
        std::string payload = line.substr(0, chain_body_pos) + "}";
        std::string expect_hmac = AuditHasher::hmac_sha256_hex(secret_key, prev_hash + payload);
        if (hmac != expect_hmac) { ok = false; break; }

        expect_prev = hmac;
        ++expect_seq;
        last_seq = seq;
    }

    out_last_seq = last_seq;
    return ok && last_seq + 1 == expect_seq;
}

bool AuditChain::verify_chain_file(const std::string& path, const std::string& secret_key) {
    uint64_t dummy = 0;
    return verify_chain_file(path, secret_key, dummy);
}

// ======================= AuditSanitizer =======================

AuditSanitizer::AuditSanitizer() {
    // 默认敏感 key
    sensitive_keys_ = {"code", "token", "secret", "password", "api_key", "apikey",
                       "argv", "command", "cmdline", "path"};
}

void AuditSanitizer::add_sensitive_key(const std::string& key) {
    sensitive_keys_.insert(key);
}

void AuditSanitizer::clear_sensitive_keys() {
    sensitive_keys_.clear();
}

bool AuditSanitizer::has_sensitive_key(const std::string& key) const {
    return sensitive_keys_.count(key) > 0;
}

std::string AuditSanitizer::mask(const std::string& value, size_t keep) {
    if (value.size() <= keep * 2) {
        return std::string(value.size(), '*');
    }
    std::string out = value.substr(0, keep);
    out.append(value.size() - keep * 2, '*');
    out += value.substr(value.size() - keep);
    return out;
}

std::string AuditSanitizer::sanitize_json(const std::string& json_line) const {
    if (sensitive_keys_.empty()) return json_line;

    std::string out = json_line;
    // 对 "key":"value" 形式的敏感 key 做脱敏（简单文本扫描，适用于自生成审计 JSON）
    for (const auto& key : sensitive_keys_) {
        std::string needle = "\"" + key + "\":\"";
        size_t pos = 0;
        while ((pos = out.find(needle, pos)) != std::string::npos) {
            size_t val_start = pos + needle.size();
            size_t val_end = out.find('"', val_start);
            if (val_end == std::string::npos) break;
            std::string val = out.substr(val_start, val_end - val_start);
            std::string masked = mask(val);
            out.replace(val_start, val_end - val_start, masked);
            pos = val_start + masked.size();
        }
    }
    return out;
}

} // namespace sandbox
} // namespace photon_kernel
