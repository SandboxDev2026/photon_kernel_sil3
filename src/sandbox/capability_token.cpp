// CapabilityToken 实现：票据签发、HMAC 签名、验证、运行时撤销。
#include "photon_kernel/sandbox/capability_token.hpp"
#include "photon_kernel/sandbox/crypto_utils.hpp"
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>
namespace photon_kernel {
namespace sandbox {
// ==================== CapabilityToken ====================
std::string CapabilityToken::serialize_for_signing() const {
    std::ostringstream oss;
    oss << token_id << "|" << sandbox_id << "|" << issuer << "|"
        << std::chrono::duration_cast<std::chrono::seconds>(issued_at.time_since_epoch()).count() << "|"
        << std::chrono::duration_cast<std::chrono::seconds>(expires_at.time_since_epoch()).count() << "|"
        << static_cast<uint32_t>(capabilities) << "|"
        << cpu_limit_ms << "|" << memory_limit_bytes << "|"
        << max_processes << "|" << max_open_files << "|";
    for (const auto& p : allowed_exec_paths) oss << p << ",";
    oss << "|";
    for (const auto& nr : network_rules) oss << nr.cidr << ":" << nr.port_min << "-" << nr.port_max << "/" << nr.protocol << ",";
    oss << "|";
    for (const auto& pr : path_rules) oss << pr.path << ":" << (pr.read?1:0) << (pr.write?1:0) << (pr.execute?1:0) << ",";
    return oss.str();
}
bool CapabilityToken::is_expired() const {
    return std::chrono::system_clock::now() > expires_at;
}
bool CapabilityToken::has(Capability cap) const {
    return has_capability(capabilities, cap);
}
bool CapabilityToken::can_exec(const std::string& path) const {
    if (!has(Capability::EXEC)) return false;
    if (allowed_exec_paths.empty()) return true;  // 空列表 = 不限制
    for (const auto& p : allowed_exec_paths) {
        if (path == p) return true;
    }
    return false;
}
bool CapabilityToken::can_network(const std::string& ip, uint16_t port, const std::string& proto) const {
    if (!has(Capability::NETWORK)) return false;
    if (network_rules.empty()) return true;  // 空列表 = 不限制
    for (const auto& rule : network_rules) {
        if (port >= rule.port_min && port <= rule.port_max &&
            (rule.protocol.empty() || rule.protocol == proto)) {
            // 简化 CIDR 匹配：按网络前缀匹配（生产环境应用 inet_pton + 位运算）
            if (rule.cidr == "0.0.0.0/0" || rule.cidr == "::/0") return true;
            size_t slash = rule.cidr.find('/');
            if (slash == std::string::npos) {
                if (ip == rule.cidr) return true;
            } else {
                std::string network = rule.cidr.substr(0, slash);
                // 取最后一个 "." 之前的部分作为网络前缀（含 "."）
                size_t last_dot = network.rfind('.');
                if (last_dot != std::string::npos) {
                    std::string net_prefix = network.substr(0, last_dot + 1);
                    if (ip.substr(0, net_prefix.length()) == net_prefix) return true;
                } else {
                    if (ip == network) return true;
                }
            }
        }
    }
    return false;
}
bool CapabilityToken::can_file(const std::string& path, bool write) const {
    Capability needed = write ? Capability::FILE_WRITE : Capability::FILE_READ;
    if (!has(needed)) return false;
    if (path_rules.empty()) return true;  // 空列表 = 不限制
    for (const auto& rule : path_rules) {
        if (path.find(rule.path) == 0) {  // 前缀匹配
            if (write && !rule.write) return false;
            if (!write && !rule.read) return false;
            return true;
        }
    }
    return false;
}
std::string CapabilityToken::to_json() const {
    std::ostringstream oss;
    oss << "{\"token_id\":\"" << token_id << "\","
        << "\"sandbox_id\":\"" << sandbox_id << "\","
        << "\"issuer\":\"" << issuer << "\","
        << "\"capabilities\":" << static_cast<uint32_t>(capabilities) << ","
        << "\"cpu_limit_ms\":" << cpu_limit_ms << ","
        << "\"memory_limit_bytes\":" << memory_limit_bytes << ","
        << "\"max_processes\":" << max_processes << ","
        << "\"max_open_files\":" << max_open_files << ","
        << "\"hmac\":\"" << hmac_signature << "\"}";
    return oss.str();
}
std::optional<CapabilityToken> CapabilityToken::from_json(const std::string& json) {
    // 简化 JSON 解析（生产环境应用完整 JSON 库）
    CapabilityToken t;
    auto extract = [&](const std::string& key) -> std::string {
        std::string search = "\"" + key + "\":";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return "";
        pos += search.length();
        if (json[pos] == '"') {
            pos++;
            size_t end = json.find('"', pos);
            return json.substr(pos, end - pos);
        } else {
            size_t end = json.find_first_of(",}", pos);
            return json.substr(pos, end - pos);
        }
    };
    t.token_id = extract("token_id");
    t.sandbox_id = extract("sandbox_id");
    t.issuer = extract("issuer");
    t.capabilities = static_cast<Capability>(std::stoul(extract("capabilities")));
    t.cpu_limit_ms = std::stoull(extract("cpu_limit_ms"));
    t.memory_limit_bytes = std::stoull(extract("memory_limit_bytes"));
    t.max_processes = std::stoul(extract("max_processes"));
    t.max_open_files = std::stoul(extract("max_open_files"));
    t.hmac_signature = extract("hmac");
    if (t.token_id.empty()) return std::nullopt;
    return t;
}
// ==================== CapabilityTokenManager ====================
CapabilityTokenManager::CapabilityTokenManager(std::string hmac_key)
    : hmac_key_(std::move(hmac_key)) {}
std::string CapabilityTokenManager::generate_uuid() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    oss << std::setw(8) << dis(gen) << "-"
        << std::setw(4) << (dis(gen) & 0xFFFF) << "-"
        << std::setw(4) << ((dis(gen) & 0x0FFF) | 0x4000) << "-"
        << std::setw(4) << ((dis(gen) & 0x3FFF) | 0x8000) << "-"
        << std::setw(12) << dis(gen) << dis(gen) % 0xFFFF;
    return oss.str();
}
std::string CapabilityTokenManager::sign(const std::string& data) const {
    auto digest = crypto::hmac_sha256(
        reinterpret_cast<const uint8_t*>(hmac_key_.data()), hmac_key_.size(),
        reinterpret_cast<const uint8_t*>(data.data()), data.size());
    return crypto::to_hex(digest);
}
CapabilityToken CapabilityTokenManager::issue(
        const std::string& sandbox_id,
        Capability caps,
        std::chrono::seconds ttl) {
    std::lock_guard<std::mutex> lock(mtx_);
    CapabilityToken token;
    token.token_id = generate_uuid();
    token.sandbox_id = sandbox_id;
    token.issuer = "photon-controller";
    token.issued_at = std::chrono::system_clock::now();
    token.expires_at = token.issued_at + ttl;
    token.capabilities = caps;
    token.hmac_signature = sign(token.serialize_for_signing());
    active_[token.token_id] = token;
    return token;
}
bool CapabilityTokenManager::verify(const CapabilityToken& token) const {
    std::lock_guard<std::mutex> lock(mtx_);
    // 1. 检查撤销列表
    if (revoked_.count(token.token_id)) return false;
    // 2. 检查过期
    if (token.is_expired()) return false;
    // 3. 验证 HMAC 签名
    std::string expected = sign(token.serialize_for_signing());
    if (expected != token.hmac_signature) return false;
    // 4. 检查是否在 active 列表中（可选，允许无状态验证）
    return true;
}
void CapabilityTokenManager::revoke(const std::string& token_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    revoked_.insert(token_id);
    active_.erase(token_id);
}
void CapabilityTokenManager::revoke_all_for_sandbox(const std::string& sandbox_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto it = active_.begin(); it != active_.end(); ) {
        if (it->second.sandbox_id == sandbox_id) {
            revoked_.insert(it->first);
            it = active_.erase(it);
        } else {
            ++it;
        }
    }
}
bool CapabilityTokenManager::is_revoked(const std::string& token_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    return revoked_.count(token_id) > 0;
}
std::optional<CapabilityToken> CapabilityTokenManager::recall_capability(
        const std::string& token_id, Capability to_remove) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = active_.find(token_id);
    if (it == active_.end()) return std::nullopt;
    // 旧票据加入撤销列表
    revoked_.insert(token_id);
    active_.erase(it);
    // 签发新票据（移除指定能力）
    CapabilityToken new_token = it->second;
    new_token.token_id = generate_uuid();
    new_token.issued_at = std::chrono::system_clock::now();
    new_token.capabilities = static_cast<Capability>(
        static_cast<uint32_t>(new_token.capabilities) & ~static_cast<uint32_t>(to_remove));
    new_token.hmac_signature = sign(new_token.serialize_for_signing());
    active_[new_token.token_id] = new_token;
    return new_token;
}
size_t CapabilityTokenManager::active_count() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return active_.size();
}
size_t CapabilityTokenManager::revoked_count() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return revoked_.size();
}
} // namespace sandbox
} // namespace photon_kernel
