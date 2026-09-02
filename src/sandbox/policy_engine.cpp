// 策略引擎实现：NetworkPolicy + PolicyCredentialVault + ToolPolicy + ApprovalManager + PolicyEngine
#include "photon_kernel/sandbox/policy_engine.hpp"
#include "photon_kernel/sandbox/crypto_utils.hpp"
#include <random>
#include <sstream>
#include <iomanip>
namespace photon_kernel {
namespace sandbox {
std::string policy_decision_name(PolicyDecision d) {
    switch (d) {
        case PolicyDecision::ALLOW: return "ALLOW";
        case PolicyDecision::DENY: return "DENY";
        case PolicyDecision::REQUIRE_APPROVAL: return "REQUIRE_APPROVAL";
    }
    return "UNKNOWN";
}
// ==================== NetworkPolicy ====================
NetworkPolicy::NetworkPolicy() {
    // 默认允许本地回环
    allow_cidrs_.insert("127.0.0.1/32");
    allow_cidrs_.insert("::1/128");
}
bool NetworkPolicy::cidr_match(const std::string& ip, const std::string& cidr) const {
    // 简化 CIDR 匹配（生产环境应用完整的 IP 前缀匹配）
    size_t slash = cidr.find('/');
    if (slash == std::string::npos) return ip == cidr;
    std::string network = cidr.substr(0, slash);
    // 简单前缀匹配（/24, /16, /8）
    std::string prefix_len = cidr.substr(slash + 1);
    int prefix = std::stoi(prefix_len);
    if (prefix >= 24) {
        // 匹配前3个字节
        size_t last_dot = network.rfind('.');
        if (last_dot == std::string::npos) return false;
        std::string net_prefix = network.substr(0, last_dot);
        return ip.substr(0, ip.rfind('.')) == net_prefix;
    }
    return ip.substr(0, 3) == network.substr(0, 3);  // 简化
}
PolicyDecision NetworkPolicy::evaluate(const NetworkRequest& req) const {
    std::lock_guard<std::mutex> lock(mtx_);
    // DNS 特殊处理
    if (req.dest_port == 53 && allow_dns_) {
        return PolicyDecision::ALLOW;
    }
    // 检查拒绝列表（优先）
    for (const auto& cidr : deny_cidrs_) {
        if (cidr_match(req.dest_ip, cidr)) {
            return PolicyDecision::DENY;
        }
    }
    // 检查允许列表
    for (const auto& cidr : allow_cidrs_) {
        if (cidr_match(req.dest_ip, cidr)) {
            // 检查端口
            if (!allow_ports_.empty() && allow_ports_.find(req.dest_port) == allow_ports_.end()) {
                return PolicyDecision::DENY;
            }
            return PolicyDecision::ALLOW;
        }
    }
    return default_decision_;
}
void NetworkPolicy::allow_cidr(const std::string& cidr) {
    std::lock_guard<std::mutex> lock(mtx_);
    allow_cidrs_.insert(cidr);
}
void NetworkPolicy::deny_cidr(const std::string& cidr) {
    std::lock_guard<std::mutex> lock(mtx_);
    deny_cidrs_.insert(cidr);
}
void NetworkPolicy::allow_port(uint16_t port) {
    std::lock_guard<std::mutex> lock(mtx_);
    allow_ports_.insert(port);
}
// ==================== PolicyCredentialVault ====================
PolicyCredentialVault& PolicyCredentialVault::instance() {
    static PolicyCredentialVault vault;
    return vault;
}
std::string PolicyCredentialVault::encrypt(const std::string& value) const {
    // 简单 XOR 加密（生产环境应用 AES-256-GCM + KMS）
    std::string key = "photon-credential-vault-key-2026";
    std::string result = value;
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] ^= key[i % key.size()];
    }
    return result;
}
std::string PolicyCredentialVault::decrypt(const std::string& encrypted) const {
    return encrypt(encrypted);  // XOR 对称
}
bool PolicyCredentialVault::store(const std::string& id, const std::string& value,
                              const std::string& tenant_id,
                              const std::vector<std::string>& allowed_callers) {
    std::lock_guard<std::mutex> lock(mtx_);
    Credential cred;
    cred.id = id;
    cred.encrypted_value = encrypt(value);
    cred.tenant_id = tenant_id;
    cred.allowed_callers = allowed_callers;
    cred.created_at = std::chrono::system_clock::now();
    credentials_[id] = cred;
    return true;
}
std::string PolicyCredentialVault::get(const CredentialRequest& req, PolicyDecision& decision) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = credentials_.find(req.credential_id);
    if (it == credentials_.end()) {
        decision = PolicyDecision::DENY;
        return "";
    }
    // 检查租户
    if (it->second.tenant_id != req.tenant_id) {
        decision = PolicyDecision::DENY;
        return "";
    }
    // 检查调用方权限
    bool allowed = false;
    for (const auto& caller : it->second.allowed_callers) {
        if (caller == req.caller_id || caller == "*") {
            allowed = true;
            break;
        }
    }
    if (!allowed) {
        decision = PolicyDecision::REQUIRE_APPROVAL;
        return dummy_value(req.credential_id);
    }
    decision = PolicyDecision::ALLOW;
    return decrypt(it->second.encrypted_value);
}
bool PolicyCredentialVault::exists(const std::string& id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    return credentials_.find(id) != credentials_.end();
}
bool PolicyCredentialVault::remove(const std::string& id) {
    std::lock_guard<std::mutex> lock(mtx_);
    return credentials_.erase(id) > 0;
}
std::vector<std::string> PolicyCredentialVault::list(const std::string& tenant_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<std::string> result;
    for (const auto& [id, cred] : credentials_) {
        if (cred.tenant_id == tenant_id) result.push_back(id);
    }
    return result;
}
std::string PolicyCredentialVault::dummy_value(const std::string& id) const {
    // 空白通行证：返回虚拟替身数据（借鉴澎湃OS空白通行证）
    if (id.find("api_key") != std::string::npos || id.find("apikey") != std::string::npos) {
        return "sk-dummy-xxxxxxxxxxxxxxxxxxxxxxxx";
    }
    if (id.find("password") != std::string::npos) {
        return "dummy_password_12345";
    }
    if (id.find("token") != std::string::npos) {
        return "dummy_token_xxxxxxxxxxxxxxxx";
    }
    return "dummy_value_for_" + id;
}
// ==================== ToolPolicy ====================
ToolPolicy::ToolPolicy() = default;
void ToolPolicy::register_tool(const std::string& name, bool enabled,
                                 bool require_approval, int max_calls) {
    std::lock_guard<std::mutex> lock(mtx_);
    ToolRule rule;
    rule.enabled = enabled;
    rule.require_approval = require_approval;
    rule.max_calls = max_calls;
    rules_[name] = rule;
}
void ToolPolicy::disable_tool(const std::string& name) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = rules_.find(name);
    if (it != rules_.end()) it->second.enabled = false;
}
void ToolPolicy::record_call(const std::string& tool_name, const std::string& caller_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = rules_.find(tool_name);
    if (it != rules_.end()) {
        it->second.call_counts[caller_id]++;
    }
}
PolicyDecision ToolPolicy::evaluate(const ToolCallRequest& req) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = rules_.find(req.tool_name);
    if (it == rules_.end()) {
        return PolicyDecision::DENY;  // 未注册的工具默认拒绝
    }
    if (!it->second.enabled) {
        return PolicyDecision::DENY;
    }
    // 检查调用次数限制
    auto count_it = it->second.call_counts.find(req.caller_id);
    if (count_it != it->second.call_counts.end() && count_it->second >= it->second.max_calls) {
        return PolicyDecision::DENY;  // 超过调用次数
    }
    if (it->second.require_approval) {
        return PolicyDecision::REQUIRE_APPROVAL;
    }
    return PolicyDecision::ALLOW;
}
// ==================== ApprovalManager ====================
ApprovalManager& ApprovalManager::instance() {
    static ApprovalManager mgr;
    return mgr;
}
std::string ApprovalManager::create_request(const std::string& type,
                                              const std::string& requester,
                                              const std::string& description,
                                              const std::string& reason,
                                              std::chrono::seconds ttl) {
    std::lock_guard<std::mutex> lock(mtx_);
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
    std::ostringstream oss;
    oss << "approval-" << std::hex << std::setfill('0') << std::setw(8) << dis(gen);
    std::string id = oss.str();
    ApprovalRequest req;
    req.id = id;
    req.type = type;
    req.requester = requester;
    req.description = description;
    req.reason = reason;
    req.created_at = std::chrono::system_clock::now();
    req.expires_at = req.created_at + ttl;
    requests_[id] = req;
    return id;
}
bool ApprovalManager::approve(const std::string& id, const std::string& approver) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = requests_.find(id);
    if (it == requests_.end()) return false;
    if (std::chrono::system_clock::now() > it->second.expires_at) return false;
    it->second.approved = true;
    it->second.approver = approver;
    return true;
}
bool ApprovalManager::reject(const std::string& id, const std::string& approver) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = requests_.find(id);
    if (it == requests_.end()) return false;
    it->second.approved = false;
    it->second.approver = approver;
    return true;
}
bool ApprovalManager::is_approved(const std::string& id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = requests_.find(id);
    if (it == requests_.end()) return false;
    if (std::chrono::system_clock::now() > it->second.expires_at) return false;
    return it->second.approved;
}
std::vector<ApprovalRequest> ApprovalManager::pending() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<ApprovalRequest> result;
    auto now = std::chrono::system_clock::now();
    for (const auto& [id, req] : requests_) {
        if (!req.approved && now < req.expires_at) {
            result.push_back(req);
        }
    }
    return result;
}
void ApprovalManager::cleanup_expired() {
    std::lock_guard<std::mutex> lock(mtx_);
    auto now = std::chrono::system_clock::now();
    for (auto it = requests_.begin(); it != requests_.end(); ) {
        if (now > it->second.expires_at) {
            it = requests_.erase(it);
        } else {
            ++it;
        }
    }
}
// ==================== PolicyEngine ====================
PolicyEngine& PolicyEngine::instance() {
    static PolicyEngine engine;
    return engine;
}
void PolicyEngine::record_decision(PolicyDecision d) {
    std::lock_guard<std::mutex> lock(mtx_);
    total_decisions_++;
    switch (d) {
        case PolicyDecision::ALLOW: allowed_++; break;
        case PolicyDecision::DENY: denied_++; break;
        case PolicyDecision::REQUIRE_APPROVAL: approvals_++; break;
    }
}
PolicyDecision PolicyEngine::evaluate_network(const NetworkRequest& req) {
    PolicyDecision d = network_.evaluate(req);
    record_decision(d);
    return d;
}
PolicyDecision PolicyEngine::evaluate_tool(const ToolCallRequest& req) {
    PolicyDecision d = tool_.evaluate(req);
    if (d == PolicyDecision::ALLOW) {
        tool_.record_call(req.tool_name, req.caller_id);
    }
    record_decision(d);
    return d;
}
PolicyDecision PolicyEngine::evaluate_credential(const CredentialRequest& req) {
    PolicyDecision d = PolicyDecision::DENY;
    PolicyCredentialVault::instance().get(req, d);
    record_decision(d);
    return d;
}
} // namespace sandbox
} // namespace photon_kernel
