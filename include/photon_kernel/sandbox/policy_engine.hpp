#ifndef PHOTON_KERNEL_SANDBOX_POLICY_ENGINE_HPP
#define PHOTON_KERNEL_SANDBOX_POLICY_ENGINE_HPP
// Policy + Identity —— 策略与身份平面
//
// 职责：对网络出口、凭证和工具调用逐次做允许、拒绝或审批
//
// 三大策略决策点：
//   1. NetworkPolicy: 网络出口白名单/黑名单/审批
//   2. PolicyCredentialVault: 凭证管理（不落入沙盒，代理中转）
//   3. ToolPolicy: 工具调用逐次允许/拒绝/审批
//
// 决策结果：ALLOW / DENY / REQUIRE_APPROVAL
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <chrono>
#include <functional>
namespace photon_kernel {
namespace sandbox {
// 决策结果
enum class PolicyDecision {
    ALLOW,              // 允许
    DENY,               // 拒绝
    REQUIRE_APPROVAL,   // 需要审批
};
std::string policy_decision_name(PolicyDecision d);
// 网络请求
struct NetworkRequest {
    std::string source_ip;
    std::string dest_ip;
    uint16_t dest_port = 0;
    std::string protocol;  // tcp/udp/icmp
    std::string domain;    // 目标域名（如果有）
    size_t bytes = 0;
    std::string task_id;
    std::string tenant_id;
};
// 工具调用请求
struct ToolCallRequest {
    std::string tool_name;
    std::string args;
    std::string caller_id;    // 调用方 ID
    std::string task_id;
    std::string tenant_id;
    std::chrono::system_clock::time_point timestamp;
};
// 凭证请求
struct CredentialRequest {
    std::string credential_id;
    std::string caller_id;
    std::string task_id;
    std::string tenant_id;
    std::string purpose;  // 使用目的
};
// 审批请求
struct ApprovalRequest {
    std::string id;
    std::string type;       // network/tool/credential
    std::string requester;
    std::string description;
    std::string reason;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;
    bool approved = false;
    std::string approver;
};
// 网络策略
class NetworkPolicy {
public:
    NetworkPolicy();
    // 评估网络请求
    PolicyDecision evaluate(const NetworkRequest& req) const;
    // 添加允许的 CIDR
    void allow_cidr(const std::string& cidr);
    // 添加拒绝的 CIDR
    void deny_cidr(const std::string& cidr);
    // 添加允许的端口
    void allow_port(uint16_t port);
    // 设置默认策略
    void set_default(PolicyDecision d) { default_decision_ = d; }
    // 是否启用 DNS
    void set_allow_dns(bool allow) { allow_dns_ = allow; }
private:
    mutable std::mutex mtx_;
    std::unordered_set<std::string> allow_cidrs_;
    std::unordered_set<std::string> deny_cidrs_;
    std::unordered_set<uint16_t> allow_ports_;
    PolicyDecision default_decision_ = PolicyDecision::DENY;
    bool allow_dns_ = true;
    bool cidr_match(const std::string& ip, const std::string& cidr) const;
};
// 凭证保险箱（借鉴 OpenSandbox Credential Vault）
class PolicyCredentialVault {
public:
    static PolicyCredentialVault& instance();
    // 存储凭证（加密存储，不落入沙盒）
    bool store(const std::string& id, const std::string& value,
               const std::string& tenant_id, const std::vector<std::string>& allowed_callers);
    // 获取凭证（经过权限校验）
    std::string get(const CredentialRequest& req, PolicyDecision& decision) const;
    // 检查凭证是否存在
    bool exists(const std::string& id) const;
    // 删除凭证
    bool remove(const std::string& id);
    // 列出凭证 ID（不返回值）
    std::vector<std::string> list(const std::string& tenant_id) const;
    // 空白通行证：无权限时返回虚拟替身数据
    std::string dummy_value(const std::string& id) const;
private:
    PolicyCredentialVault() = default;
    struct Credential {
        std::string id;
        std::string encrypted_value;  // 加密后的值
        std::string tenant_id;
        std::vector<std::string> allowed_callers;
        std::chrono::system_clock::time_point created_at;
    };
    mutable std::mutex mtx_;
    std::unordered_map<std::string, Credential> credentials_;
    // 简单加密（生产环境应用 AES-256-GCM + KMS）
    std::string encrypt(const std::string& value) const;
    std::string decrypt(const std::string& encrypted) const;
};
// 工具策略
class ToolPolicy {
public:
    ToolPolicy();
    // 评估工具调用
    PolicyDecision evaluate(const ToolCallRequest& req) const;
    // 注册工具策略
    void register_tool(const std::string& name, bool enabled,
                       bool require_approval = false, int max_calls = 100);
    // 禁用工具
    void disable_tool(const std::string& name);
    // 记录调用（用于限流）
    void record_call(const std::string& tool_name, const std::string& caller_id);
private:
    struct ToolRule {
        bool enabled = true;
        bool require_approval = false;
        int max_calls = 100;
        std::unordered_map<std::string, int> call_counts;  // caller_id -> count
    };
    mutable std::mutex mtx_;
    std::unordered_map<std::string, ToolRule> rules_;
};
// 审批管理器
class ApprovalManager {
public:
    static ApprovalManager& instance();
    // 创建审批请求
    std::string create_request(const std::string& type, const std::string& requester,
                                const std::string& description, const std::string& reason,
                                std::chrono::seconds ttl = std::chrono::minutes(5));
    // 审批通过
    bool approve(const std::string& id, const std::string& approver);
    // 审批拒绝
    bool reject(const std::string& id, const std::string& approver);
    // 检查是否已审批
    bool is_approved(const std::string& id) const;
    // 获取待审批列表
    std::vector<ApprovalRequest> pending() const;
    // 清理过期请求
    void cleanup_expired();
private:
    ApprovalManager() = default;
    mutable std::mutex mtx_;
    std::unordered_map<std::string, ApprovalRequest> requests_;
};
// 策略引擎（统一决策点）
class PolicyEngine {
public:
    static PolicyEngine& instance();
    // 评估网络请求
    PolicyDecision evaluate_network(const NetworkRequest& req);
    // 评估工具调用
    PolicyDecision evaluate_tool(const ToolCallRequest& req);
    // 评估凭证请求
    PolicyDecision evaluate_credential(const CredentialRequest& req);
    // 获取各策略组件
    NetworkPolicy& network_policy() { return network_; }
    ToolPolicy& tool_policy() { return tool_; }
    PolicyCredentialVault& credential_vault() { return PolicyCredentialVault::instance(); }
    ApprovalManager& approval_manager() { return ApprovalManager::instance(); }
    // 统计
    size_t total_decisions() const { return total_decisions_; }
    size_t allowed_count() const { return allowed_; }
    size_t denied_count() const { return denied_; }
    size_t approval_count() const { return approvals_; }
private:
    PolicyEngine() = default;
    NetworkPolicy network_;
    ToolPolicy tool_;
    mutable std::mutex mtx_;
    size_t total_decisions_ = 0;
    size_t allowed_ = 0;
    size_t denied_ = 0;
    size_t approvals_ = 0;
    void record_decision(PolicyDecision d);
};
} // namespace sandbox
} // namespace photon_kernel
#endif
