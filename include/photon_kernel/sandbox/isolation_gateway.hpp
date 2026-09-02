#ifndef PHOTON_KERNEL_SANDBOX_ISOLATION_GATEWAY_HPP
#define PHOTON_KERNEL_SANDBOX_ISOLATION_GATEWAY_HPP
// 隔离网关 —— 边界代理网关（第二层防御）
//
// 所有沙盒流量强制经过代理网关，沙盒本身没有直接路由。
// 网关做统一处理：
//   1. 域名/IP白黑名单
//   2. 出站速率限流、连接数限制，防DoS
//   3. DNS劫持与校验，防止DNS隧道、内网域名解析
//   4. 网络访问审计日志，每一条连接记录租户ID、CapabilityToken票据
//   5. 审批模式：高危外部网络请求进入人工审批（对接Policy+Identity平面）
//
// 两种实现形态：
//   1. Sidecar 模式：每个沙盒Pod附带sidecar代理（istio/envoy）
//   2. 集中式隔离网关：沙盒子网唯一网关出口
//
// 关键点：沙盒内部配置默认网关指向隔离网关；沙盒不能绕过网关直接发包。
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <chrono>
#include <memory>
namespace photon_kernel {
namespace sandbox {
// 网关模式
enum class GatewayMode {
    SIDECAR,     // Sidecar 模式（每个沙盒附带代理）
    CENTRALIZED, // 集中式隔离网关（沙盒子网唯一出口）
};
// 连接记录
struct ConnectionRecord {
    std::string connection_id;
    std::string tenant_id;
    std::string capability_token_id;
    std::string sandbox_id;
    std::string src_ip;
    uint16_t src_port = 0;
    std::string dest_ip;
    std::string dest_domain;  // 解析后的域名（如果有）
    uint16_t dest_port = 0;
    std::string protocol;  // tcp/udp/http/https
    std::chrono::system_clock::time_point timestamp;
    size_t bytes_sent = 0;
    size_t bytes_received = 0;
    std::chrono::milliseconds duration{0};
    std::string decision;  // ALLOW/DENY/APPROVED
    std::string audit_hash;  // HMAC审计哈希链
};
// 限流配置
struct RateLimitConfig {
    size_t max_connections_per_sandbox = 64;     // 每个沙盒最大并发连接
    size_t max_new_connections_per_second = 10;   // 每秒新建连接数
    size_t max_bandwidth_mbps = 100;               // 带宽限制（0=不限制）
    size_t max_requests_per_minute = 600;          // 每分钟请求数
    size_t max_bytes_per_connection = 10 * 1024 * 1024;  // 单连接最大字节数
};
// 域名规则
struct DomainRule {
    std::string domain;      // 域名（支持 *.example.com 通配符）
    bool allowed = true;     // true=白名单, false=黑名单
    bool require_approval = false;  // 是否需要审批
    std::vector<uint16_t> allowed_ports;  // 允许的端口（空=全部）
    std::string description;
};
// 网关配置
struct IsolationGatewayConfig {
    GatewayMode mode = GatewayMode::CENTRALIZED;
    std::string listen_address = "0.0.0.0";
    uint16_t listen_port = 8080;
    std::string dns_server = "127.0.0.1";
    uint16_t dns_port = 53;
    bool enable_dns_hijack = true;
    bool enable_audit_logging = true;
    bool enable_rate_limiting = true;
    bool enable_approval_mode = false;  // 审批模式（高危请求需人工审批）
    RateLimitConfig rate_limit;
    std::vector<DomainRule> domain_rules;
    std::vector<std::string> ip_whitelist;
    std::vector<std::string> ip_blacklist;
    // 内网隔离（第三层防御，在网关再次校验）
    bool enable_internal_network_block = true;
};
// 隔离网关
class IsolationGateway {
public:
    explicit IsolationGateway(const IsolationGatewayConfig& config = {});
    // 评估连接请求
    enum class GatewayDecision {
        ALLOW,           // 允许
        DENY,            // 拒绝
        REQUIRE_APPROVAL, // 需要审批
        RATE_LIMITED,    // 限流
        DNS_BLOCKED,     // DNS被拦截
    };
    struct ConnectionEvaluation {
        GatewayDecision decision;
        std::string reason;
        std::string connection_id;
        std::chrono::system_clock::time_point timestamp;
    };
    ConnectionEvaluation evaluate_connection(const std::string& sandbox_id,
                                               const std::string& tenant_id,
                                               const std::string& token_id,
                                               const std::string& dest_ip,
                                               const std::string& dest_domain,
                                               uint16_t dest_port,
                                               const std::string& protocol);
    // 记录连接完成
    void record_connection_complete(const std::string& connection_id,
                                     size_t bytes_sent, size_t bytes_received,
                                     std::chrono::milliseconds duration);
    // 添加域名规则
    void add_domain_rule(const DomainRule& rule);
    // 批量添加白名单域名
    void allow_domain(const std::string& domain, const std::string& description = "");
    // 批量添加黑名单域名
    void deny_domain(const std::string& domain, const std::string& description = "");
    // DNS 查询评估（防止DNS隧道、内网域名解析）
    bool is_dns_query_allowed(const std::string& domain, const std::string& query_type) const;
    // 获取审计日志
    std::vector<ConnectionRecord> audit_logs(size_t limit = 100) const;
    // 获取统计
    size_t total_connections() const { return total_connections_; }
    size_t allowed_connections() const { return allowed_; }
    size_t denied_connections() const { return denied_; }
    size_t rate_limited_connections() const { return rate_limited_; }
    // 配置
    const IsolationGatewayConfig& config() const { return config_; }
    // 生成 envoy 配置（Sidecar 模式）
    std::string generate_envoy_config() const;
    // 生成 iptables 规则（集中式网关模式）
    std::vector<std::string> generate_iptables_rules() const;
    // 生成 K8s NetworkPolicy
    std::string generate_k8s_network_policy() const;
private:
    IsolationGatewayConfig config_;
    mutable std::mutex mtx_;
    std::unordered_map<std::string, ConnectionRecord> connections_;
    std::unordered_map<std::string, size_t> sandbox_connection_counts_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_request_time_;
    size_t total_connections_ = 0;
    size_t allowed_ = 0;
    size_t denied_ = 0;
    size_t rate_limited_ = 0;
    std::string last_audit_hash_;
    // 域名匹配（支持通配符）
    bool domain_matches(const std::string& domain, const std::string& pattern) const;
    // 检查限流
    bool check_rate_limit(const std::string& sandbox_id);
    // 生成连接ID
    std::string generate_connection_id() const;
    // 审计记录
    void audit_connection(ConnectionRecord& record);
};
} // namespace sandbox
} // namespace photon_kernel
#endif
