// 隔离网关实现：域名白名单+限流+DNS劫持+审计+审批对接+envoy/iptables/K8s配置生成
#include "photon_kernel/sandbox/isolation_gateway.hpp"
#include "photon_kernel/sandbox/network_isolation.hpp"
#include "photon_kernel/sandbox/crypto_utils.hpp"
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>
namespace photon_kernel {
namespace sandbox {
IsolationGateway::IsolationGateway(const IsolationGatewayConfig& config)
    : config_(config) {}
std::string IsolationGateway::generate_connection_id() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
    std::ostringstream oss;
    oss << "conn-" << std::hex << std::setfill('0')
        << std::setw(8) << dis(gen) << std::setw(8) << dis(gen);
    return oss.str();
}
bool IsolationGateway::domain_matches(const std::string& domain,
                                       const std::string& pattern) const {
    if (pattern == domain) return true;
    // 通配符匹配 *.example.com
    if (pattern.substr(0, 2) == "*.") {
        std::string suffix = pattern.substr(1);  // .example.com
        if (domain.size() >= suffix.size()) {
            return domain.compare(domain.size() - suffix.size(), suffix.size(), suffix) == 0;
        }
    }
    return false;
}
bool IsolationGateway::check_rate_limit(const std::string& sandbox_id) {
    if (!config_.enable_rate_limiting) return true;
    auto now = std::chrono::steady_clock::now();
    // 检查并发连接数
    auto count_it = sandbox_connection_counts_.find(sandbox_id);
    if (count_it != sandbox_connection_counts_.end() &&
        count_it->second >= config_.rate_limit.max_connections_per_sandbox) {
        return false;
    }
    // 检查每秒新建连接数
    auto time_it = last_request_time_.find(sandbox_id);
    if (time_it != last_request_time_.end()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - time_it->second).count();
        if (elapsed < 1000 / config_.rate_limit.max_new_connections_per_second) {
            return false;
        }
    }
    last_request_time_[sandbox_id] = now;
    return true;
}
void IsolationGateway::audit_connection(ConnectionRecord& record) {
    if (!config_.enable_audit_logging) return;
    // HMAC审计哈希链
    std::string data = record.connection_id + "|" + record.tenant_id + "|" +
        record.capability_token_id + "|" + record.dest_ip + "|" +
        std::to_string(record.dest_port) + "|" + record.decision + "|" + last_audit_hash_;
    auto digest = crypto::hmac_sha256(
        reinterpret_cast<const uint8_t*>("photon-gateway-audit"), 20,
        reinterpret_cast<const uint8_t*>(data.data()), data.size());
    record.audit_hash = crypto::to_hex(digest);
    last_audit_hash_ = record.audit_hash;
}
IsolationGateway::ConnectionEvaluation IsolationGateway::evaluate_connection(
    const std::string& sandbox_id, const std::string& tenant_id,
    const std::string& token_id, const std::string& dest_ip,
    const std::string& dest_domain, uint16_t dest_port,
    const std::string& protocol) {
    std::lock_guard<std::mutex> lock(mtx_);
    total_connections_++;
    ConnectionEvaluation eval;
    eval.connection_id = generate_connection_id();
    eval.timestamp = std::chrono::system_clock::now();
    // 1. 内网隔离（第三层防御，在网关再次校验）
    if (config_.enable_internal_network_block) {
        InternalNetworkPolicy internal_policy;
        auto decision = internal_policy.check_ip(dest_ip);
        if (decision != NetworkBlockDecision::ALLOW) {
            eval.decision = GatewayDecision::DENY;
            eval.reason = "internal network blocked: " + block_decision_name(decision) +
                " (" + dest_ip + ")";
            denied_++;
            return eval;
        }
    }
    // 2. IP 黑名单
    for (const auto& ip : config_.ip_blacklist) {
        if (dest_ip == ip) {
            eval.decision = GatewayDecision::DENY;
            eval.reason = "IP blacklisted: " + dest_ip;
            denied_++;
            return eval;
        }
    }
    // 3. 域名规则
    if (!dest_domain.empty()) {
        for (const auto& rule : config_.domain_rules) {
            if (domain_matches(dest_domain, rule.domain)) {
                if (!rule.allowed) {
                    eval.decision = GatewayDecision::DENY;
                    eval.reason = "domain blacklisted: " + dest_domain;
                    denied_++;
                    return eval;
                }
                if (rule.require_approval && config_.enable_approval_mode) {
                    eval.decision = GatewayDecision::REQUIRE_APPROVAL;
                    eval.reason = "domain requires approval: " + dest_domain;
                    return eval;
                }
                // 检查端口
                if (!rule.allowed_ports.empty()) {
                    bool port_allowed = false;
                    for (uint16_t p : rule.allowed_ports) {
                        if (p == dest_port) { port_allowed = true; break; }
                    }
                    if (!port_allowed) {
                        eval.decision = GatewayDecision::DENY;
                        eval.reason = "port not allowed for domain: " +
                            std::to_string(dest_port);
                        denied_++;
                        return eval;
                    }
                }
                break;  // 匹配到第一条规则
            }
        }
    }
    // 4. IP 白名单（如果配置了白名单，只允许白名单）
    if (!config_.ip_whitelist.empty()) {
        bool allowed = false;
        for (const auto& ip : config_.ip_whitelist) {
            if (dest_ip == ip) { allowed = true; break; }
        }
        if (!allowed) {
            eval.decision = GatewayDecision::DENY;
            eval.reason = "IP not in whitelist: " + dest_ip;
            denied_++;
            return eval;
        }
    }
    // 5. 限流检查
    if (!check_rate_limit(sandbox_id)) {
        eval.decision = GatewayDecision::RATE_LIMITED;
        eval.reason = "rate limit exceeded for sandbox: " + sandbox_id;
        rate_limited_++;
        return eval;
    }
    // 6. 允许
    eval.decision = GatewayDecision::ALLOW;
    eval.reason = "allowed";
    allowed_++;
    // 记录连接（先计算audit_hash再存储）
    ConnectionRecord record;
    record.connection_id = eval.connection_id;
    record.tenant_id = tenant_id;
    record.capability_token_id = token_id;
    record.sandbox_id = sandbox_id;
    record.dest_ip = dest_ip;
    record.dest_domain = dest_domain;
    record.dest_port = dest_port;
    record.protocol = protocol;
    record.timestamp = eval.timestamp;
    record.decision = "ALLOW";
    audit_connection(record);  // 计算audit_hash
    connections_[eval.connection_id] = record;  // 存储带audit_hash的record
    sandbox_connection_counts_[sandbox_id]++;
    return eval;
}
void IsolationGateway::record_connection_complete(const std::string& connection_id,
                                                    size_t bytes_sent, size_t bytes_received,
                                                    std::chrono::milliseconds duration) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = connections_.find(connection_id);
    if (it != connections_.end()) {
        it->second.bytes_sent = bytes_sent;
        it->second.bytes_received = bytes_received;
        it->second.duration = duration;
        // 减少并发连接计数
        auto count_it = sandbox_connection_counts_.find(it->second.sandbox_id);
        if (count_it != sandbox_connection_counts_.end() && count_it->second > 0) {
            count_it->second--;
        }
    }
}
void IsolationGateway::add_domain_rule(const DomainRule& rule) {
    std::lock_guard<std::mutex> lock(mtx_);
    config_.domain_rules.push_back(rule);
}
void IsolationGateway::allow_domain(const std::string& domain, const std::string& description) {
    DomainRule rule;
    rule.domain = domain;
    rule.allowed = true;
    rule.description = description;
    add_domain_rule(rule);
}
void IsolationGateway::deny_domain(const std::string& domain, const std::string& description) {
    DomainRule rule;
    rule.domain = domain;
    rule.allowed = false;
    rule.description = description;
    add_domain_rule(rule);
}
bool IsolationGateway::is_dns_query_allowed(const std::string& domain,
                                              const std::string& query_type) const {
    if (!config_.enable_dns_hijack) return true;
    // 阻止内网域名解析
    InternalNetworkPolicy internal;
    // 检查域名是否指向内网（简单检查）
    if (domain.find(".internal") != std::string::npos ||
        domain.find(".local") != std::string::npos ||
        domain.find("metadata") != std::string::npos) {
        return false;
    }
    // 检查域名规则
    for (const auto& rule : config_.domain_rules) {
        if (domain_matches(domain, rule.domain) && !rule.allowed) {
            return false;
        }
    }
    return true;
}
std::vector<ConnectionRecord> IsolationGateway::audit_logs(size_t limit) const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<ConnectionRecord> result;
    // unordered_map 没有反向迭代器，先全部取出再按时间排序
    for (const auto& [id, record] : connections_) {
        result.push_back(record);
    }
    std::sort(result.begin(), result.end(),
              [](const ConnectionRecord& a, const ConnectionRecord& b) {
                  return a.timestamp > b.timestamp;
              });
    if (result.size() > limit) result.resize(limit);
    return result;
}
std::string IsolationGateway::generate_envoy_config() const {
    std::ostringstream oss;
    oss << "# Envoy sidecar configuration for photon-kernel-sil3 isolation gateway\n";
    oss << "# Generated for Sidecar mode\n\n";
    oss << "static_resources:\n";
    oss << "  listeners:\n";
    oss << "  - name: listener_0\n";
    oss << "    address:\n";
    oss << "      socket_address: { address: " << config_.listen_address
        << ", port_value: " << config_.listen_port << " }\n";
    oss << "    filter_chains:\n";
    oss << "    - filters:\n";
    oss << "      - name: envoy.filters.network.http_connection_manager\n";
    oss << "        typed_config:\n";
    oss << "          '@type': type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager\n";
    oss << "          stat_prefix: ingress_http\n";
    oss << "          route_config:\n";
    oss << "            name: local_route\n";
    oss << "            virtual_hosts:\n";
    oss << "            - name: local_service\n";
    oss << "              domains: ['*']\n";
    oss << "              routes:\n";
    oss << "              - match: { prefix: '/' }\n";
    oss << "                route: { cluster: service_backend }\n";
    oss << "          http_filters:\n";
    oss << "          - name: envoy.filters.http.router\n";
    oss << "  clusters:\n";
    oss << "  - name: service_backend\n";
    oss << "    connect_timeout: 0.25s\n";
    oss << "    type: STRICT_DNS\n";
    oss << "    lb_policy: ROUND_ROBIN\n";
    oss << "    load_assignment:\n";
    oss << "      cluster_name: service_backend\n";
    oss << "      endpoints:\n";
    oss << "      - lb_endpoints:\n";
    oss << "        - endpoint:\n";
    oss << "            address:\n";
    oss << "              socket_address: { address: 127.0.0.1, port_value: 80 }\n";
    return oss.str();
}
std::vector<std::string> IsolationGateway::generate_iptables_rules() const {
    std::vector<std::string> rules;
    rules.push_back("# iptables rules for centralized isolation gateway");
    rules.push_back("# Sandbox subnet default gateway points to this gateway");
    rules.push_back("iptables -P FORWARD DROP");
    rules.push_back("iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");
    // 内网隔离
    rules.push_back("# Block internal network access (third layer defense)");
    rules.push_back("iptables -A FORWARD -s 10.0.99.0/24 -d 10.0.0.0/8 -j DROP");
    rules.push_back("iptables -A FORWARD -s 10.0.99.0/24 -d 172.16.0.0/12 -j DROP");
    rules.push_back("iptables -A FORWARD -s 10.0.99.0/24 -d 192.168.0.0/16 -j DROP");
    rules.push_back("iptables -A FORWARD -s 10.0.99.0/24 -d 169.254.0.0/16 -j DROP");
    // 允许出站白名单
    rules.push_back("# Allow outbound to whitelisted IPs");
    for (const auto& ip : config_.ip_whitelist) {
        rules.push_back("iptables -A FORWARD -s 10.0.99.0/24 -d " + ip + " -j ACCEPT");
    }
    // NAT
    rules.push_back("# NAT for sandbox outbound");
    rules.push_back("iptables -t nat -A POSTROUTING -s 10.0.99.0/24 -o eth0 -j MASQUERADE");
    return rules;
}
std::string IsolationGateway::generate_k8s_network_policy() const {
    std::ostringstream oss;
    oss << "# K8s NetworkPolicy for photon-kernel-sil3 sandbox isolation\n";
    oss << "apiVersion: networking.k8s.io/v1\n";
    oss << "kind: NetworkPolicy\n";
    oss << "metadata:\n";
    oss << "  name: photon-sandbox-isolation\n";
    oss << "  namespace: photon-sandbox\n";
    oss << "spec:\n";
    oss << "  podSelector:\n";
    oss << "    matchLabels:\n";
    oss << "      app: photon-sandbox\n";
    oss << "  policyTypes:\n";
    oss << "  - Ingress\n";
    oss << "  - Egress\n";
    oss << "  ingress:\n";
    oss << "  - from:\n";
    oss << "    - podSelector:\n";
    oss << "        matchLabels:\n";
    oss << "          app: photon-gateway\n";
    oss << "  egress:\n";
    oss << "  # Only allow traffic to isolation gateway\n";
    oss << "  - to:\n";
    oss << "    - podSelector:\n";
    oss << "        matchLabels:\n";
    oss << "          app: photon-gateway\n";
    oss << "  # Allow DNS\n";
    oss << "  - to:\n";
    oss << "    - namespaceSelector: {}\n";
    oss << "      podSelector:\n";
    oss << "        matchLabels:\n";
    oss << "          k8s-app: kube-dns\n";
    oss << "    ports:\n";
    oss << "    - protocol: UDP\n";
    oss << "      port: 53\n";
    oss << "  # Deny all internal network (RFC1918)\n";
    oss << "  # (implicit deny by default, only gateway allowed)\n";
    return oss.str();
}
} // namespace sandbox
} // namespace photon_kernel
