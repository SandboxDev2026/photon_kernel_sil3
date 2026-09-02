// 内网隔离实现：RFC1918内网IP拦截 + eBPF/seccomp/iptables规则生成 + DNS劫持
#include "photon_kernel/sandbox/network_isolation.hpp"
#include <sstream>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <cstdlib>
#include <fstream>
#include <unistd.h>
namespace photon_kernel {
namespace sandbox {
std::string block_decision_name(NetworkBlockDecision d) {
    switch (d) {
        case NetworkBlockDecision::ALLOW: return "ALLOW";
        case NetworkBlockDecision::BLOCK_INTERNAL: return "BLOCK_INTERNAL";
        case NetworkBlockDecision::BLOCK_METADATA: return "BLOCK_METADATA";
        case NetworkBlockDecision::BLOCK_LOOPBACK: return "BLOCK_LOOPBACK";
        case NetworkBlockDecision::BLOCK_RESERVED: return "BLOCK_RESERVED";
        case NetworkBlockDecision::BLOCK_DENYLIST: return "BLOCK_DENYLIST";
    }
    return "UNKNOWN";
}
InternalNetworkPolicy::InternalNetworkPolicy() {
    init_default_rules();
}
void InternalNetworkPolicy::init_default_rules() {
    // RFC1918 私有地址
    internal_cidrs_.push_back({0, 0, "10.0.0.0/8", "RFC1918 Class A private"});
    internal_cidrs_.push_back({0, 0, "172.16.0.0/12", "RFC1918 Class B private"});
    internal_cidrs_.push_back({0, 0, "192.168.0.0/16", "RFC1918 Class C private"});
    // 回环
    internal_cidrs_.push_back({0, 0, "127.0.0.0/8", "Loopback (host local services)"});
    // 链路本地 + 云元数据
    IpCidrRule link_local;
    link_local.cidr = "169.254.0.0/16";
    link_local.description = "Link-local / cloud metadata (HIGH RISK)";
    link_local.is_metadata = true;
    internal_cidrs_.push_back(link_local);
    // 其他保留/特殊地址
    internal_cidrs_.push_back({0, 0, "0.0.0.0/8", "This network"});
    internal_cidrs_.push_back({0, 0, "100.64.0.0/10", "Carrier-grade NAT"});
    internal_cidrs_.push_back({0, 0, "192.0.0.0/24", "IETF Protocol Assignments"});
    internal_cidrs_.push_back({0, 0, "192.0.2.0/24", "TEST-NET-1 (documentation)"});
    internal_cidrs_.push_back({0, 0, "198.51.100.0/24", "TEST-NET-2 (documentation)"});
    internal_cidrs_.push_back({0, 0, "203.0.113.0/24", "TEST-NET-3 (documentation)"});
    internal_cidrs_.push_back({0, 0, "224.0.0.0/4", "Multicast"});
    internal_cidrs_.push_back({0, 0, "240.0.0.0/4", "Reserved"});
    internal_cidrs_.push_back({0, 0, "255.255.255.255/32", "Limited broadcast"});
    // 解析所有CIDR
    for (auto& rule : internal_cidrs_) {
        parse_cidr(rule.cidr, rule.network, rule.netmask);
    }
}
bool InternalNetworkPolicy::parse_cidr(const std::string& cidr,
                                         uint32_t& network, uint32_t& netmask) const {
    size_t slash = cidr.find('/');
    if (slash == std::string::npos) return false;
    std::string ip_str = cidr.substr(0, slash);
    int prefix = std::stoi(cidr.substr(slash + 1));
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) return false;
    network = ntohl(addr.s_addr);
    if (prefix == 0) {
        netmask = 0;
    } else {
        netmask = htonl(~((1u << (32 - prefix)) - 1));
        netmask = ntohl(netmask);
    }
    return true;
}
uint32_t InternalNetworkPolicy::ip_to_uint(const std::string& ip) const {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return 0;
    return ntohl(addr.s_addr);
}
std::string InternalNetworkPolicy::uint_to_ip(uint32_t ip) const {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}
bool InternalNetworkPolicy::matches_cidr(uint32_t ip, const IpCidrRule& rule) const {
    return (ip & rule.netmask) == (rule.network & rule.netmask);
}
NetworkBlockDecision InternalNetworkPolicy::check_ip(const std::string& ip) const {
    return check_ip(ip_to_uint(ip));
}
NetworkBlockDecision InternalNetworkPolicy::check_ip(uint32_t ip) const {
    if (!enabled_) {
        allow_count_++;
        return NetworkBlockDecision::ALLOW;
    }
    // 白名单优先
    for (const auto& rule : allowlist_cidrs_) {
        if (matches_cidr(ip, rule)) {
            allow_count_++;
            return NetworkBlockDecision::ALLOW;
        }
    }
    // 自定义黑名单
    for (const auto& rule : denylist_cidrs_) {
        if (matches_cidr(ip, rule)) {
            block_count_++;
            return NetworkBlockDecision::BLOCK_DENYLIST;
        }
    }
    // 默认内网规则
    for (const auto& rule : internal_cidrs_) {
        if (matches_cidr(ip, rule)) {
            block_count_++;
            if (rule.is_metadata) return NetworkBlockDecision::BLOCK_METADATA;
            if (rule.cidr == "127.0.0.0/8") return NetworkBlockDecision::BLOCK_LOOPBACK;
            if (rule.cidr == "10.0.0.0/8" || rule.cidr == "172.16.0.0/12" ||
                rule.cidr == "192.168.0.0/16") {
                return NetworkBlockDecision::BLOCK_INTERNAL;
            }
            return NetworkBlockDecision::BLOCK_RESERVED;
        }
    }
    allow_count_++;
    return NetworkBlockDecision::ALLOW;
}
bool InternalNetworkPolicy::is_internal_ip(const std::string& ip) const {
    NetworkBlockDecision d = check_ip(ip);
    return d == NetworkBlockDecision::BLOCK_INTERNAL ||
           d == NetworkBlockDecision::BLOCK_LOOPBACK ||
           d == NetworkBlockDecision::BLOCK_METADATA;
}
bool InternalNetworkPolicy::is_metadata_ip(const std::string& ip) const {
    return check_ip(ip) == NetworkBlockDecision::BLOCK_METADATA;
}
void InternalNetworkPolicy::add_denylist_cidr(const std::string& cidr,
                                                 const std::string& description) {
    IpCidrRule rule;
    rule.cidr = cidr;
    rule.description = description;
    if (parse_cidr(cidr, rule.network, rule.netmask)) {
        denylist_cidrs_.push_back(rule);
    }
}
void InternalNetworkPolicy::add_allowlist_cidr(const std::string& cidr,
                                                  const std::string& description) {
    IpCidrRule rule;
    rule.cidr = cidr;
    rule.description = description;
    if (parse_cidr(cidr, rule.network, rule.netmask)) {
        allowlist_cidrs_.push_back(rule);
    }
}
std::vector<IpCidrRule> InternalNetworkPolicy::default_internal_cidrs() const {
    return internal_cidrs_;
}
std::vector<IpCidrRule> InternalNetworkPolicy::all_block_rules() const {
    std::vector<IpCidrRule> all = internal_cidrs_;
    all.insert(all.end(), denylist_cidrs_.begin(), denylist_cidrs_.end());
    return all;
}
std::string InternalNetworkPolicy::generate_ebpf_filter() const {
    std::ostringstream oss;
    oss << "// eBPF filter for internal network isolation\n";
    oss << "// Auto-generated by photon-kernel-sil3 InternalNetworkPolicy\n\n";
    oss << "SEC(\"cgroup/connect4\")\n";
    oss << "int block_internal_connect(struct bpf_sock_addr *ctx) {\n";
    oss << "    __u32 daddr = ctx->user_ip4;\n";
    oss << "    // Block RFC1918 private addresses\n";
    oss << "    if ((daddr & 0xFF000000) == 0x0A000000) return 0;  // 10.0.0.0/8\n";
    oss << "    if ((daddr & 0xFFF00000) == 0xAC100000) return 0;  // 172.16.0.0/12\n";
    oss << "    if ((daddr & 0xFFFF0000) == 0xC0A80000) return 0;  // 192.168.0.0/16\n";
    oss << "    // Block loopback\n";
    oss << "    if ((daddr & 0xFF000000) == 0x7F000000) return 0;  // 127.0.0.0/8\n";
    oss << "    // Block link-local / cloud metadata (HIGH RISK)\n";
    oss << "    if ((daddr & 0xFFFF0000) == 0xA9FE0000) return 0;  // 169.254.0.0/16\n";
    oss << "    // Block multicast and reserved\n";
    oss << "    if ((daddr & 0xF0000000) == 0xE0000000) return 0;  // 224.0.0.0/4\n";
    oss << "    if ((daddr & 0xF0000000) == 0xF0000000) return 0;  // 240.0.0.0/4\n";
    oss << "    return 1;  // allow\n";
    oss << "}\n";
    return oss.str();
}
std::string InternalNetworkPolicy::generate_seccomp_rules() const {
    std::ostringstream oss;
    oss << "# Seccomp-bpf rules for internal network isolation\n";
    oss << "# Note: seccomp can only filter syscall args, not full IP matching.\n";
    oss << "# For granular IP filtering, use eBPF. Seccomp here blocks connect() entirely\n";
    oss << "# when network is disabled, or allows it with eBPF as second layer.\n\n";
    oss << "# Block connect syscall (socketcall on 32-bit)\n";
    oss << "{ \"names\": [\"connect\"], \"action\": \"SCMP_ACT_ERRNO\" }\n";
    oss << "# Block socket creation for non-allowed protocols\n";
    oss << "{ \"names\": [\"socket\"], \"action\": \"SCMP_ACT_ERRNO\",\n";
    oss << "  \"args\": [{ \"index\": 0, \"value\": 2, \"op\": \"SCMP_CMP_NE\" }] }\n";
    return oss.str();
}
std::vector<std::string> InternalNetworkPolicy::generate_iptables_rules() const {
    std::vector<std::string> rules;
    rules.push_back("# iptables rules for internal network isolation (run inside netns)");
    rules.push_back("iptables -P OUTPUT DROP");
    rules.push_back("iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");
    rules.push_back("iptables -A OUTPUT -o lo -j ACCEPT");
    // 拦截内网
    rules.push_back("# Block RFC1918 private addresses");
    rules.push_back("iptables -A OUTPUT -d 10.0.0.0/8 -j DROP");
    rules.push_back("iptables -A OUTPUT -d 172.16.0.0/12 -j DROP");
    rules.push_back("iptables -A OUTPUT -d 192.168.0.0/16 -j DROP");
    rules.push_back("# Block loopback (except lo interface which is already allowed)");
    rules.push_back("iptables -A OUTPUT -d 127.0.0.0/8 ! -o lo -j DROP");
    rules.push_back("# Block link-local / cloud metadata (HIGH RISK)");
    rules.push_back("iptables -A OUTPUT -d 169.254.0.0/16 -j DROP");
    rules.push_back("# Block multicast and reserved");
    rules.push_back("iptables -A OUTPUT -d 224.0.0.0/4 -j DROP");
    rules.push_back("iptables -A OUTPUT -d 240.0.0.0/4 -j DROP");
    // 自定义黑名单
    for (const auto& rule : denylist_cidrs_) {
        rules.push_back("iptables -A OUTPUT -d " + rule.cidr + " -j DROP");
    }
    // 白名单（在DROP之前插入）
    for (const auto& rule : allowlist_cidrs_) {
        rules.push_back("iptables -I OUTPUT -d " + rule.cidr + " -j ACCEPT");
    }
    return rules;
}
// ==================== DnsHijackManager ====================
DnsHijackManager::DnsHijackManager(const DnsHijackConfig& config) : config_(config) {}
bool DnsHijackManager::is_dns_request_allowed(const std::string& dns_server,
                                                 uint16_t port) const {
    if (!config_.enabled) return true;
    if (port != 53 && port != 5353) return false;  // 只允许标准DNS端口
    if (config_.block_custom_dns) {
        // 只允许强制DNS服务器
        if (dns_server == config_.forced_dns_server) return true;
        // 检查白名单
        for (const auto& allowed : config_.allowed_dns_servers) {
            if (dns_server == allowed) return true;
        }
        return false;
    }
    return true;
}
std::vector<std::string> DnsHijackManager::generate_iptables_rules() const {
    std::vector<std::string> rules;
    if (!config_.enabled) return rules;
    rules.push_back("# DNS hijack rules (force all DNS to isolation gateway)");
    // 劫持所有出站DNS请求到强制DNS服务器
    rules.push_back("iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to-destination " +
                    config_.forced_dns_server + ":" + std::to_string(config_.forced_dns_port));
    rules.push_back("iptables -t nat -A OUTPUT -p tcp --dport 53 -j DNAT --to-destination " +
                    config_.forced_dns_server + ":" + std::to_string(config_.forced_dns_port));
    // 阻止自定义DNS服务器（除了强制的）
    if (config_.block_custom_dns) {
        rules.push_back("iptables -A OUTPUT -p udp --dport 53 ! -d " +
                        config_.forced_dns_server + " -j DROP");
    }
    return rules;
}
std::string DnsHijackManager::generate_resolv_conf() const {
    std::ostringstream oss;
    oss << "# Auto-generated by photon-kernel-sil3 DnsHijackManager\n";
    oss << "# DNS queries are forced through the isolation gateway\n";
    oss << "nameserver " << config_.forced_dns_server << "\n";
    oss << "options timeout:2 attempts:3\n";
    return oss.str();
}

// ==================== 实际执行：iptables 规则应用 ====================

// 执行系统命令，返回退出码
static int exec_command(const std::string& cmd) {
    int ret = system(cmd.c_str());
    return WIFEXITED(ret) ? WEXITSTATUS(ret) : -1;
}

// 在 netns 内执行命令（如果指定了 netns_path）
static std::string netns_prefix(const std::string& netns_path) {
    if (netns_path.empty()) return "";
    return "nsenter --net=" + netns_path + " ";
}

int InternalNetworkPolicy::apply_iptables_rules(const std::string& netns_path) const {
    if (!enabled_) return 0;
    std::string prefix = netns_prefix(netns_path);
    auto rules = generate_iptables_rules();
    int success = 0;
    for (const auto& rule : rules) {
        if (rule.empty() || rule[0] == '#') continue;  // 跳过注释和空行
        std::string cmd = prefix + rule;
        if (exec_command(cmd) == 0) {
            success++;
        }
    }
    return success;
}

int InternalNetworkPolicy::remove_iptables_rules(const std::string& netns_path) const {
    std::string prefix = netns_prefix(netns_path);
    // 简单实现：flush OUTPUT 链（生产环境应精确匹配删除）
    std::string cmd = prefix + "iptables -F OUTPUT";
    return exec_command(cmd) == 0 ? 1 : 0;
}

// ==================== 实际执行：DNS 劫持 ====================

int DnsHijackManager::apply_dns_hijack(const std::string& netns_path) const {
    if (!config_.enabled) return 0;
    std::string prefix = netns_prefix(netns_path);
    auto rules = generate_iptables_rules();
    int success = 0;
    for (const auto& rule : rules) {
        if (rule.empty() || rule[0] == '#') continue;
        std::string cmd = prefix + rule;
        if (exec_command(cmd) == 0) {
            success++;
        }
    }
    return success;
}

int DnsHijackManager::remove_dns_hijack(const std::string& netns_path) const {
    std::string prefix = netns_prefix(netns_path);
    // 删除 nat 表的 DNS 劫持规则
    std::string cmd1 = prefix + "iptables -t nat -F OUTPUT";
    std::string cmd2 = prefix + "iptables -D OUTPUT -p udp --dport 53 -j DROP 2>/dev/null";
    int s1 = exec_command(cmd1) == 0 ? 1 : 0;
    exec_command(cmd2);  // 忽略结果（可能不存在）
    return s1;
}

bool DnsHijackManager::write_resolv_conf(const std::string& path) const {
    std::string content = generate_resolv_conf();
    std::ofstream ofs(path);
    if (!ofs.is_open()) return false;
    ofs << content;
    ofs.close();
    // 设置只读，防止沙盒内修改
    chmod(path.c_str(), 0444);
    return true;
}

} // namespace sandbox
} // namespace photon_kernel
