#ifndef PHOTON_KERNEL_SANDBOX_NETWORK_ISOLATION_HPP
#define PHOTON_KERNEL_SANDBOX_NETWORK_ISOLATION_HPP
// 内网隔离 —— 沙盒实例级网络防护（第三层防御）
//
// 即使上层网段、网关配置出错逃逸，沙盒内部直接禁止访问内网保留地址。
//
// 需要拦截的地址集合：
//   - 10.0.0.0/8       (RFC1918 A类)
//   - 172.16.0.0/12    (RFC1918 B类)
//   - 192.168.0.0/16   (RFC1918 C类)
//   - 127.0.0.0/8      (回环，防止访问宿主机本地服务)
//   - 169.254.0.0/16   (链路本地、云厂商元数据服务)
//   - 0.0.0.0/8         (本网络)
//   - 100.64.0.0/10     (运营商级NAT)
//   - 192.0.0.0/24      (IETF协议分配)
//   - 192.0.2.0/24      (TEST-NET-1)
//   - 198.51.100.0/24   (TEST-NET-2)
//   - 203.0.113.0/24    (TEST-NET-3)
//   - 224.0.0.0/4       (组播)
//   - 240.0.0.0/4       (保留)
//   - 255.255.255.255/32 (有限广播)
//
// 注意：内网隔离≠禁止全部网络；只是禁止访问内网私有网段；外网白名单照常放行。
//
// 在 photon-kernel-sil3 三处落地：
//   1. eBPF钩子：拦截connect系统调用，匹配内网IP直接拒绝（需要CAP_BPF）
//   2. seccomp-bpf：拦截connect，简单场景可用，粒度弱于eBPF
//   3. 隔离网关层再次校验：双重防护
#include <string>
#include <vector>
#include <unordered_set>
#include <cstdint>
namespace photon_kernel {
namespace sandbox {
// IP CIDR 规则
struct IpCidrRule {
    uint32_t network;   // 网络地址（主机字节序）
    uint32_t netmask;   // 子网掩码（主机字节序）
    std::string cidr;   // 原始CIDR字符串
    std::string description;
    bool is_metadata = false;  // 是否元数据地址（高危）
};
// 拦截决策
enum class NetworkBlockDecision {
    ALLOW,          // 允许
    BLOCK_INTERNAL, // 拦截：内网地址
    BLOCK_METADATA, // 拦截：元数据地址（高危）
    BLOCK_LOOPBACK, // 拦截：回环地址
    BLOCK_RESERVED, // 拦截：保留地址
    BLOCK_DENYLIST, // 拦截：黑名单
};
std::string block_decision_name(NetworkBlockDecision d);
// 内网隔离策略
class InternalNetworkPolicy {
public:
    InternalNetworkPolicy();
    // 检测IP是否为内网/保留地址
    NetworkBlockDecision check_ip(const std::string& ip) const;
    NetworkBlockDecision check_ip(uint32_t ip_host_order) const;
    // 是否为内网地址（RFC1918 + 回环 + 链路本地）
    bool is_internal_ip(const std::string& ip) const;
    // 是否为元数据地址（169.254.169.254 等，高危）
    bool is_metadata_ip(const std::string& ip) const;
    // 添加自定义黑名单
    void add_denylist_cidr(const std::string& cidr, const std::string& description = "");
    // 添加白名单（即使是内网地址也允许，用于特殊场景）
    void add_allowlist_cidr(const std::string& cidr, const std::string& description = "");
    // 获取默认内网CIDR列表
    std::vector<IpCidrRule> default_internal_cidrs() const;
    // 获取所有生效的拦截规则
    std::vector<IpCidrRule> all_block_rules() const;
    // 生成 eBPF 程序片段（用于加载到内核拦截connect）
    std::string generate_ebpf_filter() const;
    // 生成 seccomp-bpf 规则描述
    std::string generate_seccomp_rules() const;
    // 生成 iptables 规则（用于netns内）
    std::vector<std::string> generate_iptables_rules() const;
    // 启用/禁用
    void enable() { enabled_ = true; }
    void disable() { enabled_ = false; }
    bool is_enabled() const { return enabled_; }
    // 统计
    size_t block_count() const { return block_count_; }
    size_t allow_count() const { return allow_count_; }
    void reset_stats() { block_count_ = 0; allow_count_ = 0; }
private:
    bool enabled_ = true;
    std::vector<IpCidrRule> internal_cidrs_;   // 默认内网规则
    std::vector<IpCidrRule> denylist_cidrs_;    // 自定义黑名单
    std::vector<IpCidrRule> allowlist_cidrs_;   // 白名单（优先）
    mutable size_t block_count_ = 0;
    mutable size_t allow_count_ = 0;
    // 初始化默认内网规则
    void init_default_rules();
    // CIDR 解析
    bool parse_cidr(const std::string& cidr, uint32_t& network, uint32_t& netmask) const;
    // IP 字符串转 uint32
    uint32_t ip_to_uint(const std::string& ip) const;
    // uint32 转 IP 字符串
    std::string uint_to_ip(uint32_t ip) const;
    // 检查是否匹配某条规则
    bool matches_cidr(uint32_t ip, const IpCidrRule& rule) const;

    // 实际执行 iptables 规则（在 netns 内调用，需 root）
    // 返回成功执行的规则数，失败返回 -1
    int apply_iptables_rules(const std::string& netns_path = "") const;

    // 移除已应用的 iptables 规则
    int remove_iptables_rules(const std::string& netns_path = "") const;
};
// DNS 劫持与校验（防止沙盒自定义DNS绕过网关域名过滤）
struct DnsHijackConfig {
    bool enabled = true;
    std::string forced_dns_server = "127.0.0.1";  // 强制DNS服务器
    uint16_t forced_dns_port = 53;
    bool block_custom_dns = true;  // 阻止自定义DNS服务器
    std::vector<std::string> allowed_dns_servers;  // 允许的DNS服务器白名单
    bool log_dns_queries = true;  // 记录DNS查询
};
// DNS 劫持管理器
class DnsHijackManager {
public:
    explicit DnsHijackManager(const DnsHijackConfig& config = {});
    // 检查DNS请求是否允许
    bool is_dns_request_allowed(const std::string& dns_server, uint16_t port) const;
    // 生成 iptables DNS 劫持规则
    std::vector<std::string> generate_iptables_rules() const;
    // 生成 resolv.conf 配置（强制DNS）
    std::string generate_resolv_conf() const;

    // 实际执行 DNS 劫持（在 netns 内调用 iptables DNAT，需 root）
    // 把所有 53 端口流量重定向到强制 DNS 服务器
    // 返回成功执行的规则数，失败返回 -1
    int apply_dns_hijack(const std::string& netns_path = "") const;

    // 移除 DNS 劫持规则
    int remove_dns_hijack(const std::string& netns_path = "") const;

    // 写入 resolv.conf 到指定路径（沙盒内）
    bool write_resolv_conf(const std::string& path) const;

    const DnsHijackConfig& config() const { return config_; }
private:
    DnsHijackConfig config_;
};
} // namespace sandbox
} // namespace photon_kernel
#endif
