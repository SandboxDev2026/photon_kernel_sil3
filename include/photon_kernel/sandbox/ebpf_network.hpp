#ifndef PHOTON_KERNEL_SANDBOX_EBPF_NETWORK_HPP
#define PHOTON_KERNEL_SANDBOX_EBPF_NETWORK_HPP
// eBPF 出口流量白名单（核弹级优化二）。
// CubeSandbox 用 eBPF 做出口流量管控；seccomp 只能完全禁止 socket，eBPF 可实现细粒度
// IP/端口白名单（允许受限网络访问，其余出站流量在内核态丢弃）。
//
// 运行时检测：内核 CONFIG_BPF + 权限（CAP_BPF/CAP_NET_ADMIN）+ libbpf；
// 不支持时自动降级回 seccomp 全拦截（原有行为），不影响核心功能。
//
// 条件编译：检测 <linux/bpf.h> 和 <bpf/libbpf.h>；无 libbpf 时用原始 bpf() syscall。
#include <string>
#include <vector>
#include <cstdint>
namespace photon_kernel {
namespace sandbox {
struct NetworkRule {
    std::string ip;        // 允许的目标 IP（如 "10.0.0.1"），空表示任意 IP
    uint16_t port = 0;     // 允许的目标端口，0 表示任意端口
    std::string protocol;  // "tcp" / "udp" / "any"
};
struct EbpfNetworkStatus {
    bool supported = false;    // 内核是否支持 eBPF
    bool loaded = false;       // eBPF 程序是否已加载
    bool degraded = false;     // 是否降级为 seccomp 全拦截
    std::string message;
    size_t rule_count = 0;
};
class EbpfNetworkEnforcer {
public:
    static EbpfNetworkEnforcer& instance();
    // 检测 eBPF 可用性（内核 + 权限 + libbpf）
    [[nodiscard]] bool is_supported() const;
    // 加载 eBPF 程序并应用白名单规则
    // 成功返回 true；不支持或加载失败返回 false 并设置 degraded（降级回 seccomp）
    bool enable(const std::vector<NetworkRule>& allowlist);
    // 卸载 eBPF 程序
    void disable();
    // 添加运行时规则（需 eBPF 程序已加载）
    bool add_rule(const NetworkRule& rule);
    // 移除规则
    bool remove_rule(const NetworkRule& rule);
    [[nodiscard]] EbpfNetworkStatus status() const;
    // 完全禁止网络（降级模式，等价于 seccomp 拦截 socket）
    void set_deny_all();
private:
    EbpfNetworkEnforcer() = default;
    ~EbpfNetworkEnforcer();
    EbpfNetworkEnforcer(const EbpfNetworkEnforcer&) = delete;
    EbpfNetworkEnforcer& operator=(const EbpfNetworkEnforcer&) = delete;
    // 检测权限（CAP_BPF / CAP_NET_ADMIN）
    bool has_capabilities() const;
    // 用原始 bpf() syscall 加载程序（无 libbpf 时的 fallback）
    bool load_with_syscall();
    std::vector<NetworkRule> rules_;
    int prog_fd_ = -1;
    int link_fd_ = -1;
    bool supported_ = false;
    bool loaded_ = false;
    bool degraded_ = false;
};
} // namespace sandbox
} // namespace photon_kernel
#endif
