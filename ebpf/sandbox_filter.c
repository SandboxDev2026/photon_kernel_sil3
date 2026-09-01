// SPDX-License-Identifier: MIT
// Photon Kernel Sandbox - eBPF 出口流量白名单 + syscall 监控
//
// 功能：
//   1. 出口流量白名单：只允许连接到指定 CIDR:端口，其他全部 DROP
//   2. syscall 监控：记录沙盒进程的 execve/connect/open 调用，用于审计
//   3. 进程标记：通过 cgroup 标记沙盒进程，只对沙盒进程生效
//
// 编译（需要 clang + libbpf）：
//   clang -O2 -target bpf -D__TARGET_ARCH_x86_64 -I/usr/include/bpf -c sandbox_filter.c -o sandbox_filter.o
//
// 加载（需要 root + CAP_BPF）：
//   ./ebpf_loader sandbox_filter.o
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// ==================== 配置 Map ====================
// 出口流量白名单：CIDR 前缀 -> 允许的端口位图
// key: IPv4 网络地址（大端），value: 允许的端口范围（min,max）
struct whitelist_key {
    __u32 network;    // IPv4 网络地址（大端）
    __u32 prefix_len; // 前缀长度（8/16/24/32）
};
struct whitelist_val {
    __u16 port_min;
    __u16 port_max;
    __u8 protocol;    // IPPROTO_TCP / IPPROTO_UDP / 0=any
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct whitelist_key);
    __type(value, struct whitelist_val);
} egress_whitelist SEC(".maps");
// 沙盒进程 cgroup ID 集合（标记哪些进程属于沙盒）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);  // cgroup id
    __type(value, __u8);  // 1 = sandbox
} sandbox_cgroups SEC(".maps");
// 审计事件 ring buffer（用户态读取）
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} audit_events SEC(".maps");
// 统计计数器
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");
enum stat_type {
    STAT_PACKETS_TOTAL = 0,
    STAT_PACKETS_ALLOWED = 1,
    STAT_PACKETS_DROPPED = 2,
    STAT_SYSCALL_EXECVE = 3,
    STAT_SYSCALL_CONNECT = 4,
    STAT_SYSCALL_OPEN = 5,
};
// ==================== 审计事件结构 ====================
struct audit_event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    __u8 type;         // 1=execve, 2=connect, 3=open
    char comm[16];
    char detail[64];   // 路径或目标地址
};
enum audit_type {
    AUDIT_EXECVE = 1,
    AUDIT_CONNECT = 2,
    AUDIT_OPEN = 3,
};
// ==================== 工具函数 ====================
static __always_inline int is_sandbox_process() {
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *val = bpf_map_lookup_elem(&sandbox_cgroups, &cgroup_id);
    return val ? *val : 0;
}
static __always_inline void increment_stat(enum stat_type type) {
    __u32 key = type;
    __u64 *val = bpf_map_lookup_elem(&stats, &key);
    if (val) __sync_fetch_and_add(val, 1);
}
static __always_inline void emit_audit(enum audit_type type, const char *detail, int detail_len) {
    struct audit_event *ev = bpf_ringbuf_reserve(&audit_events, sizeof(*ev), 0);
    if (!ev) return;
    ev->timestamp = bpf_ktime_get_ns();
    ev->pid = bpf_get_current_pid_tgid() >> 32;
    ev->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->type = type;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    if (detail && detail_len > 0) {
        __builtin_memcpy(ev->detail, detail, detail_len < 64 ? detail_len : 64);
    }
    bpf_ringbuf_submit(ev, 0);
}
// ==================== XDP: 出口流量白名单 ====================
SEC("xdp")
int egress_filter(struct xdp_md *ctx) {
    increment_stat(STAT_PACKETS_TOTAL);
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) return XDP_PASS;
    __u8 protocol = ip->protocol;
    __u16 dst_port = 0;
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) > data_end) return XDP_PASS;
        dst_port = bpf_ntohs(tcp->dest);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) > data_end) return XDP_PASS;
        dst_port = bpf_ntohs(udp->dest);
    } else {
        return XDP_PASS;  // 非 TCP/UDP 放行（ICMP 等）
    }
    // 检查白名单
    __u32 dst_ip = ip->daddr;  // 大端
    struct whitelist_key key;
    struct whitelist_val *val;
    // 遍历常见前缀长度（简化：检查 /8 /16 /24 /32）
    __u32 masks[] = {0xFF000000, 0xFFFF0000, 0xFFFFFF00, 0xFFFFFFFF};
    __u32 prefixes[] = {8, 16, 24, 32};
    for (int i = 0; i < 4; i++) {
        key.network = dst_ip & bpf_htonl(masks[i]);
        key.prefix_len = prefixes[i];
        val = bpf_map_lookup_elem(&egress_whitelist, &key);
        if (val) {
            if ((val->protocol == 0 || val->protocol == protocol) &&
                dst_port >= val->port_min && dst_port <= val->port_max) {
                increment_stat(STAT_PACKETS_ALLOWED);
                return XDP_PASS;
            }
        }
    }
    // 不在白名单 → DROP
    increment_stat(STAT_PACKETS_DROPPED);
    return XDP_DROP;
}
// ==================== tracepoint: execve 监控 ====================
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    if (!is_sandbox_process()) return 0;
    increment_stat(STAT_SYSCALL_EXECVE);
    const char *filename = (const char *)ctx->args[0];
    char buf[64];
    if (bpf_probe_read_user_str(buf, sizeof(buf), filename) > 0) {
        emit_audit(AUDIT_EXECVE, buf, sizeof(buf));
    }
    return 0;
}
// ==================== tracepoint: connect 监控 ====================
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    if (!is_sandbox_process()) return 0;
    increment_stat(STAT_SYSCALL_CONNECT);
    emit_audit(AUDIT_CONNECT, "connect", 7);
    return 0;
}
// ==================== tracepoint: openat 监控 ====================
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    if (!is_sandbox_process()) return 0;
    increment_stat(STAT_SYSCALL_OPEN);
    const char *filename = (const char *)ctx->args[1];
    char buf[64];
    if (bpf_probe_read_user_str(buf, sizeof(buf), filename) > 0) {
        emit_audit(AUDIT_OPEN, buf, sizeof(buf));
    }
    return 0;
}
char _license[] SEC("license") = "MIT";
__u32 _version SEC("version") = 0xFFFFFFFE;
