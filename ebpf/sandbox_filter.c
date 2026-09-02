// SPDX-License-Identifier: MIT
// Photon Kernel Sandbox - eBPF 网络隔离完整实现
//
// 功能（三层防御中的第三层：沙盒实例级内网隔离）：
//   1. 内置完整内网IP黑名单（RFC1918 + 云元数据 + 回环 + 保留地址）
//      - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC1918)
//      - 127.0.0.0/8 (回环，防访问宿主机本地服务)
//      - 169.254.0.0/16 (链路本地/云元数据，含169.254.169.254，高危)
//      - 0.0.0.0/8, 100.64.0.0/10, 192.0.0.0/24, TEST-NET, 组播, 保留
//   2. cgroup/connect4: 连接级拦截（沙盒进程发起connect时直接拒绝）
//   3. XDP: 包级出口过滤（白名单模式，兜底）
//   4. DNS 强制劫持：拦截53端口到非授权DNS服务器的请求
//   5. syscall 监控：execve/connect/openat 审计
//   6. 进程标记：通过 cgroup 标记沙盒进程
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

// 出口流量白名单：CIDR 前缀 -> 允许的端口范围
struct whitelist_key {
    __u32 network;    // IPv4 网络地址（大端）
    __u32 prefix_len; // 前缀长度
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

// 授权DNS服务器集合（DNS劫持用）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);  // DNS服务器IP（大端）
    __type(value, __u8);  // 1=authorized
} authorized_dns SEC(".maps");

// 沙盒进程 cgroup ID 集合
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);  // cgroup id
    __type(value, __u8);  // 1 = sandbox
} sandbox_cgroups SEC(".maps");

// 审计事件 ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} audit_events SEC(".maps");

// 统计计数器
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

enum stat_type {
    STAT_PACKETS_TOTAL = 0,
    STAT_PACKETS_ALLOWED = 1,
    STAT_PACKETS_DROPPED = 2,
    STAT_BLOCK_INTERNAL = 3,      // 拦截内网IP
    STAT_BLOCK_METADATA = 4,      // 拦截云元数据
    STAT_BLOCK_LOOPBACK = 5,      // 拦截回环
    STAT_BLOCK_DNS = 6,            // 拦截未授权DNS
    STAT_SYSCALL_EXECVE = 7,
    STAT_SYSCALL_CONNECT = 8,
    STAT_SYSCALL_OPEN = 9,
};

// ==================== 审计事件结构 ====================
struct audit_event {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    __u8 type;         // 1=execve, 2=connect, 3=open, 4=block_internal, 5=block_metadata, 6=block_dns
    char comm[16];
    char detail[64];   // 路径或目标地址
    __u32 target_ip;   // 目标IP（大端，网络事件用）
    __u16 target_port; // 目标端口
};

enum audit_type {
    AUDIT_EXECVE = 1,
    AUDIT_CONNECT = 2,
    AUDIT_OPEN = 3,
    AUDIT_BLOCK_INTERNAL = 4,
    AUDIT_BLOCK_METADATA = 5,
    AUDIT_BLOCK_DNS = 6,
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

static __always_inline void emit_audit_net(enum audit_type type, __u32 ip, __u16 port, const char *detail) {
    struct audit_event *ev = bpf_ringbuf_reserve(&audit_events, sizeof(*ev), 0);
    if (!ev) return;
    ev->timestamp = bpf_ktime_get_ns();
    ev->pid = bpf_get_current_pid_tgid() >> 32;
    ev->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->type = type;
    ev->target_ip = ip;
    ev->target_port = port;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    if (detail) {
        __builtin_memcpy(ev->detail, detail, 64);
    }
    bpf_ringbuf_submit(ev, 0);
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

// ==================== 内置内网IP黑名单检测 ====================
// 返回值：0=允许, 1=拦截内网, 2=拦截元数据, 3=拦截回环, 4=拦截保留
// ip 参数为大端序（网络字节序）
static __always_inline int check_internal_ip(__u32 ip_be) {
    // 转换为主机序用于比较
    __u32 ip = bpf_ntohl(ip_be);

    // RFC1918 A类: 10.0.0.0/8
    if ((ip & 0xFF000000) == 0x0A000000) return 1;
    // RFC1918 B类: 172.16.0.0/12
    if ((ip & 0xFFF00000) == 0xAC100000) return 1;
    // RFC1918 C类: 192.168.0.0/16
    if ((ip & 0xFFFF0000) == 0xC0A80000) return 1;

    // 回环: 127.0.0.0/8 (防访问宿主机本地服务)
    if ((ip & 0xFF000000) == 0x7F000000) return 3;

    // 链路本地/云元数据: 169.254.0.0/16 (高危，含169.254.169.254)
    if ((ip & 0xFFFF0000) == 0xA9FE0000) return 2;

    // 0.0.0.0/8 (This network)
    if ((ip & 0xFF000000) == 0x00000000) return 4;
    // 运营商级NAT: 100.64.0.0/10
    if ((ip & 0xFFC00000) == 0x64400000) return 4;
    // IETF协议分配: 192.0.0.0/24
    if ((ip & 0xFFFFFF00) == 0xC0000000) return 4;
    // TEST-NET-1: 192.0.2.0/24
    if ((ip & 0xFFFFFF00) == 0xC0000200) return 4;
    // TEST-NET-2: 198.51.100.0/24
    if ((ip & 0xFFFFFF00) == 0xC6336400) return 4;
    // TEST-NET-3: 203.0.113.0/24
    if ((ip & 0xFFFFFF00) == 0xCB007100) return 4;
    // 组播: 224.0.0.0/4
    if ((ip & 0xF0000000) == 0xE0000000) return 4;
    // 保留: 240.0.0.0/4
    if ((ip & 0xF0000000) == 0xF0000000) return 4;
    // 有限广播: 255.255.255.255/32
    if (ip == 0xFFFFFFFF) return 4;

    return 0; // 允许
}

// ==================== cgroup/connect4: 连接级内网拦截 ====================
// 沙盒进程调用 connect() 时触发，直接在内核态拦截内网IP
// 这是最有效的拦截点：在连接建立前就拒绝，不经过网络栈
SEC("cgroup/connect4")
int block_internal_connect(struct bpf_sock_addr *ctx) {
    // 只对沙盒进程生效
    if (!is_sandbox_process()) return 1;

    __u32 dst_ip = ctx->user_ip4;  // 大端
    __u16 dst_port = bpf_ntohs(ctx->user_port);

    increment_stat(STAT_PACKETS_TOTAL);

    // 1. 内置内网IP黑名单检测
    int block_type = check_internal_ip(dst_ip);
    if (block_type != 0) {
        if (block_type == 1) {
            increment_stat(STAT_BLOCK_INTERNAL);
            emit_audit_net(AUDIT_BLOCK_INTERNAL, dst_ip, dst_port, "RFC1918 internal");
        } else if (block_type == 2) {
            increment_stat(STAT_BLOCK_METADATA);
            emit_audit_net(AUDIT_BLOCK_METADATA, dst_ip, dst_port, "cloud metadata HIGH RISK");
        } else if (block_type == 3) {
            increment_stat(STAT_BLOCK_LOOPBACK);
            emit_audit_net(AUDIT_BLOCK_INTERNAL, dst_ip, dst_port, "loopback");
        } else {
            increment_stat(STAT_BLOCK_INTERNAL);
            emit_audit_net(AUDIT_BLOCK_INTERNAL, dst_ip, dst_port, "reserved");
        }
        increment_stat(STAT_PACKETS_DROPPED);
        return 0;  // 拒绝连接
    }

    // 2. DNS 强制劫持：拦截53端口到非授权DNS服务器
    if (dst_port == 53) {
        __u8 *authorized = bpf_map_lookup_elem(&authorized_dns, &dst_ip);
        if (!authorized) {
            // 非授权DNS服务器，拒绝（防止自定义DNS绕过域名白名单）
            increment_stat(STAT_BLOCK_DNS);
            emit_audit_net(AUDIT_BLOCK_DNS, dst_ip, dst_port, "unauthorized DNS server");
            increment_stat(STAT_PACKETS_DROPPED);
            return 0;
        }
    }

    // 3. 白名单检查（如果配置了白名单）
    struct whitelist_key key;
    struct whitelist_val *val;
    __u32 masks[] = {0xFF000000, 0xFFFF0000, 0xFFFFFF00, 0xFFFFFFFF};
    __u32 prefixes[] = {8, 16, 24, 32};
    int whitelist_configured = 0;

    // 检查白名单map是否有条目（通过尝试查找一个已知key来判断）
    // 简化：如果白名单map为空，默认允许公网IP
    for (int i = 0; i < 4; i++) {
        key.network = dst_ip & bpf_htonl(masks[i]);
        key.prefix_len = prefixes[i];
        val = bpf_map_lookup_elem(&egress_whitelist, &key);
        if (val) {
            whitelist_configured = 1;
            if ((val->protocol == 0 || val->protocol == ctx->protocol) &&
                dst_port >= val->port_min && dst_port <= val->port_max) {
                increment_stat(STAT_PACKETS_ALLOWED);
                return 1;  // 允许
            }
        }
    }

    // 白名单已配置但未匹配 → 拒绝
    if (whitelist_configured) {
        increment_stat(STAT_PACKETS_DROPPED);
        return 0;
    }

    // 白名单未配置 → 默认允许公网IP（内网已在上面拦截）
    increment_stat(STAT_PACKETS_ALLOWED);
    return 1;
}

// ==================== XDP: 包级出口过滤（兜底） ====================
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
        return XDP_PASS;
    }

    __u32 dst_ip = ip->daddr;  // 大端

    // 1. 内置内网IP黑名单（XDP层兜底，cgroup/connect4是主拦截点）
    int block_type = check_internal_ip(dst_ip);
    if (block_type != 0) {
        if (block_type == 2) {
            increment_stat(STAT_BLOCK_METADATA);
        } else {
            increment_stat(STAT_BLOCK_INTERNAL);
        }
        increment_stat(STAT_PACKETS_DROPPED);
        return XDP_DROP;
    }

    // 2. DNS 劫持兜底
    if (dst_port == 53) {
        __u8 *authorized = bpf_map_lookup_elem(&authorized_dns, &dst_ip);
        if (!authorized) {
            increment_stat(STAT_BLOCK_DNS);
            increment_stat(STAT_PACKETS_DROPPED);
            return XDP_DROP;
        }
    }

    // 3. 白名单检查
    struct whitelist_key key;
    struct whitelist_val *val;
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

    // 不在白名单 → DROP（XDP默认拒绝，cgroup/connect4默认允许公网）
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
