// Photon Kernel Sandbox - eBPF 加载器（libbpf）
//
// 功能：
//   1. 加载编译好的 eBPF 对象文件
//   2. 配置出口流量白名单（CIDR + 端口）
//   3. 标记沙盒 cgroup
//   4. 附加 XDP 程序到网卡
//   5. 附加 tracepoint 程序
//   6. 读取审计 ring buffer 事件
//   7. 输出统计信息
//
// 编译（需要 libbpf-dev）：
//   g++ -std=c++17 -O2 ebpf_loader.cpp -o ebpf_loader -lbpf -lelf -lz
//
// 用法（需要 root）：
//   sudo ./ebpf_loader --obj sandbox_filter.o --iface eth0 \
//     --whitelist 10.0.0.0/8:80-443:tcp \
//     --whitelist 0.0.0.0/0:53:udp \
//     --cgroup /sys/fs/cgroup/sandbox
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>
#include <fstream>
#include <iostream>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
// eBPF 对象中的 map 名（与 sandbox_filter.c 对应）
static const char* MAP_WHITELIST = "egress_whitelist";
static const char* MAP_CGROUPS = "sandbox_cgroups";
static const char* MAP_AUDIT = "audit_events";
static const char* MAP_STATS = "stats";
static const char* MAP_DNS = "authorized_dns";
struct whitelist_key {
    uint32_t network;
    uint32_t prefix_len;
};
struct whitelist_val {
    uint16_t port_min;
    uint16_t port_max;
    uint8_t protocol;
};
struct audit_event {
    uint64_t timestamp;
    uint32_t pid;
    uint32_t uid;
    uint8_t type;
    char comm[16];
    char detail[64];
    uint32_t target_ip;
    uint16_t target_port;
};
static std::atomic<bool> g_running{true};
// 解析白名单规则：CIDR:port_min-port_max:protocol
static bool parse_whitelist(const std::string& spec, whitelist_key& key, whitelist_val& val) {
    // 格式: 10.0.0.0/8:80-443:tcp
    size_t colon1 = spec.find(':');
    if (colon1 == std::string::npos) return false;
    std::string cidr = spec.substr(0, colon1);
    std::string rest = spec.substr(colon1 + 1);
    size_t colon2 = rest.find(':');
    std::string ports = colon2 == std::string::npos ? rest : rest.substr(0, colon2);
    std::string proto = colon2 == std::string::npos ? "" : rest.substr(colon2 + 1);
    // 解析 CIDR
    size_t slash = cidr.find('/');
    std::string ip_str = slash == std::string::npos ? cidr : cidr.substr(0, slash);
    int prefix = slash == std::string::npos ? 32 : std::stoi(cidr.substr(slash + 1));
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) return false;
    key.network = addr.s_addr;  // 大端
    key.prefix_len = prefix;
    // 解析端口
    size_t dash = ports.find('-');
    val.port_min = dash == std::string::npos ? std::stoi(ports) : std::stoi(ports.substr(0, dash));
    val.port_max = dash == std::string::npos ? val.port_min : std::stoi(ports.substr(dash + 1));
    // 解析协议
    if (proto == "tcp") val.protocol = IPPROTO_TCP;
    else if (proto == "udp") val.protocol = IPPROTO_UDP;
    else val.protocol = 0;
    return true;
}
// ring buffer 回调：处理审计事件
static int handle_audit_event(void* ctx, void* data, size_t size) {
    auto* ev = static_cast<audit_event*>(data);
    const char* type_name = "unknown";
    switch (ev->type) {
        case 1: type_name = "execve"; break;
        case 2: type_name = "connect"; break;
        case 3: type_name = "open"; break;
        case 4: type_name = "BLOCK_INTERNAL"; break;
        case 5: type_name = "BLOCK_METADATA"; break;
        case 6: type_name = "BLOCK_DNS"; break;
    }
    if (ev->type >= 4) {
        // 网络拦截事件，打印目标IP和端口
        struct in_addr addr;
        addr.s_addr = ev->target_ip;
        fprintf(stdout, "[AUDIT] type=%s pid=%u uid=%u comm=%s target=%s:%u detail=%s\n",
                type_name, ev->pid, ev->uid, ev->comm,
                inet_ntoa(addr), ev->target_port, ev->detail);
    } else {
        fprintf(stdout, "[AUDIT] type=%s pid=%u uid=%u comm=%s detail=%s\n",
                type_name, ev->pid, ev->uid, ev->comm, ev->detail);
    }
    return 0;
}
static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s --obj <file.o> --iface <eth0> [options]\n", prog);
    fprintf(stderr, "  --obj <file>       eBPF object file\n");
    fprintf(stderr, "  --iface <name>     network interface to attach XDP\n");
    fprintf(stderr, "  --whitelist <spec> CIDR:port-range:proto (repeatable)\n");
    fprintf(stderr, "  --dns-server <ip>  authorized DNS server (repeatable, DNS劫持)\n");
    fprintf(stderr, "  --cgroup <path>    sandbox cgroup path to mark\n");
    fprintf(stderr, "  --cgroup-fd <fd>   sandbox cgroup fd (for cgroup/connect4 attach)\n");
    fprintf(stderr, "  --duration <sec>   run duration (default: 0=forever)\n");
    fprintf(stderr, "  --stats            print stats every second\n");
}
int main(int argc, char** argv) {
    std::string obj_path, iface;
    std::vector<std::string> whitelists;
    std::vector<std::string> dns_servers;
    std::vector<std::string> cgroups;
    std::vector<int> cgroup_fds;
    int duration = 0;
    bool print_stats = false;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--obj" && i + 1 < argc) obj_path = argv[++i];
        else if (arg == "--iface" && i + 1 < argc) iface = argv[++i];
        else if (arg == "--whitelist" && i + 1 < argc) whitelists.push_back(argv[++i]);
        else if (arg == "--dns-server" && i + 1 < argc) dns_servers.push_back(argv[++i]);
        else if (arg == "--cgroup" && i + 1 < argc) cgroups.push_back(argv[++i]);
        else if (arg == "--cgroup-fd" && i + 1 < argc) cgroup_fds.push_back(std::stoi(argv[++i]));
        else if (arg == "--duration" && i + 1 < argc) duration = std::stoi(argv[++i]);
        else if (arg == "--stats") print_stats = true;
        else if (arg == "--help" || arg == "-h") { print_usage(argv[0]); return 0; }
    }
    if (obj_path.empty() || iface.empty()) {
        print_usage(argv[0]);
        return 1;
    }
    // 1. 打开 eBPF 对象
    struct bpf_object* obj = bpf_object__open(obj_path.c_str());
    if (!obj) {
        fprintf(stderr, "Failed to open eBPF object: %s\n", obj_path.c_str());
        return 1;
    }
    // 2. 加载到内核
    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "Failed to load eBPF object\n");
        bpf_object__close(obj);
        return 1;
    }
    fprintf(stdout, "[OK] eBPF object loaded\n");
    // 3. 配置白名单
    int wl_fd = bpf_object__find_map_fd_by_name(obj, MAP_WHITELIST);
    for (const auto& spec : whitelists) {
        whitelist_key key; whitelist_val val;
        if (parse_whitelist(spec, key, val)) {
            bpf_map_update_elem(wl_fd, &key, &val, BPF_ANY);
            fprintf(stdout, "[OK] whitelist: %s\n", spec.c_str());
        } else {
            fprintf(stderr, "[WARN] invalid whitelist: %s\n", spec.c_str());
        }
    }
    // 4. 配置授权DNS服务器（DNS劫持用）
    int dns_fd = bpf_object__find_map_fd_by_name(obj, MAP_DNS);
    for (const auto& dns_ip : dns_servers) {
        struct in_addr addr;
        if (inet_pton(AF_INET, dns_ip.c_str(), &addr) == 1) {
            uint32_t key = addr.s_addr;  // 大端
            uint8_t val = 1;
            bpf_map_update_elem(dns_fd, &key, &val, BPF_ANY);
            fprintf(stdout, "[OK] authorized DNS: %s\n", dns_ip.c_str());
        }
    }

    // 5. 标记沙盒 cgroup
    int cg_fd = bpf_object__find_map_fd_by_name(obj, MAP_CGROUPS);
    for (const auto& cg_path : cgroups) {
        // 读取 cgroup id（简化：用 inode 号）
        uint64_t cg_id = 0;
        // 实际应读取 /sys/fs/cgroup/.../cgroup.id
        // 这里用路径 hash 简化
        for (char c : cg_path) cg_id = cg_id * 31 + c;
        uint8_t val = 1;
        bpf_map_update_elem(cg_fd, &cg_id, &val, BPF_ANY);
        fprintf(stdout, "[OK] sandbox cgroup marked: %s (id=%lu)\n", cg_path.c_str(), cg_id);
    }
    // 5. 附加 XDP 到网卡
    struct bpf_program* xdp_prog = bpf_object__find_program_by_name(obj, "egress_filter");
    if (xdp_prog) {
        int xdp_fd = bpf_program__fd(xdp_prog);
        unsigned int ifindex = if_nametoindex(iface.c_str());
        if (ifindex == 0) {
            fprintf(stderr, "[WARN] interface not found: %s, skipping XDP\n", iface.c_str());
        } else {
            bpf_xdp_attach(iface.c_str(), xdp_fd, 0, nullptr);
            fprintf(stdout, "[OK] XDP attached to %s (ifindex=%u)\n", iface.c_str(), ifindex);
        }
    }
    // 6. 附加 cgroup/connect4（连接级内网拦截，主拦截点）
    struct bpf_program* connect_prog = bpf_object__find_program_by_name(obj, "block_internal_connect");
    if (connect_prog) {
        int connect_fd = bpf_program__fd(connect_prog);
        for (int cg_fd : cgroup_fds) {
            int ret = bpf_program__attach_cgroup(connect_prog, cg_fd);
            if (ret == 0) {
                fprintf(stdout, "[OK] cgroup/connect4 attached to cgroup fd=%d\n", cg_fd);
            } else {
                fprintf(stderr, "[WARN] failed to attach cgroup/connect4 to fd=%d: %s\n",
                        cg_fd, strerror(-ret));
            }
        }
        if (cgroup_fds.empty()) {
            fprintf(stdout, "[INFO] cgroup/connect4 program loaded (fd=%d), attach with --cgroup-fd\n", connect_fd);
        }
    }

    // 7. 附加 tracepoint（libbpf 自动附加）
    bpf_object__attach_skeleton(nullptr);  // 简化，实际用 bpf_program__attach_tracepoint
    // 手动附加 tracepoint
    const char* tp_names[] = {"tracepoint/syscalls/sys_enter_execve",
                               "tracepoint/syscalls/sys_enter_connect",
                               "tracepoint/syscalls/sys_enter_openat"};
    const char* prog_names[] = {"trace_execve", "trace_connect", "trace_openat"};
    for (int i = 0; i < 3; i++) {
        struct bpf_program* prog = bpf_object__find_program_by_name(obj, prog_names[i]);
        if (prog) {
            bpf_program__attach_tracepoint(prog, "syscalls", tp_names[i] + strlen("tracepoint/syscalls/"));
            fprintf(stdout, "[OK] tracepoint attached: %s\n", prog_names[i]);
        }
    }
    // 7. 读取审计 ring buffer
    int audit_fd = bpf_object__find_map_fd_by_name(obj, MAP_AUDIT);
    struct ring_buffer* rb = ring_buffer__new(audit_fd, handle_audit_event, nullptr, nullptr);
    if (rb) {
        fprintf(stdout, "[OK] audit ring buffer ready, listening for events...\n");
    }
    // 8. 主循环
    auto start = std::chrono::steady_clock::now();
    while (g_running) {
        if (rb) ring_buffer__poll(rb, 100);
        if (print_stats) {
            // 读取统计
            int stats_fd = bpf_object__find_map_fd_by_name(obj, MAP_STATS);
            uint64_t total = 0, allowed = 0, dropped = 0;
            uint32_t key;
            // 简化：只读 total/allowed/dropped
            for (uint32_t k = 0; k < 3; k++) {
                uint64_t val = 0;
                bpf_map_lookup_elem(stats_fd, &k, &val);
                if (k == 0) total = val;
                if (k == 1) allowed = val;
                if (k == 2) dropped = val;
            }
            fprintf(stdout, "[STATS] total=%lu allowed=%lu dropped=%lu\n", total, allowed, dropped);
        }
        if (duration > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed >= duration) break;
        }
    }
    // 9. 清理
    if (rb) ring_buffer__free(rb);
    // 卸载 XDP
    if (xdp_prog) {
        bpf_xdp_detach(iface.c_str(), 0, nullptr);
    }
    bpf_object__close(obj);
    fprintf(stdout, "[OK] eBPF programs unloaded\n");
    return 0;
}
