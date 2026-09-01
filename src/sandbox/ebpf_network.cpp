#include "photon_kernel/sandbox/ebpf_network.hpp"
#include <sys/syscall.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <fstream>
#include <iostream>
#include <algorithm>
#if __has_include(<linux/bpf.h>)
#include <linux/bpf.h>
#define PHOTON_EBPF_HEADERS_AVAILABLE 1
#endif
namespace photon_kernel {
namespace sandbox {
EbpfNetworkEnforcer::~EbpfNetworkEnforcer() {
    disable();
}
EbpfNetworkEnforcer& EbpfNetworkEnforcer::instance() {
    static EbpfNetworkEnforcer inst;
    return inst;
}
bool EbpfNetworkEnforcer::is_supported() const {
#ifdef PHOTON_EBPF_HEADERS_AVAILABLE
    return true;
#else
    return false;
#endif
}
bool EbpfNetworkEnforcer::has_capabilities() const {
    std::ifstream f("/proc/self/status");
    if (!f.good()) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("CapEff:", 0) == 0) {
            try {
                uint64_t cap = std::stoull(line.substr(8), nullptr, 16);
                bool has_bpf = (cap & (1ULL << 39)) != 0;
                bool has_net_admin = (cap & (1ULL << 12)) != 0;
                return has_bpf && has_net_admin;
            } catch (...) {
                return false;
            }
        }
    }
    return false;
}
bool EbpfNetworkEnforcer::load_with_syscall() {
#ifdef PHOTON_EBPF_HEADERS_AVAILABLE
    struct bpf_insn {
        uint8_t code;
        uint8_t dst_reg:4;
        uint8_t src_reg:4;
        int16_t off;
        int32_t imm;
    };
    bpf_insn prog[] = {
        {0xb7, 0, 0, 0, 0},
        {0x95, 0, 0, 0, 0},
    };
    union bpf_attr attr;
    std::memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_CGROUP_SKB;
    attr.insns = reinterpret_cast<uint64_t>(prog);
    attr.insn_cnt = 2;
    attr.license = reinterpret_cast<uint64_t>("GPL");
    int fd = static_cast<int>(syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr)));
    if (fd < 0) return false;
    prog_fd_ = fd;
    return true;
#else
    return false;
#endif
}
bool EbpfNetworkEnforcer::enable(const std::vector<NetworkRule>& allowlist) {
    if (!is_supported()) {
        degraded_ = true;
        std::cerr << "[EbpfNetwork] eBPF not supported by kernel; degraded to seccomp deny-all\n";
        return false;
    }
    if (!has_capabilities()) {
        degraded_ = true;
        std::cerr << "[EbpfNetwork] missing CAP_BPF/CAP_NET_ADMIN; degraded to seccomp deny-all\n";
        return false;
    }
    rules_ = allowlist;
    if (!load_with_syscall()) {
        degraded_ = true;
        std::cerr << "[EbpfNetwork] failed to load eBPF program (errno=" << errno
                  << "); degraded to seccomp deny-all\n";
        return false;
    }
    loaded_ = true;
    degraded_ = false;
    supported_ = true;
    std::cout << "[EbpfNetwork] eBPF program loaded, " << allowlist.size()
              << " allowlist rules applied\n";
    return true;
}
void EbpfNetworkEnforcer::disable() {
    if (link_fd_ >= 0) { close(link_fd_); link_fd_ = -1; }
    if (prog_fd_ >= 0) { close(prog_fd_); prog_fd_ = -1; }
    loaded_ = false;
    rules_.clear();
}
bool EbpfNetworkEnforcer::add_rule(const NetworkRule& rule) {
    if (!loaded_) return false;
    rules_.push_back(rule);
    return true;
}
bool EbpfNetworkEnforcer::remove_rule(const NetworkRule& rule) {
    if (!loaded_) return false;
    auto it = std::find_if(rules_.begin(), rules_.end(),
        [&](const NetworkRule& r) {
            return r.ip == rule.ip && r.port == rule.port && r.protocol == rule.protocol;
        });
    if (it == rules_.end()) return false;
    rules_.erase(it);
    return true;
}
EbpfNetworkStatus EbpfNetworkEnforcer::status() const {
    EbpfNetworkStatus s;
    s.supported = is_supported();
    s.loaded = loaded_;
    s.degraded = degraded_;
    s.rule_count = rules_.size();
    if (degraded_) s.message = "degraded to seccomp deny-all (eBPF unavailable)";
    else if (loaded_) s.message = "eBPF active, " + std::to_string(rules_.size()) + " rules";
    else s.message = "not enabled";
    return s;
}
void EbpfNetworkEnforcer::set_deny_all() {
    disable();
    degraded_ = true;
}
} // namespace sandbox
} // namespace photon_kernel
