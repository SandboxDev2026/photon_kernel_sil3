#include "photon_kernel/sandbox/cgroup_manager.hpp"
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
namespace photon_kernel {
namespace sandbox {
CgroupManager::~CgroupManager() {
    cleanup();
}
CgroupManager& CgroupManager::instance() {
    static CgroupManager mgr;
    return mgr;
}
bool CgroupManager::check_writable() const {
    // 检测 cgroup v2 根目录是否可写
    std::ifstream f("/sys/fs/cgroup/cgroup.controllers");
    if (!f.good()) return false;
    // 尝试创建临时目录检测可写性
    char tmpl[] = "/sys/fs/cgroup/.photon_write_test_XXXXXX";
    if (mkdtemp(tmpl) != nullptr) {
        rmdir(tmpl);
        return true;
    }
    return false;
}
bool CgroupManager::init(const CgroupConfig& config) {
    if (initialized_) return true;
    cgroup_path_ = config.cgroup_path;
    if (!cgroup_path_.empty() && cgroup_path_.back() != '/') {
        cgroup_path_ += '/';
    }
    if (!check_writable()) {
        degraded_ = true;
        std::cerr << "[CgroupManager] cgroup v2 is read-only or unavailable; "
                     "degraded to rlimit-only (no kernel-level hard isolation)\n";
        return false;
    }
    if (mkdir(cgroup_path_.c_str(), 0755) != 0 && errno != EEXIST) {
        degraded_ = true;
        std::cerr << "[CgroupManager] mkdir(" << cgroup_path_ << ") failed: "
                  << std::strerror(errno) << "\n";
        return false;
    }
    {
        std::ofstream f(cgroup_path_ + "memory.max");
        if (f.good()) f << config.memory_max;
    }
    {
        std::ofstream f(cgroup_path_ + "cpu.max");
        if (f.good()) f << config.cpu_max_us << " " << config.cpu_period_us;
    }
    {
        std::ofstream f(cgroup_path_ + "pids.max");
        if (f.good()) f << config.pids_max;
    }
    initialized_ = true;
    degraded_ = false;
    std::cout << "[CgroupManager] Initialized cgroup v2 at " << cgroup_path_
              << " (mem=" << config.memory_max / (1024*1024) << "MB"
              << ", cpu=" << config.cpu_max_us << "/" << config.cpu_period_us << "us"
              << ", pids=" << config.pids_max << ")\n";
    return true;
}
bool CgroupManager::add_pid(pid_t pid) {
    if (!initialized_ || degraded_) return false;
    std::ofstream f(cgroup_path_ + "cgroup.procs");
    if (!f.good()) return false;
    f << pid;
    return f.good();
}
int64_t CgroupManager::get_memory_usage() const {
    if (!initialized_ || degraded_) return 0;
    std::ifstream f(cgroup_path_ + "memory.current");
    if (!f.good()) return 0;
    int64_t val = 0;
    f >> val;
    return val;
}
void CgroupManager::cleanup() {
    if (!initialized_) return;
    rmdir(cgroup_path_.c_str());
    initialized_ = false;
    degraded_ = false;
}
CgroupStatus CgroupManager::status() const {
    CgroupStatus s;
    s.initialized = initialized_.load();
    s.degraded = degraded_.load();
    if (s.degraded) {
        s.message = "cgroup v2 read-only or unavailable; degraded to rlimit-only";
    } else if (s.initialized) {
        s.message = "cgroup v2 active: " + cgroup_path_;
        s.memory_current = get_memory_usage();
    } else {
        s.message = "not initialized";
    }
    return s;
}
} // namespace sandbox
} // namespace photon_kernel
