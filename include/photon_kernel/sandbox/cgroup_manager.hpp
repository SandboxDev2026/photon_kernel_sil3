#ifndef PHOTON_KERNEL_SANDBOX_CGROUP_MANAGER_HPP
#define PHOTON_KERNEL_SANDBOX_CGROUP_MANAGER_HPP
// cgroup v2 内核级资源隔离管理器（核弹级优化二）：
// rlimit 是进程级软限制，cgroup v2 是内核级硬隔离。双管齐下，彻底锁死资源。
//
// 支持：内存上限（memory.max）、CPU 带宽（cpu.max）、进程数上限（pids.max）。
// 运行时检测 cgroup 可写性；容器内 /sys/fs/cgroup 常为只读挂载，此时自动降级
// （返回 degraded 状态，不影响沙盒核心功能，仅无 cgroup 硬隔离）。
#include <string>
#include <cstdint>
#include <atomic>
namespace photon_kernel {
namespace sandbox {
struct CgroupConfig {
    std::string cgroup_path = "/sys/fs/cgroup/photon_sandbox/";
    int64_t memory_max = 256 * 1024 * 1024;  // 256MB
    int64_t cpu_max_us = 100000;               // 100ms / 周期（=1 核）
    int64_t cpu_period_us = 100000;            // 100ms 周期
    int64_t pids_max = 64;                      // 最大进程数
};
struct CgroupStatus {
    bool initialized = false;
    bool degraded = false;       // true：cgroup 只读或不可用，已降级为仅 rlimit
    std::string message;
    int64_t memory_current = 0;  // 当前内存使用（bytes）
};
class CgroupManager {
public:
    static CgroupManager& instance();
    // 初始化 cgroup（创建目录 + 写入限制）
    // 成功返回 true；cgroup 只读/不可用返回 false 并设置 degraded
    bool init(const CgroupConfig& config = CgroupConfig{});
    // 将 PID 加入 cgroup
    bool add_pid(pid_t pid);
    // 查询当前 cgroup 内存使用（bytes）
    int64_t get_memory_usage() const;
    // 清理 cgroup（移出所有进程 + 删除目录）
    void cleanup();
    [[nodiscard]] bool initialized() const { return initialized_.load(); }
    [[nodiscard]] bool degraded() const { return degraded_.load(); }
    [[nodiscard]] CgroupStatus status() const;
private:
    CgroupManager() = default;
    ~CgroupManager();
    CgroupManager(const CgroupManager&) = delete;
    CgroupManager& operator=(const CgroupManager&) = delete;
    // 检测 cgroup v2 是否可写
    bool check_writable() const;
    std::string cgroup_path_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> degraded_{false};
};
} // namespace sandbox
} // namespace photon_kernel
#endif
