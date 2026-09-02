// strong_pool_config.hpp - StrongPool 强隔离池配置
// 进化生成的候选个体强制路由StrongPool, 禁用LightPool
// 硬资源上限: 128M内存 / 1CPU / 10s超时
// VM TTL超时强制销毁
// Firecracker快照预启动VM池
// 单机预留30%内存缓冲
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <chrono>

namespace photon_kernel::payload {

// 池类型
enum class PoolType : uint8_t {
    LIGHT = 0,    // LightPool: fork+seccomp进程沙盒(共享内核, 低延迟)
    STRONG = 1,   // StrongPool: Firecracker MicroVM(独立内核, 强隔离)
    AUTO = 2      // 自动选择(根据风险等级)
};

// StrongPool 配置
struct StrongPoolConfig {
    // ===== 核心安全策略 =====
    // 进化生成的候选个体强制路由StrongPool, 禁用LightPool
    bool force_strong_for_evolution = true;  // 进化候选强制StrongPool
    bool allow_light_pool = false;            // 全局禁用LightPool(进化场景)
    bool reject_on_no_kvm = true;             // 无KVM时拒绝任务(不静默降级)

    // ===== 硬资源上限 =====
    size_t memory_limit_bytes = 128 * 1024 * 1024;  // 每个VM 128M内存
    int    cpu_count = 1;                              // 每个VM 1个CPU
    uint32_t timeout_ms = 10 * 1000;                  // 超时10秒
    size_t disk_limit_bytes = 512 * 1024 * 1024;     // 磁盘512M
    int    max_processes = 32;                          // 最大进程数

    // ===== VM TTL =====
    bool enable_vm_ttl = true;               // 开启VM TTL
    uint32_t vm_ttl_ms = 30 * 1000;         // VM最大存活时间30秒(无论是否正常结束)
    bool force_destroy_on_ttl = true;        // TTL超时强制销毁

    // ===== Firecracker快照预启动 =====
    bool enable_snapshot_pool = true;         // 启用快照预启动池
    int  snapshot_pool_size = 8;              // 预启动VM数量
    int  snapshot_pool_min = 4;               // 最小空闲VM数
    uint32_t snapshot_restore_timeout_ms = 500;  // 快照恢复超时
    std::string snapshot_path = "/var/lib/photon/snapshots/base_vm.snap";  // 基础快照路径
    std::string firecracker_binary = "/usr/local/bin/firecracker";
    std::string kernel_image = "/var/lib/photon/kernel/vmlinux.bin";
    std::string rootfs_image = "/var/lib/photon/rootfs/rootfs.ext4";

    // ===== 单机内存缓冲 =====
    double memory_reserve_ratio = 0.30;       // 预留30%内存缓冲
    size_t memory_reserve_min_bytes = 512 * 1024 * 1024;  // 最小预留512M
    size_t max_total_vm_memory = 0;           // 最大总VM内存(0=自动计算)
    bool oom_protection = true;               // OOM保护(超过限制拒绝新任务)

    // ===== 网络隔离 =====
    bool enable_network_isolation = true;      // 网络隔离
    bool block_internal_ips = true;            // 阻止内网IP(RFC1918)
    bool block_metadata_service = true;        // 阻止云元数据服务
    std::string allowed_domains = "";          // 允许的域名白名单(空=全部禁止)

    // ===== 审计 =====
    bool enable_audit = true;                  // 审计日志
    bool audit_syscalls = true;                // 系统调用审计
    bool audit_network = true;                  // 网络访问审计

    // 计算最大并发VM数(基于可用内存)
    int calculate_max_concurrent_vms(size_t total_system_memory) const {
        size_t reserved = static_cast<size_t>(total_system_memory * memory_reserve_ratio);
        if (reserved < memory_reserve_min_bytes) reserved = memory_reserve_min_bytes;
        size_t available = total_system_memory - reserved;
        if (max_total_vm_memory > 0 && max_total_vm_memory < available) {
            available = max_total_vm_memory;
        }
        return static_cast<int>(available / memory_limit_bytes);
    }

    // 验证配置有效性
    bool validate() const {
        if (memory_limit_bytes < 16 * 1024 * 1024) return false;  // 最小16M
        if (cpu_count < 1) return false;
        if (timeout_ms < 100) return false;  // 最小100ms
        if (memory_reserve_ratio < 0.1 || memory_reserve_ratio > 0.8) return false;
        return true;
    }
};

// 进化任务专用配置(最严格)
inline StrongPoolConfig evolution_task_config() {
    StrongPoolConfig cfg;
    cfg.force_strong_for_evolution = true;
    cfg.allow_light_pool = false;           // 进化候选禁用LightPool
    cfg.reject_on_no_kvm = true;            // 无KVM拒绝任务
    cfg.memory_limit_bytes = 128 * 1024 * 1024;  // 128M
    cfg.cpu_count = 1;
    cfg.timeout_ms = 10 * 1000;             // 10s
    cfg.enable_vm_ttl = true;
    cfg.vm_ttl_ms = 30 * 1000;              // 30s TTL
    cfg.force_destroy_on_ttl = true;
    cfg.enable_snapshot_pool = true;
    cfg.snapshot_pool_size = 8;
    cfg.memory_reserve_ratio = 0.30;         // 30%缓冲
    cfg.block_internal_ips = true;
    cfg.block_metadata_service = true;
    return cfg;
}

} // namespace photon_kernel::payload
