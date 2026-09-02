// audit_disk_guard.hpp — 审计磁盘水位监控与 spool 队列保护
//
// 用途：防止审计日志/spool 队列耗尽磁盘空间，导致审计事件丢失
// 功能：
//   1. 磁盘水位监控（80% warning, 90% critical, 95% emergency）
//   2. spool 队列溢出保护（最大文件数/总大小限制）
//   3. 旧文件轮转清理（按时间/大小自动清理最旧的 spool 文件）
//   4. 告警上报（Metrics + 日志 + 可选 webhook）
//   5. 紧急模式（磁盘 >95% 时停止写入新审计事件，只保留关键事件）
//
// 风险缓解：对应 RISK_ASSESSMENT.md 第 3.5 项"审计链本身风险"
#ifndef PHOTON_KERNEL_SANDBOX_AUDIT_DISK_GUARD_HPP
#define PHOTON_KERNEL_SANDBOX_AUDIT_DISK_GUARD_HPP
#include <string>
#include <vector>
#include <cstdint>
#include <atomic>
#include <mutex>
#include <chrono>
#include <functional>
namespace photon_kernel {
namespace sandbox {
// 磁盘水位等级
enum class DiskWaterLevel {
    NORMAL = 0,     // < 80%
    WARNING = 1,    // 80% - 90%
    CRITICAL = 2,   // 90% - 95%
    EMERGENCY = 3,  // > 95%（停止写入非关键审计事件）
};
inline const char* disk_water_level_name(DiskWaterLevel level) {
    switch (level) {
        case DiskWaterLevel::NORMAL: return "normal";
        case DiskWaterLevel::WARNING: return "warning";
        case DiskWaterLevel::CRITICAL: return "critical";
        case DiskWaterLevel::EMERGENCY: return "emergency";
    }
    return "unknown";
}
// 审计磁盘守卫配置
struct AuditDiskGuardConfig {
    std::string audit_dir = "/var/log/photon/audit";  // 审计日志目录
    std::string spool_dir = "/var/spool/photon/audit"; // spool 队列目录
    // 磁盘水位阈值（百分比）
    double warning_threshold = 80.0;    // 80% 告警
    double critical_threshold = 90.0;   // 90% 严重
    double emergency_threshold = 95.0;  // 95% 紧急（停止写入）
    // spool 队列限制
    size_t max_spool_files = 1000;      // 最大 spool 文件数
    size_t max_spool_total_mb = 1024;   // spool 总大小上限（MB）
    size_t max_audit_file_mb = 100;     // 单个审计文件大小上限（MB）
    // 轮转清理
    size_t max_audit_files = 100;        // 最大审计文件数（超过则清理最旧）
    int max_audit_retention_days = 30;   // 审计文件保留天数
    // 检查间隔
    std::chrono::seconds check_interval = std::chrono::seconds(60);
    // 告警回调
    using AlertCallback = std::function<void(DiskWaterLevel, const std::string&)>;
    AlertCallback alert_callback = nullptr;
    // 是否启用紧急模式（>95% 时停止写入非关键事件）
    bool enable_emergency_mode = true;
};
// 磁盘使用状态
struct DiskUsage {
    uint64_t total_bytes = 0;
    uint64_t used_bytes = 0;
    uint64_t available_bytes = 0;
    double usage_percent = 0.0;
    DiskWaterLevel level = DiskWaterLevel::NORMAL;
};
// 审计磁盘守卫
class AuditDiskGuard {
public:
    explicit AuditDiskGuard(const AuditDiskGuardConfig& config);
    ~AuditDiskGuard();
    AuditDiskGuard(const AuditDiskGuard&) = delete;
    AuditDiskGuard& operator=(const AuditDiskGuard&) = delete;
    // 检查磁盘使用情况（手动触发）
    DiskUsage check_disk_usage();
    // 检查 spool 队列状态
    struct SpoolStatus {
        size_t file_count = 0;
        uint64_t total_bytes = 0;
        bool overflow = false;
        std::vector<std::string> oldest_files;  // 最旧的 N 个文件（用于清理）
    };
    SpoolStatus check_spool_status();
    // 检查审计日志目录状态
    struct AuditStatus {
        size_t file_count = 0;
        uint64_t total_bytes = 0;
        std::vector<std::string> oldest_files;
        std::vector<std::string> oversized_files;  // 超过单文件上限的文件
    };
    AuditStatus check_audit_status();
    // 清理旧 spool 文件（返回清理的文件数和释放的字节数）
    struct CleanupResult {
        size_t files_removed = 0;
        uint64_t bytes_freed = 0;
        bool emergency_triggered = false;
    };
    CleanupResult cleanup_old_spool();
    // 清理旧审计文件（按保留天数/文件数）
    CleanupResult cleanup_old_audit();
    // 轮转审计文件（当前文件超过大小时，归档并创建新文件）
    bool rotate_audit_file_if_needed(const std::string& current_file);
    // 判断是否允许写入审计事件（紧急模式下非关键事件被拒绝）
    bool can_write_audit(bool is_critical_event = false);
    // 获取当前磁盘水位
    DiskWaterLevel current_level() const { return current_level_.load(); }
    // 获取最后一次检查的磁盘使用情况
    DiskUsage last_disk_usage() const;
    // 获取统计信息
    struct Stats {
        uint64_t total_checks = 0;
        uint64_t total_alerts = 0;
        uint64_t total_cleanups = 0;
        uint64_t total_bytes_freed = 0;
        uint64_t emergency_activations = 0;
        std::chrono::system_clock::time_point last_check;
        std::chrono::system_clock::time_point last_alert;
        std::chrono::system_clock::time_point last_cleanup;
    };
    Stats get_stats() const;
    // 手动触发完整检查（磁盘+spool+审计，必要时清理）
    CleanupResult run_full_check();
private:
    // 获取文件系统使用情况（通过 statvfs）
    DiskUsage get_filesystem_usage(const std::string& path);
    // 计算水位等级
    DiskWaterLevel calculate_level(double usage_percent) const;
    // 触发告警
    void trigger_alert(DiskWaterLevel level, const std::string& message);
    // 列出目录中的文件（按修改时间排序，最旧的在前）
    std::vector<std::string> list_files_sorted(const std::string& dir, bool oldest_first = true);
    // 获取目录总大小
    uint64_t get_directory_size(const std::string& dir);
    // 删除文件并记录
    bool remove_file(const std::string& path, uint64_t& bytes_freed);
    AuditDiskGuardConfig config_;
    std::atomic<DiskWaterLevel> current_level_{DiskWaterLevel::NORMAL};
    std::atomic<bool> emergency_mode_{false};
    mutable std::mutex mtx_;
    DiskUsage last_usage_;
    Stats stats_;
};
} // namespace sandbox
} // namespace photon_kernel
#endif // PHOTON_KERNEL_SANDBOX_AUDIT_DISK_GUARD_HPP
