// audit_disk_guard.cpp — 审计磁盘水位监控实现
#include "photon_kernel/sandbox/audit_disk_guard.hpp"
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstring>
namespace photon_kernel {
namespace sandbox {
AuditDiskGuard::AuditDiskGuard(const AuditDiskGuardConfig& config)
    : config_(config) {
    // 确保目录存在
    std::string cmd = "mkdir -p " + config_.audit_dir + " " + config_.spool_dir + " 2>/dev/null";
    system(cmd.c_str());
    // 初始检查
    check_disk_usage();
}
AuditDiskGuard::~AuditDiskGuard() = default;
DiskUsage AuditDiskGuard::get_filesystem_usage(const std::string& path) {
    DiskUsage usage;
    struct statvfs stat;
    if (statvfs(path.c_str(), &stat) != 0) {
        return usage;
    }
    usage.total_bytes = static_cast<uint64_t>(stat.f_blocks) * stat.f_frsize;
    usage.available_bytes = static_cast<uint64_t>(stat.f_bavail) * stat.f_frsize;
    usage.used_bytes = usage.total_bytes - static_cast<uint64_t>(stat.f_bfree) * stat.f_frsize;
    if (usage.total_bytes > 0) {
        usage.usage_percent = (100.0 * usage.used_bytes) / usage.total_bytes;
    }
    usage.level = calculate_level(usage.usage_percent);
    return usage;
}
DiskWaterLevel AuditDiskGuard::calculate_level(double usage_percent) const {
    if (usage_percent >= config_.emergency_threshold) return DiskWaterLevel::EMERGENCY;
    if (usage_percent >= config_.critical_threshold) return DiskWaterLevel::CRITICAL;
    if (usage_percent >= config_.warning_threshold) return DiskWaterLevel::WARNING;
    return DiskWaterLevel::NORMAL;
}
DiskUsage AuditDiskGuard::check_disk_usage() {
    std::lock_guard<std::mutex> lock(mtx_);
    DiskUsage usage = get_filesystem_usage(config_.audit_dir);
    last_usage_ = usage;
    stats_.total_checks++;
    stats_.last_check = std::chrono::system_clock::now();
    DiskWaterLevel old_level = current_level_.load();
    current_level_.store(usage.level);
    // 水位变化时触发告警
    if (usage.level != old_level && usage.level != DiskWaterLevel::NORMAL) {
        std::ostringstream msg;
        msg << "Disk usage " << usage.usage_percent << "% ("
            << usage.used_bytes / (1024*1024) << "MB / "
            << usage.total_bytes / (1024*1024) << "MB)";
        trigger_alert(usage.level, msg.str());
    }
    // 紧急模式
    if (usage.level == DiskWaterLevel::EMERGENCY && !emergency_mode_.load()) {
        emergency_mode_.store(true);
        stats_.emergency_activations++;
        std::cerr << "[AuditDiskGuard] EMERGENCY: disk >" << config_.emergency_threshold
                  << "%, non-critical audit writes suspended\n";
    } else if (usage.level < DiskWaterLevel::CRITICAL && emergency_mode_.load()) {
        emergency_mode_.store(false);
        std::cerr << "[AuditDiskGuard] Emergency mode deactivated, disk usage normal\n";
    }
    return usage;
}
void AuditDiskGuard::trigger_alert(DiskWaterLevel level, const std::string& message) {
    stats_.total_alerts++;
    stats_.last_alert = std::chrono::system_clock::now();
    std::cerr << "[AuditDiskGuard] ALERT [" << disk_water_level_name(level) << "]: " << message << "\n";
    if (config_.alert_callback) {
        config_.alert_callback(level, message);
    }
}
std::vector<std::string> AuditDiskGuard::list_files_sorted(const std::string& dir, bool oldest_first) {
    std::vector<std::string> files;
    DIR* d = opendir(dir.c_str());
    if (!d) return files;
    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        std::string full_path = dir + "/" + entry->d_name;
        struct stat st;
        if (stat(full_path.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            files.push_back(full_path);
        }
    }
    closedir(d);
    // 按修改时间排序
    std::sort(files.begin(), files.end(), [oldest_first](const std::string& a, const std::string& b) {
        struct stat sa, sb;
        stat(a.c_str(), &sa);
        stat(b.c_str(), &sb);
        return oldest_first ? (sa.st_mtime < sb.st_mtime) : (sa.st_mtime > sb.st_mtime);
    });
    return files;
}
uint64_t AuditDiskGuard::get_directory_size(const std::string& dir) {
    uint64_t total = 0;
    DIR* d = opendir(dir.c_str());
    if (!d) return 0;
    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        std::string full_path = dir + "/" + entry->d_name;
        struct stat st;
        if (stat(full_path.c_str(), &st) == 0) {
            if (S_ISREG(st.st_mode)) {
                total += static_cast<uint64_t>(st.st_size);
            }
        }
    }
    closedir(d);
    return total;
}
bool AuditDiskGuard::remove_file(const std::string& path, uint64_t& bytes_freed) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        bytes_freed += static_cast<uint64_t>(st.st_size);
    }
    return (unlink(path.c_str()) == 0);
}
AuditDiskGuard::SpoolStatus AuditDiskGuard::check_spool_status() {
    SpoolStatus status;
    auto files = list_files_sorted(config_.spool_dir, true);
    status.file_count = files.size();
    status.total_bytes = get_directory_size(config_.spool_dir);
    status.overflow = (status.file_count > config_.max_spool_files) ||
                      (status.total_bytes > config_.max_spool_total_mb * 1024 * 1024);
    // 保留最旧的 10 个文件引用（用于清理）
    size_t take = std::min(files.size(), static_cast<size_t>(10));
    status.oldest_files.assign(files.begin(), files.begin() + take);
    return status;
}
AuditDiskGuard::AuditStatus AuditDiskGuard::check_audit_status() {
    AuditStatus status;
    auto files = list_files_sorted(config_.audit_dir, true);
    status.file_count = files.size();
    status.total_bytes = get_directory_size(config_.audit_dir);
    size_t take = std::min(files.size(), static_cast<size_t>(10));
    status.oldest_files.assign(files.begin(), files.begin() + take);
    // 检查超大文件
    for (const auto& f : files) {
        struct stat st;
        if (stat(f.c_str(), &st) == 0 && st.st_size > config_.max_audit_file_mb * 1024 * 1024) {
            status.oversized_files.push_back(f);
        }
    }
    return status;
}
AuditDiskGuard::CleanupResult AuditDiskGuard::cleanup_old_spool() {
    std::lock_guard<std::mutex> lock(mtx_);
    CleanupResult result;
    auto status = check_spool_status();
    if (!status.overflow) return result;
    // 清理最旧的文件，直到回到限制以下
    auto files = list_files_sorted(config_.spool_dir, true);
    for (const auto& f : files) {
        // 检查是否还需要清理
        auto current = check_spool_status();
        if (!current.overflow) break;
        if (remove_file(f, result.bytes_freed)) {
            result.files_removed++;
        }
    }
    stats_.total_cleanups++;
    stats_.total_bytes_freed += result.bytes_freed;
    stats_.last_cleanup = std::chrono::system_clock::now();
    return result;
}
AuditDiskGuard::CleanupResult AuditDiskGuard::cleanup_old_audit() {
    std::lock_guard<std::mutex> lock(mtx_);
    CleanupResult result;
    auto files = list_files_sorted(config_.audit_dir, true);
    auto now = std::chrono::system_clock::now();
    // 按保留天数清理
    for (const auto& f : files) {
        struct stat st;
        if (stat(f.c_str(), &st) == 0) {
            auto file_time = std::chrono::system_clock::from_time_t(st.st_mtime);
            auto age = std::chrono::duration_cast<std::chrono::hours>(now - file_time).count();
            if (age > config_.max_audit_retention_days * 24) {
                if (remove_file(f, result.bytes_freed)) {
                    result.files_removed++;
                }
            }
        }
    }
    // 按文件数限制清理（最旧的先删）
    files = list_files_sorted(config_.audit_dir, true);
    while (files.size() > config_.max_audit_files) {
        if (remove_file(files.front(), result.bytes_freed)) {
            result.files_removed++;
        }
        files.erase(files.begin());
    }
    if (result.files_removed > 0) {
        stats_.total_cleanups++;
        stats_.total_bytes_freed += result.bytes_freed;
        stats_.last_cleanup = std::chrono::system_clock::now();
    }
    return result;
}
bool AuditDiskGuard::rotate_audit_file_if_needed(const std::string& current_file) {
    struct stat st;
    if (stat(current_file.c_str(), &st) != 0) return false;
    if (st.st_size < config_.max_audit_file_mb * 1024 * 1024) return false;
    // 轮转：重命名当前文件为 .1，创建新文件
    std::string rotated = current_file + ".1";
    // 删除旧的 .1
    unlink(rotated.c_str());
    if (rename(current_file.c_str(), rotated.c_str()) != 0) return false;
    // 创建新的空文件
    std::ofstream new_file(current_file, std::ios::trunc);
    return new_file.is_open();
}
bool AuditDiskGuard::can_write_audit(bool is_critical_event) {
    if (!config_.enable_emergency_mode) return true;
    if (emergency_mode_.load() && !is_critical_event) {
        return false;  // 紧急模式下非关键事件被拒绝
    }
    return true;
}
DiskUsage AuditDiskGuard::last_disk_usage() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return last_usage_;
}
AuditDiskGuard::Stats AuditDiskGuard::get_stats() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return stats_;
}
AuditDiskGuard::CleanupResult AuditDiskGuard::run_full_check() {
    CleanupResult total;
    // 1. 检查磁盘
    auto usage = check_disk_usage();
    // 2. 检查并清理 spool
    auto spool_result = cleanup_old_spool();
    total.files_removed += spool_result.files_removed;
    total.bytes_freed += spool_result.bytes_freed;
    // 3. 检查并清理审计日志
    auto audit_result = cleanup_old_audit();
    total.files_removed += audit_result.files_removed;
    total.bytes_freed += audit_result.bytes_freed;
    // 4. 紧急模式检查
    if (usage.level == DiskWaterLevel::EMERGENCY) {
        total.emergency_triggered = true;
        // 紧急模式下更激进地清理
        auto files = list_files_sorted(config_.spool_dir, true);
        for (const auto& f : files) {
            if (remove_file(f, total.bytes_freed)) {
                total.files_removed++;
            }
        }
    }
    return total;
}
} // namespace sandbox
} // namespace photon_kernel
