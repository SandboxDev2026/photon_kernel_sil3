// PhotonBox 运行时入侵检测引擎
// 监控沙箱内进程的异常行为模式，支持可插拔检测规则。
//
// 检测维度：
//   1. 系统调用异常（频率突变、罕见调用、参数异常）
//   2. 进程行为偏离（基线对比、fork炸弹、异常exec）
//   3. 文件系统异常（敏感路径访问、大量创建删除）
//   4. 网络异常（罕见端口、大量连接、DNS隧道特征）
//   5. 资源异常（CPU/内存/FD 突增、OOM 前兆）
//
// 设计原则：
//   - 规则可插拔：每条检测规则独立实现，可启用/禁用
//   - 阈值可配置：通过 DetectionConfig 调整灵敏度
//   - 事件可追溯：每条告警包含时间、进程、证据、置信度
//   - 低开销：采样 + 增量统计，避免全量追踪
#pragma once

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <cstdint>
#include <chrono>
#include <mutex>
#include <memory>
#include "photon_kernel/sandbox/risk_level.hpp"

namespace photon_kernel {
namespace sandbox {

// ========== 告警严重程度 ==========
enum class AlertSeverity {
    INFO,       // 信息，仅记录
    LOW,        // 低风险，可能是正常行为
    MEDIUM,     // 中风险，需要关注
    HIGH,       // 高风险，可能是攻击
    CRITICAL    // 严重，确认攻击或逃逸
};

// ========== 检测规则类型 ==========
enum class DetectionRuleType {
    SYSCALL_FREQUENCY,      // 系统调用频率异常
    SYSCALL_RARE,           // 罕见系统调用
    PROCESS_FORK_BOMB,      // fork 炸弹
    PROCESS_EXEC_CHAIN,     // 异常 exec 链
    FILE_SENSITIVE_PATH,    // 敏感路径访问
    FILE_TURBULENCE,        // 文件大量创建删除
    NETWORK_RARE_PORT,      // 罕见端口连接
    NETWORK_DNS_TUNNEL,     // DNS 隧道特征
    RESOURCE_CPU_SPIKE,     // CPU 突增
    RESOURCE_MEMORY_SPIKE,  // 内存突增
    RESOURCE_FD_LEAK        // FD 泄漏
};

// ========== 检测配置 ==========
struct DetectionConfig {
    bool enabled = true;
    uint32_t sampling_interval_ms = 100;   // 采样间隔（毫秒）
    uint32_t window_size = 60;              // 统计窗口大小（秒）
    double alert_threshold = 0.7;           // 告警置信度阈值
    uint32_t max_events_per_window = 1000;  // 每窗口最大事件数

    // 各规则阈值
    uint32_t syscall_rate_threshold = 10000;   // 每秒系统调用阈值
    uint32_t fork_rate_threshold = 100;         // 每秒 fork 阈值
    uint32_t file_creation_rate_threshold = 500; // 每秒文件创建阈值
    uint32_t connection_rate_threshold = 100;    // 每秒连接阈值
    double cpu_spike_ratio = 3.0;                // CPU 突增倍数
    double memory_spike_ratio = 2.0;             // 内存突增倍数
    uint32_t fd_warning_threshold = 800;         // FD 警告阈值（占上限百分比）

    // 罕见系统调用列表（默认禁止的高危调用）
    std::unordered_set<std::string> rare_syscalls = {
        "ptrace", "kexec_load", "init_module", "finit_module",
        "mount", "umount2", "open_by_handle_at", "reboot",
        "swapon", "swapoff", "sysfs", "_sysctl", "ioperm",
        "iopl", "vm86", "vm86old", "modify_ldt"
    };

    // 敏感文件路径前缀
    std::vector<std::string> sensitive_paths = {
        "/etc/shadow", "/etc/sudoers", "/root/",
        "/proc/kcore", "/proc/sysrq-trigger",
        "/dev/mem", "/dev/kmem", "/dev/port"
    };

    // 罕见端口（非标准服务端口）
    std::unordered_set<uint16_t> common_ports = {
        22, 53, 80, 123, 443, 465, 587, 853, 993, 995,
        3306, 5432, 6379, 8080, 8443, 9090
    };
};

// ========== 进程行为统计 ==========
struct ProcessStats {
    pid_t pid = 0;
    std::string comm;           // 进程名
    uint64_t syscall_count = 0; // 系统调用总数
    uint64_t fork_count = 0;    // fork 次数
    uint64_t exec_count = 0;    // exec 次数
    uint64_t file_created = 0;  // 创建文件数
    uint64_t file_deleted = 0;  // 删除文件数
    uint64_t connections = 0;   // 网络连接数
    double cpu_usage = 0.0;     // CPU 使用率（%）
    uint64_t memory_bytes = 0;  // 内存使用（字节）
    uint32_t fd_count = 0;      // 文件描述符数
    std::chrono::steady_clock::time_point last_update;
};

// ========== 入侵告警 ==========
struct IntrusionAlert {
    uint64_t id = 0;
    std::string timestamp;           // ISO 8601 时间
    AlertSeverity severity;          // 严重程度
    DetectionRuleType rule_type;     // 触发规则
    std::string rule_name;           // 规则名称
    std::string description;         // 告警描述
    double confidence;                // 置信度（0.0 - 1.0）
    pid_t pid = 0;                   // 相关进程 ID
    std::string process_name;        // 相关进程名
    std::map<std::string, std::string> evidence;  // 证据键值对
    std::string remediation;         // 建议处置措施
    bool is_escalated = false;       // 是否已升级（触发自动响应）
};

// ========== 检测规则基类 ==========
class IDetectionRule {
public:
    virtual ~IDetectionRule() = default;
    virtual DetectionRuleType GetType() const = 0;
    virtual std::string GetName() const = 0;
    virtual bool IsEnabled() const = 0;
    virtual void SetEnabled(bool enabled) = 0;
    // 评估进程统计，返回告警（可能为空）
    virtual std::optional<IntrusionAlert> Evaluate(
        const ProcessStats& stats,
        const ProcessStats& baseline,
        const DetectionConfig& config
    ) = 0;
};

// ========== 具体检测规则实现 ==========

// 规则1：系统调用频率异常
class SyscallFrequencyRule : public IDetectionRule {
public:
    DetectionRuleType GetType() const override { return DetectionRuleType::SYSCALL_FREQUENCY; }
    std::string GetName() const override { return "syscall_frequency"; }
    bool IsEnabled() const override { return enabled_; }
    void SetEnabled(bool enabled) override { enabled_ = enabled; }

    std::optional<IntrusionAlert> Evaluate(
        const ProcessStats& stats,
        const ProcessStats& baseline,
        const DetectionConfig& config
    ) override {
        if (!enabled_) return std::nullopt;
        if (stats.syscall_count < config.syscall_rate_threshold) return std::nullopt;

        double ratio = baseline.syscall_count > 0
            ? (double)stats.syscall_count / baseline.syscall_count
            : 10.0;

        if (ratio < 5.0) return std::nullopt;

        IntrusionAlert alert;
        alert.severity = ratio > 20.0 ? AlertSeverity::HIGH : AlertSeverity::MEDIUM;
        alert.rule_type = GetType();
        alert.rule_name = GetName();
        alert.description = "系统调用频率异常：" + std::to_string(stats.syscall_count)
            + " 次/窗口，基线 " + std::to_string(baseline.syscall_count)
            + "，倍率 " + std::to_string(ratio);
        alert.confidence = std::min(1.0, ratio / 30.0);
        alert.pid = stats.pid;
        alert.process_name = stats.comm;
        alert.evidence["syscall_count"] = std::to_string(stats.syscall_count);
        alert.evidence["baseline"] = std::to_string(baseline.syscall_count);
        alert.evidence["ratio"] = std::to_string(ratio);
        alert.remediation = "检查进程是否陷入系统调用循环，考虑限制调用频率";
        return alert;
    }

private:
    bool enabled_ = true;
};

// 规则2：罕见系统调用
class RareSyscallRule : public IDetectionRule {
public:
    DetectionRuleType GetType() const override { return DetectionRuleType::SYSCALL_RARE; }
    std::string GetName() const override { return "rare_syscall"; }
    bool IsEnabled() const override { return enabled_; }
    void SetEnabled(bool enabled) override { enabled_ = enabled; }

    void AddObservedSyscall(const std::string& syscall) {
        std::lock_guard<std::mutex> lock(mutex_);
        observed_rare_.push_back(syscall);
    }

    std::optional<IntrusionAlert> Evaluate(
        const ProcessStats& stats,
        const ProcessStats& baseline,
        const DetectionConfig& config
    ) override {
        (void)stats; (void)baseline;
        if (!enabled_) return std::nullopt;

        std::lock_guard<std::mutex> lock(mutex_);
        if (observed_rare_.empty()) return std::nullopt;

        std::string syscall_list;
        for (const auto& s : observed_rare_) {
            if (!syscall_list.empty()) syscall_list += ", ";
            syscall_list += s;
        }

        IntrusionAlert alert;
        alert.severity = AlertSeverity::HIGH;
        alert.rule_type = GetType();
        alert.rule_name = GetName();
        alert.description = "检测到罕见/高危系统调用: " + syscall_list;
        alert.confidence = 0.9;
        alert.evidence["rare_syscalls"] = syscall_list;
        alert.remediation = "立即终止进程，审计是否存在逃逸尝试";
        observed_rare_.clear();
        return alert;
    }

private:
    bool enabled_ = true;
    std::mutex mutex_;
    std::vector<std::string> observed_rare_;
};

// 规则3：fork 炸弹检测
class ForkBombRule : public IDetectionRule {
public:
    DetectionRuleType GetType() const override { return DetectionRuleType::PROCESS_FORK_BOMB; }
    std::string GetName() const override { return "fork_bomb"; }
    bool IsEnabled() const override { return enabled_; }
    void SetEnabled(bool enabled) override { enabled_ = enabled; }

    std::optional<IntrusionAlert> Evaluate(
        const ProcessStats& stats,
        const ProcessStats& baseline,
        const DetectionConfig& config
    ) override {
        if (!enabled_) return std::nullopt;
        if (stats.fork_count < config.fork_rate_threshold) return std::nullopt;

        IntrusionAlert alert;
        alert.severity = AlertSeverity::CRITICAL;
        alert.rule_type = GetType();
        alert.rule_name = GetName();
        alert.description = "检测到 fork 炸弹特征：" + std::to_string(stats.fork_count)
            + " 次 fork/窗口（阈值 " + std::to_string(config.fork_rate_threshold) + "）";
        alert.confidence = 0.95;
        alert.pid = stats.pid;
        alert.process_name = stats.comm;
        alert.evidence["fork_count"] = std::to_string(stats.fork_count);
        alert.evidence["threshold"] = std::to_string(config.fork_rate_threshold);
        alert.remediation = "立即冻结进程树，检查 cgroup pids.max 限制";
        return alert;
    }

private:
    bool enabled_ = true;
};

// 规则4：敏感路径访问
class SensitivePathRule : public IDetectionRule {
public:
    DetectionRuleType GetType() const override { return DetectionRuleType::FILE_SENSITIVE_PATH; }
    std::string GetName() const override { return "sensitive_path"; }
    bool IsEnabled() const override { return enabled_; }
    void SetEnabled(bool enabled) override { enabled_ = enabled; }

    void AddPathAccess(const std::string& path) {
        std::lock_guard<std::mutex> lock(mutex_);
        accessed_paths_.push_back(path);
    }

    std::optional<IntrusionAlert> Evaluate(
        const ProcessStats& stats,
        const ProcessStats& baseline,
        const DetectionConfig& config
    ) override {
        (void)stats; (void)baseline;
        if (!enabled_) return std::nullopt;

        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> hits;
        for (const auto& path : accessed_paths_) {
            for (const auto& sensitive : config.sensitive_paths) {
                if (path.find(sensitive) == 0) {
                    hits.push_back(path);
                    break;
                }
            }
        }
        accessed_paths_.clear();

        if (hits.empty()) return std::nullopt;

        std::string path_list;
        for (const auto& p : hits) {
            if (!path_list.empty()) path_list += ", ";
            path_list += p;
        }

        IntrusionAlert alert;
        alert.severity = AlertSeverity::HIGH;
        alert.rule_type = GetType();
        alert.rule_name = GetName();
        alert.description = "检测到敏感路径访问: " + path_list;
        alert.confidence = 0.85;
        alert.evidence["accessed_paths"] = path_list;
        alert.remediation = "检查 Landlock/seccomp 路径过滤是否生效";
        return alert;
    }

private:
    bool enabled_ = true;
    std::mutex mutex_;
    std::vector<std::string> accessed_paths_;
};

// 规则5：FD 泄漏检测
class FdLeakRule : public IDetectionRule {
public:
    DetectionRuleType GetType() const override { return DetectionRuleType::RESOURCE_FD_LEAK; }
    std::string GetName() const override { return "fd_leak"; }
    bool IsEnabled() const override { return enabled_; }
    void SetEnabled(bool enabled) override { enabled_ = enabled; }

    std::optional<IntrusionAlert> Evaluate(
        const ProcessStats& stats,
        const ProcessStats& baseline,
        const DetectionConfig& config
    ) override {
        if (!enabled_) return std::nullopt;
        if (stats.fd_count < config.fd_warning_threshold) return std::nullopt;

        double usage_pct = (double)stats.fd_count / 1024.0 * 100.0;  // 假设上限 1024

        IntrusionAlert alert;
        alert.severity = usage_pct > 90.0 ? AlertSeverity::HIGH : AlertSeverity::MEDIUM;
        alert.rule_type = GetType();
        alert.rule_name = GetName();
        alert.description = "FD 使用量过高：" + std::to_string(stats.fd_count)
            + "（约 " + std::to_string((int)usage_pct) + "% 上限）";
        alert.confidence = 0.8;
        alert.pid = stats.pid;
        alert.process_name = stats.comm;
        alert.evidence["fd_count"] = std::to_string(stats.fd_count);
        alert.evidence["usage_pct"] = std::to_string(usage_pct);
        alert.remediation = "检查是否存在 FD 泄漏，考虑设置 ulimit -n";
        return alert;
    }

private:
    bool enabled_ = true;
};

// ========== 入侵检测引擎 ==========
class IntrusionDetectionEngine {
public:
    explicit IntrusionDetectionEngine(const DetectionConfig& config = {});
    ~IntrusionDetectionEngine();

    // 配置管理
    void UpdateConfig(const DetectionConfig& config);
    const DetectionConfig& GetConfig() const;

    // 规则管理
    void RegisterRule(std::unique_ptr<IDetectionRule> rule);
    void EnableRule(DetectionRuleType type, bool enabled);
    std::vector<std::string> GetRuleNames() const;

    // 数据输入
    void UpdateProcessStats(const ProcessStats& stats);
    void ReportSyscall(const std::string& syscall_name, pid_t pid);
    void ReportFileAccess(const std::string& path, pid_t pid);

    // 检测执行
    std::vector<IntrusionAlert> RunDetectionCycle();

    // 告警查询
    std::vector<IntrusionAlert> GetAlerts(AlertSeverity min_severity = AlertSeverity::INFO) const;
    std::vector<IntrusionAlert> GetUnacknowledgedAlerts() const;
    void AcknowledgeAlert(uint64_t alert_id);

    // 统计
    uint64_t GetTotalAlerts() const;
    uint64_t GetAlertsBySeverity(AlertSeverity severity) const;
    std::map<std::string, uint64_t> GetAlertCountsByRule() const;

    // 基线管理
    void SetBaseline(const ProcessStats& baseline);
    ProcessStats GetBaseline() const;
    void ResetBaseline();

private:
    DetectionConfig config_;
    std::vector<std::unique_ptr<IDetectionRule>> rules_;
    std::unordered_map<pid_t, ProcessStats> current_stats_;
    ProcessStats baseline_;
    std::vector<IntrusionAlert> alerts_;
    std::unordered_set<uint64_t> acknowledged_;
    uint64_t next_alert_id_ = 1;
    mutable std::mutex mutex_;

    void RegisterDefaultRules();
    IntrusionAlert AssignAlertId(IntrusionAlert alert);
};

} // namespace sandbox
} // namespace photon_kernel
