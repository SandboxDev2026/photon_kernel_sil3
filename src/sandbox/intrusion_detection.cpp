// PhotonBox 运行时入侵检测引擎实现
#include "photon_kernel/sandbox/intrusion_detection.hpp"

#include <algorithm>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace photon_kernel {
namespace sandbox {

namespace {

std::string GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
    localtime_r(&time_t, &tm_buf);
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S");
    return oss.str();
}

AlertSeverity MaxSeverity(AlertSeverity a, AlertSeverity b) {
    return static_cast<AlertSeverity>(std::max(
        static_cast<int>(a), static_cast<int>(b)));
}

} // anonymous namespace

// ========== IntrusionDetectionEngine ==========

IntrusionDetectionEngine::IntrusionDetectionEngine(const DetectionConfig& config)
    : config_(config) {
    RegisterDefaultRules();
}

IntrusionDetectionEngine::~IntrusionDetectionEngine() = default;

void IntrusionDetectionEngine::UpdateConfig(const DetectionConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
}

const DetectionConfig& IntrusionDetectionEngine::GetConfig() const {
    return config_;
}

void IntrusionDetectionEngine::RegisterRule(std::unique_ptr<IDetectionRule> rule) {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_.push_back(std::move(rule));
}

void IntrusionDetectionEngine::EnableRule(DetectionRuleType type, bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& rule : rules_) {
        if (rule->GetType() == type) {
            rule->SetEnabled(enabled);
        }
    }
}

std::vector<std::string> IntrusionDetectionEngine::GetRuleNames() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> names;
    names.reserve(rules_.size());
    for (const auto& rule : rules_) {
        names.push_back(rule->GetName());
    }
    return names;
}

void IntrusionDetectionEngine::UpdateProcessStats(const ProcessStats& stats) {
    std::lock_guard<std::mutex> lock(mutex_);
    current_stats_[stats.pid] = stats;
}

void IntrusionDetectionEngine::ReportSyscall(const std::string& syscall_name, pid_t pid) {
    (void)pid;
    // 检查是否为罕见系统调用
    if (config_.rare_syscalls.count(syscall_name) > 0) {
        for (auto& rule : rules_) {
            if (rule->GetType() == DetectionRuleType::SYSCALL_RARE) {
                auto* rare_rule = dynamic_cast<RareSyscallRule*>(rule.get());
                if (rare_rule) {
                    rare_rule->AddObservedSyscall(syscall_name);
                }
            }
        }
    }
}

void IntrusionDetectionEngine::ReportFileAccess(const std::string& path, pid_t pid) {
    (void)pid;
    for (auto& rule : rules_) {
        if (rule->GetType() == DetectionRuleType::FILE_SENSITIVE_PATH) {
            auto* path_rule = dynamic_cast<SensitivePathRule*>(rule.get());
            if (path_rule) {
                path_rule->AddPathAccess(path);
            }
        }
    }
}

std::vector<IntrusionAlert> IntrusionDetectionEngine::RunDetectionCycle() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<IntrusionAlert> new_alerts;

    // 先调用不依赖进程统计的规则（罕见系统调用、敏感路径等）
    // 这些规则在 ReportSyscall/ReportFileAccess 中累积数据
    ProcessStats empty_stats;
    for (const auto& rule : rules_) {
        if (!rule->IsEnabled()) continue;
        auto type = rule->GetType();
        if (type == DetectionRuleType::SYSCALL_RARE ||
            type == DetectionRuleType::FILE_SENSITIVE_PATH) {
            auto alert = rule->Evaluate(empty_stats, baseline_, config_);
            if (alert.has_value()) {
                IntrusionAlert a = AssignAlertId(std::move(*alert));
                alerts_.push_back(a);
                new_alerts.push_back(a);
            }
        }
    }

    // 再遍历进程统计，调用依赖进程数据的规则
    for (const auto& [pid, stats] : current_stats_) {
        for (const auto& rule : rules_) {
            if (!rule->IsEnabled()) continue;
            auto type = rule->GetType();
            if (type == DetectionRuleType::SYSCALL_RARE ||
                type == DetectionRuleType::FILE_SENSITIVE_PATH) {
                continue;  // 已在上面处理
            }
            auto alert = rule->Evaluate(stats, baseline_, config_);
            if (alert.has_value()) {
                IntrusionAlert a = AssignAlertId(std::move(*alert));
                alerts_.push_back(a);
                new_alerts.push_back(a);
            }
        }
    }

    return new_alerts;
}

std::vector<IntrusionAlert> IntrusionDetectionEngine::GetAlerts(AlertSeverity min_severity) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<IntrusionAlert> result;
    for (const auto& alert : alerts_) {
        if (static_cast<int>(alert.severity) >= static_cast<int>(min_severity)) {
            result.push_back(alert);
        }
    }
    return result;
}

std::vector<IntrusionAlert> IntrusionDetectionEngine::GetUnacknowledgedAlerts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<IntrusionAlert> result;
    for (const auto& alert : alerts_) {
        if (acknowledged_.count(alert.id) == 0) {
            result.push_back(alert);
        }
    }
    return result;
}

void IntrusionDetectionEngine::AcknowledgeAlert(uint64_t alert_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    acknowledged_.insert(alert_id);
}

uint64_t IntrusionDetectionEngine::GetTotalAlerts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return alerts_.size();
}

uint64_t IntrusionDetectionEngine::GetAlertsBySeverity(AlertSeverity severity) const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t count = 0;
    for (const auto& alert : alerts_) {
        if (alert.severity == severity) count++;
    }
    return count;
}

std::map<std::string, uint64_t> IntrusionDetectionEngine::GetAlertCountsByRule() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, uint64_t> counts;
    for (const auto& alert : alerts_) {
        counts[alert.rule_name]++;
    }
    return counts;
}

void IntrusionDetectionEngine::SetBaseline(const ProcessStats& baseline) {
    std::lock_guard<std::mutex> lock(mutex_);
    baseline_ = baseline;
}

ProcessStats IntrusionDetectionEngine::GetBaseline() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return baseline_;
}

void IntrusionDetectionEngine::ResetBaseline() {
    std::lock_guard<std::mutex> lock(mutex_);
    baseline_ = ProcessStats{};
}

void IntrusionDetectionEngine::RegisterDefaultRules() {
    rules_.push_back(std::make_unique<SyscallFrequencyRule>());
    rules_.push_back(std::make_unique<RareSyscallRule>());
    rules_.push_back(std::make_unique<ForkBombRule>());
    rules_.push_back(std::make_unique<SensitivePathRule>());
    rules_.push_back(std::make_unique<FdLeakRule>());
}

IntrusionAlert IntrusionDetectionEngine::AssignAlertId(IntrusionAlert alert) {
    alert.id = next_alert_id_++;
    alert.timestamp = GetCurrentTimestamp();
    return alert;
}

} // namespace sandbox
} // namespace photon_kernel
