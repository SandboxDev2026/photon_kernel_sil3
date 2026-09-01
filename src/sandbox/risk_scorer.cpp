// RiskScorer 实现：静态特征扫描，输出风险等级。
#include "photon_kernel/sandbox/risk_scorer.hpp"
#include <algorithm>
namespace photon_kernel {
namespace sandbox {
RiskScorer::RiskScorer() { init_patterns(); }
void RiskScorer::init_patterns() {
    // 网络访问
    patterns_.push_back({std::regex(R"(\b(socket|connect|urllib|requests|http\.client|httplib|curl|fetch|axios)\b)", std::regex::icase),
        "network_access", 15, RiskLevel::MEDIUM});
    patterns_.push_back({std::regex(R"(\b(0\.0\.0\.0|127\.0\.0\.1|localhost|169\.254|metadata\.google|169\.254\.169\.254)\b)"),
        "network_sensitive_target", 25, RiskLevel::HIGH});
    // 文件系统
    patterns_.push_back({std::regex(R"(/etc/(passwd|shadow|sudoers|hosts))", std::regex::icase),
        "sensitive_file_read", 30, RiskLevel::HIGH});
    patterns_.push_back({std::regex(R"(/proc/(self|1)/(environ|maps|mem|fd))", std::regex::icase),
        "proc_filesystem_access", 25, RiskLevel::HIGH});
    patterns_.push_back({std::regex(R"(/sys/(kernel|module|fs))", std::regex::icase),
        "sysfs_access", 20, RiskLevel::HIGH});
    patterns_.push_back({std::regex(R"(\b(open|write|creat|unlink|rmdir|chmod|chown)\s*\()"),
        "filesystem_write", 10, RiskLevel::MEDIUM});
    // 进程操作
    patterns_.push_back({std::regex(R"(\b(fork|vfork|clone|exec|execl|execv|system|popen|posix_spawn|subprocess|ProcessBuilder)\b)", std::regex::icase),
        "process_spawn", 20, RiskLevel::MEDIUM});
    patterns_.push_back({std::regex(R"(\b(kill|signal|ptrace|process_vm|prctl)\b)"),
        "process_manipulation", 25, RiskLevel::HIGH});
    // 提权/逃逸
    patterns_.push_back({std::regex(R"(\b(setuid|setgid|seteuid|capset|capget|sudo|su -)\b)", std::regex::icase),
        "privilege_escalation", 40, RiskLevel::HIGH});
    patterns_.push_back({std::regex(R"(\b(seccomp|prctl.*SECCOMP|unshare|mount|pivot_root|chroot)\b)", std::regex::icase),
        "sandbox_escape_attempt", 45, RiskLevel::CRITICAL});
    patterns_.push_back({std::regex(R"(\b(insmod|modprobe|init_module|/dev/(mem|kmem|port))\b)"),
        "kernel_module_attempt", 50, RiskLevel::CRITICAL});
    // 加密挖矿
    patterns_.push_back({std::regex(R"(stratum\+(tcp|ssl)|monero|bitcoin|xmrig|cpuminer|nicehash)", std::regex::icase),
        "cryptominer", 50, RiskLevel::CRITICAL});
    patterns_.push_back({std::regex(R"(while\s*\(\s*1\s*\)|while\s+True|for\s*\(\s*;;\s*\))"),
        "infinite_loop_cpu", 15, RiskLevel::MEDIUM});
    // 数据外泄（大文件读 + 网络发送组合，简化为关键词）
    patterns_.push_back({std::regex(R"(\b(base64|encode|encrypt|openssl|gpg)\b.*\b(send|post|upload|socket)\b)", std::regex::icase | std::regex::multiline),
        "data_exfiltration", 45, RiskLevel::CRITICAL});
    // 环境变量/密钥窃取
    patterns_.push_back({std::regex(R"(\b(os\.environ|getenv|ENV\[|process\.env)\b)", std::regex::icase),
        "env_access", 10, RiskLevel::LOW});
    patterns_.push_back({std::regex(R"(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|AWS_|GCP_|AZURE_)", std::regex::icase),
        "credential_access", 20, RiskLevel::MEDIUM});
}
RiskScanResult RiskScorer::scan(const std::string& code, const std::string& language) const {
    RiskScanResult result;
    result.score = 0;
    RiskLevel max_level = RiskLevel::LOW;
    for (const auto& p : patterns_) {
        if (std::regex_search(code, p.re)) {
            result.detected_patterns.push_back(p.name + " (+" + std::to_string(p.weight) + ")");
            result.score += p.weight;
            if (static_cast<int>(p.min_level) > static_cast<int>(max_level)) {
                max_level = p.min_level;
            }
        }
    }
    // 分数转等级
    if (result.score >= 80 || max_level == RiskLevel::CRITICAL) {
        result.level = RiskLevel::CRITICAL;
    } else if (result.score >= 50 || max_level == RiskLevel::HIGH) {
        result.level = RiskLevel::HIGH;
    } else if (result.score >= 20 || max_level == RiskLevel::MEDIUM) {
        result.level = RiskLevel::MEDIUM;
    } else {
        result.level = RiskLevel::LOW;
    }
    result.score = std::min(result.score, 100);
    result.recommended_domain = domain_for(result.level);
    result.recommended_backend = backend_for(result.level);
    result.reason = "score=" + std::to_string(result.score) +
        ", patterns=" + std::to_string(result.detected_patterns.size());
    return result;
}
std::string RiskScorer::domain_for(RiskLevel level) {
    switch (level) {
        case RiskLevel::LOW:
        case RiskLevel::MEDIUM:  return "DOMAIN_TRUSTED";
        case RiskLevel::HIGH:    return "DOMAIN_UNTRUSTED";
        case RiskLevel::CRITICAL: return "DOMAIN_SANDBOX_ONCE";
    }
    return "DOMAIN_TRUSTED";
}
std::string RiskScorer::backend_for(RiskLevel level) {
    switch (level) {
        case RiskLevel::LOW:
        case RiskLevel::MEDIUM:  return "LightPool (fork+seccomp)";
        case RiskLevel::HIGH:    return "StrongPool (Firecracker MicroVM)";
        case RiskLevel::CRITICAL: return "StrongPool + Once-Destroy";
    }
    return "LightPool";
}
std::string RiskScorer::level_name(RiskLevel level) {
    switch (level) {
        case RiskLevel::LOW:      return "LOW";
        case RiskLevel::MEDIUM:   return "MEDIUM";
        case RiskLevel::HIGH:     return "HIGH";
        case RiskLevel::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}
} // namespace sandbox
} // namespace photon_kernel
