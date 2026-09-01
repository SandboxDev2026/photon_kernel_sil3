#include "photon_kernel/sandbox/audit_logger.hpp"

#include <iostream>
#include <fstream>
#include <sys/stat.h>

namespace photon_kernel {
namespace sandbox {

AuditLogger& AuditLogger::instance() {
    static AuditLogger logger;
    return logger;
}

void AuditLogger::init(const std::string& file_path, bool mirror_stderr) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (file_.is_open()) {
        file_.close();
    }
    path_ = file_path;
    file_.open(file_path, std::ios::app);
    // 安全：审计日志文件权限收紧为 0600（仅所有者可读写，防止篡改/窃读）
    if (file_.is_open()) {
        ::chmod(file_path.c_str(), 0600);
    }
    mirror_stderr_ = mirror_stderr;
    initialized_ = file_.is_open();
    if (!initialized_) {
        std::cerr << "[AuditLogger] WARNING: cannot open audit file " << file_path
                  << ", falling back to stderr\n";
    }
}

void AuditLogger::set_mirror_stderr(bool on) {
    std::lock_guard<std::mutex> lock(mtx_);
    mirror_stderr_ = on;
}

void AuditLogger::set_hmac_secret(const std::string& secret) {
    std::lock_guard<std::mutex> lock(mtx_);
    chain_ = AuditChain(secret);   // 重置链（新密钥从创世开始）
    hmac_enabled_ = !secret.empty();
}

bool AuditLogger::hmac_enabled() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return hmac_enabled_;
}

void AuditLogger::set_sanitize(bool on) {
    std::lock_guard<std::mutex> lock(mtx_);
    sanitize_enabled_ = on;
}

bool AuditLogger::sanitize_enabled() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return sanitize_enabled_;
}

AuditSanitizer& AuditLogger::sanitizer() {
    return sanitizer_;
}

bool AuditLogger::verify_chain(const std::string& file_path, const std::string& secret) {
    return AuditChain::verify_chain_file(file_path, secret);
}

void AuditLogger::log_json(const std::string& json_line) {
    std::lock_guard<std::mutex> lock(mtx_);

    // 1) 脱敏（可选）
    std::string line = json_line;
    if (sanitize_enabled_) {
        line = sanitizer_.sanitize_json(line);
    }
    // 2) 防篡改哈希链（可选）
    if (hmac_enabled_) {
        line = chain_.seal(line);
    }
    // 3) 落盘
    if (initialized_ && file_.is_open()) {
        file_ << line << "\n";
        file_.flush();
    } else {
        // 未初始化时降级到 stderr，保证审计不丢
        std::cerr << line << "\n";
    }
    if (mirror_stderr_) {
        std::cerr << line << "\n";
    }
}

std::string AuditLogger::path() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return path_;
}

bool AuditLogger::is_initialized() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return initialized_;
}

} // namespace sandbox
} // namespace photon_kernel
