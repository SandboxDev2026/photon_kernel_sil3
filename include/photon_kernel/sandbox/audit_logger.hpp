#ifndef PHOTON_KERNEL_SANDBOX_AUDIT_LOGGER_HPP
#define PHOTON_KERNEL_SANDBOX_AUDIT_LOGGER_HPP

#include <string>
#include <mutex>
#include <fstream>

#include "audit_security.hpp"

namespace photon_kernel {
namespace sandbox {

// 生产级审计存储：
//  - 默认写入 JSON Lines 日志文件（每行一条审计记录，可由 logrotate 滚动）
//  - 可选镜像到 stderr（调试）
//  - 可选防篡改：HMAC-SHA256 哈希链（set_hmac_secret 开启）
//  - 可选脱敏：敏感字段打码（set_sanitize 开启）
//  - 集中式 gRPC 上报由 GrpcAuditSink 提供（异步批量 + 失败重试）
class AuditLogger {
public:
    static AuditLogger& instance();

    // 初始化审计文件（默认 ./sandbox_audit.jsonl）
    void init(const std::string& file_path = "sandbox_audit.jsonl",
              bool mirror_stderr = false);
    void set_mirror_stderr(bool on);

    // 开启防篡改：设置 HMAC 密钥后，每条记录写入哈希链（__chain 字段）
    void set_hmac_secret(const std::string& secret);
    [[nodiscard]] bool hmac_enabled() const;

    // 开启脱敏（内置敏感 key：code/token/secret/password 等）
    void set_sanitize(bool on);
    [[nodiscard]] bool sanitize_enabled() const;
    AuditSanitizer& sanitizer();

    // 校验整个审计文件哈希链（防篡改验证）
    static bool verify_chain(const std::string& file_path, const std::string& secret);

    void log_json(const std::string& json_line);
    std::string path() const;
    bool is_initialized() const;

private:
    AuditLogger() = default;
    AuditLogger(const AuditLogger&) = delete;
    AuditLogger& operator=(const AuditLogger&) = delete;

    mutable std::mutex mtx_;
    std::ofstream file_;
    std::string path_;
    bool mirror_stderr_ = false;
    bool initialized_ = false;

    bool hmac_enabled_ = false;
    AuditChain chain_;
    bool sanitize_enabled_ = false;
    AuditSanitizer sanitizer_;
};

} // namespace sandbox
} // namespace photon_kernel

#endif
