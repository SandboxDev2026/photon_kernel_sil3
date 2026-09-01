// Fuzz target: 审计日志（输入任意字节作为事件内容）
#include <cstdint>
#include <cstddef>
#include <string>
#include "photon_kernel/sandbox/audit_logger.hpp"
using namespace photon_kernel::sandbox;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    std::string payload(reinterpret_cast<const char*>(data), size);
    // 测试 AuditLogger 对任意输入的处理
    try {
        AuditLogger logger;
        AuditEvent event;
        event.event_type = "fuzz";
        event.payload = payload;
        event.severity = AuditSeverity::INFO;
        logger.log(event);
        // 测试 HMAC 哈希链对任意输入的处理
        (void)logger.get_last_hash();
    } catch (...) {}
    return 0;
}
