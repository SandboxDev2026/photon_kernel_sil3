// Fuzz target: 审计日志（输入任意字节作为事件内容）
#include <cstdint>
#include <cstddef>
#include <string>
#include "photon_kernel/sandbox/audit_logger.hpp"
using namespace photon_kernel::sandbox;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    std::string payload(reinterpret_cast<const char*>(data), size);
    try {
        // AuditLogger 是单例，使用 log_json 接口
        AuditLogger& logger = AuditLogger::instance();
        // 构造 JSON 行，包含任意 payload
        std::string json_line = "{\"event_type\":\"fuzz\",\"payload\":\"" + payload + "\"}";
        logger.log_json(json_line);
    } catch (...) {}
    return 0;
}
