#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "photon_kernel/sandbox/audit_logger.hpp"
#include "photon_kernel/sandbox/audit_grpc_sink.hpp"

using namespace photon_kernel::sandbox;

TEST(AuditLoggerTest, WritesJsonLinesToFile) {
    const std::string path = "/tmp/photon_audit_test.jsonl";
    std::remove(path.c_str());

    AuditLogger& logger = AuditLogger::instance();
    logger.init(path, /*mirror_stderr=*/false);
    EXPECT_TRUE(logger.is_initialized());
    EXPECT_EQ(logger.path(), path);

    logger.log_json("{\"a\":1}");
    logger.log_json("{\"b\":2}");
    logger.log_json("{\"c\":3}");

    // 回读验证
    std::ifstream f(path);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(f, line)) lines.push_back(line);

    EXPECT_EQ(lines.size(), 3u);
    EXPECT_EQ(lines[0], "{\"a\":1}");
    EXPECT_EQ(lines[2], "{\"c\":3}");

    std::remove(path.c_str());
}

TEST(AuditGrpcSinkTest, DisabledWithoutGrpc) {
    // 本机无 gRPC 时为空实现；测试只验证接口不崩溃
    GrpcAuditSink& sink = GrpcAuditSink::instance();
    sink.init("audit-collector:50053");
    sink.report("{\"x\":1}");
    // enabled 与否取决于构建环境，不做硬断言，仅验证可调用
    (void)sink.enabled();
}
