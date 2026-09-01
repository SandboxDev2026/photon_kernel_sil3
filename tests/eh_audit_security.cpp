#include <gtest/gtest.h>

#include <cstdio>
#include <chrono>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "photon_kernel/sandbox/audit_security.hpp"
#include "photon_kernel/sandbox/audit_logger.hpp"
#include "photon_kernel/sandbox/audit_grpc_sink.hpp"

using namespace photon_kernel::sandbox;

// ---- 审计防篡改：HMAC-SHA256 哈希链 ----
TEST(AuditSecurityTest, ChainSealAndVerify) {
    const std::string path = "/tmp/photon_chain_test.jsonl";
    std::remove(path.c_str());

    const std::string key = "test-secret";
    AuditChain chain(key);
    {
        std::ofstream f(path, std::ios::trunc);
        f << chain.seal("{\"a\":1}") << "\n";
        f << chain.seal("{\"a\":2}") << "\n";
        f << chain.seal("{\"a\":3}") << "\n";
    }
    // 链完整：verify 通过
    EXPECT_TRUE(AuditChain::verify_chain_file(path, key));

    // 错误密钥：验证失败
    EXPECT_FALSE(AuditChain::verify_chain_file(path, "wrong-key"));

    std::remove(path.c_str());
}

TEST(AuditSecurityTest, ChainDetectsTampering) {
    const std::string path = "/tmp/photon_chain_tamper.jsonl";
    std::remove(path.c_str());

    const std::string key = "tamper-key";
    AuditChain chain(key);
    std::vector<std::string> lines;
    {
        std::ofstream f(path, std::ios::trunc);
        auto l1 = chain.seal("{\"a\":1}");
        auto l2 = chain.seal("{\"a\":2}");
        auto l3 = chain.seal("{\"a\":3}");
        f << l1 << "\n" << l2 << "\n" << l3 << "\n";
        lines = {l1, l2, l3};
    }
    EXPECT_TRUE(AuditChain::verify_chain_file(path, key));

    // 篡改中间一条的 payload：链校验必须失败
    {
        std::string tampered = lines[1];
        auto p = tampered.find("\"a\":2");
        ASSERT_NE(p, std::string::npos);
        tampered.replace(p, 5, "\"a\":9");
        std::ofstream f(path, std::ios::trunc);
        f << lines[0] << "\n" << tampered << "\n" << lines[2] << "\n";
    }
    EXPECT_FALSE(AuditChain::verify_chain_file(path, key));

    // 中间删除一条：连续性校验失败
    {
        std::ofstream f(path, std::ios::trunc);
        f << lines[0] << "\n" << lines[2] << "\n";
    }
    EXPECT_FALSE(AuditChain::verify_chain_file(path, key));

    std::remove(path.c_str());
}

// ---- 审计脱敏 ----
TEST(AuditSecurityTest, SanitizerMasksSensitiveField) {
    AuditSanitizer s;
    std::string json = "{\"task\":\"run\",\"code\":\"import os; os.system('rm -rf /')\",\"risk\":\"LOW\"}";
    std::string out = s.sanitize_json(json);
    // code 字段被脱敏：不再包含原始代码
    EXPECT_EQ(out.find("rm -rf"), std::string::npos);
    // 非敏感字段保留
    EXPECT_NE(out.find("\"risk\":\"LOW\""), std::string::npos);
}

TEST(AuditSecurityTest, SanitizerCustomKey) {
    AuditSanitizer s;
    s.clear_sensitive_keys();
    s.add_sensitive_key("api_key");
    std::string json = "{\"api_key\":\"ABCDEF123456\"}";
    std::string out = s.sanitize_json(json);
    // api_key 已加入敏感 key，值被脱敏
    EXPECT_EQ(out.find("ABCDEF123456"), std::string::npos);
}

// ---- AuditLogger 集成：防篡改 + 脱敏 ----
TEST(AuditSecurityTest, LoggerHashChainAndSanitize) {
    const std::string path = "/tmp/photon_audit_hmac.jsonl";
    std::remove(path.c_str());

    AuditLogger& logger = AuditLogger::instance();
    logger.init(path, /*mirror_stderr=*/false);
    logger.set_hmac_secret("logger-key");
    logger.set_sanitize(true);
    logger.log_json("{\"task\":\"run-code\",\"code\":\"print('secret-value')\",\"risk\":\"LOW\"}");
    logger.log_json("{\"task\":\"run-code-2\",\"code\":\"print('other')\",\"risk\":\"LOW\"}");

    // 脱敏：code 内容不可见
    {
        std::ifstream f(path);
        std::string content((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
        EXPECT_EQ(content.find("secret-value"), std::string::npos);
    }
    // 防篡改链：verify 通过（用同一密钥）
    EXPECT_TRUE(AuditLogger::verify_chain(path, "logger-key"));
    // 错误密钥失败
    EXPECT_FALSE(AuditLogger::verify_chain(path, "wrong"));

    std::remove(path.c_str());
}

// ---- 异步批量上报 + 失败重试 ----
TEST(AuditSinkTest, AsyncBatchSpoolsOnFailure) {
    const std::string spool = "/tmp/photon_audit_spool.jsonl";
    std::remove(spool.c_str());

    GrpcAuditSink& sink = GrpcAuditSink::instance();
    sink.stop();  // 隔离残留状态
    sink.init("audit-collector:50053",
              /*batch_max=*/2,
              std::chrono::milliseconds(50),
              std::chrono::milliseconds(100),
              spool);
    sink.start();

    for (int i = 0; i < 5; ++i) {
        sink.report("{\"i\":" + std::to_string(i) + "}");
    }

    // 无 gRPC 环境：后台线程消费后全部失败落盘
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    sink.stop();

    EXPECT_EQ(sink.queue_size(), 0u);
    EXPECT_GE(sink.spool_size(), 5u);   // 失败记录已持久化
    EXPECT_GE(sink.failed_count(), 5u);
    EXPECT_EQ(sink.sent_count(), 0u);   // 无 gRPC 无成功发送

    std::remove(spool.c_str());
}

TEST(AuditSinkTest, SendBatchFailsWithoutGrpc) {
    // 直接调用批量发送：无 gRPC 环境返回 false（驱动失败重试路径）
    GrpcAuditSink& sink = GrpcAuditSink::instance();
    EXPECT_FALSE(sink.send_batch({"{\"x\":1}"}));
    // 空批视为成功（无事可发）
    EXPECT_TRUE(sink.send_batch({}));
}
