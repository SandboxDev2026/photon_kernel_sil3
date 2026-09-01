#include <gtest/gtest.h>
#include "photon_kernel/sandbox/capability_token.hpp"
#include "photon_kernel/sandbox/resource_proxy.hpp"
#include "photon_kernel/sandbox/risk_scorer.hpp"
#include <thread>
using namespace photon_kernel::sandbox;
// ==================== CapabilityToken 测试 ====================
TEST(CapabilityTokenTest, IssueAndVerify) {
    CapabilityTokenManager mgr("test-secret-key");
    auto token = mgr.issue("sandbox-1", Capability::EXEC | Capability::FILE_READ);
    EXPECT_FALSE(token.token_id.empty());
    EXPECT_EQ(token.sandbox_id, "sandbox-1");
    EXPECT_TRUE(token.has(Capability::EXEC));
    EXPECT_TRUE(token.has(Capability::FILE_READ));
    EXPECT_FALSE(token.has(Capability::NETWORK));
    EXPECT_TRUE(mgr.verify(token));
}
TEST(CapabilityTokenTest, TamperDetection) {
    CapabilityTokenManager mgr("test-secret-key");
    auto token = mgr.issue("sandbox-1", Capability::EXEC);
    // 篡改能力位
    token.capabilities = Capability::ALL;
    EXPECT_FALSE(mgr.verify(token));  // HMAC 签名不匹配
}
TEST(CapabilityTokenTest, Revoke) {
    CapabilityTokenManager mgr("test-secret-key");
    auto token = mgr.issue("sandbox-1", Capability::EXEC);
    EXPECT_TRUE(mgr.verify(token));
    mgr.revoke(token.token_id);
    EXPECT_FALSE(mgr.verify(token));  // 已撤销
    EXPECT_TRUE(mgr.is_revoked(token.token_id));
}
TEST(CapabilityTokenTest, RecallCapability) {
    CapabilityTokenManager mgr("test-secret-key");
    auto token = mgr.issue("sandbox-1", Capability::EXEC | Capability::NETWORK);
    EXPECT_TRUE(token.has(Capability::NETWORK));
    // 运行时撤销 NETWORK 能力（不需要销毁沙盒）
    auto new_token = mgr.recall_capability(token.token_id, Capability::NETWORK);
    ASSERT_TRUE(new_token.has_value());
    EXPECT_FALSE(new_token->has(Capability::NETWORK));
    EXPECT_TRUE(new_token->has(Capability::EXEC));
    EXPECT_FALSE(mgr.verify(token));  // 旧票据已撤销
    EXPECT_TRUE(mgr.verify(*new_token));  // 新票据有效
}
TEST(CapabilityTokenTest, ExecPathWhitelist) {
    CapabilityTokenManager mgr("key");
    auto token = mgr.issue("s1", Capability::EXEC);
    token.allowed_exec_paths = {"/usr/bin/python3", "/bin/sh"};
    EXPECT_TRUE(token.can_exec("/usr/bin/python3"));
    EXPECT_FALSE(token.can_exec("/bin/bash"));
    EXPECT_FALSE(token.can_exec("/usr/bin/curl"));
}
TEST(CapabilityTokenTest, NetworkRules) {
    CapabilityTokenManager mgr("key");
    auto token = mgr.issue("s1", Capability::NETWORK);
    token.network_rules = {{"10.0.0.0/8", 80, 443, "tcp"}};
    EXPECT_TRUE(token.can_network("10.0.0.1", 443, "tcp"));
    EXPECT_FALSE(token.can_network("10.0.0.1", 22, "tcp"));  // 端口不在范围
    EXPECT_FALSE(token.can_network("8.8.8.8", 443, "tcp"));   // CIDR 不匹配
}
TEST(CapabilityTokenTest, JsonRoundTrip) {
    CapabilityTokenManager mgr("key");
    auto token = mgr.issue("s1", Capability::EXEC | Capability::FILE_READ);
    std::string json = token.to_json();
    auto parsed = CapabilityToken::from_json(json);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->token_id, token.token_id);
    EXPECT_EQ(parsed->sandbox_id, token.sandbox_id);
    EXPECT_TRUE(parsed->has(Capability::EXEC));
}
// ==================== ResourceProxy 测试 ====================
TEST(ResourceProxyTest, CredentialVaultRealAccess) {
    auto vault = std::make_shared<CredentialVault>();
    vault->store("api_key", "sk-real-secret-12345");
    ResourceProxy proxy(vault);
    CapabilityTokenManager mgr("key");
    auto token = mgr.issue("s1", Capability::EXEC);  // 有 EXEC 能力
    auto result = proxy.access_secret("api_key", token);
    EXPECT_EQ(result.decision, ProxyDecision::ALLOW_REAL);
    EXPECT_EQ(result.data, "sk-real-secret-12345");
}
TEST(ResourceProxyTest, CredentialVaultDummyAccess) {
    auto vault = std::make_shared<CredentialVault>();
    vault->store("api_key", "sk-real-secret-12345");
    ResourceProxy proxy(vault);
    CapabilityTokenManager mgr("key");
    auto token = mgr.issue("s1", Capability::NONE);  // 无能力
    auto result = proxy.access_secret("api_key", token);
    EXPECT_EQ(result.decision, ProxyDecision::ALLOW_DUMMY);  // 空白通行证
    EXPECT_NE(result.data, "sk-real-secret-12345");  // 不是真实密钥
    EXPECT_FALSE(result.data.empty());  // 但有虚拟数据
}
TEST(ResourceProxyTest, FileAccessDenied) {
    ResourceProxy proxy;
    CapabilityTokenManager mgr("key");
    auto token = mgr.issue("s1", Capability::NONE);  // 无文件读能力
    auto result = proxy.access_file("/etc/passwd", false, "", token);
    EXPECT_EQ(result.decision, ProxyDecision::DENY);
}
TEST(ResourceProxyTest, NetworkAccessDenied) {
    ResourceProxy proxy;
    CapabilityTokenManager mgr("key");
    auto token = mgr.issue("s1", Capability::FILE_READ);  // 无网络能力
    auto result = proxy.access_network("8.8.8.8", 53, "udp", token);
    EXPECT_EQ(result.decision, ProxyDecision::DENY);
}
// ==================== RiskScorer 测试 ====================
TEST(RiskScorerTest, BenignCodeLowRisk) {
    RiskScorer scorer;
    auto result = scorer.scan("print('hello world')\nresult = 1 + 2\n");
    EXPECT_EQ(result.level, RiskLevel::LOW);
    EXPECT_LT(result.score, 20);
    EXPECT_EQ(result.recommended_domain, "DOMAIN_TRUSTED");
}
TEST(RiskScorerTest, NetworkCodeMediumRisk) {
    RiskScorer scorer;
    auto result = scorer.scan("import requests\nr = requests.get('https://example.com')\n");
    EXPECT_GE(result.score, 15);
    EXPECT_TRUE(result.level == RiskLevel::MEDIUM || result.level == RiskLevel::HIGH);
}
TEST(RiskScorerTest, PrivilegeEscalationHighRisk) {
    RiskScorer scorer;
    auto result = scorer.scan("import os\nos.setuid(0)\nprint('escalation')\n");
    EXPECT_GE(result.score, 40);
    EXPECT_TRUE(result.level == RiskLevel::HIGH || result.level == RiskLevel::CRITICAL);
}
TEST(RiskScorerTest, SandboxEscapeCritical) {
    RiskScorer scorer;
    auto result = scorer.scan("import prctl\nprctl.set_seccomp()\ninsmod('rootkit.ko')\n");
    EXPECT_EQ(result.level, RiskLevel::CRITICAL);
    EXPECT_EQ(result.recommended_domain, "DOMAIN_SANDBOX_ONCE");
}
TEST(RiskScorerTest, CryptominerCritical) {
    RiskScorer scorer;
    auto result = scorer.scan("while True:\n    mine_monero('stratum+tcp://pool.com:3333')\n");
    EXPECT_EQ(result.level, RiskLevel::CRITICAL);
}
TEST(RiskScorerTest, SensitiveFileRead) {
    RiskScorer scorer;
    auto result = scorer.scan("with open('/etc/passwd') as f:\n    print(f.read())\n");
    EXPECT_GE(result.score, 30);
}
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
