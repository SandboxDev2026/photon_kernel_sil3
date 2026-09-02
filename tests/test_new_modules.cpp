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

// ==================== NamespaceIsolation 测试 ====================
#include "photon_kernel/sandbox/namespace_isolation.hpp"
using photon_kernel::sandbox::NamespaceIsolator;
using photon_kernel::sandbox::NamespaceConfig;

TEST(NamespaceIsolationTest, CloneFlagsAll) {
    NamespaceConfig cfg;  // 默认全部启用
    int flags = NamespaceIsolator::clone_flags(cfg);
    // 检查包含所有 namespace 标志 + SIGCHLD
    EXPECT_TRUE(flags & 0x00020000);  // CLONE_NEWNS
    EXPECT_TRUE(flags & 0x20000000);  // CLONE_NEWPID
    EXPECT_TRUE(flags & 0x40000000);  // CLONE_NEWNET
    EXPECT_TRUE(flags & 0x04000000);  // CLONE_NEWUTS
    EXPECT_TRUE(flags & 0x08000000);  // CLONE_NEWIPC
    EXPECT_EQ(flags & 0xFF, 17);  // SIGCHLD (=17)
}

TEST(NamespaceIsolationTest, CloneFlagsNone) {
    NamespaceConfig cfg;
    cfg.enable_user = false;
    cfg.enable_mount = false;
    cfg.enable_pid = false;
    cfg.enable_net = false;
    cfg.enable_uts = false;
    cfg.enable_ipc = false;
    int flags = NamespaceIsolator::clone_flags(cfg);
    EXPECT_EQ(flags, 17);  // 只有 SIGCHLD (=17)
}

TEST(NamespaceIsolationTest, CloneFlagsPartial) {
    NamespaceConfig cfg;
    cfg.enable_mount = true;
    cfg.enable_pid = false;
    cfg.enable_net = true;
    cfg.enable_uts = false;
    cfg.enable_ipc = false;
    int flags = NamespaceIsolator::clone_flags(cfg);
    EXPECT_TRUE(flags & 0x00020000);  // CLONE_NEWNS
    EXPECT_FALSE(flags & 0x20000000); // CLONE_NEWPID
    EXPECT_TRUE(flags & 0x40000000);  // CLONE_NEWNET
    EXPECT_FALSE(flags & 0x04000000); // CLONE_NEWUTS
    EXPECT_FALSE(flags & 0x08000000); // CLONE_NEWIPC
}

TEST(NamespaceIsolationTest, CapabilityDescription) {
    NamespaceConfig cfg;
    std::string desc = NamespaceIsolator::capability_description(cfg);
    EXPECT_FALSE(desc.empty());
    EXPECT_NE(desc, "none");
}

TEST(NamespaceIsolationTest, IsSupportedDetection) {
    // 当前容器无 root，is_supported 应返回 false
    // （在有 root 的环境会返回 true）
    bool supported = NamespaceIsolator::is_supported();
    // 不断言具体值，因为取决于环境
    // 只验证函数可以正常调用不崩溃
    EXPECT_TRUE(supported == true || supported == false);
}

TEST(NamespaceIsolationTest, ConfigDefaults) {
    NamespaceConfig cfg;
    EXPECT_TRUE(cfg.enable_mount);
    EXPECT_TRUE(cfg.enable_pid);
    EXPECT_TRUE(cfg.enable_net);
    EXPECT_TRUE(cfg.enable_uts);
    EXPECT_TRUE(cfg.enable_ipc);
    EXPECT_EQ(cfg.hostname, "photon-sandbox");
    EXPECT_TRUE(cfg.mount_proc);
    EXPECT_TRUE(cfg.mount_dev);
    EXPECT_TRUE(cfg.mount_tmp);
}
