// P0 安全加固测试
// TaskSpec严格校验 + Release-Gate独立进程 + 密钥外部注入轮换 + 解释器白名单内核强制
#include <gtest/gtest.h>
#include "photon_kernel/sandbox/security_hardening.hpp"
using namespace photon_kernel::sandbox;
// ==================== TaskSpecValidator 测试 ====================
TEST(TaskSpecValidatorTest, ValidSpecPasses) {
    TaskSpecValidator validator;
    TaskSpec spec;
    spec.task_id = "test-001";
    spec.identity.principal = "user-1";
    spec.identity.tenant_id = "tenant-1";
    spec.resources.cpu_cores = 1.0;
    spec.resources.memory_mb = 256;
    spec.budget.ttl = std::chrono::seconds(300);
    spec.budget.execution_timeout = std::chrono::milliseconds(60000);
    auto result = validator.validate(spec);
    printf("  Valid spec: %s\n", result.valid ? "PASS" : "FAIL");
    for (const auto& e : result.errors) printf("    ERROR: %s\n", e.c_str());
    EXPECT_TRUE(result.valid);
}
TEST(TaskSpecValidatorTest, ZeroTTLRejected) {
    TaskSpecValidator validator;
    TaskSpec spec;
    spec.identity.principal = "user-1";
    spec.identity.tenant_id = "tenant-1";
    spec.budget.ttl = std::chrono::seconds(0);  // TTL=0，任务永不过期
    auto result = validator.validate(spec);
    EXPECT_FALSE(result.valid);
    bool has_ttl_error = false;
    for (const auto& e : result.errors) {
        if (e.find("ttl") != std::string::npos) has_ttl_error = true;
    }
    EXPECT_TRUE(has_ttl_error);
    printf("  Zero TTL rejected: %s\n", result.valid ? "FAIL" : "PASS");
}
TEST(TaskSpecValidatorTest, ResourceOverflowRejected) {
    TaskSpecValidator validator;
    TaskSpec spec;
    spec.identity.principal = "user-1";
    spec.identity.tenant_id = "tenant-1";
    spec.resources.cpu_cores = 128.0;  // 超过 max 64
    spec.resources.memory_mb = 131072;  // 超过 max 65536
    spec.budget.ttl = std::chrono::seconds(300);
    auto result = validator.validate(spec);
    EXPECT_FALSE(result.valid);
    printf("  Resource overflow rejected: %d errors\n", (int)result.errors.size());
    for (const auto& e : result.errors) printf("    %s\n", e.c_str());
}
TEST(TaskSpecValidatorTest, InternalCidrInAllowListRejected) {
    TaskSpecValidator validator;
    TaskSpec spec;
    spec.identity.principal = "user-1";
    spec.identity.tenant_id = "tenant-1";
    spec.network.enabled = true;
    spec.network.allow_cidrs = {"10.0.0.0/8", "169.254.169.254/32"};  // 内网+元数据
    spec.budget.ttl = std::chrono::seconds(300);
    auto result = validator.validate(spec);
    EXPECT_FALSE(result.valid);
    bool has_internal_error = false;
    for (const auto& e : result.errors) {
        if (e.find("internal") != std::string::npos || e.find("metadata") != std::string::npos) {
            has_internal_error = true;
        }
    }
    EXPECT_TRUE(has_internal_error);
    printf("  Internal CIDR in allow list rejected\n");
}
TEST(TaskSpecValidatorTest, PathTraversalRejected) {
    TaskSpecValidator validator;
    TaskSpec spec;
    spec.identity.principal = "user-1";
    spec.identity.tenant_id = "tenant-1";
    spec.workspace_path = "/var/lib/photon/sandboxes/../../etc/passwd";  // 路径遍历
    spec.budget.ttl = std::chrono::seconds(300);
    auto result = validator.validate(spec);
    EXPECT_FALSE(result.valid);
    bool has_path_error = false;
    for (const auto& e : result.errors) {
        if (e.find("path traversal") != std::string::npos) has_path_error = true;
    }
    EXPECT_TRUE(has_path_error);
    printf("  Path traversal rejected\n");
}
TEST(TaskSpecValidatorTest, EmptyIdentityRejected) {
    TaskSpecValidator validator;
    TaskSpec spec;
    // identity.principal 和 tenant_id 为空
    spec.budget.ttl = std::chrono::seconds(300);
    auto result = validator.validate(spec);
    EXPECT_FALSE(result.valid);
    printf("  Empty identity rejected: %d errors\n", (int)result.errors.size());
}
TEST(TaskSpecValidatorTest, SanitizeRemovesMetacharacters) {
    TaskSpecValidator::Config config;
    config.block_shell_metacharacters = true;
    TaskSpecValidator validator(config);
    TaskSpec spec;
    spec.task_id = "test;rm -rf /";  // shell 注入
    spec.identity.principal = "user$(whoami)";
    spec.identity.tenant_id = "tenant`id`";
    spec.budget.ttl = std::chrono::seconds(300);
    auto [sanitized, result] = validator.validate_and_sanitize(spec);
    // 清理后不应包含 shell 元字符
    EXPECT_EQ(sanitized.task_id.find(';'), std::string::npos);
    EXPECT_EQ(sanitized.identity.principal.find('$'), std::string::npos);
    printf("  Sanitized: removed %zu fields\n", result.sanitized_fields.size());
}
TEST(TaskSpecValidatorTest, ExcessiveTTLCapped) {
    TaskSpecValidator validator;
    TaskSpec spec;
    spec.identity.principal = "user-1";
    spec.identity.tenant_id = "tenant-1";
    spec.budget.ttl = std::chrono::hours(48);  // 超过 max 24h
    auto result = validator.validate(spec);
    EXPECT_FALSE(result.valid);
    printf("  Excessive TTL (48h) rejected\n");
}
// ==================== KeyManager 测试 ====================
TEST(KeyManagerTest, InitializeWithEnvKey) {
    setenv("PHOTON_HMAC_KEY", "test-secret-key-1234567890abcdef", 1);
    KeyManagerConfig config;
    config.key_env_var = "PHOTON_HMAC_KEY";
    KeyManager manager(config);
    EXPECT_TRUE(manager.initialize());
    EXPECT_TRUE(manager.using_external_key());
    EXPECT_FALSE(manager.current_key().empty());
    printf("  Env key loaded: key_id=%s\n", manager.current_key_id().c_str());
    unsetenv("PHOTON_HMAC_KEY");
}
TEST(KeyManagerTest, TemporaryKeyGeneratedWithWarning) {
    unsetenv("PHOTON_HMAC_KEY");
    KeyManagerConfig config;
    config.key_env_var = "NONEXISTENT_VAR";
    config.key_file_path = "/nonexistent/key";
    config.warn_on_generated_key = true;
    KeyManager manager(config);
    EXPECT_TRUE(manager.initialize());
    EXPECT_FALSE(manager.using_external_key());  // 临时密钥，非外部
    printf("  Temporary key generated (external=%s)\n",
           manager.using_external_key() ? "yes" : "no");
}
TEST(KeyManagerTest, EnforceExternalKeyFailsWithoutKey) {
    unsetenv("PHOTON_HMAC_KEY");
    KeyManagerConfig config;
    config.key_env_var = "NONEXISTENT_VAR";
    config.enforce_external_key = true;  // 强制要求外部密钥
    KeyManager manager(config);
    EXPECT_FALSE(manager.initialize());  // 应该失败
    printf("  Enforce external key: initialization correctly failed\n");
}
TEST(KeyManagerTest, RotateKeyWorks) {
    setenv("PHOTON_HMAC_KEY", "test-secret-key-1234567890abcdef", 1);
    KeyManagerConfig config;
    config.grace_period = std::chrono::seconds(60);
    KeyManager manager(config);
    manager.initialize();
    std::string old_key_id = manager.current_key_id();
    std::string new_key_id = manager.rotate_key();
    EXPECT_NE(old_key_id, new_key_id);
    EXPECT_EQ(manager.current_key_id(), new_key_id);
    // 旧密钥应在宽限期
    auto keys = manager.list_keys();
    EXPECT_GE(keys.size(), 2u);
    printf("  Key rotated: %s -> %s, total keys=%zu\n",
           old_key_id.c_str(), new_key_id.c_str(), keys.size());
    unsetenv("PHOTON_HMAC_KEY");
}
TEST(KeyManagerTest, SignAndVerifyWithCurrentKey) {
    setenv("PHOTON_HMAC_KEY", "test-secret-key-1234567890abcdef", 1);
    KeyManager manager;
    manager.initialize();
    std::string data = "test data to sign";
    std::string sig = manager.sign(data);  // 用当前活动密钥签名
    // 直接测试 verify_signature
    EXPECT_TRUE(manager.verify_signature(data, sig));
    EXPECT_FALSE(manager.verify_signature(data, "wrong-signature"));
    printf("  Sign/verify: current key works\n");
    unsetenv("PHOTON_HMAC_KEY");
}
TEST(KeyManagerTest, IssueAndVerifyToken) {
    setenv("PHOTON_HMAC_KEY", "test-secret-key-1234567890abcdef", 1);
    KeyManager manager;
    manager.initialize();
    auto token = manager.issue_token("sandbox-1", Capability::EXEC | Capability::NETWORK,
                                       std::chrono::hours(1));
    EXPECT_FALSE(token.hmac_signature.empty());
    EXPECT_TRUE(manager.verify_token(token));
    // 篡改 token 后验证失败
    CapabilityToken tampered = token;
    tampered.capabilities = Capability::ALL;  // 篡改权限
    EXPECT_FALSE(manager.verify_token(tampered));
    printf("  Token issue/verify: valid=%s, tampered rejected=%s\n",
           manager.verify_token(token) ? "yes" : "no",
           manager.verify_token(tampered) ? "no" : "yes");
    unsetenv("PHOTON_HMAC_KEY");
}
// ==================== InterpreterWhitelist 测试 ====================
TEST(InterpreterWhitelistTest, DefaultWhitelistAllowsPython) {
    InterpreterWhitelist whitelist;
    EXPECT_TRUE(whitelist.is_allowed("/usr/bin/python3"));
    EXPECT_TRUE(whitelist.is_allowed("/usr/bin/node"));
    printf("  Default whitelist: python3/node allowed\n");
}
TEST(InterpreterWhitelistTest, NonWhitelistRejected) {
    InterpreterWhitelist whitelist;
    EXPECT_FALSE(whitelist.is_allowed("/usr/bin/curl"));
    EXPECT_FALSE(whitelist.is_allowed("/bin/nc"));
    EXPECT_FALSE(whitelist.is_allowed("/usr/bin/wget"));
    printf("  Non-whitelist (curl/nc/wget) rejected\n");
}
TEST(InterpreterWhitelistTest, BlockShRemovesSh) {
    InterpreterWhitelistConfig config;
    config.allow_sh = false;
    InterpreterWhitelist whitelist(config);
    EXPECT_FALSE(whitelist.is_allowed("/bin/sh"));
    printf("  Block sh: /bin/sh rejected\n");
}
TEST(InterpreterWhitelistTest, AddDynamicPath) {
    InterpreterWhitelist whitelist;
    EXPECT_FALSE(whitelist.is_allowed("/custom/bin/myinterp"));
    EXPECT_TRUE(whitelist.add_path("/custom/bin/myinterp"));
    EXPECT_TRUE(whitelist.is_allowed("/custom/bin/myinterp"));
    printf("  Dynamic path added: /custom/bin/myinterp allowed\n");
}
TEST(InterpreterWhitelistTest, GenerateSeccompRules) {
    InterpreterWhitelist whitelist;
    std::string rules = whitelist.generate_seccomp_rules();
    EXPECT_FALSE(rules.empty());
    EXPECT_NE(rules.find("seccomp"), std::string::npos);
    EXPECT_NE(rules.find("execve"), std::string::npos);
    EXPECT_NE(rules.find("KILL_PROCESS"), std::string::npos);  // 内核强制杀死
    printf("  Seccomp rules generated (%zu bytes), kernel-enforced KILL_PROCESS\n",
           rules.size());
}
TEST(InterpreterWhitelistTest, GenerateEbpfProgram) {
    InterpreterWhitelist whitelist;
    std::string prog = whitelist.generate_ebpf_program();
    EXPECT_FALSE(prog.empty());
    EXPECT_NE(prog.find("lsm"), std::string::npos);
    EXPECT_NE(prog.find("bprm_check"), std::string::npos);
    printf("  eBPF LSM program generated (%zu bytes)\n", prog.size());
}
// ==================== ReleaseGate 独立进程测试 ====================
TEST(ReleaseGateServiceTest, ConfigDefaults) {
    ReleaseGateConfig config;
    EXPECT_EQ(config.run_as_user, "nobody");
    EXPECT_TRUE(config.enable_seccomp);
    EXPECT_TRUE(config.read_only_rootfs);
    EXPECT_TRUE(config.require_hmac_chain);
    printf("  ReleaseGate config: user=nobody, seccomp=%s, readonly=%s\n",
           config.enable_seccomp ? "on" : "off",
           config.read_only_rootfs ? "on" : "off");
}
TEST(ReleaseGateClientTest, ConnectFailsWithoutServer) {
    ReleaseGateClient client("/tmp/nonexistent-gate.sock");
    EXPECT_FALSE(client.connect());
    EXPECT_FALSE(client.connected());
    printf("  Client connect fails without server (expected)\n");
}
// ==================== SecurityHardening 统一测试 ====================
TEST(SecurityHardeningTest, InitializeAllSubsystems) {
    SecurityHardening::Config config;
    config.key_manager.key_env_var = "PHOTON_HMAC_KEY";
    setenv("PHOTON_HMAC_KEY", "test-secret-key-1234567890abcdef", 1);
    SecurityHardening hardening(config);
    EXPECT_TRUE(hardening.initialize());
    auto status = hardening.status();
    EXPECT_TRUE(status.task_spec_validator);
    EXPECT_TRUE(status.key_manager_initialized);
    EXPECT_TRUE(status.using_external_key);
    EXPECT_TRUE(status.interpreter_whitelist_active);
    printf("  SecurityHardening status:\n%s", status.to_string().c_str());
    unsetenv("PHOTON_HMAC_KEY");
}
TEST(SecurityHardeningTest, FullWorkflowValidateAndSign) {
    setenv("PHOTON_HMAC_KEY", "test-secret-key-1234567890abcdef", 1);
    SecurityHardening hardening;
    hardening.initialize();
    // 1. 校验 TaskSpec
    TaskSpec spec;
    spec.identity.principal = "user-1";
    spec.identity.tenant_id = "tenant-1";
    spec.budget.ttl = std::chrono::seconds(300);
    auto validation = hardening.task_spec_validator().validate(spec);
    EXPECT_TRUE(validation.valid);
    // 2. 签发 CapabilityToken
    auto token = hardening.key_manager().issue_token(
        "sandbox-1", Capability::EXEC, std::chrono::hours(1));
    EXPECT_TRUE(hardening.key_manager().verify_token(token));
    // 3. 检查解释器白名单
    EXPECT_TRUE(hardening.interpreter_whitelist().is_allowed("/usr/bin/python3"));
    EXPECT_FALSE(hardening.interpreter_whitelist().is_allowed("/usr/bin/curl"));
    printf("  Full workflow: validate -> sign -> whitelist check all PASS\n");
    unsetenv("PHOTON_HMAC_KEY");
}
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
