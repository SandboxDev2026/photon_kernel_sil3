// test_runtime_guard.cpp - RuntimeGuard + NetworkResourceGuard 测试
#include <gtest/gtest.h>
#include "photon_kernel/sandbox/runtime_guard.hpp"
#include "photon_kernel/sandbox/network_resource_guard.hpp"

using namespace photon_kernel::sandbox;

// ===== RuntimeGuard 测试 =====

TEST(RuntimeGuardTest, UntrustedInputMustUseStrongPool) {
    RuntimeGuard guard;
    TaskSecurityContext ctx;
    ctx.task_id = 1;
    ctx.is_untrusted_input = true;
    ctx.risk_level = RiskLevel::HIGH;
    ctx.assigned_backend = RuntimeBackend::LIGHT;  // 错误: 不可信任务分配到LightPool

    GuardResult result = guard.verify_before_execution(ctx);
    EXPECT_FALSE(result.allowed);
    EXPECT_TRUE(result.trigger_alert);
    EXPECT_EQ(result.alert_level, "P0");
}

TEST(RuntimeGuardTest, UntrustedInputWithStrongPoolAllowed) {
    RuntimeGuard guard;
    TaskSecurityContext ctx;
    ctx.task_id = 2;
    ctx.is_untrusted_input = true;
    ctx.risk_level = RiskLevel::HIGH;
    ctx.assigned_backend = RuntimeBackend::STRONG;  // 正确: 不可信任务分配到StrongPool

    GuardResult result = guard.verify_before_execution(ctx);
    EXPECT_TRUE(result.allowed);
}

TEST(RuntimeGuardTest, HighRiskMustUseStrongPool) {
    RuntimeGuard guard;
    TaskSecurityContext ctx;
    ctx.task_id = 3;
    ctx.is_untrusted_input = false;
    ctx.risk_level = RiskLevel::HIGH;
    ctx.assigned_backend = RuntimeBackend::LIGHT;  // 错误: 高风险分配到LightPool

    GuardResult result = guard.verify_before_execution(ctx);
    EXPECT_FALSE(result.allowed);
    EXPECT_TRUE(result.trigger_alert);
}

TEST(RuntimeGuardTest, CriticalRiskMustUseStrongPool) {
    RuntimeGuard guard;
    TaskSecurityContext ctx;
    ctx.task_id = 4;
    ctx.is_untrusted_input = false;
    ctx.risk_level = RiskLevel::CRITICAL;
    ctx.assigned_backend = RuntimeBackend::GVISOR;  // 错误: CRITICAL不能用gVisor

    GuardResult result = guard.verify_before_execution(ctx);
    EXPECT_FALSE(result.allowed);
}

TEST(RuntimeGuardTest, LowRiskLightPoolAllowed) {
    RuntimeGuard guard;
    TaskSecurityContext ctx;
    ctx.task_id = 5;
    ctx.is_untrusted_input = false;
    ctx.risk_level = RiskLevel::LOW;
    ctx.assigned_backend = RuntimeBackend::LIGHT;

    GuardResult result = guard.verify_before_execution(ctx);
    EXPECT_TRUE(result.allowed);
    EXPECT_FALSE(result.trigger_alert);
}

TEST(RuntimeGuardTest, MediumRiskLightPoolBlockedWithoutOverride) {
    RuntimeGuard guard;
    guard.set_allow_admin_override(false);
    TaskSecurityContext ctx;
    ctx.task_id = 6;
    ctx.is_untrusted_input = false;
    ctx.risk_level = RiskLevel::MEDIUM;
    ctx.assigned_backend = RuntimeBackend::LIGHT;

    GuardResult result = guard.verify_before_execution(ctx);
    EXPECT_FALSE(result.allowed);
}

TEST(RuntimeGuardTest, MediumRiskLightPoolAllowedWithOverride) {
    RuntimeGuard guard;
    guard.set_allow_admin_override(true);  // 管理员覆盖
    TaskSecurityContext ctx;
    ctx.task_id = 7;
    ctx.is_untrusted_input = false;
    ctx.risk_level = RiskLevel::MEDIUM;
    ctx.assigned_backend = RuntimeBackend::LIGHT;

    GuardResult result = guard.verify_before_execution(ctx);
    EXPECT_TRUE(result.allowed);
}

TEST(RuntimeGuardTest, UntrustedNetworkMustUseStrongPool) {
    RuntimeGuard guard;
    TaskSecurityContext ctx;
    ctx.task_id = 8;
    ctx.is_untrusted_input = true;
    ctx.requires_network = true;
    ctx.risk_level = RiskLevel::MEDIUM;
    ctx.assigned_backend = RuntimeBackend::GVISOR;  // 错误: 不可信+网络必须StrongPool

    GuardResult result = guard.verify_before_execution(ctx);
    EXPECT_FALSE(result.allowed);
    EXPECT_EQ(result.alert_level, "P0");
}

TEST(RuntimeGuardTest, MandatoryBackendMapping) {
    RuntimeGuard guard;
    EXPECT_EQ(guard.mandatory_backend(RiskLevel::LOW), RuntimeBackend::LIGHT);
    EXPECT_EQ(guard.mandatory_backend(RiskLevel::HIGH), RuntimeBackend::STRONG);
    EXPECT_EQ(guard.mandatory_backend(RiskLevel::CRITICAL), RuntimeBackend::STRONG);
}

TEST(RuntimeGuardTest, IsLightpoolAllowed) {
    RuntimeGuard guard;
    TaskSecurityContext ctx;

    ctx.is_untrusted_input = true;
    EXPECT_FALSE(guard.is_lightpool_allowed(ctx));

    ctx.is_untrusted_input = false;
    ctx.risk_level = RiskLevel::LOW;
    EXPECT_TRUE(guard.is_lightpool_allowed(ctx));

    ctx.risk_level = RiskLevel::HIGH;
    EXPECT_FALSE(guard.is_lightpool_allowed(ctx));
}

TEST(RuntimeGuardTest, Statistics) {
    RuntimeGuard guard;
    EXPECT_EQ(guard.total_checks(), 0u);
    EXPECT_EQ(guard.blocked_count(), 0u);

    TaskSecurityContext ctx;
    ctx.is_untrusted_input = true;
    ctx.assigned_backend = RuntimeBackend::LIGHT;
    guard.verify_before_execution(ctx);

    EXPECT_EQ(guard.total_checks(), 1u);
    EXPECT_EQ(guard.blocked_count(), 1u);
    EXPECT_EQ(guard.alert_count(), 1u);
}

// ===== NetworkResourceGuard 测试 =====

TEST(NetworkResourceGuardTest, RegisterAndCount) {
    NetworkResourceGuard guard;
    EXPECT_EQ(guard.leaked_count(), 0u);

    NetworkResource res;
    res.type = NetworkResourceType::TAP_DEVICE;
    res.name = "tap-test-001";
    res.vm_id = "vm-001";
    guard.register_resource(res);

    EXPECT_EQ(guard.leaked_count(), 1u);
    EXPECT_EQ(guard.total_registered(), 1u);
}

TEST(NetworkResourceGuardTest, CleanupNonexistentResource) {
    NetworkResourceGuard guard;
    NetworkResource res;
    res.type = NetworkResourceType::TAP_DEVICE;
    res.name = "tap-nonexistent-12345";
    res.vm_id = "vm-test";
    guard.register_resource(res);

    // 清理不存在的资源应该返回success(因为资源已经不存在了)
    CleanupResult result = guard.cleanup_vm_resources("vm-test", 1);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(guard.leaked_count(), 0u);
}

TEST(NetworkResourceGuardTest, MultipleResourcesSameVM) {
    NetworkResourceGuard guard;

    for (int i = 0; i < 3; i++) {
        NetworkResource res;
        res.type = NetworkResourceType::TAP_DEVICE;
        res.name = "tap-multi-" + std::to_string(i);
        res.vm_id = "vm-multi";
        guard.register_resource(res);
    }

    EXPECT_EQ(guard.leaked_count(), 3u);
    CleanupResult result = guard.cleanup_vm_resources("vm-multi", 2);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(guard.leaked_count(), 0u);
}

TEST(NetworkResourceGuardTest, CleanupAll) {
    NetworkResourceGuard guard;

    for (int i = 0; i < 5; i++) {
        NetworkResource res;
        res.type = NetworkResourceType::NETNS;
        res.name = "netns-all-" + std::to_string(i);
        res.vm_id = "vm-" + std::to_string(i);
        guard.register_resource(res);
    }

    EXPECT_EQ(guard.leaked_count(), 5u);
    CleanupResult result = guard.cleanup_all(1);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(guard.leaked_count(), 0u);
}

TEST(NetworkResourceGuardTest, GetLeakedResources) {
    NetworkResourceGuard guard;

    NetworkResource res1;
    res1.type = NetworkResourceType::TAP_DEVICE;
    res1.name = "tap-leaked-1";
    res1.vm_id = "vm-leaked";
    guard.register_resource(res1);

    auto leaked = guard.get_leaked_resources();
    EXPECT_EQ(leaked.size(), 1u);
    EXPECT_EQ(leaked[0].name, "tap-leaked-1");
}

TEST(NetworkResourceGuardTest, ForceCleanupNonexistent) {
    NetworkResourceGuard guard;
    NetworkResource res;
    res.type = NetworkResourceType::TAP_DEVICE;
    res.name = "tap-force-nonexistent";
    // 对不存在的设备执行force_cleanup应该返回true(删除命令成功或设备不存在)
    bool result = guard.force_cleanup(res);
    EXPECT_TRUE(result);  // ip link del对不存在设备返回非0, 但我们的实现可能返回false
}

TEST(NetworkResourceGuardTest, CleanupTimeout) {
    NetworkResourceGuard guard;
    guard.set_cleanup_timeout_ms(100);  // 100ms超时
    EXPECT_EQ(guard.cleanup_timeout_ms(), 100u);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
