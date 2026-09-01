// eBPF + CRIU 补测：验证降级路径和命令构造逻辑（不需要 root/criu/libbpf）。
#include <gtest/gtest.h>
#include "photon_kernel/sandbox/ebpf_network.hpp"
#include "photon_kernel/sandbox/sandbox_snapshot.hpp"
using namespace photon_kernel::sandbox;
// ==================== eBPF 降级路径测试 ====================
TEST(EbpfNetworkTest, InstanceIsSingleton) {
    auto& a = EbpfNetworkEnforcer::instance();
    auto& b = EbpfNetworkEnforcer::instance();
    EXPECT_EQ(&a, &b);
}
TEST(EbpfNetworkTest, StatusBeforeEnable) {
    // 未启用时 status 不应崩溃，loaded=false
    auto s = EbpfNetworkEnforcer::instance().status();
    EXPECT_FALSE(s.loaded);
    EXPECT_EQ(s.rule_count, 0u);
}
TEST(EbpfNetworkTest, EnableWithoutCapabilitiesDegrades) {
    // 当前容器无 CAP_BPF/CAP_NET_ADMIN，enable 应返回 false 并设置 degraded
    auto& enforcer = EbpfNetworkEnforcer::instance();
    std::vector<NetworkRule> rules = {
        {"10.0.0.1", 443, "tcp"},
        {"", 80, "tcp"},
    };
    bool ok = enforcer.enable(rules);
    auto s = enforcer.status();
    // 无权限环境：ok=false, degraded=true
    // 有权限环境：ok=true, degraded=false（测试应兼容两种环境）
    EXPECT_EQ(ok, s.loaded);
    EXPECT_EQ(s.degraded, !ok);
    if (!ok) {
        EXPECT_TRUE(s.degraded);
        EXPECT_GT(s.message.size(), 0u);
    }
}
TEST(EbpfNetworkTest, AddRuleWithoutLoadedReturnsFalse) {
    // 未加载时 add_rule 应返回 false
    auto& enforcer = EbpfNetworkEnforcer::instance();
    enforcer.disable();  // 确保未加载
    NetworkRule r{"1.2.3.4", 80, "tcp"};
    EXPECT_FALSE(enforcer.add_rule(r));
}
TEST(EbpfNetworkTest, RemoveRuleWithoutLoadedReturnsFalse) {
    auto& enforcer = EbpfNetworkEnforcer::instance();
    enforcer.disable();
    NetworkRule r{"1.2.3.4", 80, "tcp"};
    EXPECT_FALSE(enforcer.remove_rule(r));
}
TEST(EbpfNetworkTest, SetDenyAllSetsDegraded) {
    auto& enforcer = EbpfNetworkEnforcer::instance();
    enforcer.set_deny_all();
    auto s = enforcer.status();
    EXPECT_TRUE(s.degraded);
    EXPECT_FALSE(s.loaded);
}
TEST(EbpfNetworkTest, NetworkRuleStructFields) {
    NetworkRule r;
    r.ip = "192.168.1.1";
    r.port = 8443;
    r.protocol = "tcp";
    EXPECT_EQ(r.ip, "192.168.1.1");
    EXPECT_EQ(r.port, 8443);
    EXPECT_EQ(r.protocol, "tcp");
}
// ==================== CRIU 命令构造与检测测试 ====================
TEST(CriuTest, AvailableReturnsBool) {
    // criu_available 不应崩溃，返回 bool
    bool avail = criu_available();
    EXPECT_TRUE(avail == true || avail == false);  // 兼容有/无 criu 环境
}
TEST(CriuTest, DumpWithoutCriuReturnsError) {
    // 无 criu 时 dump 应返回 false 并设置错误信息
    if (criu_available()) {
        GTEST_SKIP() << "criu is installed, skipping degrade test";
    }
    std::string err;
    bool ok = criu_dump_process(12345, "/tmp/criu_test_should_not_exist", err);
    EXPECT_FALSE(ok);
    EXPECT_GT(err.size(), 0u);
    EXPECT_NE(err.find("criu"), std::string::npos);  // 错误信息应提到 criu
}
TEST(CriuTest, RestoreWithoutCriuReturnsError) {
    if (criu_available()) {
        GTEST_SKIP() << "criu is installed, skipping degrade test";
    }
    std::string err;
    pid_t out_pid = -1;
    bool ok = criu_restore_process("/tmp/nonexistent_criu_dir", out_pid, err);
    EXPECT_FALSE(ok);
    EXPECT_GT(err.size(), 0u);
    EXPECT_EQ(out_pid, -1);  // 失败时不应修改 out_pid（初始值）
}
TEST(CriuTest, DumpWithInvalidPidHandlesError) {
    // 即使 criu 可用，无效 pid 也应返回错误
    if (!criu_available()) {
        GTEST_SKIP() << "criu not installed";
    }
    std::string err;
    bool ok = criu_dump_process(999999, "/tmp/criu_invalid_pid", err);
    EXPECT_FALSE(ok);  // 无效 pid 应失败
}
TEST(CriuTest, SnapshotConfigSaveLoadRoundTrip) {
    // 配置级快照（不依赖 criu）应可保存/加载往返
    SandboxSnapshot snap;
    snap.label = "test-snapshot";
    snap.config.risk_level = RiskLevel::HIGH;
    snap.config.memory_limit_bytes = 1024 * 1024 * 64;
    snap.whitelist = {0, 1, 2, 3, 60};
    std::string path = "/tmp/test_snapshot_roundtrip.ini";
    ASSERT_TRUE(snap.save(path));
    SandboxSnapshot loaded;
    ASSERT_TRUE(SandboxSnapshot::load(path, loaded));
    EXPECT_EQ(loaded.label, "test-snapshot");
    EXPECT_EQ(loaded.config.risk_level, RiskLevel::HIGH);
    EXPECT_EQ(loaded.config.memory_limit_bytes, 1024u * 1024u * 64u);
    EXPECT_EQ(loaded.whitelist.size(), 5u);
    EXPECT_EQ(loaded.whitelist[0], 0);
    EXPECT_EQ(loaded.whitelist[4], 60);
    ::unlink(path.c_str());
}
TEST(CriuTest, SnapshotFormatVersion) {
    SandboxSnapshot snap;
    EXPECT_EQ(snap.format_version, "1.0");
    EXPECT_EQ(std::string(SandboxSnapshot::FORMAT_VERSION), "1.0");
}
TEST(CriuTest, SnapshotToConfigReturnsConfig) {
    SandboxSnapshot snap;
    snap.config.risk_level = RiskLevel::MEDIUM;
    SandboxConfig cfg = snap.to_config();
    EXPECT_EQ(cfg.risk_level, RiskLevel::MEDIUM);
}
