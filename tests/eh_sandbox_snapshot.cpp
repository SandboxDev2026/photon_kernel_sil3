#include <gtest/gtest.h>

#include <cstdio>
#include <string>

#include "photon_kernel/sandbox/sandbox_snapshot.hpp"
#include "photon_kernel/sandbox/sandbox_policy.hpp"

using namespace photon_kernel::sandbox;

TEST(SandboxSnapshotTest, SaveLoadRoundTrip) {
    const std::string path = "/tmp/photon_snapshot_test.snap";
    std::remove(path.c_str());

    SandboxSnapshot snap;
    snap.label = "test-pool";
    snap.created_at = "2026-09-01T12:00:00";
    snap.config = SandboxConfig::for_code_runner();
    snap.config.audit_prefix = "snapshot-test";
    snap.whitelist = SandboxPolicy::get_whitelist_for_code_runner();

    EXPECT_TRUE(snap.save(path));

    SandboxSnapshot loaded;
    EXPECT_TRUE(SandboxSnapshot::load(path, loaded));
    EXPECT_EQ(loaded.format_version, SandboxSnapshot::FORMAT_VERSION);
    EXPECT_EQ(loaded.label, snap.label);
    EXPECT_EQ(loaded.config.risk_level, snap.config.risk_level);
    EXPECT_EQ(loaded.config.memory_limit_bytes, snap.config.memory_limit_bytes);
    EXPECT_EQ(loaded.config.cpu_time_limit, snap.config.cpu_time_limit);
    EXPECT_EQ(loaded.config.allow_network, snap.config.allow_network);
    EXPECT_EQ(loaded.config.audit_prefix, snap.config.audit_prefix);
    EXPECT_EQ(loaded.config.read_whitelist, snap.config.read_whitelist);
    EXPECT_EQ(loaded.config.extra_allowed_syscalls, snap.config.extra_allowed_syscalls);
    EXPECT_EQ(loaded.whitelist, snap.whitelist);
    EXPECT_GT(loaded.whitelist.size(), 0u);

    // 从快照重建配置：与原始配置等价（跳过重新配置）
    SandboxConfig rebuilt = loaded.to_config();
    EXPECT_EQ(rebuilt.memory_limit_bytes, snap.config.memory_limit_bytes);

    std::remove(path.c_str());
}

TEST(SandboxSnapshotTest, LoadMissingFileFails) {
    SandboxSnapshot out;
    EXPECT_FALSE(SandboxSnapshot::load("/tmp/definitely_not_exist.snap", out));
}

TEST(SandboxSnapshotTest, CriuInterfaceCallable) {
    // 本机通常无 root/criu；只验证接口可调用、不崩溃，并如实返回状态
    std::string err;
    bool avail = criu_available();
    if (!avail) {
        GTEST_SKIP() << "criu not installed (needs root), interface only";
    }
    EXPECT_FALSE(criu_dump_process(::getpid(), "/tmp/criu_should_fail", err));
}
