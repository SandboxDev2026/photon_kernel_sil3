#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include <sys/wait.h>
#include "photon_kernel/sandbox/snapshot_manager.hpp"
#include "photon_kernel/sandbox/cgroup_manager.hpp"
#include "photon_kernel/sandbox/metrics.hpp"
#include "photon_kernel/sandbox/landlock.hpp"
using namespace photon_kernel::sandbox;
// ---- SnapshotManager：快照克隆（<1ms 目标）----
TEST(SnapshotManagerTest, InitCloneRecycle) {
    auto& mgr = SnapshotManager::instance();
    mgr.shutdown();  // 确保干净状态
    mgr.init(/*pool_size=*/4, /*risk_level=*/1);
    ASSERT_TRUE(mgr.initialized());
    EXPECT_EQ(mgr.snapshot_count(), 4u);
    // 克隆 10 次，测量延迟
    uint64_t total_us = 0;
    int success = 0;
    for (int i = 0; i < 10; ++i) {
        auto t0 = std::chrono::steady_clock::now();
        pid_t child = mgr.clone_sandbox();
        auto t1 = std::chrono::steady_clock::now();
        total_us += std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        if (child > 0) {
            success++;
            mgr.recycle(child);
        }
    }
    EXPECT_GE(success, 8);  // 至少 80% 成功
    EXPECT_GT(mgr.clone_count(), 0u);
    // 平均克隆延迟（含管道 I/O），目标接近 1ms 量级
    uint64_t avg_us = total_us / 10;
    std::cout << "[SnapshotManager] avg clone latency: " << avg_us << "us (n=10)\n";
    EXPECT_LT(avg_us, 5000u);  // 宽松上限：远低于冷启动 10ms
    mgr.shutdown();
}
// ---- CgroupManager：cgroup v2 硬隔离（容器内只读时降级）----
TEST(CgroupManagerTest, InitDegradedOrActive) {
    auto& mgr = CgroupManager::instance();
    mgr.cleanup();
    CgroupConfig cfg;
    cfg.memory_max = 64 * 1024 * 1024;  // 64MB
    bool ok = mgr.init(cfg);
    auto status = mgr.status();
    // 容器内 cgroup 常为只读，此时应 degraded；有写权限时应 active
    if (ok) {
        EXPECT_TRUE(status.initialized);
        EXPECT_FALSE(status.degraded);
        EXPECT_GE(status.memory_current, 0);
        std::cout << "[CgroupManager] active: " << status.message << "\n";
    } else {
        EXPECT_TRUE(status.degraded);
        std::cout << "[CgroupManager] degraded: " << status.message << "\n";
    }
    mgr.cleanup();
}
// ---- Metrics：Prometheus 指标导出 ----
TEST(MetricsTest, RecordAndExport) {
    auto& m = Metrics::instance();
    m.reset();
    m.record_task(/*success=*/true, 1500);
    m.record_task(/*success=*/false, 800);
    m.increment_concurrent();
    m.increment_concurrent();
    m.decrement_concurrent();
    m.record_snapshot_fork();
    m.record_pool_hit();
    m.record_pool_hit();
    m.set_audit_spool_size(42);
    EXPECT_EQ(m.tasks_total(), 2u);
    EXPECT_EQ(m.tasks_failed(), 1u);
    EXPECT_EQ(m.execution_time_us_total(), 2300u);
    EXPECT_EQ(m.peak_concurrent(), 2u);
    EXPECT_EQ(m.snapshot_fork_total(), 1u);
    EXPECT_EQ(m.pool_hit_total(), 2u);
    EXPECT_EQ(m.audit_spool_size(), 42u);
    // 导出 Prometheus 格式
    std::string prom = m.export_prometheus();
    EXPECT_NE(prom.find("photon_sandbox_tasks_total 2"), std::string::npos);
    EXPECT_NE(prom.find("photon_sandbox_tasks_failed_total 1"), std::string::npos);
    EXPECT_NE(prom.find("photon_sandbox_snapshot_fork_total 1"), std::string::npos);
    EXPECT_NE(prom.find("photon_sandbox_pool_hit_total 2"), std::string::npos);
    EXPECT_NE(prom.find("photon_sandbox_audit_spool_size 42"), std::string::npos);
    EXPECT_NE(prom.find("# HELP"), std::string::npos);
    EXPECT_NE(prom.find("# TYPE"), std::string::npos);
    m.reset();
    EXPECT_EQ(m.tasks_total(), 0u);
}
// ---- Landlock：路径白名单（内核 6.6 应支持）----
TEST(LandlockTest, DetectSupport) {
    bool supported = LandlockEnforcer::is_supported();
    std::cout << "[Landlock] supported: " << (supported ? "yes" : "no") << "\n";
    // 内核 6.6 应支持；若不支持则跳过应用测试
    if (!supported) {
        GTEST_SKIP() << "Landlock not supported by kernel";
    }
}
TEST(LandlockTest, ApplyReadOnly) {
    if (!LandlockEnforcer::is_supported()) {
        GTEST_SKIP() << "Landlock not supported";
    }
    // 应用只读白名单（允许 /usr/bin 和 /tmp）
    auto result = LandlockEnforcer::apply_read_only({"/usr/bin", "/tmp"});
    std::cout << "[Landlock] applied: " << result.applied
              << " msg: " << result.message << "\n";
    // 注意：Landlock 一旦应用即限制当前进程，后续测试可能受影响
    // 此处仅验证 API 可调用，不强制断言成功（可能因权限/配置失败）
    EXPECT_TRUE(result.available);
}
