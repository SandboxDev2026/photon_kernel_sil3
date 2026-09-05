// StrongPool (MicroVM) 工程落地测试
// 三大限制：无KVM降级、高并发内存、只读rootfs数据丢失
#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include "photon_kernel/sandbox/strong_pool.hpp"
#include "photon_kernel/sandbox/artifact_export.hpp"
#include "photon_kernel/sandbox/risk_scorer.hpp"
using namespace photon_kernel::sandbox;
namespace fs = std::filesystem;
// ==================== KVM 探测测试 ====================
TEST(KvmDetectorTest, DetectCapabilities) {
    auto caps = KvmDetector::detect();
    // 容器环境通常无KVM，但探测函数不应崩溃
    EXPECT_FALSE(caps.message.empty());
    printf("  KVM available: %s\n", caps.kvm_available ? "yes" : "no");
    printf("  Firecracker: %s\n", caps.firecracker_available ? "yes" : "no");
    printf("  CPU virt: %s\n", caps.cpu_virtualization ? "yes" : "no");
    printf("  Message: %s\n", caps.message.c_str());
}
TEST(KvmDetectorTest, KvmAvailableQuickCheck) {
    // 快速检查不应崩溃
    bool available = KvmDetector::kvm_available();
    (void)available;
}
TEST(KvmDetectorTest, CpuVirtualizationCheck) {
    bool supports = KvmDetector::cpu_supports_virtualization();
    (void)supports;
}
// ==================== StrongPool 调度器测试 ====================
TEST(StrongPoolSchedulerTest, HighRiskRejectedWithoutKvm) {
    // 关键安全点：高风险任务无KVM时直接拒绝，绝不静默降级
    StrongPoolConfig config;
    config.reject_high_risk_without_kvm = true;
    config.allow_low_risk_fallback = true;
    StrongPoolScheduler scheduler(config);
    // 模拟无KVM环境（探测结果）
    bool kvm_available = scheduler.capabilities().kvm_available &&
                         scheduler.capabilities().firecracker_available;
    if (!kvm_available) {
        // 高风险任务应该被拒绝
        auto result = scheduler.schedule("task-1", "tenant-1", RiskLevel::HIGH, 128);
        EXPECT_EQ(result.decision, SchedulingDecision::REJECT_NO_KVM);
        EXPECT_NE(result.reason.find("Refusing"), std::string::npos);
        printf("  HIGH risk without KVM: REJECTED (security policy)\n");
        // CRITICAL 也应该被拒绝
        auto result2 = scheduler.schedule("task-2", "tenant-1", RiskLevel::CRITICAL, 128);
        EXPECT_EQ(result2.decision, SchedulingDecision::REJECT_NO_KVM);
    } else {
        printf("  KVM available, skip rejection test\n");
    }
}
TEST(StrongPoolSchedulerTest, LowRiskFallbackWithoutKvm) {
    // 低风险任务无KVM时允许降级到LightPool
    StrongPoolConfig config;
    config.allow_low_risk_fallback = true;
    StrongPoolScheduler scheduler(config);
    bool kvm_available = scheduler.capabilities().kvm_available &&
                         scheduler.capabilities().firecracker_available;
    if (!kvm_available) {
        auto result = scheduler.schedule("task-3", "tenant-1", RiskLevel::LOW, 64);
        EXPECT_EQ(result.decision, SchedulingDecision::FALLBACK_PROCESS);
        printf("  LOW risk without KVM: FALLBACK to process sandbox\n");
    }
}
TEST(StrongPoolSchedulerTest, MediumRiskDefaultNoFallback) {
    // 中风险任务默认不允许降级
    StrongPoolConfig config;
    config.allow_medium_risk_fallback = false;
    StrongPoolScheduler scheduler(config);
    bool kvm_available = scheduler.capabilities().kvm_available &&
                         scheduler.capabilities().firecracker_available;
    if (!kvm_available) {
        auto result = scheduler.schedule("task-4", "tenant-1", RiskLevel::MEDIUM, 128);
        EXPECT_EQ(result.decision, SchedulingDecision::REJECT_NO_KVM);
        printf("  MEDIUM risk without KVM (fallback disabled): REJECTED\n");
    }
}
TEST(StrongPoolSchedulerTest, ConcurrentVmLimit) {
    // 并发上限测试
    StrongPoolConfig config;
    config.max_concurrent_vms = 2;
    config.max_queue_size = 5;
    // 强制KVM可用（测试模式，不实际启动VM）
    StrongPoolScheduler scheduler(config);
    bool kvm_available = scheduler.capabilities().kvm_available &&
                         scheduler.capabilities().firecracker_available;
    if (kvm_available) {
        // 前2个应该运行
        auto r1 = scheduler.schedule("t1", "tenant", RiskLevel::LOW, 64);
        auto r2 = scheduler.schedule("t2", "tenant", RiskLevel::LOW, 64);
        EXPECT_EQ(r1.decision, SchedulingDecision::RUN_MICROVM);
        EXPECT_EQ(r2.decision, SchedulingDecision::RUN_MICROVM);
        // 第3个应该排队
        auto r3 = scheduler.schedule("t3", "tenant", RiskLevel::LOW, 64);
        EXPECT_EQ(r3.decision, SchedulingDecision::QUEUED);
        printf("  Concurrent limit: 2 running, 3rd queued\n");
        // 完成一个后，排队的应该启动
        scheduler.complete(r1.vm_id);
        auto status = scheduler.status();
        EXPECT_EQ(status.active_vms, 2);  // r2 + 排队的启动
        printf("  After complete: %zu active (should be 2)\n", status.active_vms);
    } else {
        printf("  KVM not available, skip concurrent limit test\n");
    }
}
TEST(StrongPoolSchedulerTest, TtlEnforcement) {
    // TTL 测试
    StrongPoolConfig config;
    config.max_concurrent_vms = 10;
    config.max_ttl = std::chrono::seconds(0);  // 立即过期
    StrongPoolScheduler scheduler(config);
    bool kvm_available = scheduler.capabilities().kvm_available &&
                         scheduler.capabilities().firecracker_available;
    if (kvm_available) {
        auto r1 = scheduler.schedule("t1", "tenant", RiskLevel::LOW, 64);
        EXPECT_EQ(r1.decision, SchedulingDecision::RUN_MICROVM);
        // TTL=0，应该立即终止
        size_t terminated = scheduler.enforce_ttl();
        EXPECT_GT(terminated, 0u);
        printf("  TTL enforcement: %zu VMs terminated\n", terminated);
    }
}
TEST(StrongPoolSchedulerTest, PoolStatus) {
    StrongPoolConfig config;
    StrongPoolScheduler scheduler(config);
    auto status = scheduler.status();
    EXPECT_EQ(status.active_vms, 0u);
    printf("  Pool status: active=%zu, kvm=%s\n",
           status.active_vms, status.kvm_available ? "yes" : "no");
}
// ==================== 产物导出测试 ====================
TEST(ArtifactExporterTest, ComputeSha256) {
    // 创建临时文件
    std::string tmp_path = "/tmp/photon_test_artifact.txt";
    {
        std::ofstream f(tmp_path);
        f << "test content for artifact export";
    }
    std::string hash = ArtifactExporter::compute_sha256(tmp_path);
    EXPECT_FALSE(hash.empty());
    EXPECT_EQ(hash.size(), 64u);  // SHA256 = 32 bytes = 64 hex chars
    printf("  SHA256: %s\n", hash.c_str());
    std::remove(tmp_path.c_str());
}
TEST(ArtifactExporterTest, ExportFromLocalFile) {
    // 测试模式：vsock不可用时从本地文件复制
    ArtifactExporter::Config config;
    config.export_dir = "/tmp/photon_test_artifacts";
    ArtifactExporter exporter(config);
    // 创建源文件
    std::string src = "/tmp/photon_test_source.txt";
    {
        std::ofstream f(src);
        f << "artifact content";
    }
    auto result = exporter.export_from_vm("test-vm-1", {src}, "tenant-1");
    // vsock不可用，但本地文件存在，应该导出成功
    EXPECT_TRUE(result.success);
    EXPECT_GT(result.artifacts.size(), 0u);
    EXPECT_GT(result.total_bytes, 0u);
    printf("  Exported: %zu artifacts, %zu bytes\n",
           result.artifacts.size(), result.total_bytes);
    // 列出产物
    auto artifacts = exporter.list_artifacts("test-vm-1");
    EXPECT_GT(artifacts.size(), 0u);
    EXPECT_FALSE(artifacts[0].sha256.empty());
    std::remove(src.c_str());
}
// ==================== 工作区管理测试 ====================
TEST(WorkspaceManagerTest, CreateAndCleanup) {
    WorkspaceManager::Config config;
    config.storage_dir = "/tmp/photon_test_workspaces";
    WorkspaceManager manager(config);
    auto ws = manager.create_workspace("tenant-1");
    EXPECT_NE(ws, nullptr);
    EXPECT_FALSE(ws->workspace_id.empty());
    EXPECT_TRUE(fs::exists(ws->host_path));
    printf("  Workspace created: %s\n", ws->workspace_id.c_str());
    // 列出
    auto list = manager.list_workspaces();
    EXPECT_GT(list.size(), 0u);
    // 清理
    EXPECT_TRUE(manager.cleanup_workspace(ws->workspace_id));
    EXPECT_FALSE(fs::exists(ws->host_path));
    printf("  Workspace cleaned up\n");
}
TEST(WorkspaceManagerTest, InjectInputReadonly) {
    WorkspaceManager::Config config;
    config.storage_dir = "/tmp/photon_test_workspaces2";
    config.read_only_input = true;
    WorkspaceManager manager(config);
    auto ws = manager.create_workspace("tenant-1");
    // 创建输入文件
    std::string input = "/tmp/photon_test_input.txt";
    {
        std::ofstream f(input);
        f << "input content";
    }
    bool ok = manager.inject_input(ws->workspace_id, {input});
    // 无root时可能无法创建镜像，但不应崩溃
    (void)ok;
    printf("  Input inject: %s\n", ok ? "success" : "failed (no root?)");
    std::remove(input.c_str());
    manager.cleanup_workspace(ws->workspace_id);
}
// ==================== 临时磁盘测试 ====================
TEST(EphemeralDiskTest, CreateAndDestroy) {
    EphemeralDisk::Config config;
    config.mount_dir = "/tmp/photon_test_disks";
    config.default_size_mb = 16;
    EphemeralDisk disk_manager(config);
    auto disk = disk_manager.create_disk("test-vm-1", 16);
    EXPECT_NE(disk, nullptr);
    EXPECT_FALSE(disk->disk_id.empty());
    EXPECT_TRUE(fs::exists(disk->mount_path));
    printf("  Ephemeral disk: %s, size=%zuMB, mounted=%s\n",
           disk->disk_id.c_str(), disk->size_mb, disk->mounted ? "yes" : "no");
    // 列出
    auto list = disk_manager.list_disks();
    EXPECT_GT(list.size(), 0u);
    // 销毁
    EXPECT_TRUE(disk_manager.destroy_disk(disk->disk_id));
    EXPECT_FALSE(fs::exists(disk->mount_path));
    printf("  Ephemeral disk destroyed\n");
}
// ==================== 安全策略验证 ====================
TEST(SecurityPolicyTest, NoSilentDowngradeForHighRisk) {
    // 核心安全验证：高风险任务绝不静默降级
    StrongPoolConfig config;
    config.reject_high_risk_without_kvm = true;
    config.allow_low_risk_fallback = true;
    config.allow_medium_risk_fallback = false;
    StrongPoolScheduler scheduler(config);
    bool kvm_available = scheduler.capabilities().kvm_available &&
                         scheduler.capabilities().firecracker_available;
    if (!kvm_available) {
        // 遍历所有风险等级
        RiskLevel levels[] = {RiskLevel::LOW, RiskLevel::MEDIUM,
                              RiskLevel::HIGH, RiskLevel::CRITICAL};
        for (auto level : levels) {
            auto result = scheduler.schedule("test", "tenant", level, 64);
            if (level == RiskLevel::HIGH || level == RiskLevel::CRITICAL) {
                EXPECT_EQ(result.decision, SchedulingDecision::REJECT_NO_KVM);
                EXPECT_NE(result.reason.find("Refusing"), std::string::npos);
            }
        }
        printf("  Security verified: HIGH/CRITICAL never silently downgraded\n");
    }
}

// ==================== 嵌套虚拟化检测测试 ====================
TEST(KvmDetectorTest, HypervisorBitDetection) {
    // 检测 CPUID hypervisor 位（是否运行在虚拟机中）
    bool in_vm = KvmDetector::detect_hypervisor_bit();
    // 结果可以是 true 或 false，取决于运行环境
    // 但函数必须能正常执行不崩溃
    printf("  Hypervisor bit detected: %s\n", in_vm ? "YES (running in VM)" : "NO (bare metal)");
    SUCCEED();
}

TEST(KvmDetectorTest, NestedVmDetection) {
    // 嵌套虚拟化检测：在VM中 + 有vmx/svm + 有/dev/kvm
    bool is_nested = KvmDetector::detect_nested_vm();
    printf("  Nested VM detected: %s\n", is_nested ? "YES (debug only)" : "NO");
    SUCCEED();
}

TEST(KvmDetectorTest, NestedVmProductionAcceptanceInvalid) {
    // 核心安全验证：嵌套环境下 production_acceptance_valid 必须为 false
    auto caps = KvmDetector::detect();
    if (caps.is_nested_vm) {
        EXPECT_FALSE(caps.production_acceptance_valid);
        EXPECT_FALSE(caps.nested_warning.empty());
        EXPECT_NE(caps.nested_warning.find("NOT valid for production"), std::string::npos);
        printf("  Nested VM: production acceptance INVALID (correct)\n");
        printf("  Warning: %s\n", caps.nested_warning.c_str());
    } else {
        printf("  Not nested VM: skipping production acceptance check\n");
    }
}

TEST(KvmDetectorTest, CapabilitiesToStringIncludesNestedInfo) {
    // to_string() 必须包含嵌套环境信息
    auto caps = KvmDetector::detect();
    std::string str = caps.to_string();
    EXPECT_NE(str.find("nested_vm"), std::string::npos);
    EXPECT_NE(str.find("production_acceptance"), std::string::npos);
    if (caps.is_nested_vm) {
        EXPECT_NE(str.find("DEBUG ONLY"), std::string::npos);
        EXPECT_NE(str.find("INVALID"), std::string::npos);
    }
    printf("  to_string() includes nested VM info: OK\n");
}

TEST(KvmDetectorTest, HypervisorTypeDetection) {
    // Hypervisor 类型精确识别
    std::string type = KvmDetector::detect_hypervisor_type();
    EXPECT_FALSE(type.empty());
    printf("  Hypervisor type detected: %s\n", type.c_str());
    // 验证类型是已知类型之一
    bool known_type = (type == "QEMU-KVM" || type == "VMware" || type == "VirtualBox" ||
                       type == "Hyper-V" || type == "Xen" || type == "Bare-Metal" ||
                       type == "AWS Nitro" || type == "Google Compute Engine" ||
                       type == "Generic-VM" || type == "Unknown-Hypervisor" ||
                       type == "QEMU-TCG" || type == "Cloud-Hypervisor");
    EXPECT_TRUE(known_type);
}

TEST(KvmDetectorTest, NestedVirtSupportMatrix) {
    // 嵌套虚拟化支持矩阵验证
    // 支持嵌套的 hypervisor
    EXPECT_TRUE(KvmDetector::check_nested_virt_support("QEMU-KVM"));
    EXPECT_TRUE(KvmDetector::check_nested_virt_support("VMware"));
    EXPECT_TRUE(KvmDetector::check_nested_virt_support("VirtualBox"));
    EXPECT_TRUE(KvmDetector::check_nested_virt_support("Hyper-V"));
    EXPECT_TRUE(KvmDetector::check_nested_virt_support("Xen"));
    EXPECT_TRUE(KvmDetector::check_nested_virt_support("Bare-Metal"));
    // 普通云实例不支持嵌套
    EXPECT_FALSE(KvmDetector::check_nested_virt_support("AWS Nitro"));
    EXPECT_FALSE(KvmDetector::check_nested_virt_support("Google Compute Engine"));
    printf("  Nested virt support matrix: verified\n");
}

TEST(KvmDetectorTest, CapabilitiesIncludesHypervisorInfo) {
    // KvmCapabilities 必须包含 hypervisor 信息
    auto caps = KvmDetector::detect();
    EXPECT_FALSE(caps.hypervisor_type.empty());
    std::string str = caps.to_string();
    EXPECT_NE(str.find("hypervisor_type"), std::string::npos);
    EXPECT_NE(str.find("nested_virt_supported"), std::string::npos);
    printf("  Hypervisor info in capabilities: type=%s, nested_supported=%s\n",
           caps.hypervisor_type.c_str(),
           caps.nested_virt_supported ? "yes" : "no");
    if (!caps.nested_virt_note.empty()) {
        printf("  Nested virt note: %s\n", caps.nested_virt_note.c_str());
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
