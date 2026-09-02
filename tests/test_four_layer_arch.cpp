// 四层架构测试：RuntimeSelector + TaskSpec + RuntimeInterface + PolicyEngine + EvidenceRelease
#include <gtest/gtest.h>
#include "photon_kernel/sandbox/runtime_selector.hpp"
#include "photon_kernel/sandbox/task_spec.hpp"
#include "photon_kernel/sandbox/runtime_interface.hpp"
#include "photon_kernel/sandbox/policy_engine.hpp"
#include "photon_kernel/sandbox/evidence_release.hpp"
using namespace photon_kernel::sandbox;
// ==================== RuntimeSelector 测试 ====================
TEST(RuntimeSelectorTest, AllProfilesExist) {
    auto profiles = RuntimeSelector::instance().all_profiles();
    EXPECT_GE(profiles.size(), 4u);  // Container/gVisor/MicroVM/Wasm
}
TEST(RuntimeSelectorTest, UntrustedCodeSelectsMicroVM) {
    WorkloadProfile w;
    w.code_trust_level = 10;
    w.tenant_trust_level = 10;
    w.needs_full_linux_tools = true;
    auto result = RuntimeSelector::instance().select(w);
    // 低可信度 + 需要Linux工具 → MicroVM
    EXPECT_EQ(result.selected, RuntimeType::MICROVM);
    EXPECT_FALSE(result.warnings.empty());
}
TEST(RuntimeSelectorTest, HighConcurrencySelectsWasm) {
    WorkloadProfile w;
    w.code_trust_level = 90;
    w.tenant_trust_level = 90;
    w.needs_full_linux_tools = false;
    w.cold_start_sensitivity = 95;
    w.concurrency_requirement = 95;
    w.cost_sensitivity = 90;
    auto result = RuntimeSelector::instance().select(w);
    // 高可信 + 极高并发 + 高冷启动敏感 → Wasm
    EXPECT_EQ(result.selected, RuntimeType::WASM);
}
TEST(RuntimeSelectorTest, TrustedInternalSelectsContainer) {
    WorkloadProfile w;
    w.code_trust_level = 90;
    w.tenant_trust_level = 90;
    w.needs_full_linux_tools = true;
    w.cost_sensitivity = 80;
    auto result = RuntimeSelector::instance().select(w);
    // 高可信 + 需要Linux工具 + 成本敏感 → Container
    EXPECT_EQ(result.selected, RuntimeType::CONTAINER);
}
TEST(RuntimeSelectorTest, ComparisonTableGenerated) {
    std::string table = RuntimeSelector::instance().comparison_table();
    EXPECT_FALSE(table.empty());
    EXPECT_NE(table.find("Container"), std::string::npos);
    EXPECT_NE(table.find("MicroVM"), std::string::npos);
}
// ==================== TaskSpec 测试 ====================
TEST(TaskSpecTest, CompileGeneratesValidSpec) {
    WorkloadProfile w;
    w.code_trust_level = 50;
    w.tenant_trust_level = 50;
    auto spec = TaskCompiler::instance().compile("test goal", w, "tenant-1");
    EXPECT_FALSE(spec.task_id.empty());
    EXPECT_EQ(spec.goal, "test goal");
    EXPECT_EQ(spec.identity.tenant_id, "tenant-1");
    EXPECT_GT(spec.resources.memory_mb, 0u);
    EXPECT_GT(spec.budget.ttl.count(), 0);
}
TEST(TaskSpecTest, LowTrustDisablesNetwork) {
    WorkloadProfile w;
    w.code_trust_level = 10;
    w.tenant_trust_level = 10;
    w.needs_network = true;
    auto spec = TaskCompiler::instance().compile("test", w);
    EXPECT_FALSE(spec.network.enabled);  // 低可信度默认断网
}
TEST(TaskSpecTest, CodeExecutionShortTTL) {
    WorkloadProfile w;
    auto spec = TaskCompiler::instance().compile_code_execution("print(1)", "python", w);
    EXPECT_LE(spec.budget.ttl.count(), 120);  // 代码执行任务TTL短
}
TEST(TaskSpecTest, ValidateRejectsEmptyId) {
    TaskSpec spec;
    std::string error;
    EXPECT_FALSE(TaskCompiler::instance().validate(spec, error));
    EXPECT_FALSE(error.empty());
}
// ==================== RuntimeInterface 测试 ====================
TEST(RuntimeInterfaceTest, ContainerRuntimeCreateExecDestroy) {
    auto runtime = RuntimeFactory::create(RuntimeType::CONTAINER);
    ASSERT_TRUE(runtime->available());
    WorkloadProfile w;
    auto spec = TaskCompiler::instance().compile("test", w);
    std::string id = runtime->create(spec);
    EXPECT_FALSE(id.empty());
    auto result = runtime->exec(id, "echo hello", "shell");
    EXPECT_TRUE(result.success);
    EXPECT_NE(result.output.find("hello"), std::string::npos);
    runtime->destroy(id);
}
TEST(RuntimeInterfaceTest, ContainerRuntimePythonExec) {
    auto runtime = RuntimeFactory::create(RuntimeType::CONTAINER);
    WorkloadProfile w;
    auto spec = TaskCompiler::instance().compile("test", w);
    std::string id = runtime->create(spec);
    auto result = runtime->exec(id, "print(42)", "python");
    if (result.success) {
        EXPECT_NE(result.output.find("42"), std::string::npos);
    }
    runtime->destroy(id);
}
TEST(RuntimeInterfaceTest, RuntimeFactoryCreateByWorkload) {
    WorkloadProfile w;
    w.code_trust_level = 90;
    w.tenant_trust_level = 90;
    auto runtime = RuntimeFactory::create_by_workload(w);
    EXPECT_TRUE(runtime->available());
}
TEST(RuntimeInterfaceTest, MicroVMAvailabilityDetection) {
    auto runtime = RuntimeFactory::create(RuntimeType::MICROVM);
    // 容器环境通常没有 KVM
    // 不假设结果，只验证不崩溃
    EXPECT_NO_THROW(runtime->available());
}
// ==================== PolicyEngine 测试 ====================
TEST(PolicyEngineTest, NetworkPolicyDefaultDeny) {
    NetworkRequest req;
    req.dest_ip = "8.8.8.8";
    req.dest_port = 443;
    req.protocol = "tcp";
    auto decision = PolicyEngine::instance().evaluate_network(req);
    // 默认策略应该是 DENY（只允许本地回环）
    EXPECT_EQ(decision, PolicyDecision::DENY);
}
TEST(PolicyEngineTest, NetworkPolicyAllowLocalhost) {
    NetworkRequest req;
    req.dest_ip = "127.0.0.1";
    req.dest_port = 8080;
    req.protocol = "tcp";
    auto decision = PolicyEngine::instance().evaluate_network(req);
    EXPECT_EQ(decision, PolicyDecision::ALLOW);
}
TEST(PolicyEngineTest, ToolPolicyUnregisteredDenied) {
    ToolCallRequest req;
    req.tool_name = "nonexistent_tool";
    req.caller_id = "test-agent";
    auto decision = PolicyEngine::instance().evaluate_tool(req);
    EXPECT_EQ(decision, PolicyDecision::DENY);
}
TEST(PolicyEngineTest, PolicyCredentialVaultStoreAndGet) {
    auto& vault = PolicyCredentialVault::instance();
    vault.store("test-key", "secret-value-123", "tenant-1", {"agent-1", "*"});
    EXPECT_TRUE(vault.exists("test-key"));
    CredentialRequest req;
    req.credential_id = "test-key";
    req.caller_id = "agent-1";
    req.tenant_id = "tenant-1";
    PolicyDecision d;
    std::string value = vault.get(req, d);
    EXPECT_EQ(d, PolicyDecision::ALLOW);
    EXPECT_EQ(value, "secret-value-123");
    vault.remove("test-key");
}
TEST(PolicyEngineTest, PolicyCredentialVaultDummyValueForUnauthorized) {
    auto& vault = PolicyCredentialVault::instance();
    vault.store("api-key-prod", "sk-real-xxxx", "tenant-1", {"trusted-agent"});
    CredentialRequest req;
    req.credential_id = "api-key-prod";
    req.caller_id = "untrusted-agent";
    req.tenant_id = "tenant-1";
    PolicyDecision d;
    std::string value = vault.get(req, d);
    EXPECT_EQ(d, PolicyDecision::REQUIRE_APPROVAL);
    // 空白通行证：返回虚拟替身数据
    EXPECT_NE(value.find("dummy"), std::string::npos);
    vault.remove("api-key-prod");
}
TEST(PolicyEngineTest, ApprovalManagerFlow) {
    auto& mgr = ApprovalManager::instance();
    std::string id = mgr.create_request("tool", "agent-1", "execute shell", "needs shell",
                                          std::chrono::minutes(5));
    EXPECT_FALSE(id.empty());
    EXPECT_FALSE(mgr.is_approved(id));
    EXPECT_TRUE(mgr.approve(id, "admin-1"));
    EXPECT_TRUE(mgr.is_approved(id));
}
// ==================== EvidenceRelease 测试 ====================
TEST(EvidenceReleaseTest, CollectorCollectsEvidence) {
    EvidenceCollector collector;
    collector.start("task-1", "tenant-1");
    FileDiff diff;
    diff.path = "/tmp/test.txt";
    diff.type = FileDiff::Type::ADDED;
    diff.new_hash = "abc123";
    collector.record_diff(diff);
    TestResult test;
    test.name = "test_example";
    test.passed = true;
    collector.record_test(test);
    collector.record_network("1.2.3.4", 443, "tcp");
    collector.record_tool_call("code_execution", "print(1)", true);
    Artifact artifact;
    artifact.path = "/tmp/output.txt";
    artifact.sha256 = std::string(64, 'a');  // 64 char hex
    collector.record_artifact(artifact);
    EvidencePackage pkg = collector.finish();
    EXPECT_EQ(pkg.task_id, "task-1");
    EXPECT_EQ(pkg.diffs.size(), 1u);
    EXPECT_EQ(pkg.test_results.size(), 1u);
    EXPECT_EQ(pkg.total_network_calls, 1u);
    EXPECT_EQ(pkg.total_tool_calls, 1u);
    EXPECT_FALSE(pkg.root_hash.empty());
}
TEST(EvidenceReleaseTest, ReleaseGateRejectsFailedTests) {
    EvidencePackage pkg;
    pkg.task_id = "task-1";
    TestResult test;
    test.name = "failed_test";
    test.passed = false;
    pkg.test_results.push_back(test);
    pkg.root_hash = "abc";
    auto result = ReleaseGate::instance().verify(pkg);
    EXPECT_EQ(result.decision, ReleaseDecision::REJECT);
    EXPECT_NE(result.reason.find("tests"), std::string::npos);
}
TEST(EvidenceReleaseTest, ReleaseGateReleasesCleanEvidence) {
    EvidencePackage pkg;
    pkg.task_id = "task-clean";
    TestResult test;
    test.name = "passed_test";
    test.passed = true;
    pkg.test_results.push_back(test);
    Artifact artifact;
    artifact.path = "/tmp/out.txt";
    artifact.sha256 = std::string(64, 'a');
    pkg.artifacts.push_back(artifact);
    pkg.root_hash = "abc123";
    auto result = ReleaseGate::instance().verify(pkg);
    EXPECT_EQ(result.decision, ReleaseDecision::RELEASE);
}
TEST(EvidenceReleaseTest, ReleaseGateRejectsSensitiveFileModification) {
    EvidencePackage pkg;
    pkg.task_id = "task-sensitive";
    TestResult test;
    test.passed = true;
    pkg.test_results.push_back(test);
    FileDiff diff;
    diff.path = "/etc/passwd";
    diff.type = FileDiff::Type::MODIFIED;
    diff.is_sensitive = true;
    pkg.diffs.push_back(diff);
    pkg.root_hash = "abc";
    auto result = ReleaseGate::instance().verify(pkg);
    // 敏感文件修改 → REJECT 或 REQUIRE_REVIEW
    EXPECT_NE(result.decision, ReleaseDecision::RELEASE);
}
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
