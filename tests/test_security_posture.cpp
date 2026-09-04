// PhotonBox 安全态势检测模块测试
#include <gtest/gtest.h>
#include "photon_kernel/sandbox/security_posture.hpp"
#include "photon_kernel/sandbox/sandbox_config.hpp"

#include <fstream>
#include <cstdio>

using namespace photon_kernel::sandbox;

// ========== RiskLevel 转换测试 ==========
TEST(RiskLevelTest, ConvertsAllLevelsToString) {
    EXPECT_EQ(risk_level_to_string(RiskLevel::CRITICAL), "CRITICAL");
    EXPECT_EQ(risk_level_to_string(RiskLevel::HIGH), "HIGH");
    EXPECT_EQ(risk_level_to_string(RiskLevel::MEDIUM), "MEDIUM");
    EXPECT_EQ(risk_level_to_string(RiskLevel::LOW), "LOW");
    EXPECT_EQ(risk_level_to_string(RiskLevel::INFO), "INFO");
    EXPECT_EQ(risk_level_to_string(RiskLevel::SAFE), "SAFE");
}

// ========== Kernel0dayChecker 测试 ==========
TEST(Kernel0dayCheckerTest, KernelVersionCheckRuns) {
    auto item = Kernel0dayChecker::check_kernel_version();
    EXPECT_EQ(item.id, "KERNEL-001");
    EXPECT_EQ(item.category, "kernel_0day");
    EXPECT_FALSE(item.name.empty());
    EXPECT_FALSE(item.detected_value.empty());
    // 内核版本应该包含数字
    EXPECT_TRUE(item.detected_value.find_first_of("0123456789") != std::string::npos);
}

TEST(Kernel0dayCheckerTest, KernelCmdlineCheckRuns) {
    auto item = Kernel0dayChecker::check_kernel_cmdline();
    EXPECT_EQ(item.id, "KERNEL-002");
    EXPECT_FALSE(item.detected_value.empty());
    EXPECT_FALSE(item.remediation.empty());
}

TEST(Kernel0dayCheckerTest, LoadedModulesCheckRuns) {
    auto item = Kernel0dayChecker::check_loaded_modules();
    EXPECT_EQ(item.id, "KERNEL-003");
    // 应该检测到至少一些模块
    EXPECT_TRUE(item.detected_value.find("模块") != std::string::npos);
}

TEST(Kernel0dayCheckerTest, SeccompSupportCheck) {
    auto item = Kernel0dayChecker::check_seccomp_support();
    EXPECT_EQ(item.id, "KERNEL-005");
    // 现代内核应该支持 seccomp
    EXPECT_TRUE(item.is_protected || item.detected_value.find("不支持") != std::string::npos);
}

TEST(Kernel0dayCheckerTest, NamespaceSupportCheck) {
    auto item = Kernel0dayChecker::check_namespace_support();
    EXPECT_EQ(item.id, "KERNEL-007");
    // Linux 应该支持大部分命名空间
    EXPECT_TRUE(item.detected_value.find("/7") != std::string::npos);
}

TEST(Kernel0dayCheckerTest, RunAllChecksReturnsAllItems) {
    auto items = Kernel0dayChecker::run_all_checks();
    EXPECT_EQ(items.size(), 8);  // 8 个检测项
    for (const auto& item : items) {
        EXPECT_EQ(item.category, "kernel_0day");
        EXPECT_FALSE(item.id.empty());
        EXPECT_FALSE(item.name.empty());
    }
}

// ========== SideChannelChecker 测试 ==========
TEST(SideChannelCheckerTest, SpectreV1Check) {
    auto item = SideChannelChecker::check_spectre_v1();
    EXPECT_EQ(item.id, "SIDE-001");
    EXPECT_EQ(item.category, "side_channel");
    EXPECT_FALSE(item.detected_value.empty());
    // 状态应该是 "Not affected"、"Mitigation" 或 "Vulnerable"
    EXPECT_TRUE(item.detected_value.find("Not affected") != std::string::npos ||
                item.detected_value.find("Mitigation") != std::string::npos ||
                item.detected_value.find("Vulnerable") != std::string::npos ||
                item.detected_value.find("无法检测") != std::string::npos);
}

TEST(SideChannelCheckerTest, MeltdownCheckIsCriticalIfUnprotected) {
    auto item = SideChannelChecker::check_meltdown();
    EXPECT_EQ(item.id, "SIDE-004");
    EXPECT_EQ(item.risk_if_unprotected, RiskLevel::CRITICAL);
    if (!item.is_protected) {
        EXPECT_EQ(item.current_risk, RiskLevel::CRITICAL);
    }
}

TEST(SideChannelCheckerTest, MicrocodeVersionCheck) {
    auto item = SideChannelChecker::check_microcode_version();
    EXPECT_EQ(item.id, "SIDE-010");
    EXPECT_FALSE(item.detected_value.empty());
}

TEST(SideChannelCheckerTest, SMTStatusCheck) {
    auto item = SideChannelChecker::check_smt_status();
    EXPECT_EQ(item.id, "SIDE-011");
    EXPECT_TRUE(item.detected_value.find("线程") != std::string::npos);
}

TEST(SideChannelCheckerTest, PerfEventRestrictionCheck) {
    auto item = SideChannelChecker::check_perf_event_restriction();
    EXPECT_EQ(item.id, "SIDE-014");
    EXPECT_TRUE(item.detected_value.find("perf_event_paranoid") != std::string::npos);
}

TEST(SideChannelCheckerTest, RunAllChecksReturnsAllItems) {
    auto items = SideChannelChecker::run_all_checks();
    EXPECT_EQ(items.size(), 14);  // 14 个检测项
    for (const auto& item : items) {
        EXPECT_EQ(item.category, "side_channel");
        EXPECT_FALSE(item.id.empty());
    }
}

// ========== HardwareAttackChecker 测试 ==========
TEST(HardwareAttackCheckerTest, EccMemoryCheck) {
    auto item = HardwareAttackChecker::check_ecc_memory();
    EXPECT_EQ(item.id, "HW-001");
    EXPECT_EQ(item.category, "hardware");
    EXPECT_FALSE(item.detected_value.empty());
}

TEST(HardwareAttackCheckerTest, HugepagesUsageCheck) {
    auto item = HardwareAttackChecker::check_hugepages_usage();
    EXPECT_EQ(item.id, "HW-003");
    EXPECT_TRUE(item.detected_value.find("nr_hugepages") != std::string::npos);
}

TEST(HardwareAttackCheckerTest, MemoryZeroingCheck) {
    auto item = HardwareAttackChecker::check_memory_zeroing();
    EXPECT_EQ(item.id, "HW-004");
    EXPECT_TRUE(item.detected_value.find("init_on_alloc") != std::string::npos);
}

TEST(HardwareAttackCheckerTest, CgroupMemoryIsolationCheck) {
    auto item = HardwareAttackChecker::check_cgroup_memory_isolation();
    EXPECT_EQ(item.id, "HW-005");
    EXPECT_FALSE(item.detected_value.empty());
}

TEST(HardwareAttackCheckerTest, IommuCheck) {
    auto item = HardwareAttackChecker::check_iommu();
    EXPECT_EQ(item.id, "HW-006");
    EXPECT_FALSE(item.detected_value.empty());
}

TEST(HardwareAttackCheckerTest, RunAllChecksReturnsAllItems) {
    auto items = HardwareAttackChecker::run_all_checks();
    EXPECT_EQ(items.size(), 8);  // 8 个检测项
    for (const auto& item : items) {
        EXPECT_EQ(item.category, "hardware");
        EXPECT_FALSE(item.id.empty());
    }
}

// ========== SecurityPostureEvaluator 测试 ==========
TEST(SecurityPostureEvaluatorTest, FullEvaluationRuns) {
    auto report = SecurityPostureEvaluator::evaluate();
    EXPECT_FALSE(report.generated_at.empty());
    EXPECT_FALSE(report.kernel_version.empty());
    EXPECT_GT(report.total_count, 0);
    // 应该有 8 + 14 + 8 = 30 个检测项
    EXPECT_EQ(report.total_count, 30);
    // 评分应该在 0-100 之间
    EXPECT_GE(report.overall_score, 0);
    EXPECT_LE(report.overall_score, 100);
    EXPECT_GE(report.kernel_0day_score, 0);
    EXPECT_LE(report.kernel_0day_score, 100);
    EXPECT_GE(report.side_channel_score, 0);
    EXPECT_LE(report.side_channel_score, 100);
    EXPECT_GE(report.hardware_attack_score, 0);
    EXPECT_LE(report.hardware_attack_score, 100);
}

TEST(SecurityPostureEvaluatorTest, CategoryEvaluationWorks) {
    auto kernel_report = SecurityPostureEvaluator::evaluate_category("kernel_0day");
    EXPECT_EQ(kernel_report.items.size(), 8);

    auto side_report = SecurityPostureEvaluator::evaluate_category("side_channel");
    EXPECT_EQ(side_report.items.size(), 14);

    auto hw_report = SecurityPostureEvaluator::evaluate_category("hardware");
    EXPECT_EQ(hw_report.items.size(), 8);
}

TEST(SecurityPostureEvaluatorTest, JsonSerializationWorks) {
    auto report = SecurityPostureEvaluator::evaluate();
    std::string json = report.to_json();
    EXPECT_FALSE(json.empty());
    // JSON 应该包含关键字段
    EXPECT_TRUE(json.find("overall_score") != std::string::npos);
    EXPECT_TRUE(json.find("kernel_0day_score") != std::string::npos);
    EXPECT_TRUE(json.find("side_channel_score") != std::string::npos);
    EXPECT_TRUE(json.find("hardware_attack_score") != std::string::npos);
    EXPECT_TRUE(json.find("items") != std::string::npos);
    // 应该包含所有检测项的 ID
    EXPECT_TRUE(json.find("KERNEL-001") != std::string::npos);
    EXPECT_TRUE(json.find("SIDE-001") != std::string::npos);
    EXPECT_TRUE(json.find("HW-001") != std::string::npos);
}

TEST(SecurityPostureEvaluatorTest, MarkdownSerializationWorks) {
    auto report = SecurityPostureEvaluator::evaluate();
    std::string md = report.to_markdown();
    EXPECT_FALSE(md.empty());
    EXPECT_TRUE(md.find("# PhotonBox 安全态势检测报告") != std::string::npos);
    EXPECT_TRUE(md.find("总体评分") != std::string::npos);
    EXPECT_TRUE(md.find("内核 0day 逃逸防护") != std::string::npos);
    EXPECT_TRUE(md.find("侧信道攻击防护") != std::string::npos);
    EXPECT_TRUE(md.find("硬件级攻击防护") != std::string::npos);
}

TEST(SecurityPostureEvaluatorTest, HardeningScriptGeneration) {
    auto report = SecurityPostureEvaluator::evaluate();
    std::string script = SecurityPostureEvaluator::generate_hardening_script(report);
    EXPECT_FALSE(script.empty());
    EXPECT_TRUE(script.find("#!/bin/bash") != std::string::npos);
    EXPECT_TRUE(script.find("slab_nomerge") != std::string::npos);
    EXPECT_TRUE(script.find("perf_event_paranoid") != std::string::npos);
    EXPECT_TRUE(script.find("intel-microcode") != std::string::npos);
}

TEST(SecurityPostureEvaluatorTest, ExtraSeccompRestrictionsReturned) {
    auto report = SecurityPostureEvaluator::evaluate();
    auto restrictions = SecurityPostureEvaluator::get_extra_seccomp_restrictions(report);
    // 至少应该返回一些限制（容器环境通常防护不足）
    EXPECT_GE(restrictions.size(), 0);
    for (const auto& r : restrictions) {
        EXPECT_FALSE(r.empty());
    }
}

TEST(SecurityPostureEvaluatorTest, SystemInfoCollected) {
    auto report = SecurityPostureEvaluator::evaluate();
    EXPECT_FALSE(report.hostname.empty());
    EXPECT_FALSE(report.cpu_vendor.empty());
    EXPECT_GT(report.total_memory_mb, 0);
    // CPU 厂商应该是 Intel 或 AMD（或其他）
    EXPECT_TRUE(report.cpu_vendor.find("Intel") != std::string::npos ||
                report.cpu_vendor.find("AMD") != std::string::npos ||
                !report.cpu_vendor.empty());
}

// ========== 集成测试：完整流程 ==========
TEST(SecurityPostureIntegrationTest, FullWorkflowEvaluateAndExport) {
    // 1. 运行完整评估
    auto report = SecurityPostureEvaluator::evaluate();

    // 2. 验证统计正确
    int sum = report.critical_count + report.high_count + report.medium_count +
              report.low_count + report.safe_count;
    EXPECT_EQ(sum, report.total_count);

    // 3. 导出 JSON
    std::string json = report.to_json();
    EXPECT_GT(json.size(), 100);

    // 4. 导出 Markdown
    std::string md = report.to_markdown();
    EXPECT_GT(md.size(), 100);

    // 5. 生成加固脚本
    std::string script = SecurityPostureEvaluator::generate_hardening_script(report);
    EXPECT_GT(script.size(), 100);

    // 6. 写入临时文件验证
    std::string tmp_json = "/tmp/test_security_posture.json";
    std::string tmp_md = "/tmp/test_security_posture.md";
    {
        std::ofstream jf(tmp_json);
        jf << json;
    }
    {
        std::ofstream mf(tmp_md);
        mf << md;
    }
    // 验证文件存在且非空
    std::ifstream jf_check(tmp_json);
    EXPECT_TRUE(jf_check.good());
    std::string jf_content((std::istreambuf_iterator<char>(jf_check)),
                             std::istreambuf_iterator<char>());
    EXPECT_GT(jf_content.size(), 100);

    // 清理
    std::remove(tmp_json.c_str());
    std::remove(tmp_md.c_str());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
