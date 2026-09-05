// PhotonBox 运行时入侵检测引擎 - 单元测试
#include <gtest/gtest.h>
#include "photon_kernel/sandbox/intrusion_detection.hpp"

using namespace photon_kernel::sandbox;

class IntrusionDetectionTest : public ::testing::Test {
protected:
    void SetUp() override {
        DetectionConfig config;
        config.syscall_rate_threshold = 100;
        config.fork_rate_threshold = 10;
        config.fd_warning_threshold = 50;
        engine_ = std::make_unique<IntrusionDetectionEngine>(config);
    }

    std::unique_ptr<IntrusionDetectionEngine> engine_;
};

// ========== 基础功能测试 ==========

TEST_F(IntrusionDetectionTest, EngineCreation) {
    EXPECT_NE(engine_, nullptr);
    auto names = engine_->GetRuleNames();
    EXPECT_EQ(names.size(), 5);  // 5条默认规则
}

TEST_F(IntrusionDetectionTest, ConfigUpdate) {
    DetectionConfig new_config;
    new_config.syscall_rate_threshold = 999;
    engine_->UpdateConfig(new_config);
    EXPECT_EQ(engine_->GetConfig().syscall_rate_threshold, 999);
}

TEST_F(IntrusionDetectionTest, RuleEnableDisable) {
    engine_->EnableRule(DetectionRuleType::SYSCALL_FREQUENCY, false);
    // 禁用后不应该产生告警
    ProcessStats stats;
    stats.pid = 1234;
    stats.comm = "test";
    stats.syscall_count = 100000;
    engine_->UpdateProcessStats(stats);
    auto alerts = engine_->RunDetectionCycle();
    // 可能有其他规则触发，但 syscall_frequency 不应该
    bool has_syscall_freq = false;
    for (const auto& a : alerts) {
        if (a.rule_type == DetectionRuleType::SYSCALL_FREQUENCY) {
            has_syscall_freq = true;
        }
    }
    EXPECT_FALSE(has_syscall_freq);
}

// ========== 规则1：系统调用频率异常 ==========

TEST_F(IntrusionDetectionTest, SyscallFrequencyNormal) {
    ProcessStats stats;
    stats.pid = 100;
    stats.comm = "normal_proc";
    stats.syscall_count = 50;  // 低于阈值
    engine_->UpdateProcessStats(stats);
    auto alerts = engine_->RunDetectionCycle();
    EXPECT_EQ(alerts.size(), 0);
}

TEST_F(IntrusionDetectionTest, SyscallFrequencyAbnormal) {
    ProcessStats baseline;
    baseline.syscall_count = 10;
    engine_->SetBaseline(baseline);

    ProcessStats stats;
    stats.pid = 101;
    stats.comm = "suspicious";
    stats.syscall_count = 500;  // 远超阈值和基线
    engine_->UpdateProcessStats(stats);
    auto alerts = engine_->RunDetectionCycle();

    bool found = false;
    for (const auto& a : alerts) {
        if (a.rule_type == DetectionRuleType::SYSCALL_FREQUENCY) {
            found = true;
            EXPECT_GE(a.confidence, 0.0);
            EXPECT_LE(a.confidence, 1.0);
        }
    }
    EXPECT_TRUE(found);
}

// ========== 规则2：罕见系统调用 ==========

TEST_F(IntrusionDetectionTest, RareSyscallDetection) {
    engine_->ReportSyscall("ptrace", 200);
    auto alerts = engine_->RunDetectionCycle();

    bool found = false;
    for (const auto& a : alerts) {
        if (a.rule_type == DetectionRuleType::SYSCALL_RARE) {
            found = true;
            EXPECT_EQ(a.severity, AlertSeverity::HIGH);
            EXPECT_GT(a.confidence, 0.8);
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(IntrusionDetectionTest, CommonSyscallNoAlert) {
    engine_->ReportSyscall("read", 201);
    engine_->ReportSyscall("write", 201);
    engine_->ReportSyscall("openat", 201);
    auto alerts = engine_->RunDetectionCycle();
    bool found = false;
    for (const auto& a : alerts) {
        if (a.rule_type == DetectionRuleType::SYSCALL_RARE) found = true;
    }
    EXPECT_FALSE(found);
}

// ========== 规则3：fork 炸弹 ==========

TEST_F(IntrusionDetectionTest, ForkBombDetection) {
    ProcessStats stats;
    stats.pid = 300;
    stats.comm = "fork_bomb";
    stats.fork_count = 500;  // 远超阈值
    engine_->UpdateProcessStats(stats);
    auto alerts = engine_->RunDetectionCycle();

    bool found = false;
    for (const auto& a : alerts) {
        if (a.rule_type == DetectionRuleType::PROCESS_FORK_BOMB) {
            found = true;
            EXPECT_EQ(a.severity, AlertSeverity::CRITICAL);
            EXPECT_GT(a.confidence, 0.9);
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(IntrusionDetectionTest, NormalForkNoAlert) {
    ProcessStats stats;
    stats.pid = 301;
    stats.comm = "normal";
    stats.fork_count = 5;  // 正常范围
    engine_->UpdateProcessStats(stats);
    auto alerts = engine_->RunDetectionCycle();
    bool found = false;
    for (const auto& a : alerts) {
        if (a.rule_type == DetectionRuleType::PROCESS_FORK_BOMB) found = true;
    }
    EXPECT_FALSE(found);
}

// ========== 规则4：敏感路径访问 ==========

TEST_F(IntrusionDetectionTest, SensitivePathDetection) {
    engine_->ReportFileAccess("/etc/shadow", 400);
    auto alerts = engine_->RunDetectionCycle();

    bool found = false;
    for (const auto& a : alerts) {
        if (a.rule_type == DetectionRuleType::FILE_SENSITIVE_PATH) {
            found = true;
            EXPECT_EQ(a.severity, AlertSeverity::HIGH);
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(IntrusionDetectionTest, SensitivePathRootDirectory) {
    engine_->ReportFileAccess("/root/.ssh/id_rsa", 401);
    auto alerts = engine_->RunDetectionCycle();
    bool found = false;
    for (const auto& a : alerts) {
        if (a.rule_type == DetectionRuleType::FILE_SENSITIVE_PATH) found = true;
    }
    EXPECT_TRUE(found);
}

TEST_F(IntrusionDetectionTest, NormalPathNoAlert) {
    engine_->ReportFileAccess("/tmp/normal_file.txt", 402);
    engine_->ReportFileAccess("/home/user/doc.txt", 402);
    auto alerts = engine_->RunDetectionCycle();
    bool found = false;
    for (const auto& a : alerts) {
        if (a.rule_type == DetectionRuleType::FILE_SENSITIVE_PATH) found = true;
    }
    EXPECT_FALSE(found);
}

// ========== 规则5：FD 泄漏 ==========

TEST_F(IntrusionDetectionTest, FdLeakDetection) {
    ProcessStats stats;
    stats.pid = 500;
    stats.comm = "fd_leak";
    stats.fd_count = 900;  // 超过阈值
    engine_->UpdateProcessStats(stats);
    auto alerts = engine_->RunDetectionCycle();

    bool found = false;
    for (const auto& a : alerts) {
        if (a.rule_type == DetectionRuleType::RESOURCE_FD_LEAK) {
            found = true;
            EXPECT_GE(a.severity, AlertSeverity::MEDIUM);
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(IntrusionDetectionTest, NormalFdNoAlert) {
    ProcessStats stats;
    stats.pid = 501;
    stats.comm = "normal";
    stats.fd_count = 10;
    engine_->UpdateProcessStats(stats);
    auto alerts = engine_->RunDetectionCycle();
    bool found = false;
    for (const auto& a : alerts) {
        if (a.rule_type == DetectionRuleType::RESOURCE_FD_LEAK) found = true;
    }
    EXPECT_FALSE(found);
}

// ========== 告警管理测试 ==========

TEST_F(IntrusionDetectionTest, AlertAcknowledgement) {
    engine_->ReportSyscall("ptrace", 600);
    engine_->RunDetectionCycle();

    auto unacked = engine_->GetUnacknowledgedAlerts();
    EXPECT_GT(unacked.size(), 0);

    uint64_t first_id = unacked[0].id;
    engine_->AcknowledgeAlert(first_id);

    auto unacked2 = engine_->GetUnacknowledgedAlerts();
    for (const auto& a : unacked2) {
        EXPECT_NE(a.id, first_id);
    }
}

TEST_F(IntrusionDetectionTest, AlertFilterBySeverity) {
    // 触发不同严重程度的告警
    ProcessStats stats1;
    stats1.pid = 700;
    stats1.comm = "critical";
    stats1.fork_count = 500;  // CRITICAL
    engine_->UpdateProcessStats(stats1);

    ProcessStats stats2;
    stats2.pid = 701;
    stats2.comm = "high";
    stats2.fd_count = 950;  // HIGH
    engine_->UpdateProcessStats(stats2);

    engine_->RunDetectionCycle();

    auto critical_alerts = engine_->GetAlerts(AlertSeverity::CRITICAL);
    auto high_alerts = engine_->GetAlerts(AlertSeverity::HIGH);
    auto all_alerts = engine_->GetAlerts(AlertSeverity::INFO);

    EXPECT_GE(all_alerts.size(), high_alerts.size());
    EXPECT_GE(high_alerts.size(), critical_alerts.size());
}

TEST_F(IntrusionDetectionTest, AlertStats) {
    engine_->ReportSyscall("ptrace", 800);
    engine_->ReportSyscall("kexec_load", 800);
    engine_->RunDetectionCycle();

    EXPECT_GT(engine_->GetTotalAlerts(), 0);
    auto counts = engine_->GetAlertCountsByRule();
    EXPECT_GT(counts.size(), 0);
    EXPECT_GT(counts["rare_syscall"], 0);
}

// ========== 基线管理测试 ==========

TEST_F(IntrusionDetectionTest, BaselineManagement) {
    ProcessStats baseline;
    baseline.pid = 999;
    baseline.comm = "baseline";
    baseline.syscall_count = 100;
    engine_->SetBaseline(baseline);

    auto retrieved = engine_->GetBaseline();
    EXPECT_EQ(retrieved.syscall_count, 100);

    engine_->ResetBaseline();
    auto reset = engine_->GetBaseline();
    EXPECT_EQ(reset.syscall_count, 0);
}

// ========== 多进程检测测试 ==========

TEST_F(IntrusionDetectionTest, MultipleProcesses) {
    for (int i = 0; i < 5; i++) {
        ProcessStats stats;
        stats.pid = 1000 + i;
        stats.comm = "proc_" + std::to_string(i);
        stats.fork_count = 200;  // 每个都触发 fork 炸弹
        engine_->UpdateProcessStats(stats);
    }
    auto alerts = engine_->RunDetectionCycle();
    EXPECT_GE(alerts.size(), 5);  // 每个进程至少一个告警
}

// ========== 告警结构测试 ==========

TEST_F(IntrusionDetectionTest, AlertStructure) {
    engine_->ReportSyscall("ptrace", 1100);
    auto alerts = engine_->RunDetectionCycle();
    ASSERT_GT(alerts.size(), 0);

    const auto& alert = alerts[0];
    EXPECT_GT(alert.id, 0);
    EXPECT_FALSE(alert.timestamp.empty());
    EXPECT_FALSE(alert.description.empty());
    EXPECT_GE(alert.confidence, 0.0);
    EXPECT_LE(alert.confidence, 1.0);
    EXPECT_FALSE(alert.remediation.empty());
}

// ========== 自定义规则测试 ==========

class CustomTestRule : public IDetectionRule {
public:
    DetectionRuleType GetType() const override { return DetectionRuleType::SYSCALL_FREQUENCY; }
    std::string GetName() const override { return "custom_test_rule"; }
    bool IsEnabled() const override { return enabled; }
    void SetEnabled(bool e) override { enabled = e; }
    std::optional<IntrusionAlert> Evaluate(
        const ProcessStats& stats,
        const ProcessStats& baseline,
        const DetectionConfig& config
    ) override {
        (void)baseline; (void)config;
        if (stats.comm == "trigger_custom") {
            IntrusionAlert alert;
            alert.severity = AlertSeverity::MEDIUM;
            alert.description = "自定义规则触发";
            alert.confidence = 0.5;
            return alert;
        }
        return std::nullopt;
    }
    bool enabled = true;
};

TEST_F(IntrusionDetectionTest, CustomRuleRegistration) {
    auto custom_rule = std::make_unique<CustomTestRule>();
    engine_->RegisterRule(std::move(custom_rule));

    auto names = engine_->GetRuleNames();
    bool found = false;
    for (const auto& n : names) {
        if (n == "custom_test_rule") found = true;
    }
    EXPECT_TRUE(found);

    ProcessStats stats;
    stats.pid = 1200;
    stats.comm = "trigger_custom";
    engine_->UpdateProcessStats(stats);
    auto alerts = engine_->RunDetectionCycle();

    bool custom_found = false;
    for (const auto& a : alerts) {
        if (a.description == "自定义规则触发") custom_found = true;
    }
    EXPECT_TRUE(custom_found);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
