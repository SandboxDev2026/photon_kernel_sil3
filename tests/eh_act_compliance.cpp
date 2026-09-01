#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "photon_kernel/act/act_defs.hpp"
#include "photon_kernel/act/act_risk_grade.hpp"
#include "photon_kernel/act/act_output_limiter.hpp"
#include "photon_kernel/act/act_circuit_breaker.hpp"
#include "photon_kernel/act/act_self_diagnosis.hpp"
#include "photon_kernel/act/act_governance.hpp"
#include "photon_kernel/act/act_lifecycle.hpp"
#include "photon_kernel/act/act_penalty.hpp"
#include "photon_kernel/act/act_compliance.hpp"
#include "photon_kernel/act/act_audit_events.hpp"
#include "photon_kernel/sandbox/audit_logger.hpp"

using namespace photon_kernel::act;

// ---- 法案条款常量 ----
TEST(ActDefsTest, All22ArticlesPresent) {
    for (int n = 1; n <= 22; ++n) {
        ActArticle a = act_article(n);
        EXPECT_EQ(a.id, n);
        EXPECT_NE(a.title, nullptr);
        EXPECT_NE(a.requirement, nullptr);
    }
    EXPECT_EQ(act_article(0).id, 0);
    EXPECT_EQ(act_article(23).id, 0);
}

// ---- 第七条 风险分级 ----
TEST(ActRiskGradeTest, GradeByImpact) {
    EXPECT_EQ(grade_by_impact(OutputImpact::INFORMATION_ONLY), ActRiskGrade::LOW);
    EXPECT_EQ(grade_by_impact(OutputImpact::ASSISTED_DECISION), ActRiskGrade::MEDIUM);
    EXPECT_EQ(grade_by_impact(OutputImpact::PHYSICAL_EXECUTOR), ActRiskGrade::HIGH);
}

TEST(ActRiskGradeTest, RegisterConfirmAndChange) {
    RiskRegister reg;
    reg.self_assess(OutputImpact::PHYSICAL_EXECUTOR);
    EXPECT_EQ(reg.current_grade(), ActRiskGrade::HIGH);
    EXPECT_FALSE(reg.self_check_pass());  // 未委员会确认前不通过

    reg.committee_confirm(ActRiskGrade::HIGH, "SC-2026-01");
    EXPECT_TRUE(reg.is_confirmed());
    EXPECT_TRUE(reg.self_check_pass());

    reg.change_grade(ActRiskGrade::MEDIUM, "scope reduced");
    EXPECT_EQ(reg.current_grade(), ActRiskGrade::MEDIUM);
    EXPECT_GE(reg.change_count(), 1u);
}

// ---- 第八条 豁免 ----
TEST(ActRiskGradeTest, Exemption) {
    RiskRegister reg;
    reg.apply_exemption(ExemptionReason::PURE_RESEARCH, "lab-a");
    EXPECT_TRUE(reg.is_exempt());
    EXPECT_TRUE(reg.self_check_pass());  // 豁免视为合规
}

// ---- 第十二条 输出限幅 ----
TEST(OutputLimiterTest, ClampToBounds) {
    OutputLimiter lim;
    lim.set_bounds(-10.0, 10.0);
    bool trig = false;
    EXPECT_DOUBLE_EQ(lim.apply(5.0, &trig), 5.0);
    EXPECT_FALSE(trig);
    EXPECT_DOUBLE_EQ(lim.apply(99.0, &trig), 10.0);
    EXPECT_TRUE(trig);
    EXPECT_DOUBLE_EQ(lim.apply(-99.0, &trig), -10.0);
    EXPECT_TRUE(trig);
    EXPECT_EQ(lim.trigger_count(), 2u);
}

TEST(OutputLimiterTest, SelfCheckRequiresVerified) {
    OutputLimiter lim;
    lim.set_bounds(0.0, 1.0);
    EXPECT_FALSE(lim.self_check_pass());  // 边界已备案但未实测
    lim.mark_verified_in_test();
    EXPECT_TRUE(lim.self_check_pass());
}

// ---- 第十三条 逻辑熔断 ----
TEST(CircuitBreakerTest, DynamicBaselineAndReject) {
    CircuitBreaker br({BreakerLimits{100.0, 0.50, 0.90}});
    // 正常指标：基线随样本平滑，不熔断
    for (int i = 0; i < 10; ++i) {
        br.record_latency(20.0);
        br.record_error(false);
        br.record_resource(0.3);
    }
    EXPECT_EQ(br.check_accept(), BreakerError::OK);
    EXPECT_EQ(br.state(), BreakerState::CLOSED);

    // 延迟超绝对硬限制 -> 熔断拒绝，返回明确错误码
    for (int i = 0; i < 10; ++i) {
        br.record_latency(5000.0);
    }
    EXPECT_EQ(br.check_accept(), BreakerError::REJECTED_HIGH_LATENCY);
    EXPECT_EQ(br.state(), BreakerState::OPEN);
}

TEST(CircuitBreakerTest, RejectOnErrorRate) {
    CircuitBreaker br({BreakerLimits{1000.0, 0.20, 0.90}});
    for (int i = 0; i < 10; ++i) {
        br.record_error(true);
    }
    EXPECT_EQ(br.check_accept(), BreakerError::REJECTED_HIGH_ERROR_RATE);
    EXPECT_EQ(br.state(), BreakerState::OPEN);
}

TEST(CircuitBreakerTest, RejectOnResourceWatermark) {
    CircuitBreaker br({BreakerLimits{1000.0, 0.50, 0.80}});
    for (int i = 0; i < 10; ++i) {
        br.record_resource(0.99);
    }
    EXPECT_EQ(br.check_accept(), BreakerError::REJECTED_HIGH_RESOURCE);
    EXPECT_EQ(br.state(), BreakerState::OPEN);
}

// ---- 第十四条 硬件自诊断 ----
TEST(SelfDiagnosisTest, SensorFaultDetected) {
    HardwareSelfDiagnosis diag;
    diag.register_sensor("motor_current", true, "1.2A");
    diag.register_sensor("brake_pressure", true, "8.0bar");
    auto r = diag.pre_inference_check();
    EXPECT_TRUE(r.ok);

    diag.set_sensor_status("brake_pressure", false, "0.1bar");
    r = diag.pre_inference_check();
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.message.find("brake_pressure"), std::string::npos);
}

TEST(SelfDiagnosisTest, ContainerResourceCheck) {
    HardwareSelfDiagnosis diag;
    // 本机为容器/裸机都安全返回；无 cgroup 时 container_checked=false 不误报
    auto r = diag.check_container_resources();
    EXPECT_GE(r.memory_watermark, 0.0);
    EXPECT_LE(r.memory_watermark, 1.0);
}

// ---- 第四~六条 治理 ----
TEST(GovernanceTest, ResponsibleRoles) {
    ActGovernance gov;
    EXPECT_FALSE(gov.self_check_pass());  // 未登记齐
    gov.assign(ResponsibleRole::DEVELOPER, "alice");
    gov.assign(ResponsibleRole::SAFETY_OFFICER, "bob");
    gov.assign(ResponsibleRole::DEPLOYER, "carol");
    gov.assign(ResponsibleRole::COMPLIANCE_AUDITOR, "dave");
    EXPECT_TRUE(gov.self_check_pass());
    EXPECT_EQ(gov.role_holders(ResponsibleRole::DEVELOPER).size(), 1u);
}

TEST(GovernanceTest, CommitteeAndAppeal) {
    ActGovernance gov;
    gov.add_committee_member("a", "safety");
    gov.add_committee_member("b", "tech");
    gov.add_committee_member("c", "legal");
    EXPECT_TRUE(gov.committee_quorum(3));

    EXPECT_TRUE(gov.submit_appeal("party-x", "decision-1"));
    EXPECT_TRUE(gov.is_appeal_pending());
    EXPECT_TRUE(gov.conclude_review("overturned"));
    EXPECT_TRUE(gov.review_concluded());
    EXPECT_FALSE(gov.is_appeal_pending());
}

// ---- 第九~十一条 研发阶段 ----
TEST(LifecycleTest, RequirementStage) {
    ActLifecycleChecklist lc;
    EXPECT_FALSE(lc.stage_complete(LifecycleStage::REQUIREMENT));
    EXPECT_TRUE(lc.complete(LifecycleStage::REQUIREMENT, "风险等级自评", "SR-2026-01"));
    EXPECT_TRUE(lc.complete(LifecycleStage::REQUIREMENT,
                            "安全需求规格文档（含数据来源合法性声明）", "SRS-2026"));
    EXPECT_TRUE(lc.complete(LifecycleStage::REQUIREMENT, "第三方依赖合规审查", "DPA-2026"));
    EXPECT_TRUE(lc.stage_complete(LifecycleStage::REQUIREMENT));
    EXPECT_EQ(lc.items_of(LifecycleStage::REQUIREMENT).size(), 3u);
}

// ---- 第十九条 违规认定 ----
TEST(PenaltyTest, PenaltyMapping) {
    EXPECT_EQ(penalty_for(Violation::AUDIT_LOG_FORGED).escalate, true);
    EXPECT_EQ(penalty_for(Violation::OUTPUT_LIMITER_MISSING).deadline, std::string("30天"));
    EXPECT_EQ(penalty_for(Violation::LOGIC_BREAKER_MISSING).deadline, std::string("30天"));
    EXPECT_EQ(penalty_for(Violation::HARDWARE_SELFDIAG_MISSING).deadline, std::string("30天"));
}

TEST(PenaltyTest, IssueAndAppeal) {
    ActPenalty p;
    auto d = p.issue(Violation::OUTPUT_LIMITER_MISSING, "limiter not configured");
    EXPECT_EQ(d.article, 19);
    EXPECT_FALSE(d.appealed);
    EXPECT_TRUE(p.self_check_pass());  // 非永久性违规
    p.issue(Violation::AUDIT_LOG_FORGED, "log tampered");
    EXPECT_FALSE(p.self_check_pass());  // 审计造假 → 严重违规
}

// ---- 第十五条 审计事件 ----
TEST(AuditEventsTest, SixEventTypesRecorded) {
    const std::string path = "/tmp/photon_act_audit.jsonl";
    std::remove(path.c_str());
    auto& logger = photon_kernel::sandbox::AuditLogger::instance();
    logger.init(path, /*mirror_stderr=*/false);
    logger.set_sanitize(true);

    ActAuditRecorder rec;
    rec.record_inference("t-1", "sha256:deadbeef");
    rec.record(AuditEventType::LIMITER_TRIGGERED, "clamped", "\"raw\":999,\"clamped\":10");
    rec.record(AuditEventType::BREAKER_STATE_CHANGE, "CLOSED -> OPEN");
    rec.record(AuditEventType::PERMISSION_OR_MODEL_CHANGE, "model v2 -> v3");
    rec.record_manual_override("operator-x", "emergency stop");
    rec.record(AuditEventType::EXECUTOR_FEEDBACK_THRESHOLD, "sensor fault: brake");

    // 6 类事件全部落盘
    std::ifstream f(path);
    std::string content((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("\"inference_request\""), std::string::npos);
    EXPECT_NE(content.find("\"limiter_triggered\""), std::string::npos);
    EXPECT_NE(content.find("\"breaker_state_change\""), std::string::npos);
    EXPECT_NE(content.find("\"permission_or_model_change\""), std::string::npos);
    EXPECT_NE(content.find("\"manual_override\""), std::string::npos);
    EXPECT_NE(content.find("\"executor_feedback_threshold\""), std::string::npos);
    std::remove(path.c_str());
}

// ---- 合规引擎：完整配置场景全条款 PASS ----
static ActComplianceEngine build_compliant_engine() {
    // 静态对象：生命周期贯穿测试
    static RiskRegister risk;
    static OutputLimiter lim;
    static CircuitBreaker br;
    static HardwareSelfDiagnosis diag;
    static ActGovernance gov;
    static ActLifecycleChecklist lc;
    static ActPenalty pen;

    risk.self_assess(OutputImpact::PHYSICAL_EXECUTOR);   // HIGH
    risk.committee_confirm(ActRiskGrade::HIGH, "SC-2026-01");

    lim.set_bounds(-1.0, 1.0);
    lim.mark_verified_in_test();

    br.set_limits(BreakerLimits{1000.0, 0.50, 0.90});
    br.mark_verified_in_test();

    diag.register_sensor("motor", true, "1.2A");
    diag.mark_verified_in_test();

    gov.assign(ResponsibleRole::DEVELOPER, "alice");
    gov.assign(ResponsibleRole::SAFETY_OFFICER, "bob");
    gov.assign(ResponsibleRole::DEPLOYER, "carol");
    gov.assign(ResponsibleRole::COMPLIANCE_AUDITOR, "dave");
    gov.add_committee_member("a", "safety");
    gov.add_committee_member("b", "tech");
    gov.add_committee_member("c", "legal");

    lc.complete(LifecycleStage::REQUIREMENT, "风险等级自评", "SR-1");
    lc.complete(LifecycleStage::REQUIREMENT, "安全需求规格文档（含数据来源合法性声明）", "SRS-1");
    lc.complete(LifecycleStage::REQUIREMENT, "第三方依赖合规审查", "DPA-1");
    lc.complete(LifecycleStage::DEVELOPMENT, "代码提交记录完整可追溯", "git-1");
    lc.complete(LifecycleStage::DEVELOPMENT, "核心模块静态分析与单元测试", "tests-1");
    lc.complete(LifecycleStage::DEVELOPMENT, "数据脱敏与权限控制", "san-1");
    lc.complete(LifecycleStage::DEVELOPMENT, "接口输入输出边界与异常处理", "api-1");
    lc.complete(LifecycleStage::TESTING, "正常/边界/异常路径用例", "t-1");
    lc.complete(LifecycleStage::TESTING, "输出限幅机制实测", "lim-test");
    lc.complete(LifecycleStage::TESTING, "高风险红队测试/沙盒推演", "redteam");

    ActComplianceEngine engine;
    engine.attach(&risk, &lim, &br, &diag, &gov, &lc, &pen);
    return engine;
}

TEST(ComplianceEngineTest, FullConfigAllCompliant) {
    auto engine = build_compliant_engine();
    auto items = engine.self_check();
    ASSERT_EQ(items.size(), 22u);
    for (const auto& it : items) {
        EXPECT_NE(it.status, ComplianceStatus::FAIL)
            << "article " << it.article << " (" << it.title << ") failed";
    }
    EXPECT_TRUE(engine.all_compliant());
    // N/A 仅允许豁免（第 8 条）
    int na_count = 0;
    for (const auto& it : items) if (it.status == ComplianceStatus::NA) ++na_count;
    EXPECT_LE(na_count, 1);
}

TEST(ComplianceEngineTest, ReportContains22Articles) {
    auto engine = build_compliant_engine();
    std::string report = engine.generate_report();
    // 粗略统计 "id": 出现 22 次
    size_t count = 0, pos = 0;
    while ((pos = report.find("\"id\":", pos)) != std::string::npos) {
        ++count; pos += 5;
    }
    EXPECT_EQ(count, 22u);
}

TEST(ComplianceEngineTest, MissingLimiterFailsArticle12) {
    static RiskRegister risk;
    static OutputLimiter lim;  // 未 set_bounds / 未实测
    static CircuitBreaker br;
    static HardwareSelfDiagnosis diag;
    static ActGovernance gov;
    static ActLifecycleChecklist lc;
    static ActPenalty pen;

    risk.self_assess(OutputImpact::ASSISTED_DECISION);  // MEDIUM
    risk.committee_confirm(ActRiskGrade::MEDIUM, "SC-2");
    br.set_limits(BreakerLimits{1000, 0.5, 0.9});
    br.mark_verified_in_test();
    diag.register_sensor("x", true, "0");  // 未 mark_verified -> 第14条对 MEDIUM 为 NA
    gov.assign(ResponsibleRole::DEVELOPER, "a");
    gov.assign(ResponsibleRole::SAFETY_OFFICER, "b");
    gov.assign(ResponsibleRole::DEPLOYER, "c");
    gov.assign(ResponsibleRole::COMPLIANCE_AUDITOR, "d");
    gov.add_committee_member("x", "s");
    gov.add_committee_member("y", "t");
    gov.add_committee_member("z", "l");
    for (int i = 0; i < 4; ++i) {
        lc.complete(LifecycleStage::DEVELOPMENT,
                    i == 0 ? "代码提交记录完整可追溯" :
                    i == 1 ? "核心模块静态分析与单元测试" :
                    i == 2 ? "数据脱敏与权限控制" : "接口输入输出边界与异常处理", "1");
    }
    for (int i = 0; i < 3; ++i) {
        lc.complete(LifecycleStage::TESTING,
                    i == 0 ? "正常/边界/异常路径用例" :
                    i == 1 ? "输出限幅机制实测" : "高风险红队测试/沙盒推演", "1");
    }

    ActComplianceEngine engine;
    engine.attach(&risk, &lim, &br, &diag, &gov, &lc, &pen);
    EXPECT_FALSE(engine.all_compliant());

    // 第 12 条（输出限幅）为 FAIL；第 14 条（高风险自诊断）此时为 NA（MEDIUM）
    ComplianceItem a12 = engine.check_article(12);
    EXPECT_EQ(a12.status, ComplianceStatus::FAIL);
    ComplianceItem a14 = engine.check_article(14);
    EXPECT_EQ(a14.status, ComplianceStatus::NA);
}

// ---- 可追溯性证据链（V4.14 第十六条，补强 4） ----
TEST(EvidenceLoggerTest, TraceChainWithGitCommit) {
    EvidenceLogger ev;
    // 未绑定 commit 时不可追溯
    ev.add(EvidenceStage::REQUIREMENT, "PRD §3.2", "risk self-assessment");
    ev.add(EvidenceStage::DEVELOPMENT, "src/sandbox.cpp", "seccomp impl");
    ev.add(EvidenceStage::TESTING, "tests/test_sandbox.cpp", "8 regression tests");
    EXPECT_FALSE(ev.self_check_pass());  // 未绑定 git commit

    // 绑定 Git commit
    ev.set_git_commit("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
    EXPECT_TRUE(ev.has_git_commit());

    // 建立需求→代码→测试双向链
    EXPECT_TRUE(ev.link("EVID-1", "EVID-2"));
    EXPECT_TRUE(ev.link("EVID-2", "EVID-3"));
    EXPECT_FALSE(ev.link("EVID-1", "NOPE"));  // 不存在的证据不可链

    EXPECT_TRUE(ev.self_check_pass());
    EXPECT_EQ(ev.records_of(EvidenceStage::REQUIREMENT).size(), 1u);
    EXPECT_EQ(ev.trace_links().size(), 2u);
}

TEST(EvidenceLoggerTest, ReadCommitFromEnv) {
    setenv("GIT_COMMIT", "abc123", 1);
    EvidenceLogger ev;
    ev.add(EvidenceStage::REQUIREMENT, "R1", "n1");
    ev.add(EvidenceStage::DEVELOPMENT, "D1", "n2");
    ev.add(EvidenceStage::TESTING, "T1", "n3");
    ev.read_git_commit_from_env();
    EXPECT_EQ(ev.git_commit(), "abc123");
    ev.link("EVID-1", "EVID-2");
    ev.link("EVID-2", "EVID-3");
    EXPECT_TRUE(ev.self_check_pass());
    unsetenv("GIT_COMMIT");
}

// ---- 硬件自诊断降级路径（补强 3） ----
TEST(SelfDiagnosisTest, ContainerCheckDegradedSafe) {
    HardwareSelfDiagnosis diag;
    auto r = diag.check_container_resources();
    // 任何平台都不应误报失败：watermark 在 [0,1]，degraded 为 true 时结果仍 ok
    EXPECT_GE(r.memory_watermark, 0.0);
    EXPECT_LE(r.memory_watermark, 1.0);
    EXPECT_TRUE(r.ok);
    if (r.degraded) {
        EXPECT_NE(r.message.find("degraded"), std::string::npos);
    }
}

// ---- 合规引擎集成证据链：完整配置场景仍全 PASS ----
TEST(ComplianceEngineTest, FullConfigWithEvidenceStillCompliant) {
    auto engine = build_compliant_engine();
    // 附加证据链
    static EvidenceLogger ev;
    ev.set_git_commit("deadbeef");
    ev.add(EvidenceStage::REQUIREMENT, "PRD", "req");
    ev.add(EvidenceStage::DEVELOPMENT, "src", "code");
    ev.add(EvidenceStage::TESTING, "tests", "tests");
    ev.link("EVID-1", "EVID-2");
    ev.link("EVID-2", "EVID-3");
    engine.attach(&ev);

    auto items = engine.self_check();
    bool any_fail = false;
    for (const auto& it : items) if (it.status == ComplianceStatus::FAIL) any_fail = true;
    EXPECT_FALSE(any_fail);
    EXPECT_TRUE(engine.all_compliant());
    // 第 3 条证据包含 commit
    ComplianceItem a3 = engine.check_article(3);
    EXPECT_NE(a3.evidence.find("deadbeef"), std::string::npos);
}
