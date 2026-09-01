#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "photon_kernel/safety/jump_counter.hpp"
#include "photon_kernel/incremental_compliance.hpp"

using namespace photon_kernel;
using namespace photon_kernel::safety;

// ---- V4.14 跳数归零 ----
TEST(V414JumpCounterTest, EmptyChainNotHopZero) {
    JumpCounter jc;
    EXPECT_FALSE(jc.is_hop_zero());
}

TEST(V414JumpCounterTest, FinalHopPlannedDeploymentIsHopZero) {
    JumpCounter jc;
    jc.add_hop(JumpHop{"encoder", /*is_active_communication=*/false,
                       /*is_planned_deployment=*/false, 0});
    jc.add_hop(JumpHop{"decoder", false, false, 1});
    // 最终执行器层：已规划实际部署 -> 跳数归零
    jc.add_hop(JumpHop{"executor", false, true, 2});
    EXPECT_TRUE(jc.is_hop_zero());
    EXPECT_EQ(jc.get_hop_chain().size(), 3u);
}

TEST(V414JumpCounterTest, FinalHopNotDeployedNotHopZero) {
    JumpCounter jc;
    jc.add_hop(JumpHop{"encoder", false, false, 0});
    jc.add_hop(JumpHop{"executor", false, false, 1});
    EXPECT_FALSE(jc.is_hop_zero());
}

TEST(V414JumpCounterTest, ActiveCommunicationAlsoHopZero) {
    JumpCounter jc;
    jc.add_hop(JumpHop{"model", true, false, 0});
    EXPECT_TRUE(jc.is_hop_zero());
}

TEST(V414JumpCounterTest, ResetClearsChain) {
    JumpCounter jc;
    jc.add_hop(JumpHop{"encoder", false, true, 0});
    EXPECT_TRUE(jc.is_hop_zero());
    jc.reset();
    EXPECT_FALSE(jc.is_hop_zero());
    EXPECT_TRUE(jc.get_hop_chain().empty());
}

TEST(V414JumpCounterTest, ComplianceReviewFlag) {
    JumpCounter jc;
    EXPECT_FALSE(jc.is_review_needed());
    jc.mark_compliance_review_needed();
    EXPECT_TRUE(jc.is_review_needed());
}

// ---- V4.14 增量合规（变更后 30 天重新评估）----
TEST(V414IncrementalComplianceTest, InitiallyCompliant) {
    IncrementalComplianceTracker tracker;
    EXPECT_TRUE(tracker.is_compliant());
    EXPECT_TRUE(tracker.get_pending_changes().empty());
}

TEST(V414IncrementalComplianceTest, ChangeMakesNonCompliant) {
    IncrementalComplianceTracker tracker;
    tracker.record_change("weights", "quantized to int8");
    EXPECT_FALSE(tracker.is_compliant());

    auto pending = tracker.get_pending_changes();
    ASSERT_EQ(pending.size(), 1u);
    EXPECT_EQ(pending[0].change_type, "weights");
    EXPECT_FALSE(pending[0].review_completed);
}

TEST(V414IncrementalComplianceTest, CompleteReviewRestoresCompliance) {
    IncrementalComplianceTracker tracker;
    tracker.record_change("inference_logic", "switched to greedy decoding");
    EXPECT_FALSE(tracker.is_compliant());
    tracker.complete_review("inference_logic");
    EXPECT_TRUE(tracker.is_compliant());
    EXPECT_TRUE(tracker.get_pending_changes().empty());
}

TEST(V414IncrementalComplianceTest, ReviewDeadlineIsThirtyDays) {
    IncrementalComplianceTracker tracker;
    tracker.record_change("training_data", "added 2026 dataset");
    auto pending = tracker.get_pending_changes();
    ASSERT_EQ(pending.size(), 1u);
    // 变更评估周期不超过 30 天
    auto gap = pending[0].review_deadline - pending[0].change_time;
    auto gap_hours = std::chrono::duration_cast<std::chrono::hours>(gap).count();
    EXPECT_LE(gap_hours, 24 * 30);
    EXPECT_GE(gap_hours, 24 * 29);
}

// ---- 第九条：跳数声明验证（下游规则校验层存在性）----
TEST(V414JumpCounterTest, HopZeroClaimMissingEvidence) {
    JumpCounter jc;
    // 最终跳声明归零，但未携带验证证据
    jc.add_hop(JumpHop{"encoder", false, false, 0});
    jc.add_hop(JumpHop{"executor", true, false, 1});  // 活跃通信但无证据
    auto v = jc.verify_hop_zero_claim();
    EXPECT_FALSE(v.verified);
    EXPECT_FALSE(v.evidence_complete);
    EXPECT_FALSE(v.rule_layer_present);
}

TEST(V414JumpCounterTest, HopZeroClaimUnregisteredRuleLayer) {
    JumpCounter jc;
    jc.add_hop(JumpHop{"executor", false, true, 0, "rule-base-v2", "digest-abc"});
    // 证据完整，但规则校验层未注册 -> 不通过
    auto v = jc.verify_hop_zero_claim();
    EXPECT_TRUE(v.evidence_complete);
    EXPECT_FALSE(v.rule_layer_present);
    EXPECT_FALSE(v.verified);
    EXPECT_EQ(v.rule_base_version, "rule-base-v2");
    EXPECT_EQ(v.digest, "digest-abc");
}

TEST(V414JumpCounterTest, HopZeroClaimVerifiedWithRegisteredRuleLayer) {
    JumpCounter jc;
    // 注册下游规则校验层（存在性登记）
    jc.register_rule_layer("rule-base-v2", "k8s://photon/rule-checker");
    EXPECT_TRUE(jc.has_rule_layer("rule-base-v2"));
    EXPECT_FALSE(jc.has_rule_layer("rule-base-other"));

    jc.add_hop(JumpHop{"encoder", false, false, 0});
    jc.add_hop(JumpHop{"executor", false, true, 1, "rule-base-v2", "digest-abc"});
    auto v = jc.verify_hop_zero_claim();
    EXPECT_TRUE(v.evidence_complete);
    EXPECT_TRUE(v.rule_layer_present);
    EXPECT_TRUE(v.verified);
    EXPECT_NE(v.message.find("verified"), std::string::npos);
}

TEST(V414JumpCounterTest, RegisterRuleLayerDedup) {
    JumpCounter jc;
    jc.register_rule_layer("rl1", "ref-a");
    jc.register_rule_layer("rl1", "ref-a");
    jc.register_rule_layer("rl1", "ref-b");
    EXPECT_EQ(jc.get_rule_layers().size(), 2u);
}
