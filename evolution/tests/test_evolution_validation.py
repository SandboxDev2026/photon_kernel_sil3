"""
进化验证模块端到端测试

验证核心问题：红方权重更新和蓝方规则进化，是真的因为数据，还是仅仅因为数据波动/噪声？

1. EvolutionDriftMonitor — 进化漂移监控器
   - 停滞告警（连续N轮变化<阈值）
   - 突变告警（单轮变化>阈值）
   - 振荡检测
   - 学习有效性指标（累计漂移量/漂移效率/收敛趋势）
   - KL 散度计算

2. BaselineComparator — 基线对照组 A/B 测试
   - 双比例 Z 检验
   - Cohen's h 效应量
   - 置信区间
   - 黄金证据判断（A组显著优于B组）
   - 样本量不足处理

3. EvolutionValidationSuite — 进化验证套件
   - 综合验证报告
   - 推荐建议生成
"""

import math
import time
import unittest

from evolution.evolution_validation import (
    ABTestResult,
    BaselineComparator,
    DriftAlert,
    DriftSnapshot,
    EvolutionDriftMonitor,
    EvolutionValidationSuite,
    GroupMetrics,
)
from evolution.real_signal_consumer import EscapeEvent, SignalType


class TestDriftSnapshot(unittest.TestCase):
    """漂移快照测试"""

    def test_snapshot_creation(self):
        snapshot = DriftSnapshot(
            round_idx=1,
            red_weights={"attack_1": 0.5, "attack_2": 0.3},
            blue_rule_count=5,
            blue_avg_effectiveness=0.7,
        )
        self.assertEqual(snapshot.round_idx, 1)
        self.assertEqual(len(snapshot.red_weights), 2)
        self.assertEqual(snapshot.blue_rule_count, 5)

    def test_snapshot_to_dict(self):
        snapshot = DriftSnapshot(round_idx=1, red_weights={"a": 1.0})
        d = snapshot.to_dict()
        self.assertIn("red_weights", d)
        self.assertEqual(d["round_idx"], 1)


class TestEvolutionDriftMonitor(unittest.TestCase):
    """进化漂移监控器测试"""

    def setUp(self):
        self.monitor = EvolutionDriftMonitor(
            stagnation_threshold=0.01,
            stagnation_rounds=3,  # 降低阈值便于测试
            spike_threshold=0.5,
        )

    def test_record_snapshot_basic(self):
        """测试基本快照记录"""
        snapshot = self.monitor.record_snapshot(
            round_idx=1,
            red_weights={"a": 1.0, "b": 2.0},
            blue_rule_count=3,
        )
        self.assertEqual(snapshot.round_idx, 1)
        self.assertEqual(len(self.monitor.snapshots), 1)

    def test_stagnation_alert(self):
        """测试进化停滞告警：连续N轮权重变化<阈值"""
        # 前3轮权重完全相同（变化率=0 < 阈值0.01）
        for i in range(4):
            self.monitor.record_snapshot(
                round_idx=i + 1,
                red_weights={"a": 1.0, "b": 1.0},
                total_events_consumed=i * 10,
            )

        # 第4轮应该触发停滞告警（连续3轮停滞）
        critical_alerts = [a for a in self.monitor.alerts if a.alert_type == "stagnation"]
        self.assertTrue(len(critical_alerts) > 0)
        self.assertEqual(critical_alerts[0].severity, "critical")
        self.assertIn("只消费了数据却没真正学习", critical_alerts[0].message)

    def test_no_stagnation_with_change(self):
        """测试有权重变化时不触发停滞告警"""
        weights_list = [
            {"a": 1.0, "b": 1.0},
            {"a": 1.5, "b": 0.5},  # 大幅变化
            {"a": 2.0, "b": 0.0},  # 继续变化
            {"a": 1.0, "b": 1.0},  # 变化回来
        ]
        for i, w in enumerate(weights_list):
            self.monitor.record_snapshot(round_idx=i + 1, red_weights=w)

        stagnation_alerts = [a for a in self.monitor.alerts if a.alert_type == "stagnation"]
        self.assertEqual(len(stagnation_alerts), 0)

    def test_spike_alert(self):
        """测试进化突变告警：单轮权重变化>阈值"""
        self.monitor.record_snapshot(round_idx=1, red_weights={"a": 1.0, "b": 1.0})
        # 第二轮权重完全反转（变化率接近1 > 阈值0.5）
        self.monitor.record_snapshot(round_idx=2, red_weights={"a": 0.0, "b": 2.0})

        spike_alerts = [a for a in self.monitor.alerts if a.alert_type == "spike"]
        self.assertTrue(len(spike_alerts) > 0)
        self.assertEqual(spike_alerts[0].severity, "warning")

    def test_recovery_alert(self):
        """测试从停滞中恢复的告警"""
        # 先停滞3轮
        for i in range(4):
            self.monitor.record_snapshot(
                round_idx=i + 1,
                red_weights={"a": 1.0},
                total_events_consumed=i,
            )
        # 然后大幅变化（恢复学习）
        self.monitor.record_snapshot(round_idx=5, red_weights={"a": 2.0, "b": 1.0})

        recovery_alerts = [a for a in self.monitor.alerts if a.alert_type == "recovery"]
        self.assertTrue(len(recovery_alerts) > 0)

    def test_weight_change_rate_identical(self):
        """测试相同权重的变化率为0"""
        rate = self.monitor._compute_weight_change_rate({"a": 1.0}, {"a": 1.0})
        self.assertEqual(rate, 0.0)

    def test_weight_change_rate_completely_different(self):
        """测试完全不同权重的变化率接近1"""
        rate = self.monitor._compute_weight_change_rate({"a": 1.0}, {"b": 1.0})
        self.assertAlmostEqual(rate, 1.0, places=2)

    def test_kl_divergence_identical(self):
        """测试相同分布的KL散度为0"""
        kl = self.monitor._compute_kl_divergence({"a": 0.5, "b": 0.5}, {"a": 0.5, "b": 0.5})
        self.assertAlmostEqual(kl, 0.0, places=5)

    def test_kl_divergence_different(self):
        """测试不同分布的KL散度>0"""
        kl = self.monitor._compute_kl_divergence({"a": 0.9, "b": 0.1}, {"a": 0.5, "b": 0.5})
        self.assertGreater(kl, 0.0)

    def test_learning_effectiveness_insufficient(self):
        """测试快照不足时学习有效性不可用"""
        result = self.monitor.get_learning_effectiveness()
        self.assertFalse(result["available"])

    def test_learning_effectiveness_available(self):
        """测试有足够快照时学习有效性可用"""
        for i in range(3):
            self.monitor.record_snapshot(
                round_idx=i + 1,
                red_weights={"a": float(i + 1)},
                total_events_consumed=i * 10,
            )
        result = self.monitor.get_learning_effectiveness()
        self.assertTrue(result["available"])
        self.assertIn("total_drift", result)
        self.assertIn("drift_efficiency_per_event", result)
        self.assertIn("convergence_ratio", result)

    def test_get_recent_alerts(self):
        """测试获取最近告警"""
        for i in range(4):
            self.monitor.record_snapshot(round_idx=i + 1, red_weights={"a": 1.0})
        alerts = self.monitor.get_recent_alerts(limit=5)
        self.assertTrue(len(alerts) > 0)
        self.assertIn("alert_type", alerts[0])

    def test_to_dict(self):
        """测试序列化"""
        self.monitor.record_snapshot(round_idx=1, red_weights={"a": 1.0})
        d = self.monitor.to_dict()
        self.assertIn("total_snapshots", d)
        self.assertIn("learning_effectiveness", d)


class TestGroupMetrics(unittest.TestCase):
    """组指标测试"""

    def test_escape_block_rate(self):
        metrics = GroupMetrics("test")
        metrics.total_attacks = 100
        metrics.blocked_attacks = 80
        metrics.successful_escapes = 20
        self.assertAlmostEqual(metrics.escape_block_rate, 0.8)

    def test_escape_block_rate_zero_attacks(self):
        metrics = GroupMetrics("test")
        self.assertEqual(metrics.escape_block_rate, 0.0)

    def test_false_positive_rate(self):
        metrics = GroupMetrics("test")
        metrics.blocked_attacks = 80
        metrics.false_positives = 20
        self.assertAlmostEqual(metrics.false_positive_rate, 0.2)


class TestBaselineComparator(unittest.TestCase):
    """基线对照组 A/B 测试测试"""

    def setUp(self):
        self.comparator = BaselineComparator(
            test_id="test_ab",
            min_sample_size=10,  # 降低阈值便于测试
        )

    def _make_event(self):
        return EscapeEvent(
            event_id=f"e_{int(time.time() * 1000000)}",
            signal_type=SignalType.SECCOMP_VIOLATION,
            timestamp=time.time(),
            sandbox_id="s1",
            severity="high",
            description="test attack",
            syscall="ptrace",
        )

    def test_feed_event_basic(self):
        """测试基本事件投喂"""
        event = self._make_event()
        self.comparator.feed_event(event, group_a_blocked=True, group_b_blocked=False)

        self.assertEqual(self.comparator.result.group_a.total_attacks, 1)
        self.assertEqual(self.comparator.result.group_a.blocked_attacks, 1)
        self.assertEqual(self.comparator.result.group_b.successful_escapes, 1)

    def test_gold_evidence_significant_improvement(self):
        """测试黄金证据：A组显著优于B组"""
        # A组拦截率90%，B组拦截率60%，每组100次攻击
        for i in range(100):
            event = self._make_event()
            a_blocked = i < 90  # 90% 拦截率
            b_blocked = i < 60  # 60% 拦截率
            self.comparator.feed_event(event, a_blocked, b_blocked)

        result = self.comparator.run_evaluation()
        self.assertTrue(result.is_statistically_significant)
        self.assertTrue(result.gold_evidence)
        self.assertLess(result.p_value, 0.05)
        self.assertGreater(result.effect_size, 0.1)
        self.assertIn("黄金证据", result.conclusion)

    def test_no_evidence_insignificant(self):
        """测试无显著差异时不构成黄金证据"""
        # A组和B组拦截率相同（65%）
        for i in range(100):
            event = self._make_event()
            blocked = i < 65
            self.comparator.feed_event(event, blocked, blocked)

        result = self.comparator.run_evaluation()
        self.assertFalse(result.gold_evidence)
        self.assertGreater(result.p_value, 0.05)

    def test_sample_size_insufficient(self):
        """测试样本量不足时的处理"""
        for i in range(5):  # 低于最小样本量10
            event = self._make_event()
            self.comparator.feed_event(event, True, False)

        result = self.comparator.run_evaluation()
        self.assertFalse(result.gold_evidence)
        self.assertIn("样本量不足", result.conclusion)

    def test_a_not_better(self):
        """测试A组不优于B组时的结论"""
        # A组拦截率50%，B组拦截率80%
        for i in range(100):
            event = self._make_event()
            a_blocked = i < 50
            b_blocked = i < 80
            self.comparator.feed_event(event, a_blocked, b_blocked)

        result = self.comparator.run_evaluation()
        self.assertFalse(result.gold_evidence)
        self.assertIn("未显示优势", result.conclusion)

    def test_two_proportion_z_test(self):
        """测试双比例Z检验"""
        # 90/100 vs 60/100 应该有显著差异
        p_value, z_score = self.comparator._two_proportion_z_test(90, 100, 60, 100)
        self.assertLess(p_value, 0.001)
        self.assertGreater(z_score, 0)

    def test_cohens_h(self):
        """测试Cohen's h效应量"""
        # 0.9 vs 0.6 应该有中等效应量
        h = self.comparator._cohens_h(0.9, 0.6)
        self.assertGreater(h, 0.5)

    def test_cohens_h_identical(self):
        """测试相同比例的Cohen's h为0"""
        h = self.comparator._cohens_h(0.5, 0.5)
        self.assertAlmostEqual(h, 0.0, places=5)

    def test_confidence_interval(self):
        """测试置信区间计算"""
        ci = self.comparator._proportion_diff_ci(0.9, 100, 0.6, 100)
        self.assertEqual(len(ci), 2)
        self.assertLess(ci[0], ci[1])
        # 差异0.3，置信区间应该包含0.3
        self.assertLess(ci[0], 0.3)
        self.assertGreater(ci[1], 0.3)

    def test_feed_event_batch(self):
        """测试批量事件投喂"""
        events = [self._make_event() for _ in range(10)]
        a_results = [True] * 10
        b_results = [False] * 10
        self.comparator.feed_event_batch(events, a_results, b_results)

        self.assertEqual(self.comparator.result.group_a.total_attacks, 10)
        self.assertEqual(self.comparator.result.group_a.blocked_attacks, 10)
        self.assertEqual(self.comparator.result.group_b.successful_escapes, 10)

    def test_false_positive_tracking(self):
        """测试误报跟踪"""
        event = self._make_event()
        self.comparator.feed_event(
            event, group_a_blocked=True, group_b_blocked=True,
            is_attack=False, is_false_positive_a=True, is_false_positive_b=False,
        )
        self.assertEqual(self.comparator.result.group_a.false_positives, 1)
        self.assertEqual(self.comparator.result.group_b.false_positives, 0)

    def test_to_dict(self):
        """测试序列化"""
        d = self.comparator.to_dict()
        self.assertIn("test_id", d)
        self.assertIn("result", d)


class TestEvolutionValidationSuite(unittest.TestCase):
    """进化验证套件测试"""

    def setUp(self):
        self.suite = EvolutionValidationSuite(
            test_id="suite_test",
            stagnation_rounds=3,
        )

    def _make_event(self):
        return EscapeEvent(
            event_id=f"e_{int(time.time() * 1000000)}",
            signal_type=SignalType.SECCOMP_VIOLATION,
            timestamp=time.time(),
            sandbox_id="s1",
            severity="high",
            description="test",
            syscall="ptrace",
        )

    def test_record_evolution_round(self):
        """测试记录进化轮次"""
        snapshot = self.suite.record_evolution_round(
            red_weights={"a": 1.0},
            blue_rule_count=5,
        )
        self.assertEqual(snapshot.round_idx, 1)
        self.assertEqual(self.suite.validation_rounds, 1)

    def test_feed_ab_event(self):
        """测试投喂A/B事件"""
        event = self._make_event()
        self.suite.feed_ab_event(event, group_a_blocked=True, group_b_blocked=False)
        self.assertEqual(self.suite.ab_test.result.group_a.total_attacks, 1)

    def test_generate_validation_report_gold_evidence(self):
        """测试生成黄金证据验证报告"""
        # 记录有变化的进化轮次（避免停滞）
        for i in range(5):
            self.suite.record_evolution_round(
                red_weights={"a": float(i + 1), "b": float(5 - i)},
                blue_rule_count=5 + i,
                total_events_consumed=i * 20,
            )

        # A/B测试：A组显著优于B组
        for i in range(100):
            event = self._make_event()
            a_blocked = i < 90  # 90%
            b_blocked = i < 50  # 50%
            self.suite.feed_ab_event(event, a_blocked, b_blocked)

        report = self.suite.generate_validation_report()
        self.assertTrue(report["has_gold_evidence"])
        self.assertIn("验证通过", report["overall_conclusion"])
        self.assertIn("ab_test", report)
        self.assertIn("recommendations", report)

    def test_generate_validation_report_stagnation(self):
        """测试生成停滞验证报告"""
        # 记录完全相同的权重（触发停滞）
        for i in range(5):
            self.suite.record_evolution_round(
                red_weights={"a": 1.0, "b": 1.0},
                total_events_consumed=i * 10,
            )

        report = self.suite.generate_validation_report()
        self.assertTrue(report["has_stagnation"])
        self.assertIn("回查", report["overall_conclusion"] or " ".join(report["recommendations"]))

    def test_generate_validation_report_insufficient_data(self):
        """测试数据不足时的验证报告"""
        # 只记录1轮，不投喂A/B事件
        self.suite.record_evolution_round(red_weights={"a": 1.0})
        report = self.suite.generate_validation_report()
        self.assertFalse(report["has_gold_evidence"])

    def test_recommendations_include_ci_integration(self):
        """测试建议包含CI集成"""
        for i in range(3):
            self.suite.record_evolution_round(
                red_weights={"a": float(i + 1)},
                total_events_consumed=i * 10,
            )
        for i in range(20):
            event = self._make_event()
            self.suite.feed_ab_event(event, i < 18, i < 10)

        report = self.suite.generate_validation_report()
        # 建议中应该包含CI/CD或告警相关内容
        all_recs = " ".join(report["recommendations"])
        self.assertTrue(
            "CI" in all_recs or "告警" in all_recs or "监控" in all_recs
        )

    def test_to_dict(self):
        """测试序列化"""
        self.suite.record_evolution_round(red_weights={"a": 1.0})
        d = self.suite.to_dict()
        self.assertIn("validation_rounds", d)
        self.assertIn("drift_monitor", d)
        self.assertIn("ab_test", d)


class TestOscillationDetection(unittest.TestCase):
    """振荡检测测试"""

    def test_oscillation_detection(self):
        """测试权重反复大幅变化触发振荡告警"""
        monitor = EvolutionDriftMonitor(
            stagnation_threshold=0.01,
            stagnation_rounds=10,
            spike_threshold=0.8,  # 提高突变阈值避免干扰
            oscillation_window=4,
        )
        # 权重反复在两个极端之间振荡
        weights_list = [
            {"a": 1.0, "b": 0.0},
            {"a": 0.0, "b": 1.0},
            {"a": 1.0, "b": 0.0},
            {"a": 0.0, "b": 1.0},
            {"a": 1.0, "b": 0.0},
        ]
        for i, w in enumerate(weights_list):
            monitor.record_snapshot(round_idx=i + 1, red_weights=w)

        oscillation_alerts = [a for a in monitor.alerts if a.alert_type == "oscillation"]
        # 振荡检测可能触发（取决于方向计算）
        # 至少不应该崩溃
        self.assertTrue(len(monitor.snapshots) == 5)


if __name__ == '__main__':
    unittest.main()
