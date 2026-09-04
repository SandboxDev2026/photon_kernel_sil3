"""
红蓝对抗进化策略优化器端到端测试

验证完整链路：真实信号 → 攻击模式提取 → 智能触发 → 对抗评估 → 红方策略优化 → 蓝方策略优化 → 进化执行
"""

import json
import time
import unittest

from evolution.adversarial_strategy_optimizer import (
    AdversarialEvaluationResult,
    AdversarialEvaluator,
    AdversarialStrategyOrchestrator,
    AttackPattern,
    BlueStrategyOptimizer,
    DefenseGap,
    EvolutionTrigger,
    RedStrategyOptimizer,
)
from evolution.real_signal_consumer import (
    ConsumeMode,
    EscapeEvent,
    NetworkVector,
    RealSignalConsumer,
    SignalType,
)


class TestAttackPattern(unittest.TestCase):
    """攻击模式测试"""

    def test_attack_pattern_creation(self):
        """测试攻击模式创建"""
        pattern = AttackPattern(
            pattern_id="test_001",
            attack_type="syscall_ptrace",
            signal_type=SignalType.SECCOMP_VIOLATION,
            severity="critical",
            syscall="ptrace",
        )
        self.assertEqual(pattern.occurrence_count, 1)
        self.assertEqual(pattern.success_rate, 0.0)
        self.assertTrue(pattern.is_high_priority)

    def test_attack_pattern_success_rate(self):
        """测试攻击模式成功率计算"""
        pattern = AttackPattern(
            pattern_id="test_002",
            attack_type="syscall_mount",
            signal_type=SignalType.SECCOMP_VIOLATION,
            severity="high",
            syscall="mount",
        )
        pattern.success_count = 7
        pattern.blocked_count = 3
        self.assertAlmostEqual(pattern.success_rate, 0.7)

    def test_attack_pattern_high_priority_frequency(self):
        """测试高频攻击模式被标记为高优先级"""
        pattern = AttackPattern(
            pattern_id="test_003",
            attack_type="syscall_read",
            signal_type=SignalType.SECCOMP_VIOLATION,
            severity="low",
            syscall="read",
        )
        pattern.occurrence_count = 10
        self.assertTrue(pattern.is_high_priority)

    def test_attack_pattern_low_priority(self):
        """测试低风险攻击模式不被标记为高优先级"""
        pattern = AttackPattern(
            pattern_id="test_004",
            attack_type="syscall_write",
            signal_type=SignalType.SECCOMP_VIOLATION,
            severity="low",
            syscall="write",
        )
        pattern.occurrence_count = 2
        self.assertFalse(pattern.is_high_priority)


class TestAdversarialEvaluator(unittest.TestCase):
    """对抗评估器测试"""

    def setUp(self):
        self.evaluator = AdversarialEvaluator()

    def _make_pattern(self, attack_type, severity="high", count=5, success=3, blocked=2):
        pattern = AttackPattern(
            pattern_id=f"p_{attack_type}",
            attack_type=attack_type,
            signal_type=SignalType.SECCOMP_VIOLATION,
            severity=severity,
        )
        pattern.occurrence_count = count
        pattern.success_count = success
        pattern.blocked_count = blocked
        return pattern

    def test_evaluate_basic(self):
        """测试基本对抗评估"""
        patterns = [self._make_pattern("attack_1")]
        result = self.evaluator.evaluate([], [], patterns)

        self.assertEqual(result.total_attack_cases, 0)
        self.assertGreater(result.attack_success_rate, 0)
        self.assertGreater(result.defense_success_rate, 0)

    def test_identify_defense_gaps(self):
        """测试防御盲区识别"""
        patterns = [self._make_pattern("ungarded_attack", severity="critical", count=10)]
        result = self.evaluator.evaluate([], [], patterns)

        self.assertTrue(len(result.defense_gaps) > 0)
        self.assertEqual(result.defense_gaps[0].attack_type, "ungarded_attack")
        self.assertEqual(result.defense_gaps[0].gap_severity, "critical")

    def test_identify_ineffective_rules(self):
        """测试无效规则识别"""
        class MockRule:
            def __init__(self, rule_id, effectiveness, trigger_count):
                self.rule_id = rule_id
                self.effectiveness = effectiveness
                self.trigger_count = trigger_count
                self.target_attack_types = []

        rules = [
            MockRule("good_rule", 0.8, 5),
            MockRule("low_eff_rule", 0.3, 3),
            MockRule("never_hit_rule", 0.7, 0),
        ]
        patterns = [self._make_pattern("attack_1")]
        result = self.evaluator.evaluate([], rules, patterns)

        self.assertTrue(any("low_eff_rule" in r for r in result.ineffective_rules))
        self.assertTrue(any("never_hit_rule" in r for r in result.ineffective_rules))

    def test_generate_recommendations(self):
        """测试进化建议生成"""
        patterns = [self._make_pattern("critical_attack", severity="critical", count=15)]
        result = self.evaluator.evaluate([], [], patterns)

        self.assertTrue(len(result.recommendations) > 0)
        # 应该包含临界防御盲区建议
        self.assertTrue(any("临界" in r or "critical" in r.lower() for r in result.recommendations))

    def test_evaluation_history(self):
        """测试评估历史记录"""
        patterns = [self._make_pattern("attack_1")]
        self.evaluator.evaluate([], [], patterns)
        self.evaluator.evaluate([], [], patterns)

        self.assertEqual(len(self.evaluator.evaluation_history), 2)

    def test_get_trend(self):
        """测试评估趋势"""
        # 少于2次评估时趋势不可用
        self.assertFalse(self.evaluator.get_trend()["trend_available"])

        patterns = [self._make_pattern("attack_1")]
        self.evaluator.evaluate([], [], patterns)
        self.evaluator.evaluate([], [], patterns)

        trend = self.evaluator.get_trend()
        self.assertTrue(trend["trend_available"])
        self.assertEqual(trend["evaluations_count"], 2)


class TestRedStrategyOptimizer(unittest.TestCase):
    """红方策略优化器测试"""

    def setUp(self):
        self.optimizer = RedStrategyOptimizer()

    def _make_escape_event(self, syscall="ptrace", severity="critical"):
        return EscapeEvent(
            event_id=f"e_{int(time.time() * 1000)}",
            signal_type=SignalType.SECCOMP_VIOLATION,
            timestamp=time.time(),
            sandbox_id="s1",
            severity=severity,
            description=f"test {syscall}",
            syscall=syscall,
        )

    def test_extract_attack_pattern_new(self):
        """测试提取新攻击模式"""
        event = self._make_escape_event("ptrace")
        pattern = self.optimizer.extract_attack_pattern(event)

        self.assertEqual(pattern.syscall, "ptrace")
        self.assertEqual(pattern.occurrence_count, 1)
        self.assertEqual(len(self.optimizer.attack_patterns), 1)

    def test_extract_attack_pattern_existing(self):
        """测试更新已有攻击模式"""
        event1 = self._make_escape_event("ptrace")
        event2 = self._make_escape_event("ptrace")
        self.optimizer.extract_attack_pattern(event1)
        pattern = self.optimizer.extract_attack_pattern(event2)

        self.assertEqual(pattern.occurrence_count, 2)
        self.assertEqual(len(self.optimizer.attack_patterns), 1)

    def test_record_attack_result(self):
        """测试记录攻击结果"""
        event = self._make_escape_event("ptrace")
        pattern = self.optimizer.extract_attack_pattern(event)

        self.optimizer.record_attack_result(pattern.pattern_id, success=True)
        self.optimizer.record_attack_result(pattern.pattern_id, success=False)

        self.assertEqual(pattern.success_count, 1)
        self.assertEqual(pattern.blocked_count, 1)
        self.assertAlmostEqual(pattern.success_rate, 0.5)

    def test_optimize_strategy_weights(self):
        """测试基于防御盲区优化策略权重"""
        event = self._make_escape_event("ptrace")
        self.optimizer.extract_attack_pattern(event)

        eval_result = AdversarialEvaluationResult()
        eval_result.defense_gaps = [
            DefenseGap(
                attack_type="syscall_ptrace",
                signal_type=SignalType.SECCOMP_VIOLATION,
                occurrence_count=10,
                severity="critical",
                current_defense_count=0,
                avg_defense_effectiveness=0.0,
                gap_severity="critical",
            )
        ]

        weights = self.optimizer.optimize_strategy_weights(eval_result)
        self.assertIn("syscall_ptrace", weights)
        self.assertGreaterEqual(weights["syscall_ptrace"], 2.0)

    def test_get_priority_attack_patterns(self):
        """测试获取优先级最高的攻击模式"""
        for syscall, severity in [("ptrace", "critical"), ("read", "low"), ("mount", "high")]:
            event = self._make_escape_event(syscall, severity)
            self.optimizer.extract_attack_pattern(event)

        priority = self.optimizer.get_priority_attack_patterns(top_n=2)
        self.assertEqual(len(priority), 2)
        # ptrace 应该排第一（critical）
        self.assertEqual(priority[0].syscall, "ptrace")

    def test_compute_novelty(self):
        """测试攻击用例新颖性计算"""
        novelty1 = self.optimizer.compute_novelty("unique_attack_001")
        self.assertEqual(novelty1, 1.0)

        # 重复的攻击用例新颖性为0
        novelty2 = self.optimizer.compute_novelty("unique_attack_001")
        self.assertEqual(novelty2, 0.0)

    def test_get_stats(self):
        """测试红方策略统计"""
        event = self._make_escape_event("ptrace")
        self.optimizer.extract_attack_pattern(event)

        stats = self.optimizer.get_stats()
        self.assertEqual(stats["total_attack_patterns"], 1)
        self.assertEqual(stats["high_risk_patterns"], 1)


class TestBlueStrategyOptimizer(unittest.TestCase):
    """蓝方策略优化器测试"""

    def setUp(self):
        self.optimizer = BlueStrategyOptimizer()

    def _make_attack_pattern(self, attack_type="syscall_ptrace", severity="critical", count=10):
        pattern = AttackPattern(
            pattern_id=f"p_{attack_type}",
            attack_type=attack_type,
            signal_type=SignalType.SECCOMP_VIOLATION,
            severity=severity,
            syscall="ptrace",
        )
        pattern.occurrence_count = count
        return pattern

    def test_generate_targeted_defense(self):
        """测试生成针对性防御规则"""
        pattern = self._make_attack_pattern()
        defense = self.optimizer.generate_targeted_defense(pattern)

        self.assertIn("targeted_", defense["rule_id"])
        self.assertEqual(defense["defense_type"], "system_call_monitor")
        self.assertIn("ptrace", defense["detection_logic"])
        self.assertGreater(defense["effectiveness"], 0.3)
        self.assertGreaterEqual(defense["priority"], 5)

    def test_generate_targeted_defense_with_gap(self):
        """测试基于防御盲区生成针对性防御"""
        pattern = self._make_attack_pattern()
        gap = DefenseGap(
            attack_type="syscall_ptrace",
            signal_type=SignalType.SECCOMP_VIOLATION,
            occurrence_count=10,
            severity="critical",
            current_defense_count=0,
            avg_defense_effectiveness=0.0,
            gap_severity="critical",
        )
        defense = self.optimizer.generate_targeted_defense(pattern, gap)

        # 临界盲区应该有更高的优先级和有效性
        self.assertGreaterEqual(defense["priority"], 8)

    def test_update_rule_effectiveness(self):
        """测试更新规则有效性历史"""
        self.optimizer.update_rule_effectiveness("rule_001", 0.8)
        self.optimizer.update_rule_effectiveness("rule_001", 0.6)

        avg = self.optimizer.get_rule_avg_effectiveness("rule_001")
        self.assertAlmostEqual(avg, 0.7)

    def test_record_false_positive(self):
        """测试记录规则误报"""
        self.optimizer.record_false_positive("rule_001")
        self.optimizer.record_false_positive("rule_001")

        self.assertEqual(self.optimizer.rule_false_positives["rule_001"], 2)

    def test_identify_rules_to_prune_low_effectiveness(self):
        """测试识别低有效性规则需要淘汰"""
        class MockRule:
            def __init__(self, rule_id, effectiveness):
                self.rule_id = rule_id
                self.effectiveness = effectiveness
                self.trigger_count = 5
                self.target_attack_types = []

        rules = [
            MockRule("good_rule", 0.8),
            MockRule("bad_rule", 0.2),
        ]
        self.optimizer.update_rule_effectiveness("bad_rule", 0.2)

        to_prune = self.optimizer.identify_rules_to_prune(rules)
        self.assertIn("bad_rule", to_prune)
        self.assertNotIn("good_rule", to_prune)

    def test_get_stats(self):
        """测试蓝方策略统计"""
        self.optimizer.update_rule_effectiveness("rule_001", 0.8)
        stats = self.optimizer.get_stats()

        self.assertEqual(stats["rules_tracked"], 1)


class TestEvolutionTrigger(unittest.TestCase):
    """智能进化触发器测试"""

    def setUp(self):
        self.trigger = EvolutionTrigger(cooldown_seconds=1.0, batch_size=5, frequency_threshold=3)

    def _make_event(self, syscall="ptrace", severity="high", event_id=None):
        return EscapeEvent(
            event_id=event_id or f"e_{int(time.time() * 1000000)}",
            signal_type=SignalType.SECCOMP_VIOLATION,
            timestamp=time.time(),
            sandbox_id="s1",
            severity=severity,
            description="test",
            syscall=syscall,
        )

    def test_critical_severity_triggers_immediately(self):
        """测试 critical 严重程度立即触发进化"""
        event = self._make_event(severity="critical")
        should_evolve, reason = self.trigger.should_evolve(event)

        self.assertTrue(should_evolve)
        self.assertEqual(reason, "critical_severity")

    def test_novel_event_type_triggers(self):
        """测试新类型事件触发进化"""
        event = self._make_event(syscall="new_syscall")
        should_evolve, reason = self.trigger.should_evolve(event)

        self.assertTrue(should_evolve)
        self.assertEqual(reason, "novel_event_type")

    def test_high_frequency_triggers(self):
        """测试高频事件触发进化"""
        # 先添加一个已知类型（不触发新颖性）
        self.trigger.seen_event_types.add("seccomp_ptrace")

        # 发送 frequency_threshold 个相同类型事件
        for i in range(3):
            event = self._make_event(syscall="ptrace", event_id=f"freq_{i}")
            should_evolve, reason = self.trigger.should_evolve(event)

        self.assertTrue(should_evolve)
        self.assertIn("high_frequency", reason)

    def test_batch_full_triggers(self):
        """测试缓冲满触发进化"""
        self.trigger.batch_size = 3
        # 使用不同类型的低严重度事件，避免新颖性和高频触发
        for i, syscall in enumerate(["read", "write", "open"]):
            self.trigger.seen_event_types.add(f"seccomp_{syscall}")
            event = self._make_event(syscall=syscall, severity="low", event_id=f"batch_{i}")
            should_evolve, reason = self.trigger.should_evolve(event)

        self.assertTrue(should_evolve)
        self.assertIn("batch_full", reason)

    def test_cooldown_prevents_repeat(self):
        """测试冷却期防止重复触发"""
        # 第一次 critical 触发
        event1 = self._make_event(severity="critical", event_id="cool_1")
        should_evolve1, _ = self.trigger.should_evolve(event1)
        self.assertTrue(should_evolve1)

        # 冷却期内同类型不触发
        event2 = self._make_event(severity="critical", event_id="cool_2")
        should_evolve2, reason = self.trigger.should_evolve(event2)
        self.assertFalse(should_evolve2)
        self.assertEqual(reason, "cooldown")

    def test_low_severity_known_type_waits(self):
        """测试低严重程度已知类型等待更多事件"""
        self.trigger.seen_event_types.add("seccomp_write")
        event = self._make_event(syscall="write", severity="low")

        should_evolve, reason = self.trigger.should_evolve(event)
        self.assertFalse(should_evolve)
        self.assertEqual(reason, "waiting")

    def test_clear_buffer(self):
        """测试清空缓冲"""
        event = self._make_event(severity="critical")
        self.trigger.should_evolve(event)
        self.assertGreater(len(self.trigger.event_buffer), 0)

        self.trigger.clear_buffer()
        self.assertEqual(len(self.trigger.event_buffer), 0)

    def test_get_stats(self):
        """测试触发器统计"""
        event = self._make_event(severity="critical")
        self.trigger.should_evolve(event)

        stats = self.trigger.get_stats()
        self.assertEqual(stats["total_triggers"], 1)
        self.assertEqual(stats["severity_triggers"], 1)


class TestAdversarialStrategyOrchestrator(unittest.TestCase):
    """红蓝对抗进化策略编排器端到端测试"""

    def setUp(self):
        self.orchestrator = AdversarialStrategyOrchestrator(cooldown_seconds=0.1, batch_size=10)

    def _make_event(self, syscall="ptrace", severity="critical"):
        return EscapeEvent(
            event_id=f"e_{int(time.time() * 1000000)}",
            signal_type=SignalType.SECCOMP_VIOLATION,
            timestamp=time.time(),
            sandbox_id="s1",
            severity=severity,
            description=f"test {syscall}",
            syscall=syscall,
        )

    def test_process_real_event_triggers_evolution(self):
        """测试处理真实事件触发进化"""
        event = self._make_event(severity="critical")
        result = self.orchestrator.process_real_event(event)

        self.assertTrue(result["should_evolve"])
        self.assertEqual(result["trigger_reason"], "critical_severity")
        self.assertIn("evolution", result)
        self.assertIn("evaluation", result["evolution"])

    def test_process_real_event_extracts_pattern(self):
        """测试处理真实事件提取攻击模式"""
        event = self._make_event(syscall="ptrace")
        result = self.orchestrator.process_real_event(event)

        self.assertIn("pattern_extracted", result)
        self.assertIn("ptrace", result["pattern_extracted"])

    def test_orchestrator_generates_targeted_defenses(self):
        """测试编排器生成针对性防御建议"""
        event = self._make_event(syscall="ptrace", severity="critical")
        result = self.orchestrator.process_real_event(event)

        evolution = result["evolution"]
        self.assertIn("targeted_defenses", evolution)
        # 应该至少有一个针对 ptrace 的防御建议
        if evolution["targeted_defenses"]:
            self.assertIn("ptrace", evolution["targeted_defenses"][0]["detection_logic"])

    def test_orchestrator_identifies_defense_gaps(self):
        """测试编排器识别防御盲区"""
        event = self._make_event(syscall="new_attack", severity="critical")
        result = self.orchestrator.process_real_event(event)

        evolution = result["evolution"]
        self.assertGreater(len(evolution["evaluation"]["defense_gaps"]), 0)

    def test_orchestrator_red_optimization(self):
        """测试编排器红方策略优化"""
        event = self._make_event(syscall="ptrace", severity="critical")
        result = self.orchestrator.process_real_event(event)

        evolution = result["evolution"]
        self.assertIn("red_strategy_weights", evolution)
        self.assertIn("priority_attack_patterns", evolution)

    def test_orchestrator_evolution_history(self):
        """测试编排器进化历史记录"""
        for i in range(3):
            event = self._make_event(syscall=f"attack_{i}", severity="critical")
            self.orchestrator.process_real_event(event)
            time.sleep(0.15)  # 等待冷却期

        self.assertEqual(len(self.orchestrator.evolution_history), 3)

    def test_orchestrator_summary(self):
        """测试编排器摘要"""
        event = self._make_event(severity="critical")
        self.orchestrator.process_real_event(event)

        summary = self.orchestrator.get_summary()
        self.assertEqual(summary["total_evolutions"], 1)
        self.assertIn("trigger_stats", summary)
        self.assertIn("red_stats", summary)
        self.assertIn("blue_stats", summary)

    def test_full_pipeline_with_real_signal_consumer(self):
        """测试与 RealSignalConsumer 集成的完整管道"""
        consumer = RealSignalConsumer(mode=ConsumeMode.BATCH)
        consumer.register_callback(
            lambda e: self.orchestrator.process_real_event(e)
        )

        # 消费真实格式日志
        log_line = json.dumps({
            "event_id": "pipeline_001",
            "event_type": "SECCOMP_VIOLATION",
            "timestamp": time.time(),
            "sandbox_id": "sandbox_001",
            "syscall": "ptrace",
            "action": "KILL",
            "pid": 1234,
            "comm": "malware",
        })
        event = consumer.consume_line(log_line)

        self.assertIsNotNone(event)
        self.assertEqual(event.syscall, "ptrace")
        self.assertEqual(event.severity, "critical")

        # 编排器应该已经处理了这个事件
        summary = self.orchestrator.get_summary()
        self.assertGreaterEqual(summary["total_evolutions"], 1)


if __name__ == '__main__':
    unittest.main()
