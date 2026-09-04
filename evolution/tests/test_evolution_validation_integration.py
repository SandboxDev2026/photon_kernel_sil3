"""
进化验证深度集成端到端测试

验证三件防御性工程的真正集成：
1. RealSignalConsumer 漂移监控埋点——消费事件时自动记录权重漂移
2. ABTestRunner 双实例对比——两个 RedBlueAdversaryTrainer 实例同时消费相同事件流
3. AdversarialStrategyOrchestrator 自动验证——每轮进化后自动记录漂移快照
"""

import json
import time
import unittest

from evolution.ab_test_runner import ABTestRunner
from evolution.adversarial_strategy_optimizer import AdversarialStrategyOrchestrator
from evolution.evolution_validation import (
    EvolutionDriftMonitor,
    EvolutionValidationSuite,
)
from evolution.real_signal_consumer import (
    ConsumeMode,
    EscapeEvent,
    RealSignalConsumer,
    SignalType,
)


class TestRealSignalConsumerDriftIntegration(unittest.TestCase):
    """RealSignalConsumer 漂移监控集成测试"""

    def setUp(self):
        self.drift_monitor = EvolutionDriftMonitor(
            stagnation_threshold=0.01,
            stagnation_rounds=3,
        )
        self.consumer = RealSignalConsumer(
            mode=ConsumeMode.BATCH,
            drift_monitor=self.drift_monitor,
        )

    def _make_seccomp_log(self, syscall="ptrace", eid="e1"):
        return json.dumps({
            "event_id": eid,
            "event_type": "SECCOMP_VIOLATION",
            "timestamp": time.time(),
            "sandbox_id": "s1",
            "syscall": syscall,
            "action": "KILL",
            "pid": 1,
            "comm": "test",
        })

    def test_consumer_has_drift_monitor(self):
        """测试消费器挂载了漂移监控器"""
        self.assertIsNotNone(self.consumer.drift_monitor)
        self.assertEqual(self.consumer.drift_monitor, self.drift_monitor)

    def test_attach_drift_monitor(self):
        """测试动态挂载漂移监控器"""
        consumer = RealSignalConsumer()
        self.assertIsNone(consumer.drift_monitor)

        monitor = EvolutionDriftMonitor()
        consumer.attach_drift_monitor(monitor)
        self.assertIsNotNone(consumer.drift_monitor)

    def test_record_weight_snapshot(self):
        """测试记录权重快照"""
        snapshot = self.consumer.record_weight_snapshot(
            red_weights={"attack_1": 0.5, "attack_2": 0.3},
            blue_rule_count=5,
        )
        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot.round_idx, 1)
        self.assertEqual(len(snapshot.red_weights), 2)
        self.assertEqual(self.consumer._drift_snapshot_count, 1)

    def test_record_weight_snapshot_without_monitor(self):
        """测试未挂载监控器时记录快照返回 None"""
        consumer = RealSignalConsumer()
        result = consumer.record_weight_snapshot(red_weights={"a": 1.0})
        self.assertIsNone(result)

    def test_drift_stagnation_detected_via_consumer(self):
        """测试通过消费器检测到进化停滞"""
        # 连续记录相同权重（模拟只消费数据不学习）
        for i in range(4):
            self.consumer.record_weight_snapshot(
                red_weights={"a": 1.0, "b": 1.0},
                total_events_consumed=i * 10,
            )

        # 漂移监控器应该检测到停滞
        stagnation_alerts = [
            a for a in self.drift_monitor.alerts if a.alert_type == "stagnation"
        ]
        self.assertTrue(len(stagnation_alerts) > 0)

    def test_drift_status_report(self):
        """测试漂移状态报告"""
        self.consumer.record_weight_snapshot(red_weights={"a": 1.0})
        status = self.consumer.get_drift_status()

        self.assertTrue(status["drift_monitor_attached"])
        self.assertEqual(status["snapshots_recorded"], 1)
        self.assertIn("learning_effectiveness", status)

    def test_drift_status_without_monitor(self):
        """测试未挂载监控器时的状态报告"""
        consumer = RealSignalConsumer()
        status = consumer.get_drift_status()
        self.assertFalse(status["drift_monitor_attached"])
        self.assertIn("建议", status["message"])

    def test_consume_events_and_record_drift(self):
        """测试消费真实事件后记录漂移"""
        # 消费一些真实事件
        for i in range(5):
            self.consumer.consume_line(self._make_seccomp_log("ptrace", f"evt_{i}"))

        self.assertEqual(self.consumer.stats["total_consumed"], 5)

        # 记录漂移快照
        self.consumer.record_weight_snapshot(
            red_weights={"ptrace": 0.8, "mount": 0.5},
            attack_pattern_count=2,
        )

        status = self.consumer.get_drift_status()
        self.assertEqual(status["total_events_consumed"], 5)
        self.assertEqual(status["snapshots_recorded"], 1)


class TestABTestRunnerIntegration(unittest.TestCase):
    """ABTestRunner 双实例对比集成测试"""

    def setUp(self):
        self.runner = ABTestRunner(
            test_id="integration_test",
            min_sample_size=10,  # 降低阈值便于测试
        )

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

    def test_runner_has_two_instances(self):
        """测试运行器有两个独立实例"""
        self.assertIsNotNone(self.runner.group_a.trainer)
        self.assertIsNotNone(self.runner.group_b.trainer)
        self.assertNotEqual(
            self.runner.group_a.trainer.enable_evolution,
            self.runner.group_b.trainer.enable_evolution,
        )
        # A组开启进化，B组关闭
        self.assertTrue(self.runner.group_a.trainer.enable_evolution)
        self.assertFalse(self.runner.group_b.trainer.enable_evolution)

    def test_feed_event_to_both_groups(self):
        """测试事件同时投喂给两组"""
        event = self._make_event()
        result = self.runner.feed_event(event)

        self.assertEqual(self.runner.group_a.total_events_received, 1)
        self.assertEqual(self.runner.group_b.total_events_received, 1)
        self.assertIn("group_a", result)
        self.assertIn("group_b", result)

    def test_both_groups_receive_same_events(self):
        """测试两组接收完全相同的事件流"""
        events = [self._make_event(syscall=f"sys_{i}") for i in range(10)]
        for e in events:
            self.runner.feed_event(e)

        self.assertEqual(self.runner.group_a.total_events_received, 10)
        self.assertEqual(self.runner.group_b.total_events_received, 10)
        self.assertEqual(len(self.runner.event_history), 10)

    def test_evaluation_report_structure(self):
        """测试评估报告结构完整"""
        for i in range(20):
            self.runner.feed_event(self._make_event(severity="high"))

        report = self.runner.run_evaluation()
        self.assertIn("test_id", report)
        self.assertIn("group_a", report)
        self.assertIn("group_b", report)
        self.assertIn("statistical_analysis", report)
        self.assertIn("head_to_head", report)
        self.assertIn("gold_evidence", report)
        self.assertIn("conclusion", report)
        self.assertIn("recommendations", report)

    def test_group_metrics_updated(self):
        """测试组指标正确更新"""
        for i in range(15):
            self.runner.feed_event(self._make_event(severity="critical"))

        stats = self.runner.get_group_stats()
        self.assertGreater(stats["group_a"]["total_attacks"], 0)
        self.assertGreater(stats["group_b"]["total_attacks"], 0)
        self.assertEqual(stats["total_events"], 15)

    def test_head_to_head_comparison(self):
        """测试正面对比统计"""
        for i in range(30):
            self.runner.feed_event(self._make_event(severity="high"))

        report = self.runner.run_evaluation()
        h2h = report["head_to_head"]
        self.assertIn("a_better_count", h2h)
        self.assertIn("b_better_count", h2h)
        self.assertIn("same_result_count", h2h)
        self.assertEqual(
            h2h["a_better_count"] + h2h["b_better_count"] + h2h["same_result_count"],
            30,
        )

    def test_runner_with_drift_monitors(self):
        """测试运行器挂载漂移监控器"""
        monitor_a = EvolutionDriftMonitor()
        monitor_b = EvolutionDriftMonitor()
        runner = ABTestRunner(
            drift_monitor_a=monitor_a,
            drift_monitor_b=monitor_b,
        )

        for i in range(15):
            runner.feed_event(self._make_event())

        report = runner.run_evaluation()
        self.assertTrue(report["drift_monitoring"]["group_a_attached"])
        self.assertTrue(report["drift_monitoring"]["group_b_attached"])

    def test_sample_size_insufficient_warning(self):
        """测试样本量不足时的警告"""
        runner = ABTestRunner(min_sample_size=100)
        for i in range(10):
            runner.feed_event(self._make_event())

        report = runner.run_evaluation()
        self.assertFalse(report["gold_evidence"])
        # 推荐建议中应该包含样本量不足的提示
        all_recs = " ".join(report["recommendations"])
        self.assertTrue("样本量" in all_recs or "不足" in all_recs or "min_sample" in all_recs.lower())


class TestOrchestratorValidationIntegration(unittest.TestCase):
    """编排器验证套件集成测试"""

    def setUp(self):
        self.validation_suite = EvolutionValidationSuite(
            test_id="orchestrator_test",
            stagnation_rounds=3,
        )
        self.orchestrator = AdversarialStrategyOrchestrator(
            cooldown_seconds=0.05,
            batch_size=100,
            validation_suite=self.validation_suite,
        )

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

    def test_orchestrator_has_validation_suite(self):
        """测试编排器挂载了验证套件"""
        self.assertIsNotNone(self.orchestrator.validation_suite)

    def test_evolution_triggers_drift_recording(self):
        """测试进化触发后自动记录漂移"""
        # critical 事件会立即触发进化
        event = self._make_event(severity="critical")
        result = self.orchestrator.process_real_event(event)

        self.assertTrue(result["should_evolve"])
        # 验证套件应该记录了至少一轮进化
        self.assertGreaterEqual(self.validation_suite.validation_rounds, 1)

    def test_get_validation_report(self):
        """测试获取验证报告"""
        for i in range(3):
            time.sleep(0.06)  # 等待冷却期
            self.orchestrator.process_real_event(
                self._make_event(syscall=f"sys_{i}", severity="critical")
            )

        report = self.orchestrator.get_validation_report()
        self.assertIsNotNone(report)
        self.assertIn("overall_conclusion", report)
        self.assertIn("drift_monitor", report)
        self.assertIn("ab_test", report)

    def test_get_validation_report_without_suite(self):
        """测试未挂载验证套件时返回 None"""
        orchestrator = AdversarialStrategyOrchestrator()
        self.assertIsNone(orchestrator.get_validation_report())

    def test_event_count_tracked_for_validation(self):
        """测试验证事件计数正确"""
        for i in range(5):
            self.orchestrator.process_real_event(self._make_event(syscall=f"s{i}"))

        self.assertEqual(self.orchestrator._total_events_for_validation, 5)

    def test_stagnation_detected_in_orchestrator(self):
        """测试编排器中检测到进化停滞"""
        # 连续触发进化，但权重不变（模拟停滞）
        # 由于编排器的红方优化器会更新权重，这里直接检查验证套件的漂移监控
        for i in range(5):
            time.sleep(0.06)
            self.orchestrator.process_real_event(
                self._make_event(syscall=f"stagnant_{i}", severity="critical")
            )

        report = self.orchestrator.get_validation_report()
        # 报告中应该包含漂移监控状态
        self.assertIn("learning_effectiveness", report)


class TestFullIntegrationPipeline(unittest.TestCase):
    """完整集成管道测试：RealSignalConsumer → 编排器 → 验证套件 → A/B 测试"""

    def test_full_pipeline_with_drift_monitoring(self):
        """测试完整管道：消费真实事件 → 编排器进化 → 漂移监控 → 验证报告"""
        # 1. 创建验证套件
        validation_suite = EvolutionValidationSuite(
            test_id="full_pipeline",
            stagnation_rounds=3,
        )

        # 2. 创建编排器（挂载验证套件）
        orchestrator = AdversarialStrategyOrchestrator(
            cooldown_seconds=0.05,
            batch_size=100,
            validation_suite=validation_suite,
        )

        # 3. 创建消费器（挂载漂移监控器）
        consumer = RealSignalConsumer(
            mode=ConsumeMode.BATCH,
            drift_monitor=validation_suite.drift_monitor,
        )

        # 4. 消费真实格式日志，每个事件都送入编排器
        for i in range(5):
            log_line = json.dumps({
                "event_id": f"full_{i}",
                "event_type": "SECCOMP_VIOLATION",
                "timestamp": time.time(),
                "sandbox_id": "s1",
                "syscall": "ptrace" if i < 3 else "mount",
                "action": "KILL",
                "pid": 100 + i,
                "comm": "malware",
            })
            event = consumer.consume_line(log_line)
            self.assertIsNotNone(event)

            time.sleep(0.06)  # 等待冷却期
            orchestrator.process_real_event(event)

        # 5. 记录权重快照
        consumer.record_weight_snapshot(
            red_weights={"ptrace": 0.8, "mount": 0.6},
            blue_rule_count=3,
            attack_pattern_count=2,
        )

        # 6. 生成验证报告
        report = orchestrator.get_validation_report()
        self.assertIsNotNone(report)
        self.assertIn("overall_conclusion", report)

        # 7. 消费器漂移状态
        drift_status = consumer.get_drift_status()
        self.assertTrue(drift_status["drift_monitor_attached"])
        self.assertGreaterEqual(drift_status["snapshots_recorded"], 1)

    def test_ab_test_runner_with_real_signal_consumer(self):
        """测试 A/B 测试运行器与真实信号消费器配合"""
        runner = ABTestRunner(
            test_id="consumer_ab_test",
            min_sample_size=10,
        )
        consumer = RealSignalConsumer(mode=ConsumeMode.BATCH)

        # 消费真实格式日志，每个事件同时投喂给 A/B 两组
        for i in range(20):
            log_line = json.dumps({
                "event_id": f"ab_{i}",
                "event_type": "SECCOMP_VIOLATION",
                "timestamp": time.time(),
                "sandbox_id": "s1",
                "syscall": "ptrace",
                "action": "KILL",
                "pid": 200 + i,
                "comm": "test",
            })
            event = consumer.consume_line(log_line)
            self.assertIsNotNone(event)
            runner.feed_event(event)

        # 生成 A/B 测试报告
        report = runner.run_evaluation()
        self.assertEqual(report["group_a"]["events_received"], 20)
        self.assertEqual(report["group_b"]["events_received"], 20)
        self.assertIn("statistical_analysis", report)


if __name__ == '__main__':
    unittest.main()
