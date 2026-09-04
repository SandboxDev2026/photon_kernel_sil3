"""
进化-防御桥接器与红蓝对抗框架集成测试

验证完整闭环：
真实事件 → 红蓝对抗训练 → 进化出防御规则 → 桥接器自动下发到底层沙盒
→ 规则触发监控 → 反馈同步回训练循环 → 再进化
"""

import time
import unittest

from evolution.evolution_defense_bridge import EvolutionDefenseBridge
from evolution.real_data_adapter import EventSource, SecurityEvent
from evolution.red_blue_adversary import RedBlueAdversaryTrainer


def make_security_event(
    event_id="evt_001",
    source=EventSource.SECCOMP_VIOLATION,
    severity="high",
    anomaly_score=0.8,
):
    return SecurityEvent(
        event_id=event_id,
        source=source,
        timestamp=time.time(),
        sandbox_id="sandbox_001",
        severity=severity,
        description="测试安全事件",
        payload={"syscall": "ptrace"},
        anomaly_type=None,
        anomaly_score=anomaly_score,
    )


class TestBridgeIntegrationBasic(unittest.TestCase):
    """桥接器集成基础测试"""

    def setUp(self):
        self.bridge = EvolutionDefenseBridge(
            min_triggers_before_monitoring=3,
            dry_run=True,
        )
        self.trainer = RedBlueAdversaryTrainer(
            defense_bridge=self.bridge,
            auto_deploy_evolved_rules=True,
        )

    def test_trainer_with_bridge_initialization(self):
        """测试带桥接器的训练器初始化"""
        self.assertIsNotNone(self.trainer.defense_bridge)
        self.assertTrue(self.trainer.auto_deploy_evolved_rules)
        self.assertEqual(len(self.trainer.bridge_deployment_history), 0)

    def test_trainer_without_bridge_no_auto_deploy(self):
        """测试无桥接器时自动部署关闭"""
        trainer = RedBlueAdversaryTrainer(auto_deploy_evolved_rules=True)
        self.assertIsNone(trainer.defense_bridge)
        self.assertFalse(trainer.auto_deploy_evolved_rules)

    def test_trainer_bridge_but_auto_deploy_off(self):
        """测试有桥接器但自动部署关闭"""
        trainer = RedBlueAdversaryTrainer(
            defense_bridge=self.bridge,
            auto_deploy_evolved_rules=False,
        )
        self.assertIsNotNone(trainer.defense_bridge)
        self.assertFalse(trainer.auto_deploy_evolved_rules)


class TestAutoDeploymentOnEvolution(unittest.TestCase):
    """进化时自动部署测试"""

    def setUp(self):
        self.bridge = EvolutionDefenseBridge(
            min_triggers_before_monitoring=3,
            dry_run=True,
        )
        self.trainer = RedBlueAdversaryTrainer(
            defense_bridge=self.bridge,
            auto_deploy_evolved_rules=True,
        )

    def test_high_severity_event_triggers_evolution_and_deploy(self):
        """测试高严重度事件触发进化并自动部署"""
        event = make_security_event(severity="high")
        result = self.trainer.ingest_real_event(event)

        self.assertTrue(result["triggered_evolution"])
        self.assertIn("bridge_deployment", result)
        self.assertTrue(result["bridge_deployment"]["deployed"])
        self.assertGreater(result["bridge_deployment"]["config_updates"], 0)

        # 部署历史应该有记录
        self.assertEqual(len(self.trainer.bridge_deployment_history), 1)
        self.assertEqual(
            self.trainer.bridge_deployment_history[0]["rule_id"],
            result["bridge_deployment"]["rule_id"],
        )

    def test_critical_severity_event_triggers_evolution_and_deploy(self):
        """测试 critical 严重度事件触发进化并自动部署"""
        event = make_security_event(severity="critical")
        result = self.trainer.ingest_real_event(event)

        self.assertTrue(result["triggered_evolution"])
        self.assertIn("bridge_deployment", result)
        self.assertTrue(result["bridge_deployment"]["deployed"])

    def test_low_severity_event_no_evolution_no_deploy(self):
        """测试低严重度事件不触发进化和部署"""
        event = make_security_event(severity="low")
        result = self.trainer.ingest_real_event(event)

        self.assertFalse(result["triggered_evolution"])
        self.assertNotIn("bridge_deployment", result)
        self.assertEqual(len(self.trainer.bridge_deployment_history), 0)

    def test_medium_severity_event_no_evolution_no_deploy(self):
        """测试中严重度事件不触发进化和部署"""
        event = make_security_event(severity="medium")
        result = self.trainer.ingest_real_event(event)

        self.assertFalse(result["triggered_evolution"])
        self.assertNotIn("bridge_deployment", result)

    def test_auto_deploy_off_no_bridge_deployment(self):
        """测试自动部署关闭时不通过桥接器下发"""
        trainer = RedBlueAdversaryTrainer(
            defense_bridge=self.bridge,
            auto_deploy_evolved_rules=False,
        )
        event = make_security_event(severity="high")
        result = trainer.ingest_real_event(event)

        self.assertTrue(result["triggered_evolution"])
        self.assertNotIn("bridge_deployment", result)
        self.assertEqual(len(trainer.bridge_deployment_history), 0)

    def test_multiple_events_multiple_deployments(self):
        """测试多个事件触发多次部署"""
        for i in range(3):
            event = make_security_event(event_id=f"evt_{i}", severity="high")
            self.trainer.ingest_real_event(event)

        self.assertEqual(len(self.trainer.bridge_deployment_history), 3)
        # 每个部署的 rule_id 应该不同
        rule_ids = [d["rule_id"] for d in self.trainer.bridge_deployment_history]
        self.assertEqual(len(set(rule_ids)), 3)


class TestRuleTriggerFeedbackSync(unittest.TestCase):
    """规则触发反馈同步测试"""

    def setUp(self):
        self.bridge = EvolutionDefenseBridge(
            min_triggers_before_monitoring=3,
            dry_run=True,
        )
        self.trainer = RedBlueAdversaryTrainer(
            defense_bridge=self.bridge,
            auto_deploy_evolved_rules=True,
        )

    def test_sync_rule_triggers_from_bridge(self):
        """测试从桥接器同步规则触发数据"""
        # 1. 进化并部署一条规则
        event = make_security_event(severity="high")
        result = self.trainer.ingest_real_event(event)
        rule_id = result["bridge_deployment"]["rule_id"]

        # 2. 在桥接器中记录触发（模拟底层沙盒的规则拦截效果）
        # 假阳性放在最后，避免前3次触发时误报率超阈值熔断
        for i in range(5):
            self.bridge.record_rule_trigger(rule_id, is_true_positive=(i < 4))

        # 3. 同步触发数据回训练循环
        sync_result = self.trainer.sync_rule_triggers_from_bridge()

        self.assertGreater(sync_result["synced"], 0)
        self.assertEqual(sync_result["bridge_circuit_broken"], 0)

        # 4. 验证规则的触发记录已更新
        rule = next(
            (r for r in self.trainer.blue_agent.defense_rules if r.rule_id == rule_id),
            None,
        )
        self.assertIsNotNone(rule)
        self.assertGreater(rule.trigger_count, 0)

    def test_sync_updates_rule_effectiveness(self):
        """测试同步更新规则 effectiveness"""
        event = make_security_event(severity="high")
        result = self.trainer.ingest_real_event(event)
        rule_id = result["bridge_deployment"]["rule_id"]

        # 记录 8 次真阳性，2 次假阳性（精确率 80%）
        for i in range(10):
            self.bridge.record_rule_trigger(rule_id, is_true_positive=(i < 8))

        self.trainer.sync_rule_triggers_from_bridge()

        rule = next(
            (r for r in self.trainer.blue_agent.defense_rules if r.rule_id == rule_id),
            None,
        )
        self.assertIsNotNone(rule)
        # effectiveness 应该接近 0.8（桥接器精确率）
        self.assertAlmostEqual(rule.effectiveness, 0.8, delta=0.05)

    def test_sync_without_bridge(self):
        """测试无桥接器时同步返回空"""
        trainer = RedBlueAdversaryTrainer()
        result = trainer.sync_rule_triggers_from_bridge()
        self.assertEqual(result["synced"], 0)
        self.assertEqual(result["reason"], "no_bridge")


class TestBridgeDeploymentStats(unittest.TestCase):
    """桥接器部署统计测试"""

    def setUp(self):
        self.bridge = EvolutionDefenseBridge(
            min_triggers_before_monitoring=3,
            dry_run=True,
        )
        self.trainer = RedBlueAdversaryTrainer(
            defense_bridge=self.bridge,
            auto_deploy_evolved_rules=True,
        )

    def test_get_bridge_deployment_stats_empty(self):
        """测试空部署统计"""
        stats = self.trainer.get_bridge_deployment_stats()
        self.assertTrue(stats["enabled"])
        self.assertTrue(stats["auto_deploy"])
        self.assertEqual(stats["total_deployments"], 0)
        self.assertEqual(stats["successful_deployments"], 0)

    def test_get_bridge_deployment_stats_after_deploy(self):
        """测试部署后统计"""
        for i in range(2):
            event = make_security_event(event_id=f"evt_{i}", severity="high")
            self.trainer.ingest_real_event(event)

        stats = self.trainer.get_bridge_deployment_stats()
        self.assertEqual(stats["total_deployments"], 2)
        self.assertEqual(stats["successful_deployments"], 2)
        self.assertEqual(len(stats["recent_deployments"]), 2)

    def test_get_bridge_deployment_stats_without_bridge(self):
        """测试无桥接器时统计"""
        trainer = RedBlueAdversaryTrainer()
        stats = trainer.get_bridge_deployment_stats()
        self.assertFalse(stats["enabled"])


class TestFullClosedLoop(unittest.TestCase):
    """完整闭环端到端测试"""

    def test_full_loop_evolve_deploy_monitor_sync_re_evolve(self):
        """测试完整闭环：进化→部署→监控→同步→再进化"""
        bridge = EvolutionDefenseBridge(
            min_triggers_before_monitoring=3,
            false_positive_threshold=0.3,
            auto_rollback_enabled=False,
            dry_run=True,
        )
        trainer = RedBlueAdversaryTrainer(
            defense_bridge=bridge,
            auto_deploy_evolved_rules=True,
        )

        # 阶段1：真实事件触发进化并自动部署
        event1 = make_security_event(event_id="evt_001", severity="high")
        result1 = trainer.ingest_real_event(event1)
        self.assertTrue(result1["triggered_evolution"])
        self.assertTrue(result1["bridge_deployment"]["deployed"])
        rule_id = result1["bridge_deployment"]["rule_id"]

        initial_rule_count = len(trainer.blue_agent.defense_rules)
        self.assertGreaterEqual(initial_rule_count, 1)

        # 阶段2：底层沙盒规则拦截效果监控（模拟）
        # 规则表现良好：8次真阳性，2次假阳性
        for i in range(10):
            bridge.record_rule_trigger(rule_id, is_true_positive=(i < 8))

        # 阶段3：同步触发数据回训练循环
        sync_result = trainer.sync_rule_triggers_from_bridge()
        self.assertGreater(sync_result["synced"], 0)

        # 验证规则 effectiveness 已更新
        rule = next(
            (r for r in trainer.blue_agent.defense_rules if r.rule_id == rule_id),
            None,
        )
        self.assertIsNotNone(rule)
        self.assertAlmostEqual(rule.effectiveness, 0.8, delta=0.05)

        # 阶段4：新的真实事件触发再进化
        event2 = make_security_event(
            event_id="evt_002",
            source=EventSource.NETWORK_BLOCK,
            severity="critical",
        )
        result2 = trainer.ingest_real_event(event2)
        self.assertTrue(result2["triggered_evolution"])
        self.assertTrue(result2["bridge_deployment"]["deployed"])

        # 规则数量应该增加
        self.assertGreater(len(trainer.blue_agent.defense_rules), initial_rule_count)

        # 部署历史应该有2条
        self.assertEqual(len(trainer.bridge_deployment_history), 2)

        # 阶段5：验证桥接器统计
        stats = trainer.get_bridge_deployment_stats()
        self.assertEqual(stats["total_deployments"], 2)
        self.assertEqual(stats["successful_deployments"], 2)

    def test_full_loop_with_circuit_breaker(self):
        """测试完整闭环中熔断器触发后的行为"""
        bridge = EvolutionDefenseBridge(
            min_triggers_before_monitoring=3,
            false_positive_threshold=0.3,
            auto_rollback_enabled=True,
            dry_run=True,
        )
        trainer = RedBlueAdversaryTrainer(
            defense_bridge=bridge,
            auto_deploy_evolved_rules=True,
        )

        # 进化并部署规则
        event = make_security_event(severity="high")
        result = trainer.ingest_real_event(event)
        rule_id = result["bridge_deployment"]["rule_id"]

        # 规则表现差：全部假阳性，触发熔断+自动回滚（5次确保同步阈值满足）
        for i in range(5):
            bridge.record_rule_trigger(rule_id, is_true_positive=False)

        # 验证规则已熔断并回滚
        status = bridge.get_deployment_status(rule_id)
        self.assertEqual(status["deployment_status"], "rolled_back")

        # 同步后，规则 effectiveness 应该很低
        trainer.sync_rule_triggers_from_bridge()
        rule = next(
            (r for r in trainer.blue_agent.defense_rules if r.rule_id == rule_id),
            None,
        )
        self.assertIsNotNone(rule)
        self.assertLess(rule.effectiveness, 0.5)

        # 桥接器统计应该显示熔断
        stats = trainer.get_bridge_deployment_stats()
        self.assertGreater(stats["bridge_stats"]["total_circuit_breaks"], 0)
        self.assertGreater(stats["bridge_stats"]["total_rollbacks"], 0)


if __name__ == '__main__':
    unittest.main()
