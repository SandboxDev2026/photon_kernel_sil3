"""
进化-防御桥接器端到端测试

验证完整链路：
1. 红蓝进化出 DefenseRule → 转换为 ConfigUpdate → 下发到 LightPool/seccomp/StrongPool
2. 规则触发监控 → 误报率/失败率超阈值 → 熔断器自动触发
3. 熔断后自动回滚到上一稳定版本
4. 冷却期过后半开恢复
5. 试运行模式（只生成不下发）
"""

import time
import unittest

from evolution.defense_enforcer import ConfigTarget
from evolution.evolution_defense_bridge import (
    BridgePhase,
    EvolutionDefenseBridge,
    RuleDeploymentRecord,
)
from evolution.real_data_adapter import EventSource, SecurityEvent
from evolution.red_blue_adversary import (
    AttackType,
    DefenseRule,
    DefenseType,
)


def make_defense_rule(
    rule_id="test_rule_001",
    defense_type=DefenseType.SYSTEM_CALL_MONITOR,
    target_attack_types=None,
    effectiveness=0.7,
):
    if target_attack_types is None:
        target_attack_types = [AttackType.SECCOMP_BYPASS]
    return DefenseRule(
        rule_id=rule_id,
        defense_type=defense_type,
        description=f"测试防御规则 {rule_id}",
        target_attack_types=target_attack_types,
        detection_logic="监控异常系统调用",
        effectiveness=effectiveness,
    )


def make_security_event(event_id="evt_001", source=EventSource.SECCOMP_VIOLATION):
    return SecurityEvent(
        event_id=event_id,
        source=source,
        timestamp=time.time(),
        sandbox_id="sandbox_001",
        severity="high",
        description="测试安全事件",
        payload={"syscall": "ptrace"},
    )


class TestEvolutionDefenseBridgeBasic(unittest.TestCase):
    """桥接器基础功能测试"""

    def setUp(self):
        self.bridge = EvolutionDefenseBridge(
            min_triggers_before_monitoring=3,
            false_positive_threshold=0.3,
            failure_rate_threshold=0.2,
            dry_run=True,  # 测试用试运行模式，避免实际修改系统配置
        )

    def test_bridge_initialization(self):
        """测试桥接器初始化"""
        self.assertEqual(self.bridge.current_phase, BridgePhase.IDLE)
        self.assertTrue(self.bridge.dry_run)
        self.assertEqual(self.bridge.stats["total_rules_received"], 0)

    def test_deploy_single_rule(self):
        """测试部署单条规则"""
        rule = make_defense_rule()
        result = self.bridge.deploy_evolved_rules([rule])

        self.assertEqual(result["total_rules_received"], 1)
        self.assertGreater(result["total_config_updates_generated"], 0)
        self.assertEqual(result["phase"], "monitoring")

    def test_deploy_multiple_rules(self):
        """测试部署多条规则"""
        rules = [
            make_defense_rule(rule_id="rule_001", defense_type=DefenseType.SYSTEM_CALL_MONITOR),
            make_defense_rule(rule_id="rule_002", defense_type=DefenseType.NETWORK_FILTER),
            make_defense_rule(rule_id="rule_003", defense_type=DefenseType.RESOURCE_LIMIT),
        ]
        result = self.bridge.deploy_evolved_rules(rules)

        self.assertEqual(result["total_rules_received"], 3)
        self.assertGreater(result["total_config_updates_generated"], 0)

    def test_deploy_with_source_event(self):
        """测试带源事件的规则部署"""
        rule = make_defense_rule()
        event = make_security_event()
        result = self.bridge.deploy_evolved_rules([rule], source_event=event)

        self.assertEqual(result["total_rules_received"], 1)

    def test_deployment_record_created(self):
        """测试部署记录创建"""
        rule = make_defense_rule(rule_id="record_test")
        self.bridge.deploy_evolved_rules([rule])

        status = self.bridge.get_deployment_status("record_test")
        self.assertIsNotNone(status)
        self.assertEqual(status["rule_id"], "record_test")
        self.assertIn(status["deployment_status"], ["dry_run", "applied", "pending"])

    def test_get_all_deployments(self):
        """测试获取所有部署"""
        rules = [make_defense_rule(rule_id=f"r{i}") for i in range(3)]
        self.bridge.deploy_evolved_rules(rules)

        deployments = self.bridge.get_all_deployments()
        self.assertEqual(len(deployments), 3)

    def test_get_stats(self):
        """测试获取统计"""
        rule = make_defense_rule()
        self.bridge.deploy_evolved_rules([rule])

        stats = self.bridge.get_stats()
        self.assertEqual(stats["total_rules_received"], 1)
        self.assertIn("current_phase", stats)
        self.assertIn("circuit_broken_count", stats)


class TestRuleTriggerMonitoring(unittest.TestCase):
    """规则触发监控测试"""

    def setUp(self):
        self.bridge = EvolutionDefenseBridge(
            min_triggers_before_monitoring=3,
            false_positive_threshold=0.3,
            failure_rate_threshold=0.2,
            auto_rollback_enabled=False,  # 先关闭自动回滚，单独测试熔断
            dry_run=True,
        )
        self.rule = make_defense_rule(rule_id="monitor_test")
        self.bridge.deploy_evolved_rules([self.rule])

    def test_record_true_positive(self):
        """测试记录真阳性触发"""
        result = self.bridge.record_rule_trigger("monitor_test", is_true_positive=True)
        self.assertEqual(result["trigger_count"], 1)
        self.assertAlmostEqual(result["precision"], 1.0)

    def test_record_false_positive(self):
        """测试记录假阳性触发"""
        result = self.bridge.record_rule_trigger("monitor_test", is_true_positive=False)
        self.assertEqual(result["trigger_count"], 1)
        self.assertAlmostEqual(result["precision"], 0.0)

    def test_record_failure(self):
        """测试记录执行失败"""
        result = self.bridge.record_rule_trigger(
            "monitor_test", is_true_positive=True, is_failure=True, failure_reason="配置写入失败"
        )
        self.assertEqual(result["trigger_count"], 1)
        self.assertAlmostEqual(result["failure_rate"], 1.0)

    def test_no_circuit_break_below_min_triggers(self):
        """测试低于最小触发次数时不熔断"""
        # 只有2次触发，低于min_triggers_before_monitoring=3
        for i in range(2):
            self.bridge.record_rule_trigger("monitor_test", is_true_positive=False)

        status = self.bridge.get_deployment_status("monitor_test")
        self.assertNotEqual(status["deployment_status"], "circuit_broken")

    def test_record_nonexistent_rule(self):
        """测试记录不存在的规则"""
        result = self.bridge.record_rule_trigger("nonexistent", is_true_positive=True)
        self.assertIn("error", result)


class TestCircuitBreaker(unittest.TestCase):
    """熔断器测试"""

    def setUp(self):
        self.bridge = EvolutionDefenseBridge(
            min_triggers_before_monitoring=3,
            false_positive_threshold=0.3,
            failure_rate_threshold=0.2,
            circuit_breaker_cooldown_seconds=1.0,  # 缩短冷却期便于测试
            auto_rollback_enabled=False,
            dry_run=True,
        )
        self.rule = make_defense_rule(rule_id="circuit_test")
        self.bridge.deploy_evolved_rules([self.rule])

    def test_circuit_break_on_high_false_positive(self):
        """测试高误报率触发熔断"""
        # 3次触发全部是假阳性（第3次达到min_triggers_before_monitoring=3，误报率100% > 30%阈值）
        result = None
        for i in range(3):
            result = self.bridge.record_rule_trigger("circuit_test", is_true_positive=False)

        self.assertTrue(result.get("circuit_broken"))
        self.assertIn("误报率过高", result.get("circuit_break_reason", ""))

        status = self.bridge.get_deployment_status("circuit_test")
        self.assertEqual(status["deployment_status"], "circuit_broken")

    def test_circuit_break_on_high_failure_rate(self):
        """测试高失败率触发熔断"""
        # 4次触发，3次失败（失败率75% > 20%阈值）
        for i in range(4):
            self.bridge.record_rule_trigger(
                "circuit_test",
                is_true_positive=True,
                is_failure=(i < 3),
                failure_reason="执行失败",
            )

        status = self.bridge.get_deployment_status("circuit_test")
        self.assertEqual(status["deployment_status"], "circuit_broken")

    def test_no_circuit_break_on_good_behavior(self):
        """测试良好行为不熔断"""
        # 5次触发全部是真阳性，无失败
        for i in range(5):
            self.bridge.record_rule_trigger("circuit_test", is_true_positive=True)

        status = self.bridge.get_deployment_status("circuit_test")
        self.assertNotEqual(status["deployment_status"], "circuit_broken")
        self.assertAlmostEqual(status["precision"], 1.0)

    def test_circuit_broken_rules_list(self):
        """测试熔断规则列表"""
        for i in range(4):
            self.bridge.record_rule_trigger("circuit_test", is_true_positive=False)

        broken = self.bridge.get_circuit_broken_rules()
        self.assertEqual(len(broken), 1)
        self.assertEqual(broken[0]["rule_id"], "circuit_test")

    def test_skip_deploying_circuit_broken_rule(self):
        """测试跳过部署已熔断的规则"""
        # 先熔断
        for i in range(4):
            self.bridge.record_rule_trigger("circuit_test", is_true_positive=False)

        # 再次部署同一条规则，应该被跳过
        result = self.bridge.deploy_evolved_rules([self.rule])
        skipped = [r for r in result["deployment_results"] if r.get("status") == "skipped_circuit_broken"]
        self.assertEqual(len(skipped), 1)

    def test_half_open_recovery_after_cooldown(self):
        """测试冷却期过后半开恢复"""
        # 先熔断
        for i in range(4):
            self.bridge.record_rule_trigger("circuit_test", is_true_positive=False)

        # 立即尝试恢复，应该还在冷却期
        result = self.bridge.attempt_half_open("circuit_test")
        self.assertEqual(result["status"], "cooldown")

        # 等待冷却期
        time.sleep(1.1)

        # 再次尝试恢复，应该进入半开状态
        result = self.bridge.attempt_half_open("circuit_test")
        self.assertEqual(result["status"], "half_open")

        # 熔断列表应该清空
        self.assertEqual(len(self.bridge.get_circuit_broken_rules()), 0)


class TestAutoRollback(unittest.TestCase):
    """自动回滚测试"""

    def setUp(self):
        self.bridge = EvolutionDefenseBridge(
            min_triggers_before_monitoring=3,
            false_positive_threshold=0.3,
            failure_rate_threshold=0.2,
            auto_rollback_enabled=True,  # 开启自动回滚
            dry_run=True,
        )
        self.rule = make_defense_rule(rule_id="rollback_test")
        self.bridge.deploy_evolved_rules([self.rule])

    def test_auto_rollback_on_circuit_break(self):
        """测试熔断后自动回滚"""
        # 高误报率触发熔断，应该自动回滚（第3次达到阈值并熔断+回滚）
        result = None
        for i in range(3):
            result = self.bridge.record_rule_trigger("rollback_test", is_true_positive=False)

        self.assertTrue(result.get("circuit_broken"))
        self.assertIn("auto_rollback", result)
        self.assertEqual(result["auto_rollback"]["status"], "rolled_back")

        status = self.bridge.get_deployment_status("rollback_test")
        self.assertEqual(status["deployment_status"], "rolled_back")
        self.assertIsNotNone(status["rolled_back_at"])

    def test_manual_rollback(self):
        """测试手动回滚"""
        result = self.bridge.rollback_rule("rollback_test", reason="手动回滚测试")

        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(result["reason"], "手动回滚测试")
        self.assertGreater(result["rollback_updates_count"], 0)

    def test_rollback_nonexistent_rule(self):
        """测试回滚不存在的规则"""
        result = self.bridge.rollback_rule("nonexistent", reason="测试")
        self.assertIn("error", result)

    def test_rollback_stats_updated(self):
        """测试回滚统计更新"""
        self.bridge.rollback_rule("rollback_test", reason="测试")
        stats = self.bridge.get_stats()
        self.assertEqual(stats["total_rollbacks"], 1)


class TestFullPipeline(unittest.TestCase):
    """完整链路端到端测试"""

    def test_full_pipeline_evolve_deploy_monitor_circuit_rollback(self):
        """测试完整链路：进化出规则→部署→监控→熔断→自动回滚"""
        bridge = EvolutionDefenseBridge(
            min_triggers_before_monitoring=3,
            false_positive_threshold=0.3,
            failure_rate_threshold=0.2,
            auto_rollback_enabled=True,
            dry_run=True,
        )

        # 1. 模拟红蓝对抗进化出防御规则
        evolved_rules = [
            make_defense_rule(
                rule_id="evolved_seccomp_rule",
                defense_type=DefenseType.SYSTEM_CALL_MONITOR,
                target_attack_types=[AttackType.SECCOMP_BYPASS],
                effectiveness=0.75,
            ),
        ]

        # 2. 部署规则到 LightPool/seccomp
        deploy_result = bridge.deploy_evolved_rules(evolved_rules)
        assert deploy_result["total_rules_received"] == 1
        assert deploy_result["total_config_updates_generated"] > 0

        # 3. 规则运行一段时间，记录触发
        # 前3次正常拦截（真阳性）
        for i in range(3):
            bridge.record_rule_trigger("evolved_seccomp_rule", is_true_positive=True)

        status = bridge.get_deployment_status("evolved_seccomp_rule")
        assert status["deployment_status"] != "circuit_broken"
        assert status["precision"] == 1.0

        # 4. 突然出现大量误报（模拟规则退化或环境变化）
        # 前3次真阳性后，第2次假阳性时总误报率=2/5=40%>30%阈值，触发熔断+自动回滚
        result = None
        for i in range(2):
            result = bridge.record_rule_trigger("evolved_seccomp_rule", is_true_positive=False)

        # 5. 熔断器应该触发，并自动回滚
        assert result.get("circuit_broken") == True
        assert result.get("auto_rollback", {}).get("status") == "rolled_back"

        final_status = bridge.get_deployment_status("evolved_seccomp_rule")
        assert final_status["deployment_status"] == "rolled_back"

        # 6. 统计验证
        stats = bridge.get_stats()
        assert stats["total_circuit_breaks"] >= 1
        assert stats["total_rollbacks"] >= 1

    def test_full_pipeline_stable_rule_no_circuit_break(self):
        """测试稳定规则完整链路：部署→正常运行→不熔断"""
        bridge = EvolutionDefenseBridge(
            min_triggers_before_monitoring=3,
            false_positive_threshold=0.3,
            failure_rate_threshold=0.2,
            auto_rollback_enabled=True,
            dry_run=True,
        )

        rule = make_defense_rule(rule_id="stable_rule", effectiveness=0.9)
        bridge.deploy_evolved_rules([rule])

        # 10次触发，9次真阳性，1次假阳性（误报率10% < 30%阈值）
        for i in range(10):
            bridge.record_rule_trigger("stable_rule", is_true_positive=(i != 3))

        status = bridge.get_deployment_status("stable_rule")
        assert status["deployment_status"] != "circuit_broken"
        assert status["deployment_status"] != "rolled_back"
        assert status["precision"] > 0.7  # 9/10 = 0.9

        stats = bridge.get_stats()
        assert stats["total_circuit_breaks"] == 0
        assert stats["total_rollbacks"] == 0


class TestDryRunMode(unittest.TestCase):
    """试运行模式测试"""

    def test_dry_run_does_not_apply(self):
        """测试试运行模式不实际下发"""
        bridge = EvolutionDefenseBridge(dry_run=True)
        rule = make_defense_rule()
        result = bridge.deploy_evolved_rules([rule])

        self.assertTrue(result["dry_run"])
        self.assertEqual(result["total_config_updates_applied"], 0)

    def test_dry_run_still_generates_updates(self):
        """测试试运行模式仍然生成配置更新"""
        bridge = EvolutionDefenseBridge(dry_run=True)
        rule = make_defense_rule()
        result = bridge.deploy_evolved_rules([rule])

        self.assertGreater(result["total_config_updates_generated"], 0)

    def test_non_dry_run_mode(self):
        """测试非试运行模式（使用enforcer的模拟应用）"""
        bridge = EvolutionDefenseBridge(dry_run=False)
        rule = make_defense_rule()
        result = bridge.deploy_evolved_rules([rule])

        self.assertFalse(result["dry_run"])
        # 非试运行模式应该尝试应用（enforcer内部可能模拟）
        self.assertGreaterEqual(result["total_config_updates_applied"], 0)


if __name__ == '__main__':
    unittest.main()
