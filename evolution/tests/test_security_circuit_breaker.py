"""
PhotonBox 安全熔断隔离引擎 - 单元测试
"""

import unittest
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evolution.security_circuit_breaker import (
    SecurityCircuitBreaker,
    SecurityEvent,
    CircuitBreakerAction,
    CircuitBreakerLevel,
    CircuitBreakerState,
    TriggerType,
    TriggerRule,
    create_circuit_breaker,
)


class TestSecurityEvent(unittest.TestCase):
    """安全事件测试"""

    def test_create_event(self):
        event = SecurityEvent(
            event_id="evt_001",
            timestamp=time.time(),
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            severity="critical",
            instance_id="inst-001",
            description="ptrace attempt",
        )
        self.assertEqual(event.event_id, "evt_001")
        self.assertEqual(event.trigger_type, TriggerType.HIGH_RISK_SYSCALL)
        self.assertEqual(event.severity, "critical")

    def test_event_to_dict(self):
        event = SecurityEvent(
            event_id="evt_002",
            timestamp=1234567890.0,
            trigger_type=TriggerType.C2_CONNECTION,
            severity="critical",
        )
        d = event.to_dict()
        self.assertEqual(d["event_id"], "evt_002")
        self.assertEqual(d["trigger_type"], "c2_connection")
        self.assertEqual(d["severity"], "critical")


class TestCircuitBreakerLevel(unittest.TestCase):
    """熔断级别测试"""

    def test_level_order(self):
        levels = list(CircuitBreakerLevel)
        self.assertEqual(levels[0], CircuitBreakerLevel.L1_INSTANCE)
        self.assertEqual(levels[1], CircuitBreakerLevel.L2_NODE)
        self.assertEqual(levels[2], CircuitBreakerLevel.L3_CLUSTER)
        self.assertEqual(levels[3], CircuitBreakerLevel.L4_EMERGENCY)


class TestCircuitBreakerState(unittest.TestCase):
    """熔断状态测试"""

    def test_states(self):
        self.assertEqual(CircuitBreakerState.CLOSED.value, "closed")
        self.assertEqual(CircuitBreakerState.OPEN.value, "open")
        self.assertEqual(CircuitBreakerState.HALF_OPEN.value, "half_open")
        self.assertEqual(CircuitBreakerState.MANUAL_HOLD.value, "manual_hold")


class TestTriggerRule(unittest.TestCase):
    """触发规则测试"""

    def test_create_rule(self):
        rule = TriggerRule(
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            level=CircuitBreakerLevel.L1_INSTANCE,
            threshold=1,
            window_seconds=60,
            description="test rule",
        )
        self.assertTrue(rule.enabled)
        self.assertEqual(rule.cooldown_seconds, 300)

    def test_disable_rule(self):
        rule = TriggerRule(
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            level=CircuitBreakerLevel.L1_INSTANCE,
            threshold=1,
            window_seconds=60,
        )
        rule.enabled = False
        self.assertFalse(rule.enabled)


class TestSecurityCircuitBreaker(unittest.TestCase):
    """安全熔断引擎测试"""

    def setUp(self):
        self.alerts = []
        self.isolations = []

        def alert_cb(action):
            self.alerts.append(action)

        def isolation_cb(instance_id, level):
            self.isolations.append((instance_id, level))
            return True

        self.cb = SecurityCircuitBreaker(
            node_id="test-node",
            alert_callback=alert_cb,
            isolation_callback=isolation_cb,
        )

    def tearDown(self):
        self.cb.shutdown()

    def test_initial_state(self):
        state = self.cb.get_current_state()
        self.assertEqual(state["state"], "closed")
        self.assertIsNone(state["level"])

    def test_high_risk_syscall_triggers_l1(self):
        event = SecurityEvent(
            event_id="evt_001",
            timestamp=time.time(),
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            severity="critical",
            instance_id="inst-001",
            description="ptrace",
        )
        action = self.cb.report_event(event)
        self.assertIsNotNone(action)
        self.assertEqual(action.level, CircuitBreakerLevel.L1_INSTANCE)
        self.assertEqual(action.state, CircuitBreakerState.OPEN)
        self.assertEqual(len(self.alerts), 1)
        self.assertEqual(len(self.isolations), 1)

    def test_c2_connection_triggers_l1(self):
        event = SecurityEvent(
            event_id="evt_002",
            timestamp=time.time(),
            trigger_type=TriggerType.C2_CONNECTION,
            severity="critical",
            instance_id="inst-002",
            description="C2 connection",
        )
        action = self.cb.report_event(event)
        self.assertIsNotNone(action)
        self.assertEqual(action.level, CircuitBreakerLevel.L1_INSTANCE)

    def test_audit_hmac_triggers_l3(self):
        event = SecurityEvent(
            event_id="evt_003",
            timestamp=time.time(),
            trigger_type=TriggerType.AUDIT_HMAC_ANOMALY,
            severity="critical",
            description="HMAC mismatch",
        )
        action = self.cb.report_event(event)
        self.assertIsNotNone(action)
        self.assertEqual(action.level, CircuitBreakerLevel.L3_CLUSTER)
        self.assertTrue(action.requires_manual_confirmation)

    def test_manual_recover(self):
        event = SecurityEvent(
            event_id="evt_004",
            timestamp=time.time(),
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            severity="critical",
            instance_id="inst-004",
        )
        action = self.cb.report_event(event)
        self.assertIsNotNone(action)

        success = self.cb.manual_recover(action.action_id, "admin")
        self.assertTrue(success)

        state = self.cb.get_current_state()
        self.assertEqual(state["state"], "closed")
        self.assertIsNone(state["level"])

    def test_manual_recover_invalid_id(self):
        success = self.cb.manual_recover("nonexistent", "admin")
        self.assertFalse(success)

    def test_manual_trigger(self):
        action = self.cb.manual_trigger(
            level=CircuitBreakerLevel.L4_EMERGENCY,
            reason="emergency shutdown",
        )
        self.assertEqual(action.level, CircuitBreakerLevel.L4_EMERGENCY)
        self.assertTrue(action.requires_manual_confirmation)

    def test_seccomp_surge_triggers_l2(self):
        for i in range(105):
            event = SecurityEvent(
                event_id=f"evt_{i}",
                timestamp=time.time(),
                trigger_type=TriggerType.SECCOMP_VIOLATION_SURGE,
                severity="warning",
                instance_id=f"inst-{i}",
            )
            result = self.cb.report_event(event)
            if result:
                self.assertEqual(result.level, CircuitBreakerLevel.L2_NODE)
                break
        else:
            self.fail("L2 circuit breaker not triggered")

    def test_cooldown_prevents_retrigger(self):
        event = SecurityEvent(
            event_id="evt_cd1",
            timestamp=time.time(),
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            severity="critical",
            instance_id="inst-cd1",
        )
        action1 = self.cb.report_event(event)
        self.assertIsNotNone(action1)

        # 立即再次触发，应该被冷却阻止
        event2 = SecurityEvent(
            event_id="evt_cd2",
            timestamp=time.time(),
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            severity="critical",
            instance_id="inst-cd2",
        )
        action2 = self.cb.report_event(event2)
        self.assertIsNone(action2)

    def test_c2_indicator_detection(self):
        self.cb.add_c2_indicator("evil.example.com")
        self.assertTrue(self.cb.check_c2_connection("evil.example.com"))
        self.assertFalse(self.cb.check_c2_connection("good.example.com"))

    def test_c2_indicator_case_insensitive(self):
        self.cb.add_c2_indicator("Evil.Example.COM")
        self.assertTrue(self.cb.check_c2_connection("evil.example.com"))

    def test_get_stats(self):
        event = SecurityEvent(
            event_id="evt_stats",
            timestamp=time.time(),
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            severity="critical",
            instance_id="inst-stats",
        )
        self.cb.report_event(event)

        stats = self.cb.get_stats()
        self.assertEqual(stats["node_id"], "test-node")
        self.assertGreater(stats["total_events"], 0)
        self.assertGreater(stats["total_actions"], 0)
        self.assertIn("L1_instance", stats["actions_by_level"])

    def test_get_action_history(self):
        for i in range(3):
            event = SecurityEvent(
                event_id=f"evt_hist_{i}",
                timestamp=time.time(),
                trigger_type=TriggerType.C2_CONNECTION,
                severity="critical",
                instance_id=f"inst-hist-{i}",
            )
            self.cb.report_event(event)
            time.sleep(0.1)  # 避免冷却

        history = self.cb.get_action_history()
        self.assertGreaterEqual(len(history), 1)

    def test_update_rule(self):
        self.cb.update_rule(
            TriggerType.HIGH_RISK_SYSCALL,
            threshold=5,
            cooldown_seconds=60,
        )
        # 验证规则已更新（通过检查触发行为）
        for i in range(4):
            event = SecurityEvent(
                event_id=f"evt_update_{i}",
                timestamp=time.time(),
                trigger_type=TriggerType.HIGH_RISK_SYSCALL,
                severity="critical",
                instance_id=f"inst-update-{i}",
            )
            result = self.cb.report_event(event)
            self.assertIsNone(result)  # 阈值提高到5，4次不应触发

    def test_no_isolation_callback(self):
        cb = SecurityCircuitBreaker(node_id="test-no-iso")
        event = SecurityEvent(
            event_id="evt_no_iso",
            timestamp=time.time(),
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            severity="critical",
            instance_id="inst-no-iso",
        )
        action = cb.report_event(event)
        self.assertIsNotNone(action)
        cb.shutdown()

    def test_isolation_failure(self):
        def failing_isolation(instance_id, level):
            return False

        cb = SecurityCircuitBreaker(
            node_id="test-fail-iso",
            isolation_callback=failing_isolation,
        )
        event = SecurityEvent(
            event_id="evt_fail_iso",
            timestamp=time.time(),
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            severity="critical",
            instance_id="inst-fail-iso",
        )
        action = cb.report_event(event)
        self.assertIsNotNone(action)  # 隔离失败不影响熔断触发
        cb.shutdown()

    def test_resource_spike_trigger(self):
        event = SecurityEvent(
            event_id="evt_resource",
            timestamp=time.time(),
            trigger_type=TriggerType.RESOURCE_SPIKE,
            severity="warning",
            instance_id="inst-resource",
            metadata={"spike_ratio": 5.0},
        )
        action = self.cb.report_event(event)
        self.assertIsNotNone(action)
        self.assertEqual(action.level, CircuitBreakerLevel.L1_INSTANCE)

    def test_rule_confidence_drop_trigger(self):
        event = SecurityEvent(
            event_id="evt_confidence",
            timestamp=time.time(),
            trigger_type=TriggerType.RULE_CONFIDENCE_DROP,
            severity="warning",
            metadata={"confidence": 0.005},
        )
        action = self.cb.report_event(event)
        self.assertIsNotNone(action)
        self.assertEqual(action.level, CircuitBreakerLevel.L2_NODE)


class TestCreateCircuitBreaker(unittest.TestCase):
    """便捷函数测试"""

    def test_create_default(self):
        cb = create_circuit_breaker()
        self.assertIsInstance(cb, SecurityCircuitBreaker)
        self.assertEqual(cb.node_id, "default-node")
        cb.shutdown()

    def test_create_with_callbacks(self):
        cb = create_circuit_breaker(
            node_id="custom-node",
            alert_callback=lambda x: None,
            isolation_callback=lambda x, y: True,
        )
        self.assertEqual(cb.node_id, "custom-node")
        cb.shutdown()


class TestCircuitBreakerAction(unittest.TestCase):
    """熔断动作测试"""

    def test_create_action(self):
        action = CircuitBreakerAction(
            action_id="act_001",
            timestamp=time.time(),
            level=CircuitBreakerLevel.L1_INSTANCE,
            state=CircuitBreakerState.OPEN,
            trigger_event_id="evt_001",
            description="test",
        )
        self.assertEqual(action.action_id, "act_001")
        self.assertFalse(action.requires_manual_confirmation)

    def test_action_to_dict(self):
        action = CircuitBreakerAction(
            action_id="act_002",
            timestamp=1234567890.0,
            level=CircuitBreakerLevel.L3_CLUSTER,
            state=CircuitBreakerState.OPEN,
            trigger_event_id="evt_002",
            requires_manual_confirmation=True,
        )
        d = action.to_dict()
        self.assertEqual(d["action_id"], "act_002")
        self.assertEqual(d["level"], "L3_cluster")
        self.assertTrue(d["requires_manual_confirmation"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
