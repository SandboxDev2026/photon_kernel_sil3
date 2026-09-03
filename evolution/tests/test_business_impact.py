"""
业务影响面度量模块测试（第十三条）
"""

import unittest
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from ops.business_impact_metrics import (
    BusinessImpactTracker, PoolType, ImpactEventType,
    ImpactEvent, PoolCapacity
)


class TestBusinessImpactTracker(unittest.TestCase):
    """业务影响面跟踪器测试"""

    def setUp(self):
        self.tracker = BusinessImpactTracker()
        # 配置LightPool容量
        self.tracker.configure_pool(PoolCapacity(
            pool_type=PoolType.LIGHT_POOL,
            total_concurrent=500,
            total_qps=1000.0,
            node_total_memory_mb=32768,
            node_total_cpu_cores=16.0,
            max_instances_per_node=50,
            per_instance_concurrent=10,
            per_instance_memory_mb=256,
            per_instance_cpu_cores=0.5,
        ))
        # 配置StrongPool容量
        self.tracker.configure_pool(PoolCapacity(
            pool_type=PoolType.STRONG_POOL,
            total_concurrent=160,
            total_qps=320.0,
            node_total_memory_mb=32768,
            node_total_cpu_cores=16.0,
            max_instances_per_node=32,
            per_instance_concurrent=5,
            per_instance_memory_mb=512,
            per_instance_cpu_cores=0.5,
        ))

    def test_threshold_is_5_percent(self):
        """验证业务影响面阈值为5%（第十三条）"""
        self.assertEqual(BusinessImpactTracker.IMPACT_THRESHOLD_PERCENT, 5.0)

    def test_configure_pool(self):
        """测试池容量配置"""
        self.assertEqual(len(self.tracker._pool_capacities), 2)
        self.assertIn(PoolType.LIGHT_POOL, self.tracker._pool_capacities)
        self.assertIn(PoolType.STRONG_POOL, self.tracker._pool_capacities)

    def test_record_request(self):
        """测试请求记录"""
        self.tracker.record_request()
        self.tracker.record_request()
        self.assertEqual(self.tracker._total_requests_window, 2)

    def test_record_impact_event(self):
        """测试影响事件记录"""
        event = ImpactEvent(
            event_id="evt-001",
            pool_type=PoolType.LIGHT_POOL,
            instance_id="worker-001",
            event_type=ImpactEventType.WORKER_CRASH,
            timestamp=time.time(),
            affected_requests=5,
            affected_tenants=1,
            duration_ms=1000,
        )
        self.tracker.record_impact_event(event)
        self.assertEqual(len(self.tracker._events), 1)

    def test_low_impact_no_alert(self):
        """测试低影响事件不触发告警"""
        event = ImpactEvent(
            event_id="evt-low",
            pool_type=PoolType.LIGHT_POOL,
            instance_id="worker-001",
            event_type=ImpactEventType.WORKER_CRASH,
            timestamp=time.time(),
            affected_requests=1,
            duration_ms=100,  # 10 QPS影响, 1000总QPS = 1% < 5%
        )
        self.tracker.record_impact_event(event)
        self.assertEqual(len(self.tracker._alerts), 0)

    def test_high_impact_triggers_alert(self):
        """测试高影响事件触发告警"""
        event = ImpactEvent(
            event_id="evt-high",
            pool_type=PoolType.LIGHT_POOL,
            instance_id="worker-001",
            event_type=ImpactEventType.WORKER_CRASH,
            timestamp=time.time(),
            affected_requests=200,
            duration_ms=1000,  # 200 QPS影响, 1000总QPS = 20% > 10%
        )
        self.tracker.record_impact_event(event)
        self.assertEqual(len(self.tracker._alerts), 1)
        self.assertEqual(self.tracker._alerts[0]["severity"], "critical")

    def test_validate_light_pool_configuration(self):
        """测试LightPool配置校验（应通过）"""
        result = self.tracker.validate_configuration(PoolType.LIGHT_POOL)
        self.assertTrue(result["all_passed"])
        self.assertIn("concurrency_impact", result["checks"])
        self.assertIn("memory_impact", result["checks"])
        self.assertIn("cpu_impact", result["checks"])

    def test_validate_strong_pool_configuration(self):
        """测试StrongPool配置校验（应通过）"""
        result = self.tracker.validate_configuration(PoolType.STRONG_POOL)
        self.assertTrue(result["all_passed"])

    def test_validate_invalid_cpu_configuration(self):
        """测试CPU影响面超标的配置校验（应失败）"""
        tracker = BusinessImpactTracker()
        tracker.configure_pool(PoolCapacity(
            pool_type=PoolType.STRONG_POOL,
            total_concurrent=160,
            total_qps=320.0,
            node_total_memory_mb=32768,
            node_total_cpu_cores=16.0,
            per_instance_concurrent=5,
            per_instance_memory_mb=512,
            per_instance_cpu_cores=2.0,  # 2/16 = 12.5% > 5%
        ))
        result = tracker.validate_configuration(PoolType.STRONG_POOL)
        self.assertFalse(result["all_passed"])
        self.assertFalse(result["checks"]["cpu_impact"]["passed"])

    def test_get_impact_summary(self):
        """测试影响面汇总"""
        summary = self.tracker.get_impact_summary()
        self.assertEqual(summary["threshold_percent"], 5.0)
        self.assertEqual(summary["current_impact_percent"], 0.0)
        self.assertTrue(summary["compliant"])
        self.assertFalse(summary["threshold_exceeded"])

    def test_active_impact_percent(self):
        """测试活跃影响面百分比计算"""
        event = ImpactEvent(
            event_id="evt-active",
            pool_type=PoolType.LIGHT_POOL,
            instance_id="worker-001",
            event_type=ImpactEventType.WORKER_CRASH,
            timestamp=time.time(),
            affected_requests=30,
            duration_ms=1000,  # 30 QPS / 1000 QPS = 3%
            recovered=False,
        )
        self.tracker.record_impact_event(event)
        impact = self.tracker.get_current_impact_percent()
        self.assertGreater(impact, 0)
        self.assertLessEqual(impact, 5.0)

    def test_recovered_event_not_counted(self):
        """测试已恢复事件不计入当前影响面"""
        event = ImpactEvent(
            event_id="evt-recovered",
            pool_type=PoolType.LIGHT_POOL,
            instance_id="worker-001",
            event_type=ImpactEventType.WORKER_CRASH,
            timestamp=time.time(),
            affected_requests=100,
            duration_ms=1000,
            recovered=True,
            recovery_time_ms=500,
        )
        self.tracker.record_impact_event(event)
        self.assertEqual(self.tracker.get_current_impact_percent(), 0.0)

    def test_export_prometheus(self):
        """测试Prometheus导出"""
        metrics = self.tracker.export_prometheus()
        self.assertIn("photon_business_impact_percent", metrics)
        self.assertIn("photon_business_impact_threshold", metrics)
        self.assertIn("photon_business_impact_compliant", metrics)
        self.assertIn("photon_business_impact_light_pool_percent", metrics)
        self.assertIn("photon_business_impact_strong_pool_percent", metrics)

    def test_reset(self):
        """测试重置"""
        event = ImpactEvent(
            event_id="evt-reset",
            pool_type=PoolType.LIGHT_POOL,
            instance_id="worker-001",
            event_type=ImpactEventType.WORKER_CRASH,
            timestamp=time.time(),
            affected_requests=100,
            duration_ms=1000,
        )
        self.tracker.record_impact_event(event)
        self.tracker.reset()
        self.assertEqual(len(self.tracker._events), 0)
        self.assertEqual(len(self.tracker._alerts), 0)

    def test_pool_type_enum(self):
        """测试池类型枚举"""
        self.assertEqual(PoolType.LIGHT_POOL.value, "light_pool")
        self.assertEqual(PoolType.STRONG_POOL.value, "strong_pool")

    def test_impact_event_type_enum(self):
        """测试影响事件类型枚举"""
        self.assertEqual(ImpactEventType.WORKER_CRASH.value, "worker_crash")
        self.assertEqual(ImpactEventType.VM_ESCAPE_ATTEMPT.value, "vm_escape_attempt")
        self.assertEqual(ImpactEventType.OOM_KILL.value, "oom_kill")


if __name__ == '__main__':
    unittest.main()
