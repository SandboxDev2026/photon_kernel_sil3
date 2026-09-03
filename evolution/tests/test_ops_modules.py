"""
ops模块测试 - 产品化增强6大模块

覆盖：
1. PlaybookEngine - 自动化剧本编排
2. TicketSystem - 工单流转系统
3. InferenceMetrics - 推理指标监控
4. MonitorDashboard - 可视化大屏
"""

import unittest
import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ops.playbook_engine import (
    PlaybookEngine, Playbook, Action, Trigger,
    TriggerType, ActionType, RiskLevel, PlaybookStatus,
)
from ops.ticket_system import (
    TicketSystem, TicketStatus, TicketPriority, TicketCategory,
    PostMortem, SLAStatus,
)
from ops.inference_metrics import InferenceMetrics, MetricSnapshot
from ops.monitor_dashboard import MonitorDashboard


class TestPlaybookEngine(unittest.TestCase):
    """PlaybookEngine 自动化剧本编排测试"""

    def setUp(self):
        self.engine = PlaybookEngine()

    def test_register_and_trigger_playbook(self):
        """注册剧本并触发"""
        playbook = Playbook(
            id="test-escape",
            name="逃逸自动隔离",
            trigger=Trigger(type=TriggerType.ESCAPE_ATTEMPT),
            actions=[
                Action(type=ActionType.SNAPSHOT_EVIDENCE),
                Action(type=ActionType.ISOLATE_CONTAINER, params={"container_id": "{container_id}"}),
                Action(type=ActionType.CREATE_TICKET),
            ],
        )
        self.engine.register_playbook(playbook)

        executions = self.engine.handle_event({
            "type": "escape_attempt",
            "container_id": "c123",
            "tenant_id": "t456",
        })

        self.assertEqual(len(executions), 1)
        self.assertEqual(executions[0].status, PlaybookStatus.COMPLETED)
        self.assertEqual(len(executions[0].action_results), 3)

    def test_no_match_trigger(self):
        """不匹配的触发器不执行"""
        playbook = Playbook(
            id="test",
            name="测试",
            trigger=Trigger(type=TriggerType.ESCAPE_ATTEMPT),
            actions=[Action(type=ActionType.SEND_ALERT)],
        )
        self.engine.register_playbook(playbook)

        executions = self.engine.handle_event({"type": "other_event"})
        self.assertEqual(len(executions), 0)

    def test_metric_threshold_trigger(self):
        """指标阈值触发器"""
        playbook = Playbook(
            id="test-metric",
            name="高延迟自动扩容",
            trigger=Trigger(
                type=TriggerType.METRIC_THRESHOLD,
                metric_name="p99_latency",
                threshold=500,
                comparison=">",
            ),
            actions=[Action(type=ActionType.SCALE_UP)],
        )
        self.engine.register_playbook(playbook)

        # 超过阈值，触发
        executions = self.engine.handle_event({
            "type": "metric_threshold",
            "metrics": {"p99_latency": 600},
        })
        self.assertEqual(len(executions), 1)

        # 未超过阈值，不触发
        executions = self.engine.handle_event({
            "type": "metric_threshold",
            "metrics": {"p99_latency": 400},
        })
        self.assertEqual(len(executions), 0)

    def test_action_requires_approval(self):
        """需要审批的动作暂停执行"""
        playbook = Playbook(
            id="test-approval",
            name="需要审批",
            trigger=Trigger(type=TriggerType.SECURITY_THREAT),
            actions=[
                Action(type=ActionType.SEND_ALERT),
                Action(type=ActionType.SHUTDOWN_SANDBOX, require_approval=True),
            ],
        )
        self.engine.register_playbook(playbook)

        executions = self.engine.handle_event({"type": "security_threat"})
        self.assertEqual(executions[0].status, PlaybookStatus.WAITING_APPROVAL)
        self.assertEqual(len(self.engine.get_pending_approvals()), 1)

        # 审批通过
        execution = self.engine.approve_execution(executions[0].execution_id, "admin")
        self.assertIsNotNone(execution)

    def test_param_template_resolution(self):
        """参数模板替换"""
        playbook = Playbook(
            id="test-params",
            name="参数替换",
            trigger=Trigger(type=TriggerType.COMPLIANCE_VIOLATION),
            actions=[
                Action(type=ActionType.FREEZE_ACCOUNT, params={"tenant_id": "{tenant_id}"}),
            ],
        )
        self.engine.register_playbook(playbook)

        # 注册自定义处理器验证参数
        resolved_params = {}
        def freeze_handler(params, event):
            resolved_params.update(params)
            return {"frozen": True}
        self.engine.register_action_handler(ActionType.FREEZE_ACCOUNT, freeze_handler)

        self.engine.handle_event({
            "type": "compliance_violation",
            "tenant_id": "tenant-123",
        })

        self.assertEqual(resolved_params.get("tenant_id"), "tenant-123")

    def test_priority_ordering(self):
        """剧本按优先级执行"""
        p1 = Playbook(id="p1", name="低优先级", priority=200,
                      trigger=Trigger(type=TriggerType.ESCAPE_ATTEMPT),
                      actions=[Action(type=ActionType.SEND_ALERT)])
        p2 = Playbook(id="p2", name="高优先级", priority=50,
                      trigger=Trigger(type=TriggerType.ESCAPE_ATTEMPT),
                      actions=[Action(type=ActionType.SEND_ALERT)])
        self.engine.register_playbook(p1)
        self.engine.register_playbook(p2)

        executions = self.engine.handle_event({"type": "escape_attempt"})
        self.assertEqual(len(executions), 2)
        self.assertEqual(executions[0].playbook_id, "p2")  # 高优先级先执行


class TestTicketSystem(unittest.TestCase):
    """TicketSystem 工单流转系统测试"""

    def setUp(self):
        self.ts = TicketSystem()

    def test_create_ticket(self):
        """创建工单"""
        ticket = self.ts.create(
            title="测试工单",
            description="测试描述",
            category=TicketCategory.SECURITY_THREAT,
            priority=TicketPriority.P1_CRITICAL,
        )
        self.assertIsNotNone(ticket.id)
        self.assertEqual(ticket.status, TicketStatus.CREATED)
        self.assertEqual(ticket.priority, TicketPriority.P1_CRITICAL)

    def test_create_from_event(self):
        """从事件自动创建工单"""
        ticket = self.ts.create_from_event({
            "type": "escape_attempt",
            "container_id": "c123",
            "risk_level": "critical",
        })
        self.assertEqual(ticket.category, TicketCategory.ESCAPE_ATTEMPT)
        self.assertEqual(ticket.priority, TicketPriority.P1_CRITICAL)
        self.assertIn("c123", ticket.description)

    def test_ticket_lifecycle(self):
        """工单完整生命周期"""
        ticket = self.ts.create("测试", "描述", TicketCategory.SYSTEM_ERROR, TicketPriority.P2_HIGH)

        # 指派
        ticket = self.ts.assign(ticket.id, "admin")
        self.assertEqual(ticket.assignee, "admin")
        self.assertEqual(ticket.status, TicketStatus.TRIAGED)

        # 开始处理
        ticket = self.ts.start_progress(ticket.id)
        self.assertEqual(ticket.status, TicketStatus.IN_PROGRESS)

        # 解决
        ticket = self.ts.resolve(ticket.id, "已修复")
        self.assertEqual(ticket.status, TicketStatus.RESOLVED)
        self.assertGreater(ticket.resolved_at, 0)

        # 关闭
        ticket = self.ts.close(ticket.id)
        self.assertEqual(ticket.status, TicketStatus.CLOSED)

    def test_reopen_ticket(self):
        """重开工单"""
        ticket = self.ts.create("测试", "描述", TicketCategory.SYSTEM_ERROR, TicketPriority.P3_MEDIUM)
        self.ts.assign(ticket.id, "admin")
        self.ts.resolve(ticket.id, "已修复")
        self.ts.close(ticket.id)

        ticket = self.ts.reopen(ticket.id, "问题复现")
        self.assertEqual(ticket.status, TicketStatus.REOPENED)

    def test_escalate_ticket(self):
        """升级工单"""
        ticket = self.ts.create("测试", "描述", TicketCategory.SYSTEM_ERROR, TicketPriority.P3_MEDIUM)
        ticket = self.ts.escalate(ticket.id, "超时未处理")
        self.assertEqual(ticket.status, TicketStatus.ESCALATED)
        self.assertEqual(ticket.escalation_count, 1)

    def test_add_comment(self):
        """添加评论"""
        ticket = self.ts.create("测试", "描述", TicketCategory.SYSTEM_ERROR, TicketPriority.P3_MEDIUM)
        comment = self.ts.add_comment(ticket.id, "admin", "正在处理")
        self.assertIsNotNone(comment)
        self.assertEqual(len(ticket.comments), 1)

    def test_post_mortem(self):
        """添加复盘记录"""
        ticket = self.ts.create("测试", "描述", TicketCategory.SECURITY_THREAT, TicketPriority.P1_CRITICAL)
        pm = PostMortem(
            root_cause="配置错误",
            impact="影响10个租户",
            corrective_actions=["修复配置", "增加检测"],
            preventive_actions=["增加CI检查"],
            lessons_learned="需要加强配置审核",
        )
        ticket = self.ts.add_post_mortem(ticket.id, pm)
        self.assertIsNotNone(ticket.post_mortem)
        self.assertEqual(ticket.post_mortem.root_cause, "配置错误")

    def test_sla_status(self):
        """SLA状态检查"""
        ticket = self.ts.create("测试", "描述", TicketCategory.SYSTEM_ERROR, TicketPriority.P1_CRITICAL)
        sla = self.ts.get_sla_status(ticket)
        self.assertIn("response", sla)
        self.assertIn("resolve", sla)
        # 刚创建应该是OK
        self.assertEqual(sla["response"], SLAStatus.OK)

    def test_stats(self):
        """统计信息"""
        for i in range(5):
            self.ts.create(f"工单{i}", "描述", TicketCategory.SYSTEM_ERROR, TicketPriority.P3_MEDIUM)

        stats = self.ts.get_stats()
        self.assertEqual(stats["total"], 5)
        self.assertIn("by_status", stats)
        self.assertIn("by_priority", stats)

    def test_list_tickets(self):
        """列出工单（带过滤）"""
        t1 = self.ts.create("工单1", "描述", TicketCategory.SECURITY_THREAT, TicketPriority.P1_CRITICAL)
        t2 = self.ts.create("工单2", "描述", TicketCategory.SYSTEM_ERROR, TicketPriority.P3_MEDIUM)

        # 按类别过滤
        security_tickets = self.ts.list_tickets(category=TicketCategory.SECURITY_THREAT)
        self.assertEqual(len(security_tickets), 1)
        self.assertEqual(security_tickets[0].id, t1.id)


class TestInferenceMetrics(unittest.TestCase):
    """InferenceMetrics 推理指标监控测试"""

    def setUp(self):
        self.metrics = InferenceMetrics(window_seconds=60)

    def test_record_request(self):
        """记录请求"""
        self.metrics.record_request(
            latency_ms=100.0,
            ttft_ms=30.0,
            input_tokens=50,
            output_tokens=100,
            success=True,
        )
        snapshot = self.metrics.get_snapshot()
        self.assertEqual(snapshot.total_requests, 1)
        self.assertEqual(snapshot.success_count, 1)
        self.assertAlmostEqual(snapshot.avg_latency_ms, 100.0, places=1)

    def test_qps_calculation(self):
        """QPS计算"""
        # 记录10个请求
        for i in range(10):
            self.metrics.record_request(
                latency_ms=50.0 + i,
                ttft_ms=20.0,
                input_tokens=10,
                output_tokens=20,
                success=True,
            )
        snapshot = self.metrics.get_snapshot()
        self.assertGreater(snapshot.qps, 0)

    def test_percentile_calculation(self):
        """百分位数计算"""
        for i in range(100):
            self.metrics.record_request(
                latency_ms=float(i + 1),
                ttft_ms=10.0,
                input_tokens=10,
                output_tokens=20,
                success=True,
            )
        snapshot = self.metrics.get_snapshot()
        self.assertGreater(snapshot.p99_latency_ms, snapshot.p95_latency_ms)
        self.assertGreater(snapshot.p95_latency_ms, snapshot.p50_latency_ms)

    def test_error_rate(self):
        """错误率计算"""
        # 90个成功，10个失败
        for i in range(90):
            self.metrics.record_request(100, 30, 10, 20, True)
        for i in range(10):
            self.metrics.record_request(100, 30, 10, 20, False, error_type="timeout")

        snapshot = self.metrics.get_snapshot()
        self.assertAlmostEqual(snapshot.error_rate, 10.0, places=0)
        self.assertEqual(snapshot.error_count, 10)

    def test_gpu_metrics(self):
        """GPU指标更新"""
        self.metrics.update_gpu(
            vram_usage_gb=12.5,
            vram_total_gb=24.0,
            vram_fragmentation=8.5,
            gpu_util=75.0,
        )
        snapshot = self.metrics.get_snapshot()
        self.assertEqual(snapshot.vram_usage_gb, 12.5)
        self.assertEqual(snapshot.vram_total_gb, 24.0)
        self.assertEqual(snapshot.vram_fragmentation_rate, 8.5)
        self.assertEqual(snapshot.gpu_utilization, 75.0)

    def test_active_requests(self):
        """活跃请求计数"""
        self.assertEqual(self.metrics._active_requests, 0)
        self.metrics.start_request()
        self.metrics.start_request()
        self.assertEqual(self.metrics._active_requests, 2)
        self.metrics.end_request()
        self.assertEqual(self.metrics._active_requests, 1)

    def test_alert_thresholds(self):
        """告警阈值检查"""
        # 记录高延迟请求
        for i in range(10):
            self.metrics.record_request(
                latency_ms=600.0,  # 超过500ms阈值
                ttft_ms=100.0,
                input_tokens=10,
                output_tokens=20,
                success=True,
            )
        alerts = self.metrics.check_alerts({
            "p99_latency_ms": 500,
            "error_rate": 1.0,
        })
        # 应该有P99延迟告警
        p99_alerts = [a for a in alerts if a["metric"] == "p99_latency_ms"]
        self.assertEqual(len(p99_alerts), 1)
        self.assertEqual(p99_alerts[0]["level"], "critical")

    def test_vram_fragmentation_alert(self):
        """显存碎片率告警"""
        self.metrics.update_gpu(10, 24, 18.0, 50)  # 碎片率18% > 15%阈值
        alerts = self.metrics.check_alerts({"vram_fragmentation_rate": 15})
        frag_alerts = [a for a in alerts if a["metric"] == "vram_fragmentation_rate"]
        self.assertEqual(len(frag_alerts), 1)
        self.assertEqual(frag_alerts[0]["level"], "warning")

    def test_prometheus_export(self):
        """Prometheus格式导出"""
        self.metrics.record_request(100, 30, 10, 20, True)
        self.metrics.update_gpu(12, 24, 8, 75)
        prom = self.metrics.export_prometheus()
        self.assertIn("photon_inference_qps", prom)
        self.assertIn("photon_vram_fragmentation_rate", prom)
        self.assertIn("photon_gpu_utilization", prom)

    def test_counters(self):
        """累计计数器"""
        for i in range(5):
            self.metrics.record_request(100, 30, 10, 20, True)
        counters = self.metrics.get_counters()
        self.assertEqual(counters["total_requests"], 5)
        self.assertEqual(counters["total_success"], 5)
        self.assertEqual(counters["total_input_tokens"], 50)
        self.assertEqual(counters["total_output_tokens"], 100)

    def test_reset(self):
        """重置指标"""
        self.metrics.record_request(100, 30, 10, 20, True)
        self.metrics.reset()
        snapshot = self.metrics.get_snapshot()
        self.assertEqual(snapshot.total_requests, 0)


class TestMonitorDashboard(unittest.TestCase):
    """MonitorDashboard 可视化大屏测试"""

    def setUp(self):
        self.dashboard = MonitorDashboard(title="测试大屏")

    def test_add_metric(self):
        """添加指标"""
        self.dashboard.add_metric("QPS", 125.5, "req/s")
        html = self.dashboard.render()
        self.assertIn("QPS", html)
        self.assertIn("125.50", html)

    def test_add_alert(self):
        """添加告警"""
        self.dashboard.add_alert({
            "level": "critical",
            "message": "P99延迟超标",
        })
        alerts = self.dashboard.get_alert_summary()
        self.assertEqual(alerts["critical"], 1)

    def test_health_status(self):
        """健康状态"""
        # 无告警=健康
        self.assertEqual(self.dashboard.get_health_status(), "healthy")

        # 严重告警=critical
        self.dashboard.add_alert({"level": "critical", "message": "测试"})
        self.assertEqual(self.dashboard.get_health_status(), "critical")

    def test_render_html(self):
        """渲染HTML"""
        self.dashboard.add_metric("QPS", 100)
        self.dashboard.add_alert({"level": "warning", "message": "测试告警"})
        html = self.dashboard.render()
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("测试大屏", html)
        self.assertIn("测试告警", html)

    def test_render_json(self):
        """渲染JSON"""
        self.dashboard.add_metric("QPS", 100)
        data = self.dashboard.render_json()
        self.assertEqual(data["title"], "测试大屏")
        self.assertIn("QPS", data["metrics"])
        self.assertEqual(data["health_status"], "healthy")

    def test_threshold_display(self):
        """阈值显示"""
        html = self.dashboard.render()
        self.assertIn("500", html)  # P99延迟阈值
        self.assertIn("1.0", html)  # 错误率阈值
        self.assertIn("15", html)  # 显存碎片率阈值

    def test_add_node(self):
        """添加集群节点"""
        self.dashboard.add_node({
            "name": "node-1",
            "ip": "10.0.0.1",
            "status": "ready",
            "pods": 5,
        })
        html = self.dashboard.render()
        self.assertIn("node-1", html)
        self.assertIn("10.0.0.1", html)

    def test_alert_history_limit(self):
        """告警历史限制（最多100条）"""
        for i in range(150):
            self.dashboard.add_alert({"level": "info", "message": f"告警{i}"})
        self.assertEqual(len(self.dashboard._alerts), 100)


if __name__ == "__main__":
    unittest.main(verbosity=2)
