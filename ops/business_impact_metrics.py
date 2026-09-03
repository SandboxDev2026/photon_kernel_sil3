"""
业务影响面度量模块（第十三条）

跟踪沙盒实例故障对业务的影响范围，确保单实例故障业务影响面 ≤ 5%。

参考文档: docs/business_impact_metrics.md
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class PoolType(Enum):
    """沙盒池类型"""
    LIGHT_POOL = "light_pool"
    STRONG_POOL = "strong_pool"


class ImpactEventType(Enum):
    """影响事件类型"""
    WORKER_CRASH = "worker_crash"           # worker进程崩溃
    VM_ESCAPE_ATTEMPT = "vm_escape_attempt"  # VM逃逸尝试
    OOM_KILL = "oom_kill"                    # OOM杀死
    CPU_SATURATION = "cpu_saturation"        # CPU打满
    NETWORK_ISOLATION_BREACH = "network_isolation_breach"  # 网络隔离突破
    SNAPSHOT_CORRUPTION = "snapshot_corruption"  # 快照损坏
    RESOURCE_EXHAUSTION = "resource_exhaustion"  # 资源耗尽


@dataclass
class ImpactEvent:
    """单实例影响事件"""
    event_id: str
    pool_type: PoolType
    instance_id: str
    event_type: ImpactEventType
    timestamp: float
    affected_requests: int = 0           # 受影响请求数
    affected_tenants: int = 0            # 受影响租户数
    affected_business_functions: int = 0  # 受影响业务功能数
    duration_ms: int = 0                 # 影响持续时间
    recovered: bool = False              # 是否已恢复
    recovery_time_ms: int = 0            # 恢复耗时
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PoolCapacity:
    """池容量配置（用于计算影响面百分比）"""
    pool_type: PoolType
    total_concurrent: int = 0            # 集群总并发
    total_qps: float = 0.0               # 集群总QPS
    node_total_memory_mb: int = 0        # 节点总内存(MB)
    node_total_cpu_cores: float = 0.0    # 节点总CPU核数
    max_instances_per_node: int = 0      # 单节点最大实例数
    per_instance_concurrent: int = 0     # 单实例并发上限
    per_instance_memory_mb: int = 0      # 单实例内存上限
    per_instance_cpu_cores: float = 0.0  # 单实例CPU上限


class BusinessImpactTracker:
    """
    业务影响面跟踪器

    核心职责：
    1. 记录单实例故障事件
    2. 计算业务影响面百分比
    3. 校验 ≤ 5% 起步上限
    4. 导出 metrics 供监控看板使用
    """

    IMPACT_THRESHOLD_PERCENT = 5.0  # 第十三条：业务影响面起步上限

    def __init__(self):
        self._events: List[ImpactEvent] = []
        self._pool_capacities: Dict[PoolType, PoolCapacity] = {}
        self._total_requests_window: int = 0  # 时间窗口内总请求数
        self._window_start: float = time.time()
        self._window_seconds: int = 300  # 5分钟滑动窗口
        self._alerts: List[Dict[str, Any]] = []

    def configure_pool(self, capacity: PoolCapacity) -> None:
        """配置池容量（用于计算影响面百分比）"""
        self._pool_capacities[capacity.pool_type] = capacity

    def record_request(self) -> None:
        """记录一个请求（用于计算总请求数基数）"""
        self._total_requests_window += 1
        # 滑动窗口清理
        now = time.time()
        if now - self._window_start > self._window_seconds:
            self._total_requests_window = 0
            self._window_start = now

    def record_impact_event(self, event: ImpactEvent) -> None:
        """记录单实例影响事件"""
        self._events.append(event)
        # 检查是否超过阈值
        impact_percent = self._calculate_event_impact_percent(event)
        if impact_percent > self.IMPACT_THRESHOLD_PERCENT:
            self._alerts.append({
                "event_id": event.event_id,
                "pool_type": event.pool_type.value,
                "instance_id": event.instance_id,
                "event_type": event.event_type.value,
                "impact_percent": impact_percent,
                "threshold": self.IMPACT_THRESHOLD_PERCENT,
                "timestamp": event.timestamp,
                "severity": "critical" if impact_percent > 10 else "warning",
            })

    def _calculate_event_impact_percent(self, event: ImpactEvent) -> float:
        """计算单个事件的业务影响面百分比"""
        capacity = self._pool_capacities.get(event.pool_type)
        if not capacity or capacity.total_qps <= 0:
            # 无法计算时，基于受影响请求数和窗口总请求数估算
            if self._total_requests_window > 0:
                return (event.affected_requests / self._total_requests_window) * 100
            return 0.0

        # 基于QPS计算影响面
        if event.duration_ms > 0:
            affected_qps = event.affected_requests / (event.duration_ms / 1000.0)
            return (affected_qps / capacity.total_qps) * 100

        # 基于并发计算影响面
        if capacity.total_concurrent > 0:
            return (event.affected_requests / capacity.total_concurrent) * 100

        return 0.0

    def get_current_impact_percent(self, pool_type: Optional[PoolType] = None) -> float:
        """获取当前业务影响面百分比（滑动窗口内未恢复事件）"""
        now = time.time()
        window_start = now - self._window_seconds
        active_events = [
            e for e in self._events
            if e.timestamp >= window_start and not e.recovered
            and (pool_type is None or e.pool_type == pool_type)
        ]

        if not active_events:
            return 0.0

        total_impact = sum(self._calculate_event_impact_percent(e) for e in active_events)
        return min(total_impact, 100.0)

    def get_impact_summary(self) -> Dict[str, Any]:
        """获取业务影响面汇总"""
        now = time.time()
        window_start = now - self._window_seconds
        window_events = [e for e in self._events if e.timestamp >= window_start]

        light_events = [e for e in window_events if e.pool_type == PoolType.LIGHT_POOL]
        strong_events = [e for e in window_events if e.pool_type == PoolType.STRONG_POOL]

        return {
            "threshold_percent": self.IMPACT_THRESHOLD_PERCENT,
            "current_impact_percent": self.get_current_impact_percent(),
            "light_pool_impact_percent": self.get_current_impact_percent(PoolType.LIGHT_POOL),
            "strong_pool_impact_percent": self.get_current_impact_percent(PoolType.STRONG_POOL),
            "total_events_window": len(window_events),
            "light_pool_events": len(light_events),
            "strong_pool_events": len(strong_events),
            "active_unrecovered_events": len([e for e in window_events if not e.recovered]),
            "total_affected_requests": sum(e.affected_requests for e in window_events),
            "total_affected_tenants": sum(e.affected_tenants for e in window_events),
            "avg_recovery_time_ms": self._avg_recovery_time(window_events),
            "alerts": len(self._alerts),
            "threshold_exceeded": self.get_current_impact_percent() > self.IMPACT_THRESHOLD_PERCENT,
            "compliant": self.get_current_impact_percent() <= self.IMPACT_THRESHOLD_PERCENT,
        }

    def _avg_recovery_time(self, events: List[ImpactEvent]) -> float:
        """计算平均恢复时间"""
        recovered = [e for e in events if e.recovered and e.recovery_time_ms > 0]
        if not recovered:
            return 0.0
        return sum(e.recovery_time_ms for e in recovered) / len(recovered)

    def validate_configuration(self, pool_type: PoolType) -> Dict[str, Any]:
        """
        校验池配置是否满足业务影响面 ≤ 5% 要求

        基于配置静态计算各维度影响面，返回校验结果。
        """
        capacity = self._pool_capacities.get(pool_type)
        if not capacity:
            return {"valid": False, "reason": "池容量未配置"}

        results = {
            "pool_type": pool_type.value,
            "checks": {},
            "all_passed": True,
        }

        # 1. 并发影响面：单实例并发 / 集群总并发
        if capacity.total_concurrent > 0:
            concurrency_impact = (capacity.per_instance_concurrent / capacity.total_concurrent) * 100
            results["checks"]["concurrency_impact"] = {
                "value_percent": concurrency_impact,
                "threshold": self.IMPACT_THRESHOLD_PERCENT,
                "passed": concurrency_impact <= self.IMPACT_THRESHOLD_PERCENT,
            }
            if concurrency_impact > self.IMPACT_THRESHOLD_PERCENT:
                results["all_passed"] = False

        # 2. 内存影响面：单实例内存 / 节点总内存
        if capacity.node_total_memory_mb > 0:
            memory_impact = (capacity.per_instance_memory_mb / capacity.node_total_memory_mb) * 100
            results["checks"]["memory_impact"] = {
                "value_percent": memory_impact,
                "threshold": self.IMPACT_THRESHOLD_PERCENT,
                "passed": memory_impact <= self.IMPACT_THRESHOLD_PERCENT,
            }
            if memory_impact > self.IMPACT_THRESHOLD_PERCENT:
                results["all_passed"] = False

        # 3. CPU影响面：单实例CPU / 节点总CPU
        if capacity.node_total_cpu_cores > 0:
            cpu_impact = (capacity.per_instance_cpu_cores / capacity.node_total_cpu_cores) * 100
            results["checks"]["cpu_impact"] = {
                "value_percent": cpu_impact,
                "threshold": self.IMPACT_THRESHOLD_PERCENT,
                "passed": cpu_impact <= self.IMPACT_THRESHOLD_PERCENT,
            }
            if cpu_impact > self.IMPACT_THRESHOLD_PERCENT:
                results["all_passed"] = False

        return results

    def get_alerts(self, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """获取告警列表"""
        if severity:
            return [a for a in self._alerts if a["severity"] == severity]
        return self._alerts

    def export_prometheus(self) -> str:
        """导出 Prometheus 格式 metrics"""
        summary = self.get_impact_summary()
        lines = [
            "# HELP photon_business_impact_percent 当前业务影响面百分比",
            "# TYPE photon_business_impact_percent gauge",
            f'photon_business_impact_percent {summary["current_impact_percent"]:.4f}',
            "",
            "# HELP photon_business_impact_threshold 业务影响面阈值(%)",
            "# TYPE photon_business_impact_threshold gauge",
            f'photon_business_impact_threshold {self.IMPACT_THRESHOLD_PERCENT}',
            "",
            "# HELP photon_business_impact_light_pool_percent LightPool业务影响面百分比",
            "# TYPE photon_business_impact_light_pool_percent gauge",
            f'photon_business_impact_light_pool_percent {summary["light_pool_impact_percent"]:.4f}',
            "",
            "# HELP photon_business_impact_strong_pool_percent StrongPool业务影响面百分比",
            "# TYPE photon_business_impact_strong_pool_percent gauge",
            f'photon_business_impact_strong_pool_percent {summary["strong_pool_impact_percent"]:.4f}',
            "",
            "# HELP photon_business_impact_events_total 影响事件总数",
            "# TYPE photon_business_impact_events_total counter",
            f'photon_business_impact_events_total {summary["total_events_window"]}',
            "",
            "# HELP photon_business_impact_active_unrecovered 未恢复事件数",
            "# TYPE photon_business_impact_active_unrecovered gauge",
            f'photon_business_impact_active_unrecovered {summary["active_unrecovered_events"]}',
            "",
            "# HELP photon_business_impact_alerts_total 告警总数",
            "# TYPE photon_business_impact_alerts_total counter",
            f'photon_business_impact_alerts_total {summary["alerts"]}',
            "",
            "# HELP photon_business_impact_compliant 是否合规(1=合规,0=违规)",
            "# TYPE photon_business_impact_compliant gauge",
            f'photon_business_impact_compliant {1 if summary["compliant"] else 0}',
        ]
        return "\n".join(lines)

    def reset(self) -> None:
        """重置跟踪器"""
        self._events.clear()
        self._alerts.clear()
        self._total_requests_window = 0
        self._window_start = time.time()
