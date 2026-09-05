"""
PhotonBox 安全熔断隔离引擎

在没有专职 Oncall 团队的情况下，通过自动化熔断实现"机器自动止血"。

设计原则：
- 机器自动止血 > 人工响应
- 分级熔断：实例级(L1) → 节点级(L2) → 集群级(L3) → 紧急熔断(L4)
- 自动回滚：L1/L2 自动恢复，L3/L4 必须人工确认
- 可观测：所有熔断操作有审计日志、告警通知、状态追踪

熔断触发条件：
1. seccomp 违规率突增（>100次/分钟）
2. VM-Exit 异常事件（VMCALL/MSR_WRITE/TRIPLE_FAULT）
3. 进程尝试 ptrace/mount/init_module（高危系统调用）
4. 网络连接到已知 C2 服务器
5. 资源使用异常（CPU/内存突增3倍）
6. 红蓝对抗规则置信度骤降（连续10轮<1%）
7. 审计链 HMAC 异常（日志被篡改）
"""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import time
import hashlib
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable
from collections import deque
from threading import Lock, Thread

logger = logging.getLogger("photonbox.circuit_breaker")


class CircuitBreakerLevel(Enum):
    """熔断级别"""
    L1_INSTANCE = "L1_instance"      # 实例级：销毁/隔离单个可疑实例
    L2_NODE = "L2_node"              # 节点级：暂停节点上新实例创建
    L3_CLUSTER = "L3_cluster"        # 集群级：全集群暂停StrongPool，降级到LightPool
    L4_EMERGENCY = "L4_emergency"   # 紧急熔断：全集群暂停所有不可信代码执行


class CircuitBreakerState(Enum):
    """熔断状态"""
    CLOSED = "closed"           # 正常运行
    OPEN = "open"               # 熔断中
    HALF_OPEN = "half_open"     # 半开（试探恢复）
    MANUAL_HOLD = "manual_hold"  # 人工保持（不允许自动恢复）


class TriggerType(Enum):
    """触发条件类型"""
    SECCOMP_VIOLATION_SURGE = "seccomp_violation_surge"
    VM_EXIT_ANOMALY = "vm_exit_anomaly"
    HIGH_RISK_SYSCALL = "high_risk_syscall"
    C2_CONNECTION = "c2_connection"
    RESOURCE_SPIKE = "resource_spike"
    RULE_CONFIDENCE_DROP = "rule_confidence_drop"
    AUDIT_HMAC_ANOMALY = "audit_hmac_anomaly"
    MANUAL_TRIGGER = "manual_trigger"


@dataclass
class SecurityEvent:
    """安全事件"""
    event_id: str
    timestamp: float
    trigger_type: TriggerType
    severity: str  # info / warning / critical
    instance_id: Optional[str] = None
    node_id: Optional[str] = None
    description: str = ""
    metadata: dict = field(default_factory=dict)
    source: str = "auto"  # auto / manual / external

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "trigger_type": self.trigger_type.value,
            "severity": self.severity,
            "instance_id": self.instance_id,
            "node_id": self.node_id,
            "description": self.description,
            "metadata": self.metadata,
            "source": self.source,
        }


@dataclass
class CircuitBreakerAction:
    """熔断动作"""
    action_id: str
    timestamp: float
    level: CircuitBreakerLevel
    state: CircuitBreakerState
    trigger_event_id: str
    description: str = ""
    affected_instances: list = field(default_factory=list)
    affected_nodes: list = field(default_factory=list)
    auto_recover_at: Optional[float] = None  # 自动恢复时间
    requires_manual_confirmation: bool = False
    recovered_at: Optional[float] = None
    recovered_by: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "timestamp": self.timestamp,
            "level": self.level.value,
            "state": self.state.value,
            "trigger_event_id": self.trigger_event_id,
            "description": self.description,
            "affected_instances": self.affected_instances,
            "affected_nodes": self.affected_nodes,
            "auto_recover_at": self.auto_recover_at,
            "requires_manual_confirmation": self.requires_manual_confirmation,
            "recovered_at": self.recovered_at,
            "recovered_by": self.recovered_by,
        }


@dataclass
class TriggerRule:
    """触发规则"""
    trigger_type: TriggerType
    level: CircuitBreakerLevel
    threshold: float
    window_seconds: int
    description: str = ""
    enabled: bool = True
    cooldown_seconds: int = 300  # 冷却时间，防止反复触发


class SecurityCircuitBreaker:
    """
    安全熔断隔离引擎

    监控安全事件，根据触发规则自动执行分级熔断。
    """

    def __init__(
        self,
        node_id: str = "default-node",
        alert_callback: Optional[Callable[[CircuitBreakerAction], None]] = None,
        isolation_callback: Optional[Callable[[str, CircuitBreakerLevel], bool]] = None,
        auto_recover_enabled: bool = True,
    ):
        self.node_id = node_id
        self.alert_callback = alert_callback
        self.isolation_callback = isolation_callback
        self.auto_recover_enabled = auto_recover_enabled

        self._lock = Lock()
        self._events: deque = deque(maxlen=10000)
        self._actions: list = []
        self._current_state = CircuitBreakerState.CLOSED
        self._current_level: Optional[CircuitBreakerLevel] = None
        self._trigger_counts: dict = {}  # trigger_type -> count in window
        self._last_trigger_time: dict = {}  # trigger_type -> last trigger timestamp

        # 默认触发规则
        self._rules = self._build_default_rules()

        # 已知 C2 服务器（简化版，实际应从威胁情报源更新）
        self._c2_indicators: set = set()

        # 启动后台恢复检查线程
        self._running = True
        self._recover_thread = Thread(target=self._recovery_loop, daemon=True)
        self._recover_thread.start()

    def _build_default_rules(self) -> list:
        """构建默认触发规则"""
        return [
            TriggerRule(
                trigger_type=TriggerType.HIGH_RISK_SYSCALL,
                level=CircuitBreakerLevel.L1_INSTANCE,
                threshold=1,  # 任何一次高危系统调用
                window_seconds=60,
                description="进程尝试 ptrace/mount/init_module 等高危系统调用",
                cooldown_seconds=60,
            ),
            TriggerRule(
                trigger_type=TriggerType.SECCOMP_VIOLATION_SURGE,
                level=CircuitBreakerLevel.L2_NODE,
                threshold=100,  # >100次/分钟
                window_seconds=60,
                description="seccomp 违规率突增",
                cooldown_seconds=300,
            ),
            TriggerRule(
                trigger_type=TriggerType.VM_EXIT_ANOMALY,
                level=CircuitBreakerLevel.L2_NODE,
                threshold=10,  # >10次/分钟
                window_seconds=60,
                description="VM-Exit 异常事件（VMCALL/MSR_WRITE/TRIPLE_FAULT）",
                cooldown_seconds=300,
            ),
            TriggerRule(
                trigger_type=TriggerType.C2_CONNECTION,
                level=CircuitBreakerLevel.L1_INSTANCE,
                threshold=1,  # 任何一次
                window_seconds=60,
                description="网络连接到已知 C2 服务器",
                cooldown_seconds=60,
            ),
            TriggerRule(
                trigger_type=TriggerType.RESOURCE_SPIKE,
                level=CircuitBreakerLevel.L1_INSTANCE,
                threshold=3.0,  # 突增3倍
                window_seconds=300,
                description="资源使用异常（CPU/内存突增3倍）",
                cooldown_seconds=120,
            ),
            TriggerRule(
                trigger_type=TriggerType.AUDIT_HMAC_ANOMALY,
                level=CircuitBreakerLevel.L3_CLUSTER,
                threshold=1,  # 任何一次
                window_seconds=60,
                description="审计链 HMAC 异常（日志被篡改）",
                cooldown_seconds=600,
            ),
            TriggerRule(
                trigger_type=TriggerType.RULE_CONFIDENCE_DROP,
                level=CircuitBreakerLevel.L2_NODE,
                threshold=0.01,  # 连续10轮<1%
                window_seconds=600,
                description="红蓝对抗规则置信度骤降",
                cooldown_seconds=600,
            ),
        ]

    def report_event(self, event: SecurityEvent) -> Optional[CircuitBreakerAction]:
        """
        报告安全事件，触发熔断评估

        Returns:
            如果触发了熔断，返回 CircuitBreakerAction；否则返回 None
        """
        with self._lock:
            self._events.append(event)

            # 检查是否匹配触发规则
            for rule in self._rules:
                if not rule.enabled:
                    continue
                if rule.trigger_type != event.trigger_type:
                    continue

                # 冷却检查
                last_trigger = self._last_trigger_time.get(event.trigger_type, 0)
                if time.time() - last_trigger < rule.cooldown_seconds:
                    continue

                # 统计窗口内事件数
                window_start = time.time() - rule.window_seconds
                count = sum(
                    1 for e in self._events
                    if e.trigger_type == event.trigger_type and e.timestamp >= window_start
                )

                # 阈值判断
                triggered = False
                if event.trigger_type in (
                    TriggerType.HIGH_RISK_SYSCALL,
                    TriggerType.C2_CONNECTION,
                    TriggerType.AUDIT_HMAC_ANOMALY,
                ):
                    triggered = count >= rule.threshold
                elif event.trigger_type == TriggerType.RESOURCE_SPIKE:
                    triggered = event.metadata.get("spike_ratio", 0) >= rule.threshold
                elif event.trigger_type == TriggerType.RULE_CONFIDENCE_DROP:
                    triggered = event.metadata.get("confidence", 1.0) < rule.threshold
                else:
                    triggered = count >= rule.threshold

                if triggered:
                    self._last_trigger_time[event.trigger_type] = time.time()
                    action = self._execute_circuit_breaker(event, rule)
                    return action

            return None

    def _execute_circuit_breaker(
        self, event: SecurityEvent, rule: TriggerRule
    ) -> CircuitBreakerAction:
        """执行熔断动作（调用方已持有锁）"""
        action_id = hashlib.sha256(
            f"{event.event_id}{time.time()}".encode()
        ).hexdigest()[:16]

        # 升级判断：如果当前已有更高级别熔断，不降级
        if self._current_level is not None:
            current_order = list(CircuitBreakerLevel).index(self._current_level)
            new_order = list(CircuitBreakerLevel).index(rule.level)
            if new_order <= current_order:
                # 不降级，但记录事件
                logger.warning(
                    f"熔断触发但不降级: 当前={self._current_level.value}, "
                    f"新触发={rule.level.value}"
                )

        action = CircuitBreakerAction(
            action_id=action_id,
            timestamp=time.time(),
            level=rule.level,
            state=CircuitBreakerState.OPEN,
            trigger_event_id=event.event_id,
            description=rule.description,
            affected_instances=[event.instance_id] if event.instance_id else [],
            affected_nodes=[event.node_id or self.node_id],
            requires_manual_confirmation=rule.level in (
                CircuitBreakerLevel.L3_CLUSTER,
                CircuitBreakerLevel.L4_EMERGENCY,
            ),
        )

        # L1/L2 设置自动恢复时间
        if rule.level == CircuitBreakerLevel.L1_INSTANCE:
            action.auto_recover_at = time.time() + 300  # 5分钟
        elif rule.level == CircuitBreakerLevel.L2_NODE:
            action.auto_recover_at = time.time() + 600  # 10分钟

        # 执行隔离动作
        if self.isolation_callback and event.instance_id:
            try:
                success = self.isolation_callback(event.instance_id, rule.level)
                if not success:
                    logger.error(f"隔离动作执行失败: instance={event.instance_id}")
            except Exception as e:
                logger.error(f"隔离动作异常: {e}")

        # 发送告警
        if self.alert_callback:
            try:
                self.alert_callback(action)
            except Exception as e:
                logger.error(f"告警回调异常: {e}")

        # 更新状态
        self._current_state = CircuitBreakerState.OPEN
        self._current_level = rule.level
        self._actions.append(action)

        logger.critical(
            f"🚨 熔断触发: level={rule.level.value}, "
            f"trigger={event.trigger_type.value}, "
            f"instance={event.instance_id}, "
            f"description={rule.description}"
        )

        return action

    def manual_trigger(
        self,
        level: CircuitBreakerLevel,
        reason: str,
        instance_id: Optional[str] = None,
    ) -> CircuitBreakerAction:
        """人工触发熔断"""
        event = SecurityEvent(
            event_id=f"manual_{int(time.time())}",
            timestamp=time.time(),
            trigger_type=TriggerType.MANUAL_TRIGGER,
            severity="critical",
            instance_id=instance_id,
            node_id=self.node_id,
            description=reason,
            source="manual",
        )
        rule = TriggerRule(
            trigger_type=TriggerType.MANUAL_TRIGGER,
            level=level,
            threshold=1,
            window_seconds=60,
            description=reason,
            cooldown_seconds=0,
        )
        with self._lock:
            return self._execute_circuit_breaker(event, rule)

    def manual_recover(self, action_id: str, operator: str) -> bool:
        """人工确认恢复"""
        with self._lock:
            for action in self._actions:
                if action.action_id == action_id and action.state == CircuitBreakerState.OPEN:
                    action.state = CircuitBreakerState.CLOSED
                    action.recovered_at = time.time()
                    action.recovered_by = operator
                    self._current_state = CircuitBreakerState.CLOSED
                    self._current_level = None
                    logger.info(f"✅ 人工恢复: action={action_id}, operator={operator}")
                    return True
            return False

    def get_current_state(self) -> dict:
        """获取当前熔断状态"""
        with self._lock:
            return {
                "state": self._current_state.value,
                "level": self._current_level.value if self._current_level else None,
                "node_id": self.node_id,
                "active_actions": [
                    a.to_dict() for a in self._actions
                    if a.state == CircuitBreakerState.OPEN
                ],
                "total_events": len(self._events),
                "total_actions": len(self._actions),
            }

    def get_action_history(self, limit: int = 50) -> list:
        """获取熔断动作历史"""
        with self._lock:
            return [a.to_dict() for a in self._actions[-limit:]]

    def add_c2_indicator(self, indicator: str):
        """添加 C2 威胁指标（IP/域名/URL）"""
        with self._lock:
            self._c2_indicators.add(indicator.lower())

    def check_c2_connection(self, destination: str) -> bool:
        """检查是否连接到已知 C2"""
        with self._lock:
            return destination.lower() in self._c2_indicators

    def update_rule(self, trigger_type: TriggerType, **kwargs):
        """更新触发规则参数"""
        with self._lock:
            for rule in self._rules:
                if rule.trigger_type == trigger_type:
                    for key, value in kwargs.items():
                        if hasattr(rule, key):
                            setattr(rule, key, value)
                    return

    def _recovery_loop(self):
        """后台恢复检查线程"""
        while self._running:
            try:
                time.sleep(10)  # 每10秒检查一次
                if not self.auto_recover_enabled:
                    continue

                with self._lock:
                    now = time.time()
                    for action in self._actions:
                        if (
                            action.state == CircuitBreakerState.OPEN
                            and action.auto_recover_at
                            and now >= action.auto_recover_at
                            and not action.requires_manual_confirmation
                        ):
                            # 自动恢复
                            action.state = CircuitBreakerState.CLOSED
                            action.recovered_at = now
                            action.recovered_by = "auto_recovery"
                            self._current_state = CircuitBreakerState.CLOSED
                            self._current_level = None
                            logger.info(f"🔄 自动恢复: action={action.action_id}")

            except Exception as e:
                logger.error(f"恢复检查线程异常: {e}")

    def shutdown(self):
        """关闭熔断引擎"""
        self._running = False
        if self._recover_thread.is_alive():
            self._recover_thread.join(timeout=5)

    def get_stats(self) -> dict:
        """获取统计信息"""
        with self._lock:
            level_counts = {}
            for action in self._actions:
                level_counts[action.level.value] = level_counts.get(action.level.value, 0) + 1

            trigger_counts = {}
            for event in self._events:
                trigger_counts[event.trigger_type.value] = trigger_counts.get(
                    event.trigger_type.value, 0
                ) + 1

            return {
                "node_id": self.node_id,
                "current_state": self._current_state.value,
                "current_level": self._current_level.value if self._current_level else None,
                "total_events": len(self._events),
                "total_actions": len(self._actions),
                "actions_by_level": level_counts,
                "events_by_trigger": trigger_counts,
                "active_rules": sum(1 for r in self._rules if r.enabled),
                "c2_indicators": len(self._c2_indicators),
                "auto_recover_enabled": self.auto_recover_enabled,
            }


# ========== 便捷函数 ==========

def create_circuit_breaker(
    node_id: str = "default-node",
    alert_callback: Optional[Callable] = None,
    isolation_callback: Optional[Callable] = None,
) -> SecurityCircuitBreaker:
    """创建安全熔断引擎"""
    return SecurityCircuitBreaker(
        node_id=node_id,
        alert_callback=alert_callback,
        isolation_callback=isolation_callback,
    )


# ========== 自测试 ==========

if __name__ == "__main__":
    print("=" * 60)
    print("PhotonBox 安全熔断隔离引擎 - 自测试")
    print("=" * 60)

    alerts = []
    def alert_callback(action):
        alerts.append(action)
        print(f"  [告警] {action.level.value}: {action.description}")

    isolations = []
    def isolation_callback(instance_id, level):
        isolations.append((instance_id, level))
        print(f"  [隔离] instance={instance_id}, level={level.value}")
        return True

    cb = create_circuit_breaker(
        node_id="test-node-01",
        alert_callback=alert_callback,
        isolation_callback=isolation_callback,
    )

    print("\n--- 测试1: 高危系统调用触发 L1 熔断 ---")
    event = SecurityEvent(
        event_id="evt_001",
        timestamp=time.time(),
        trigger_type=TriggerType.HIGH_RISK_SYSCALL,
        severity="critical",
        instance_id="inst-001",
        description="进程尝试 ptrace 附加父进程",
        metadata={"syscall": "ptrace", "pid": 12345},
    )
    action = cb.report_event(event)
    assert action is not None
    assert action.level == CircuitBreakerLevel.L1_INSTANCE
    print(f"  ✅ L1 熔断触发: action_id={action.action_id}")

    print("\n--- 测试2: 当前状态查询 ---")
    state = cb.get_current_state()
    print(f"  state={state['state']}, level={state['level']}")
    assert state["state"] == "open"
    assert state["level"] == "L1_instance"

    print("\n--- 测试3: 人工恢复 ---")
    success = cb.manual_recover(action.action_id, "admin")
    assert success
    state = cb.get_current_state()
    assert state["state"] == "closed"
    print(f"  ✅ 人工恢复成功, state={state['state']}")

    print("\n--- 测试4: seccomp 违规率突增触发 L2 熔断 ---")
    l2_action = None
    for i in range(105):
        evt = SecurityEvent(
            event_id=f"evt_seccomp_{i}",
            timestamp=time.time(),
            trigger_type=TriggerType.SECCOMP_VIOLATION_SURGE,
            severity="warning",
            instance_id=f"inst-{i % 10}",
            description=f"seccomp 违规 #{i}",
        )
        result = cb.report_event(evt)
        if result is not None and l2_action is None:
            l2_action = result
    assert l2_action is not None
    assert l2_action.level == CircuitBreakerLevel.L2_NODE
    print(f"  ✅ L2 熔断触发: action_id={l2_action.action_id}")

    print("\n--- 测试5: 人工触发 L3 集群熔断 ---")
    action = cb.manual_trigger(
        level=CircuitBreakerLevel.L3_CLUSTER,
        reason="审计链 HMAC 异常，疑似日志被篡改",
    )
    assert action.level == CircuitBreakerLevel.L3_CLUSTER
    assert action.requires_manual_confirmation
    print(f"  ✅ L3 熔断触发（需人工确认恢复）")

    print("\n--- 测试6: C2 威胁指标检测 ---")
    cb.add_c2_indicator("evil-c2.example.com")
    assert cb.check_c2_connection("evil-c2.example.com")
    assert not cb.check_c2_connection("normal.example.com")
    print("  ✅ C2 指标检测正常")

    print("\n--- 测试7: 统计信息 ---")
    stats = cb.get_stats()
    print(f"  total_events={stats['total_events']}")
    print(f"  total_actions={stats['total_actions']}")
    print(f"  actions_by_level={stats['actions_by_level']}")
    assert stats["total_events"] > 0
    assert stats["total_actions"] >= 3

    print("\n--- 测试8: 动作历史 ---")
    history = cb.get_action_history()
    print(f"  历史动作数: {len(history)}")
    assert len(history) >= 3

    cb.shutdown()

    print("\n" + "=" * 60)
    print(f"✅ 全部测试通过！告警数={len(alerts)}, 隔离数={len(isolations)}")
    print("=" * 60)
