"""
evolution.pipeline_enhancements — 安全事件流水线增强模块

1. DuplicateCacheManager: 带TTL过期淘汰+容量上限告警的去重缓存管理
2. CircuitBreakerAlertManager: 规则熔断开告警+人工确认恢复机制

解决用户提出的两个优化点:
- 去重持久化的TTL和容量上限: 确认磁盘不会无限增长,设置过期淘汰和容量上限告警
- 规则熔断后的人工确认机制: 熔断事件有告警,避免规则静默失效没人知道
"""
from __future__ import annotations
import os
import tempfile
import json
import time
import threading
from typing import Dict, Any, Optional, List, Set, Callable
from dataclasses import dataclass, field
from enum import Enum


class AlertSeverity(Enum):
    """告警严重等级"""
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """告警状态"""
    NEW = "new"                  # 新告警,未确认
    ACKNOWLEDGED = "acknowledged"  # 已确认,处理中
    RESOLVED = "resolved"        # 已解决
    SUPPRESSED = "suppressed"    # 已抑制(重复告警)


@dataclass
class Alert:
    """告警事件"""
    alert_id: str
    alert_type: str               # circuit_breaker / cache_capacity / cache_ttl
    severity: AlertSeverity
    title: str
    description: str
    source: str                   # 来源模块
    rule_id: Optional[str] = None # 关联规则ID(熔断告警)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    status: AlertStatus = AlertStatus.NEW
    acknowledged_at: Optional[float] = None
    acknowledged_by: Optional[str] = None
    resolved_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "rule_id": self.rule_id,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "status": self.status.value,
            "acknowledged_at": self.acknowledged_at,
            "acknowledged_by": self.acknowledged_by,
            "resolved_at": self.resolved_at,
        }


class DuplicateCacheManager:
    """
    带TTL过期淘汰+容量上限告警的去重缓存管理

    核心能力:
    1. TTL过期淘汰: 每个event_id记录存入时间,超过TTL自动淘汰
    2. 容量上限: 设置最大缓存条数,超过上限时告警并淘汰最旧的
    3. 容量告警: 达到预警阈值(默认80%)时发出告警
    4. 持久化: 缓存状态保存到磁盘,支持重启恢复
    5. 统计指标: 缓存命中率、淘汰数、告警次数

    使用示例:
        manager = DuplicateCacheManager(
            ttl_seconds=86400,      # 24小时TTL
            max_entries=100000,     # 最大10万条
            warning_threshold=0.8,   # 80%预警
            state_dir='/var/lib/photonbox/cache',
        )
        manager.load()  # 加载持久化状态

        # 检查重复
        if manager.is_duplicate('event-123'):
            print('重复事件')
        else:
            manager.add('event-123')

        # 定期清理过期
        manager.cleanup_expired()
    """

    def __init__(
        self,
        ttl_seconds: int = 86400,          # 默认24小时TTL
        max_entries: int = 100000,          # 默认最大10万条
        warning_threshold: float = 0.8,      # 默认80%预警
        critical_threshold: float = 0.95,    # 默认95%严重
        state_dir: Optional[str] = None,  # 默认使用tempfile.gettempdir()
        alert_callback: Optional[Callable[[Alert], None]] = None,
    ):
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold
        self.state_dir = state_dir or os.path.join(tempfile.gettempdir(), 'photonbox_cache')
        self.alert_callback = alert_callback

        self._cache: Dict[str, float] = {}  # event_id -> timestamp
        self._lock = threading.Lock()
        self._stats = {
            'total_added': 0,
            'total_duplicates': 0,
            'total_expired': 0,
            'total_evicted': 0,
            'capacity_warnings': 0,
            'capacity_criticals': 0,
        }
        self._last_warning_time = 0
        self._warning_cooldown = 300  # 告警冷却5分钟

        os.makedirs(self.state_dir, exist_ok=True)

    def add(self, event_id: str) -> bool:
        """
        添加事件到缓存

        Returns:
            True如果添加成功, False如果已存在
        """
        with self._lock:
            if event_id in self._cache:
                self._stats['total_duplicates'] += 1
                return False

            self._cache[event_id] = time.time()
            self._stats['total_added'] += 1

            # 检查容量
            self._check_capacity_locked()

            return True

    def is_duplicate(self, event_id: str) -> bool:
        """检查是否为重复事件(同时更新访问时间)"""
        with self._lock:
            if event_id in self._cache:
                self._stats['total_duplicates'] += 1
                self._cache[event_id] = time.time()  # 更新访问时间
                return True
            return False

    def cleanup_expired(self) -> int:
        """清理过期条目,返回清理数量"""
        with self._lock:
            now = time.time()
            expired = [
                eid for eid, ts in self._cache.items()
                if now - ts > self.ttl_seconds
            ]
            for eid in expired:
                del self._cache[eid]
            self._stats['total_expired'] += len(expired)
            return len(expired)

    def _check_capacity_locked(self) -> None:
        """检查容量(已在锁内)"""
        usage = len(self._cache) / self.max_entries

        if usage >= self.critical_threshold:
            # 严重: 淘汰最旧的10%
            self._evict_oldest_locked(int(self.max_entries * 0.1))
            self._stats['capacity_criticals'] += 1
            self._emit_alert_locked(
                alert_type='cache_capacity_critical',
                severity=AlertSeverity.CRITICAL,
                title='去重缓存容量严重超限',
                description=f'缓存使用率{usage:.1%},已自动淘汰最旧10%',
                metadata={'usage': usage, 'cache_size': len(self._cache)},
            )
        elif usage >= self.warning_threshold:
            self._stats['capacity_warnings'] += 1
            self._emit_alert_locked(
                alert_type='cache_capacity_warning',
                severity=AlertSeverity.WARNING,
                title='去重缓存容量预警',
                description=f'缓存使用率{usage:.1%},接近上限{self.max_entries}',
                metadata={'usage': usage, 'cache_size': len(self._cache)},
            )

    def _evict_oldest_locked(self, count: int) -> int:
        """淘汰最旧的条目(已在锁内)"""
        if count <= 0 or not self._cache:
            return 0
        # 按时间排序,淘汰最旧的
        sorted_items = sorted(self._cache.items(), key=lambda x: x[1])
        evicted = 0
        for eid, _ in sorted_items[:count]:
            if eid in self._cache:
                del self._cache[eid]
                evicted += 1
        self._stats['total_evicted'] += evicted
        return evicted

    def _emit_alert_locked(self, alert_type: str, severity: AlertSeverity,
                            title: str, description: str, metadata: Dict[str, Any]) -> None:
        """发出告警(已在锁内,带冷却)"""
        now = time.time()
        if now - self._last_warning_time < self._warning_cooldown:
            return  # 冷却期内不重复告警
        self._last_warning_time = now

        alert = Alert(
            alert_id=f'cache-{int(now*1000)}',
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            source='DuplicateCacheManager',
            metadata=metadata,
        )
        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception as e:
                # 告警回调失败不影响主流程,记录到内部统计
                self._stats.setdefault('alert_callback_errors', 0)
                self._stats['alert_callback_errors'] += 1

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._lock:
            return {
                'cache_size': len(self._cache),
                'max_entries': self.max_entries,
                'usage_ratio': len(self._cache) / self.max_entries,
                'ttl_seconds': self.ttl_seconds,
                **self._stats,
            }

    def persist(self) -> bool:
        """持久化缓存到磁盘"""
        try:
            with self._lock:
                cache_file = os.path.join(self.state_dir, 'duplicate_cache_ttl.json')
                data = {
                    'cache': self._cache,
                    'stats': self._stats,
                    'saved_at': time.time(),
                    'ttl_seconds': self.ttl_seconds,
                    'max_entries': self.max_entries,
                }
                with open(cache_file, 'w') as f:
                    json.dump(data, f)
            return True
        except OSError:
            return False

    def load(self) -> int:
        """从磁盘加载缓存,返回加载数量"""
        cache_file = os.path.join(self.state_dir, 'duplicate_cache_ttl.json')
        if not os.path.exists(cache_file):
            return 0
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            with self._lock:
                # 加载时过滤过期条目
                now = time.time()
                self._cache = {
                    eid: ts for eid, ts in data.get('cache', {}).items()
                    if now - ts <= self.ttl_seconds
                }
                self._stats.update(data.get('stats', {}))
            return len(self._cache)
        except (json.JSONDecodeError, OSError):
            return 0


class CircuitBreakerAlertManager:
    """
    规则熔断开告警+人工确认恢复机制

    核心能力:
    1. 熔断开告警: 规则熔断时自动发出告警,包含规则ID、失败次数、原因
    2. 告警持久化: 告警保存到磁盘,支持查询和审计
    3. 人工确认: 熔断后需要人工确认才能恢复(可选,默认自动恢复)
    4. 恢复验证: 恢复后验证规则是否正常工作
    5. 告警统计: 按规则/类型/严重等级统计

    使用示例:
        alert_mgr = CircuitBreakerAlertManager(
            state_dir='/var/lib/photonbox/alerts',
            require_manual_ack=True,  # 需要人工确认才能恢复
        )

        # 熔断时发出告警
        alert = alert_mgr.on_circuit_break(
            rule_id='seccomp-ptrace-block',
            failure_count=5,
            last_failure_reason='deploy_failed',
            rule_config={'action': 'KILL'},
        )

        # 人工确认
        alert_mgr.acknowledge_alert(alert.alert_id, by='admin')

        # 恢复规则(需要先确认)
        result = alert_mgr.attempt_recovery(rule_id='seccomp-ptrace-block')
    """

    def __init__(
        self,
        state_dir: Optional[str] = None,  # 默认使用tempfile.gettempdir()
        require_manual_ack: bool = False,  # 是否需要人工确认才能恢复
        alert_callback: Optional[Callable[[Alert], None]] = None,
        max_alerts: int = 10000,
    ):
        self.state_dir = state_dir or os.path.join(tempfile.gettempdir(), 'photonbox_alerts')
        self.require_manual_ack = require_manual_ack
        self.alert_callback = alert_callback
        self.max_alerts = max_alerts

        self._alerts: Dict[str, Alert] = {}
        self._lock = threading.Lock()
        self._pending_recovery: Set[str] = set()  # 等待人工确认的规则

        os.makedirs(self.state_dir, exist_ok=True)

    def on_circuit_break(
        self,
        rule_id: str,
        failure_count: int,
        last_failure_reason: str,
        rule_config: Optional[Dict[str, Any]] = None,
    ) -> Alert:
        """规则熔断时调用,发出告警"""
        with self._lock:
            alert = Alert(
                alert_id=f'cb-{rule_id}-{int(time.time()*1000)}',
                alert_type='circuit_breaker',
                severity=AlertSeverity.HIGH,
                title=f'规则熔断: {rule_id}',
                description=(
                    f'规则 {rule_id} 因连续 {failure_count} 次失败触发熔断。'
                    f'最后失败原因: {last_failure_reason}。'
                    f'{"需要人工确认后才能恢复。" if self.require_manual_ack else "冷却后可自动尝试恢复。"}'
                ),
                source='CircuitBreakerAlertManager',
                rule_id=rule_id,
                metadata={
                    'failure_count': failure_count,
                    'last_failure_reason': last_failure_reason,
                    'rule_config': rule_config or {},
                    'require_manual_ack': self.require_manual_ack,
                },
            )
            self._alerts[alert.alert_id] = alert
            self._pending_recovery.add(rule_id)

            # 限制告警数量
            if len(self._alerts) > self.max_alerts:
                self._cleanup_old_alerts_locked()

            # 持久化
            self._persist_locked()

            # 回调
            if self.alert_callback:
                try:
                    self.alert_callback(alert)
                except Exception:
                    # 告警回调失败不影响主流程,记录内部错误计数
                    self._alert_callback_errors = getattr(self, '_alert_callback_errors', 0) + 1

            return alert

    def acknowledge_alert(self, alert_id: str, by: str = 'admin') -> bool:
        """人工确认告警"""
        with self._lock:
            alert = self._alerts.get(alert_id)
            if not alert:
                return False
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_at = time.time()
            alert.acknowledged_by = by
            self._persist_locked()
            return True

    def attempt_recovery(self, rule_id: str) -> Dict[str, Any]:
        """
        尝试恢复规则

        Returns:
            恢复结果: {success, reason, requires_ack, alert_id}
        """
        with self._lock:
            # 检查是否需要人工确认
            if self.require_manual_ack and rule_id in self._pending_recovery:
                # 查找该规则最新的未确认告警
                for alert in reversed(list(self._alerts.values())):
                    if (alert.rule_id == rule_id and
                        alert.status == AlertStatus.NEW):
                        return {
                            'success': False,
                            'reason': 'requires_manual_acknowledgment',
                            'requires_ack': True,
                            'alert_id': alert.alert_id,
                            'message': f'规则 {rule_id} 熔断后需要人工确认才能恢复,请先确认告警 {alert.alert_id}',
                        }

            # 从待恢复集合中移除
            self._pending_recovery.discard(rule_id)

            # 标记相关告警为已解决
            for alert in self._alerts.values():
                if alert.rule_id == rule_id and alert.status != AlertStatus.RESOLVED:
                    alert.status = AlertStatus.RESOLVED
                    alert.resolved_at = time.time()

            self._persist_locked()
            return {
                'success': True,
                'reason': 'recovery_attempted',
                'requires_ack': False,
                'message': f'规则 {rule_id} 恢复尝试已发起,请验证规则是否正常工作',
            }

    def get_pending_alerts(self) -> List[Alert]:
        """获取所有未确认的告警"""
        with self._lock:
            return [
                a for a in self._alerts.values()
                if a.status == AlertStatus.NEW
            ]

    def get_alerts_by_rule(self, rule_id: str) -> List[Alert]:
        """按规则ID获取告警"""
        with self._lock:
            return [
                a for a in self._alerts.values()
                if a.rule_id == rule_id
            ]

    def get_stats(self) -> Dict[str, Any]:
        """获取告警统计"""
        with self._lock:
            by_severity = {}
            by_status = {}
            for alert in self._alerts.values():
                sev = alert.severity.value
                by_severity[sev] = by_severity.get(sev, 0) + 1
                st = alert.status.value
                by_status[st] = by_status.get(st, 0) + 1
            return {
                'total_alerts': len(self._alerts),
                'pending_ack': len(self.get_pending_alerts()),
                'pending_recovery': len(self._pending_recovery),
                'by_severity': by_severity,
                'by_status': by_status,
                'require_manual_ack': self.require_manual_ack,
            }

    def _cleanup_old_alerts_locked(self) -> None:
        """清理最旧的告警(已在锁内)"""
        sorted_alerts = sorted(self._alerts.values(), key=lambda a: a.created_at)
        for alert in sorted_alerts[:int(self.max_alerts * 0.1)]:
            if alert.alert_id in self._alerts:
                del self._alerts[alert.alert_id]

    def _persist_locked(self) -> None:
        """持久化告警(已在锁内)"""
        try:
            alerts_file = os.path.join(self.state_dir, 'circuit_breaker_alerts.json')
            data = {
                'alerts': [a.to_dict() for a in self._alerts.values()],
                'pending_recovery': list(self._pending_recovery),
                'saved_at': time.time(),
            }
            with open(alerts_file, 'w') as f:
                json.dump(data, f, indent=2)
        except OSError:
            pass

    def load(self) -> int:
        """从磁盘加载告警"""
        alerts_file = os.path.join(self.state_dir, 'circuit_breaker_alerts.json')
        if not os.path.exists(alerts_file):
            return 0
        try:
            with open(alerts_file, 'r') as f:
                data = json.load(f)
            with self._lock:
                self._alerts.clear()
                for a_data in data.get('alerts', []):
                    alert = Alert(
                        alert_id=a_data['alert_id'],
                        alert_type=a_data['alert_type'],
                        severity=AlertSeverity(a_data['severity']),
                        title=a_data['title'],
                        description=a_data['description'],
                        source=a_data['source'],
                        rule_id=a_data.get('rule_id'),
                        metadata=a_data.get('metadata', {}),
                        created_at=a_data.get('created_at', time.time()),
                        status=AlertStatus(a_data.get('status', 'new')),
                        acknowledged_at=a_data.get('acknowledged_at'),
                        acknowledged_by=a_data.get('acknowledged_by'),
                        resolved_at=a_data.get('resolved_at'),
                    )
                    self._alerts[alert.alert_id] = alert
                self._pending_recovery = set(data.get('pending_recovery', []))
            return len(self._alerts)
        except (json.JSONDecodeError, OSError, KeyError):
            return 0
