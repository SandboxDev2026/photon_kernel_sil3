"""
PhotonBox SDK - 安全监控模块

逃逸检测引擎和安全监控接口。
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
from enum import Enum

# 导入内部逃逸检测引擎
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))


class EscapeSeverity(Enum):
    """逃逸严重程度"""
    SUSPICIOUS = "suspicious"      # 可疑行为
    LIKELY_ATTEMPT = "likely"      # 可能的逃逸尝试
    CONFIRMED_ATTEMPT = "confirmed"  # 确认的逃逸尝试
    CRITICAL = "critical"           # 严重逃逸事件


@dataclass
class EscapeEvent:
    """逃逸事件"""
    event_id: str
    timestamp: float
    severity: EscapeSeverity
    description: str
    sandbox_id: str
    source: str  # seccomp / namespace / network / audit
    details: Dict[str, Any] = field(default_factory=dict)
    blocked: bool = True
    action_taken: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "severity": self.severity.value,
            "description": self.description,
            "sandbox_id": self.sandbox_id,
            "source": self.source,
            "blocked": self.blocked,
            "action_taken": self.action_taken,
        }


class EscapeDetectionEngine:
    """
    逃逸检测引擎

    基于真实事件特征的逃逸检测规则，
    对接seccomp违规、namespace异常、网络隧道、审计链断裂等信号。
    """

    def __init__(self, auto_block: bool = True):
        self.auto_block = auto_block
        self.detected_events: List[EscapeEvent] = []
        self.detection_rules: List[Dict[str, Any]] = self._load_default_rules()
        self.on_escape: Optional[Callable[[EscapeEvent], None]] = None
        self._stats = {"total_checks": 0, "detected": 0, "blocked": 0}

    def _load_default_rules(self) -> List[Dict[str, Any]]:
        """加载默认检测规则"""
        return [
            {
                "rule_id": "ESC-001",
                "name": "seccomp高危系统调用",
                "source": "seccomp",
                "pattern": {"syscall": ["ptrace", "kexec_load", "init_module", "reboot"]},
                "severity": EscapeSeverity.CONFIRMED_ATTEMPT,
                "action": "kill_sandbox",
            },
            {
                "rule_id": "ESC-002",
                "name": "namespace逃逸尝试",
                "source": "namespace",
                "pattern": {"syscall": ["setns", "unshare"], "flags": ["CLONE_NEWUSER", "CLONE_NEWNS"]},
                "severity": EscapeSeverity.LIKELY_ATTEMPT,
                "action": "block_syscall",
            },
            {
                "rule_id": "ESC-003",
                "name": "内网访问尝试",
                "source": "network",
                "pattern": {"dst_cidr": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]},
                "severity": EscapeSeverity.SUSPICIOUS,
                "action": "drop_packet",
            },
            {
                "rule_id": "ESC-004",
                "name": "DNS隧道",
                "source": "network",
                "pattern": {"query_type": "TXT", "domain_length": ">50"},
                "severity": EscapeSeverity.LIKELY_ATTEMPT,
                "action": "block_dns",
            },
            {
                "rule_id": "ESC-005",
                "name": "审计链断裂",
                "source": "audit",
                "pattern": {"anomaly_type": "hash_chain_break"},
                "severity": EscapeSeverity.CRITICAL,
                "action": "freeze_sandbox",
            },
            {
                "rule_id": "ESC-006",
                "name": "敏感文件访问",
                "source": "filesystem",
                "pattern": {"path": ["/etc/shadow", "/etc/sudoers", "/proc/1/environ", "/root/.ssh"]},
                "severity": EscapeSeverity.SUSPICIOUS,
                "action": "deny_access",
            },
            {
                "rule_id": "ESC-007",
                "name": "fork bomb",
                "source": "resource",
                "pattern": {"fork_rate": ">100/s"},
                "severity": EscapeSeverity.LIKELY_ATTEMPT,
                "action": "kill_sandbox",
            },
            {
                "rule_id": "ESC-008",
                "name": "docker.sock访问",
                "source": "filesystem",
                "pattern": {"path": ["/var/run/docker.sock"]},
                "severity": EscapeSeverity.CONFIRMED_ATTEMPT,
                "action": "deny_access",
            },
        ]

    def check_event(self, event: Dict[str, Any]) -> Optional[EscapeEvent]:
        """
        检查事件是否匹配逃逸检测规则

        Args:
            event: 安全事件字典

        Returns:
            逃逸事件（如果匹配规则），否则None
        """
        self._stats["total_checks"] += 1
        event_source = event.get("source", event.get("event_source", "unknown"))

        for rule in self.detection_rules:
            if rule["source"] != event_source:
                continue

            if self._match_rule(rule, event):
                escape_event = EscapeEvent(
                    event_id=f"esc-{int(time.time()*1000)}",
                    timestamp=event.get("timestamp", time.time()),
                    severity=rule["severity"],
                    description=f"[{rule['rule_id']}] {rule['name']}: {event.get('description', '')}",
                    sandbox_id=event.get("sandbox_id", "unknown"),
                    source=event_source,
                    details=event,
                    blocked=self.auto_block,
                    action_taken=rule["action"] if self.auto_block else "none",
                )

                self.detected_events.append(escape_event)
                self._stats["detected"] += 1
                if self.auto_block:
                    self._stats["blocked"] += 1

                if self.on_escape:
                    self.on_escape(escape_event)

                return escape_event

        return None

    def _match_rule(self, rule: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """检查事件是否匹配规则"""
        pattern = rule.get("pattern", {})
        for key, expected_values in pattern.items():
            actual_value = event.get(key)
            if actual_value is None:
                continue
            if isinstance(expected_values, list):
                if actual_value not in expected_values:
                    return False
            elif isinstance(expected_values, str) and expected_values.startswith(">"):
                threshold = float(expected_values[1:])
                if float(actual_value) <= threshold:
                    return False
            elif actual_value != expected_values:
                return False
        return True

    def get_stats(self) -> Dict[str, Any]:
        """获取检测统计"""
        return {
            **self._stats,
            "rules_count": len(self.detection_rules),
            "events_count": len(self.detected_events),
            "by_severity": {
                sev.value: sum(1 for e in self.detected_events if e.severity == sev)
                for sev in EscapeSeverity
            },
        }

    def get_recent_events(self, limit: int = 50) -> List[EscapeEvent]:
        """获取最近的逃逸事件"""
        return self.detected_events[-limit:]


class SecurityMonitor:
    """
    安全监控器

    整合逃逸检测、审计日志、资源监控的统一监控接口。
    """

    def __init__(self, auto_escape_block: bool = True):
        self.escape_engine = EscapeDetectionEngine(auto_block=auto_escape_block)
        self.audit_events: List[Dict[str, Any]] = []
        self.resource_alerts: List[Dict[str, Any]] = []
        self._callbacks: Dict[str, List[Callable]] = {
            "escape": [],
            "audit": [],
            "resource": [],
        }

    def register_callback(self, event_type: str, callback: Callable) -> None:
        """注册事件回调"""
        if event_type in self._callbacks:
            self._callbacks[event_type].append(callback)

    def ingest_security_event(self, event: Dict[str, Any]) -> None:
        """摄入安全事件"""
        self.audit_events.append(event)

        # 逃逸检测
        escape_event = self.escape_engine.check_event(event)
        if escape_event:
            for cb in self._callbacks["escape"]:
                cb(escape_event)

        for cb in self._callbacks["audit"]:
            cb(event)

    def get_security_summary(self) -> Dict[str, Any]:
        """获取安全摘要"""
        return {
            "escape_detection": self.escape_engine.get_stats(),
            "audit_events_count": len(self.audit_events),
            "resource_alerts_count": len(self.resource_alerts),
            "recent_escapes": [e.to_dict() for e in self.escape_engine.get_recent_events(10)],
        }
