"""
evolution.real_data_adapter — 真实数据适配器

将 RedBlueAdversaryTrainer 的输入源从模拟数据，改为消费真实模块的产物：

1. LightPool 的 seccomp 违规日志
2. StrongPool 的 KVM VM-Exit 事件统计
3. HMAC 审计链中的异常模式

设计原则：
- 适配器层独立于红蓝对抗框架，可单独测试
- 支持多种真实数据源（文件、gRPC流、内存队列）
- 真实事件转换为标准化的 SecurityEvent，再注入红蓝对抗框架
- 异常模式检测：频率异常、序列异常、哈希链断裂
"""
from __future__ import annotations
import json
import os
import re
import time
import hashlib
import hmac
from typing import List, Dict, Any, Optional, Tuple, Iterator
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque


class EventSource(Enum):
    """事件来源"""
    SECCOMP_VIOLATION = "seccomp_violation"      # LightPool seccomp违规
    KVM_VM_EXIT = "kvm_vm_exit"                    # StrongPool KVM VM-Exit
    AUDIT_CHAIN_ANOMALY = "audit_chain_anomaly"    # HMAC审计链异常
    NETWORK_BLOCK = "network_block"                 # eBPF网络拦截
    RESOURCE_EXCEED = "resource_exceed"             # 资源超限
    CAPABILITY_DROP = "capability_drop"             # 能力位删除事件


class AnomalyType(Enum):
    """异常类型"""
    FREQUENCY_SPIKE = "frequency_spike"           # 频率突增
    SEQUENCE_ANOMALY = "sequence_anomaly"         # 序列异常
    HASH_CHAIN_BREAK = "hash_chain_break"         # 哈希链断裂
    MISSING_EVENTS = "missing_events"             # 事件丢失
    DUPLICATE_EVENTS = "duplicate_events"         # 重复事件
    TIMESTAMP_JUMP = "timestamp_jump"             # 时间戳跳跃


@dataclass
class SecurityEvent:
    """
    标准化安全事件

    从各种真实数据源转换而来的统一事件格式，
    可直接注入 RedBlueAdversaryTrainer 作为攻击/防御输入。
    """
    event_id: str
    source: EventSource
    timestamp: float
    sandbox_id: str
    severity: str  # "low", "medium", "high", "critical"
    description: str
    payload: Dict[str, Any] = field(default_factory=dict)
    raw_event: Optional[Dict[str, Any]] = None
    anomaly_type: Optional[AnomalyType] = None
    anomaly_score: float = 0.0  # 0.0-1.0，异常程度

    def to_attack_case_params(self) -> Dict[str, Any]:
        """
        转换为攻击用例参数

        将真实安全事件转换为红蓝对抗框架中红方可使用的攻击参数。
        """
        return {
            "event_id": self.event_id,
            "source": self.source.value,
            "severity": self.severity,
            "description": self.description,
            "payload": self.payload,
            "anomaly_type": self.anomaly_type.value if self.anomaly_type else None,
            "anomaly_score": self.anomaly_score,
        }


class SeccompViolationParser:
    """
    LightPool seccomp 违规日志解析器

    解析 C++ AuditLogger 生成的 JSONL 审计日志中的 seccomp 违规事件。
    支持标准格式和HMAC哈希链格式。
    """

    # seccomp违规事件的关键词模式
    SECCOMP_PATTERNS = [
        r"seccomp.*violat",
        r"SECCOMP_VIOLATION",
        r"syscall.*blocked",
        r"syscall.*denied",
        r"blocked_syscall",
    ]

    def __init__(self, hmac_secret: Optional[str] = None):
        self.hmac_secret = hmac_secret
        self.parsed_events: List[SecurityEvent] = []
        self.violation_counts: Dict[str, int] = defaultdict(int)
        self.syscall_frequency: Dict[str, List[float]] = defaultdict(list)

    def parse_line(self, line: str) -> Optional[SecurityEvent]:
        """
        解析单行审计日志

        支持两种格式：
        1. 纯JSON格式
        2. HMAC哈希链格式（包含seq, prev_hash, hmac字段）
        """
        line = line.strip()
        if not line:
            return None

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        # 检查是否为seccomp违规事件
        is_seccomp = self._is_seccomp_violation(data)
        if not is_seccomp:
            return None

        # 构建安全事件
        event = self._build_event(data)
        self.parsed_events.append(event)

        # 更新统计
        syscall = data.get("syscall", data.get("syscall_num", "unknown"))
        self.violation_counts[str(syscall)] += 1
        self.syscall_frequency[str(syscall)].append(event.timestamp)

        return event

    def _is_seccomp_violation(self, data: Dict[str, Any]) -> bool:
        """判断是否为seccomp违规事件"""
        # 检查event_type字段
        event_type = str(data.get("event_type", "")).upper()
        if "SECCOMP" in event_type or "VIOLATION" in event_type:
            return True

        # 检查关键词
        text = json.dumps(data).lower()
        for pattern in self.SECCOMP_PATTERNS:
            if re.search(pattern, text):
                return True

        return False

    def _build_event(self, data: Dict[str, Any]) -> SecurityEvent:
        """从原始数据构建安全事件"""
        syscall = data.get("syscall", data.get("syscall_num", "unknown"))
        sandbox_id = data.get("sandbox_id", data.get("instance_id", "unknown"))
        timestamp = data.get("timestamp", time.time())

        # 严重程度判断
        severity = "medium"
        if syscall in ["ptrace", "kexec_load", "init_module", "reboot"]:
            severity = "critical"
        elif syscall in ["socket", "connect", "bind", "mount"]:
            severity = "high"

        return SecurityEvent(
            event_id=data.get("event_id", hashlib.md5(json.dumps(data).encode(), usedforsecurity=False).hexdigest()[:16]),
            source=EventSource.SECCOMP_VIOLATION,
            timestamp=float(timestamp),
            sandbox_id=str(sandbox_id),
            severity=severity,
            description=f"seccomp违规: syscall={syscall}, sandbox={sandbox_id}",
            payload={
                "syscall": syscall,
                "syscall_num": data.get("syscall_num"),
                "arch": data.get("arch", "x86_64"),
                "pid": data.get("pid"),
                "seccomp_action": data.get("action", "KILL"),
            },
            raw_event=data,
        )

    def get_top_violations(self, n: int = 10) -> List[Tuple[str, int]]:
        """获取Top-N违规系统调用"""
        return sorted(self.violation_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def detect_frequency_anomalies(self, window_seconds: float = 60.0, threshold: float = 3.0) -> List[SecurityEvent]:
        """
        检测频率异常

        在指定时间窗口内，如果某syscall违规频率超过历史均值的threshold倍，
        标记为频率异常。
        """
        anomalies = []
        for syscall, timestamps in self.syscall_frequency.items():
            if len(timestamps) < 5:
                continue

            # 计算滑动窗口内的频率
            timestamps.sort()
            for i in range(len(timestamps)):
                window_start = timestamps[i]
                window_end = window_start + window_seconds
                window_count = sum(1 for t in timestamps if window_start <= t <= window_end)

                # 历史均值（排除当前窗口）
                historical = [t for t in timestamps if t < window_start or t > window_end]
                if len(historical) < 3:
                    continue

                historical_rate = len(historical) / (max(historical) - min(historical) + 1) * window_seconds
                if historical_rate > 0 and window_count > historical_rate * threshold:
                    # 找到对应的事件
                    for event in self.parsed_events:
                        if (event.payload.get("syscall") == syscall and
                            window_start <= event.timestamp <= window_end and
                            event.anomaly_type is None):
                            event.anomaly_type = AnomalyType.FREQUENCY_SPIKE
                            event.anomaly_score = min(1.0, window_count / (historical_rate * threshold))
                            anomalies.append(event)
                            break

        return anomalies


class KvmVmExitParser:
    """
    StrongPool KVM VM-Exit 事件统计解析器

    解析 Firecracker MicroVM 的 VM-Exit 事件统计，
    识别异常的VM-Exit模式（可能表明逃逸尝试或性能问题）。
    """

    # 可疑的VM-Exit原因
    SUSPICIOUS_EXIT_REASONS = [
        "IO_INSTRUCTION",
        "MSR_WRITE",
        "EXCEPTION_NMI",
        "TRIPLE_FAULT",
        "SHUTDOWN",
        "INIT_SIGNAL",
        "HLT",
    ]

    # 高风险VM-Exit原因（可能表明逃逸尝试）
    HIGH_RISK_EXIT_REASONS = [
        "VMCALL",
        "VMMCALL",
        "CPUID",
        "RDMSR",
        "WRMSR",
        "XSETBV",
    ]

    def __init__(self):
        self.parsed_events: List[SecurityEvent] = []
        self.exit_reason_counts: Dict[str, int] = defaultdict(int)
        self.vm_exit_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def parse_event(self, data: Dict[str, Any]) -> Optional[SecurityEvent]:
        """
        解析单个VM-Exit事件

        期望格式（来自Firecracker metrics或KVM trace）：
        {
            "vm_id": "vm-xxx",
            "exit_reason": "IO_INSTRUCTION",
            "exit_count": 1,
            "timestamp": 1234567890.0,
            "vcpu_id": 0,
            "guest_rip": "0xffff...",
            "qualification": "..."
        }
        """
        exit_reason = data.get("exit_reason", data.get("reason", "UNKNOWN"))
        vm_id = data.get("vm_id", data.get("sandbox_id", "unknown"))
        timestamp = float(data.get("timestamp", time.time()))

        # 判断风险等级
        severity = "low"
        if exit_reason in self.HIGH_RISK_EXIT_REASONS:
            severity = "high"
        elif exit_reason in self.SUSPICIOUS_EXIT_REASONS:
            severity = "medium"

        # 检查是否为异常模式（短时间内大量相同exit_reason）
        anomaly_score = 0.0
        anomaly_type = None

        history = self.vm_exit_history[vm_id]
        recent_exits = [e for e in history if timestamp - e["timestamp"] < 1.0]
        same_reason_recent = sum(1 for e in recent_exits if e["exit_reason"] == exit_reason)

        if same_reason_recent > 100:  # 1秒内超过100次相同exit
            anomaly_type = AnomalyType.FREQUENCY_SPIKE
            anomaly_score = min(1.0, same_reason_recent / 1000.0)
            severity = "critical" if severity in ["low", "medium"] else severity

        event = SecurityEvent(
            event_id=data.get("event_id", hashlib.md5(json.dumps(data).encode(), usedforsecurity=False).hexdigest()[:16]),
            source=EventSource.KVM_VM_EXIT,
            timestamp=timestamp,
            sandbox_id=str(vm_id),
            severity=severity,
            description=f"KVM VM-Exit: reason={exit_reason}, vm={vm_id}, count={same_reason_recent}/s",
            payload={
                "exit_reason": exit_reason,
                "vcpu_id": data.get("vcpu_id"),
                "guest_rip": data.get("guest_rip"),
                "qualification": data.get("qualification"),
                "exit_rate_per_second": same_reason_recent,
            },
            raw_event=data,
            anomaly_type=anomaly_type,
            anomaly_score=anomaly_score,
        )

        self.parsed_events.append(event)
        self.exit_reason_counts[exit_reason] += 1
        self.vm_exit_history[vm_id].append({
            "timestamp": timestamp,
            "exit_reason": exit_reason,
        })

        return event

    def get_top_exit_reasons(self, n: int = 10) -> List[Tuple[str, int]]:
        """获取Top-N VM-Exit原因"""
        return sorted(self.exit_reason_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def detect_escape_attempts(self) -> List[SecurityEvent]:
        """
        检测潜在的逃逸尝试

        基于VM-Exit模式识别逃逸尝试：
        1. 大量VMCALL/VMMCALL（尝试hypercall）
        2. 大量RDMSR/WRMSR（尝试访问敏感MSR）
        3. TRIPLE_FAULT/SHUTDOWN（可能是崩溃攻击）
        """
        escape_attempts = []
        for event in self.parsed_events:
            reason = event.payload.get("exit_reason", "")
            if reason in self.HIGH_RISK_EXIT_REASONS and event.anomaly_score > 0.3:
                event.description += " [潜在逃逸尝试]"
                escape_attempts.append(event)
        return escape_attempts


class AuditChainAnomalyDetector:
    """
    HMAC 审计链异常检测器

    检测审计日志中的异常模式：
    1. 哈希链断裂（prev_hash不匹配）
    2. HMAC验证失败
    3. 序列号不连续（事件丢失）
    4. 时间戳异常跳跃
    5. 重复事件
    """

    def __init__(self, hmac_secret: str = "photon-sandbox-audit-chain-default-key"):
        self.hmac_secret = hmac_secret
        self.anomalies: List[SecurityEvent] = []
        self.last_seq: Optional[int] = None
        self.last_hash: Optional[str] = None
        self.last_timestamp: Optional[float] = None
        self.seen_event_ids: set = set()

    def verify_and_detect(self, line: str) -> Tuple[bool, Optional[SecurityEvent]]:
        """
        验证单行审计日志并检测异常

        返回: (是否有效, 异常事件(如果有))
        """
        line = line.strip()
        if not line:
            return True, None

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return False, None

        # 检查HMAC链字段
        seq = data.get("seq")
        prev_hash = data.get("prev_hash")
        hmac_val = data.get("hmac")

        anomaly_type = None
        anomaly_score = 0.0
        description = ""

        # 1. 检测哈希链断裂（只有非第一条记录才检查）
        if self.last_hash is not None and prev_hash is not None:
            if prev_hash != self.last_hash:
                anomaly_type = AnomalyType.HASH_CHAIN_BREAK
                anomaly_score = 1.0
                description = f"哈希链断裂: expected={self.last_hash[:16]}..., got={prev_hash[:16]}..."

        # 2. 检测HMAC验证失败（只有非第一条记录才检查）
        if hmac_val is not None and prev_hash is not None and self.last_hash is not None:
            # 重新计算HMAC（排除hmac字段）
            payload = {k: v for k, v in data.items() if k != "hmac"}
            expected_hmac = self._compute_hmac(json.dumps(payload, sort_keys=True))
            if hmac_val != expected_hmac:
                anomaly_type = AnomalyType.HASH_CHAIN_BREAK
                anomaly_score = 1.0
                description = f"HMAC验证失败: expected={expected_hmac[:16]}..., got={hmac_val[:16]}..."

        # 3. 检测序列号不连续
        if seq is not None and self.last_seq is not None:
            if seq != self.last_seq + 1:
                missing = seq - self.last_seq - 1
                anomaly_type = AnomalyType.MISSING_EVENTS
                anomaly_score = min(1.0, missing / 10.0)
                description = f"序列号不连续: expected={self.last_seq + 1}, got={seq}, missing={missing}"

        # 4. 检测时间戳跳跃
        timestamp = data.get("timestamp")
        if timestamp is not None and self.last_timestamp is not None:
            time_jump = float(timestamp) - self.last_timestamp
            if time_jump > 3600:  # 超过1小时
                anomaly_type = AnomalyType.TIMESTAMP_JUMP
                anomaly_score = min(1.0, time_jump / 86400.0)
                description = f"时间戳跳跃: {time_jump:.0f}秒"

        # 5. 检测重复事件
        event_id = data.get("event_id")
        if event_id is not None:
            if event_id in self.seen_event_ids:
                anomaly_type = AnomalyType.DUPLICATE_EVENTS
                anomaly_score = 0.5
                description = f"重复事件: event_id={event_id}"
            else:
                self.seen_event_ids.add(event_id)

        # 更新状态
        if seq is not None:
            self.last_seq = seq
        if hmac_val is not None:
            # 计算当前记录的hash（用于下一条的prev_hash验证）
            self.last_hash = self._compute_hash(line)
        if timestamp is not None:
            self.last_timestamp = float(timestamp)

        # 如果检测到异常，构建异常事件
        if anomaly_type is not None:
            anomaly_event = SecurityEvent(
                event_id=f"anomaly_{hashlib.md5(line.encode(), usedforsecurity=False).hexdigest()[:16]}",
                source=EventSource.AUDIT_CHAIN_ANOMALY,
                timestamp=float(timestamp) if timestamp else time.time(),
                sandbox_id=str(data.get("sandbox_id", "unknown")),
                severity="high" if anomaly_score > 0.7 else "medium",
                description=description,
                payload={"raw_event": data, "anomaly_details": description},
                raw_event=data,
                anomaly_type=anomaly_type,
                anomaly_score=anomaly_score,
            )
            self.anomalies.append(anomaly_event)
            return False, anomaly_event

        return True, None

    def _compute_hmac(self, payload: str) -> str:
        """计算HMAC-SHA256"""
        return hmac.new(
            self.hmac_secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

    def _compute_hash(self, data: str) -> str:
        """计算SHA256哈希"""
        return hashlib.sha256(data.encode()).hexdigest()

    def get_anomaly_summary(self) -> Dict[str, Any]:
        """获取异常摘要"""
        by_type: Dict[str, int] = defaultdict(int)
        for anomaly in self.anomalies:
            if anomaly.anomaly_type:
                by_type[anomaly.anomaly_type.value] += 1

        return {
            "total_anomalies": len(self.anomalies),
            "by_type": dict(by_type),
            "critical_count": sum(1 for a in self.anomalies if a.severity == "critical"),
            "high_count": sum(1 for a in self.anomalies if a.severity == "high"),
        }


class RealDataAdapter:
    """
    真实数据适配器

    整合多种真实数据源，将真实安全事件转换为红蓝对抗框架的输入。

    支持的数据源：
    1. LightPool seccomp违规日志（JSONL文件）
    2. StrongPool KVM VM-Exit事件（JSON文件或流）
    3. HMAC审计链异常（JSONL文件）

    使用方式：
    ```python
    adapter = RealDataAdapter()
    adapter.load_seccomp_log("/var/log/photon/seccomp_violations.jsonl")
    adapter.load_kvm_vm_exit_metrics("/var/log/photon/kvm_vm_exit.json")
    adapter.load_audit_chain("/var/log/photon/sandbox_audit.jsonl")

    # 获取所有真实安全事件
    events = adapter.get_all_events()

    # 获取异常事件（可直接注入红蓝对抗框架）
    anomalies = adapter.get_anomaly_events()

    # 注入红蓝对抗框架
    for event in anomalies:
        trainer.ingest_real_event(event)
    ```
    """

    def __init__(self, hmac_secret: Optional[str] = None):
        self.seccomp_parser = SeccompViolationParser(hmac_secret)
        self.kvm_parser = KvmVmExitParser()
        self.audit_detector = AuditChainAnomalyDetector(hmac_secret or "photon-sandbox-audit-chain-default-key")
        self.all_events: List[SecurityEvent] = []
        self.anomaly_events: List[SecurityEvent] = []

    def load_seccomp_log(self, file_path: str) -> int:
        """
        加载LightPool seccomp违规日志

        返回: 解析出的seccomp违规事件数
        """
        if not os.path.exists(file_path):
            return 0

        count = 0
        with open(file_path, 'r') as f:
            for line in f:
                event = self.seccomp_parser.parse_line(line)
                if event:
                    self.all_events.append(event)
                    count += 1

        # 检测频率异常
        frequency_anomalies = self.seccomp_parser.detect_frequency_anomalies()
        self.anomaly_events.extend(frequency_anomalies)

        return count

    def load_kvm_vm_exit_metrics(self, file_path: str) -> int:
        """
        加载StrongPool KVM VM-Exit事件统计

        支持JSON数组格式或JSONL格式。
        返回: 解析出的VM-Exit事件数
        """
        if not os.path.exists(file_path):
            return 0

        count = 0
        with open(file_path, 'r') as f:
            content = f.read().strip()

        # 尝试JSON数组格式
        try:
            events = json.loads(content)
            if isinstance(events, list):
                for data in events:
                    event = self.kvm_parser.parse_event(data)
                    if event:
                        self.all_events.append(event)
                        count += 1
                return count
        except json.JSONDecodeError:
            pass

        # 尝试JSONL格式
        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                event = self.kvm_parser.parse_event(data)
                if event:
                    self.all_events.append(event)
                    count += 1
            except json.JSONDecodeError:
                continue

        # 检测逃逸尝试
        escape_attempts = self.kvm_parser.detect_escape_attempts()
        self.anomaly_events.extend(escape_attempts)

        return count

    def load_audit_chain(self, file_path: str) -> Tuple[int, int]:
        """
        加载HMAC审计链并检测异常

        返回: (有效记录数, 异常事件数)
        """
        if not os.path.exists(file_path):
            return 0, 0

        valid_count = 0
        anomaly_count = 0

        with open(file_path, 'r') as f:
            for line in f:
                is_valid, anomaly = self.audit_detector.verify_and_detect(line)
                if is_valid:
                    valid_count += 1
                if anomaly:
                    self.all_events.append(anomaly)
                    self.anomaly_events.append(anomaly)
                    anomaly_count += 1

        return valid_count, anomaly_count

    def ingest_event(self, event: Dict[str, Any], source: EventSource) -> Optional[SecurityEvent]:
        """
        直接摄入单个事件（用于实时流）

        Args:
            event: 原始事件数据
            source: 事件来源类型

        返回: 标准化的安全事件
        """
        if source == EventSource.SECCOMP_VIOLATION:
            return self.seccomp_parser.parse_line(json.dumps(event))
        elif source == EventSource.KVM_VM_EXIT:
            return self.kvm_parser.parse_event(event)
        elif source == EventSource.AUDIT_CHAIN_ANOMALY:
            _, anomaly = self.audit_detector.verify_and_detect(json.dumps(event))
            return anomaly
        return None

    def get_all_events(self, min_severity: str = "low") -> List[SecurityEvent]:
        """获取所有安全事件（按严重程度过滤）"""
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_level = severity_order.get(min_severity, 0)
        return [e for e in self.all_events if severity_order.get(e.severity, 0) >= min_level]

    def get_anomaly_events(self) -> List[SecurityEvent]:
        """获取所有异常事件"""
        return self.anomaly_events

    def get_high_risk_events(self) -> List[SecurityEvent]:
        """获取高风险事件（high或critical）"""
        return [e for e in self.all_events if e.severity in ["high", "critical"]]

    def get_statistics(self) -> Dict[str, Any]:
        """获取适配器统计信息"""
        return {
            "total_events": len(self.all_events),
            "anomaly_events": len(self.anomaly_events),
            "seccomp_violations": len(self.seccomp_parser.parsed_events),
            "kvm_vm_exits": len(self.kvm_parser.parsed_events),
            "audit_chain_anomalies": len(self.audit_detector.anomalies),
            "top_seccomp_violations": self.seccomp_parser.get_top_violations(5),
            "top_kvm_exit_reasons": self.kvm_parser.get_top_exit_reasons(5),
            "audit_anomaly_summary": self.audit_detector.get_anomaly_summary(),
            "high_risk_count": len(self.get_high_risk_events()),
        }

    def generate_realistic_test_data(self, output_dir: str, num_events: int = 100) -> Dict[str, str]:
        """
        生成真实格式的测试数据

        用于在没有真实日志的情况下测试适配器。
        生成符合C++ AuditLogger格式的JSONL文件。

        返回: 生成的文件路径字典
        """
        os.makedirs(output_dir, exist_ok=True)
        generated = {}

        # 1. 生成seccomp违规日志
        seccomp_path = os.path.join(output_dir, "seccomp_violations.jsonl")
        with open(seccomp_path, 'w') as f:
            syscalls = ["ptrace", "kexec_load", "socket", "connect", "mount", "reboot", "init_module"]
            for i in range(num_events):
                event = {
                    "event_id": f"seccomp_{i:06d}",
                    "event_type": "SECCOMP_VIOLATION",
                    "timestamp": time.time() - (num_events - i) * 0.1,
                    "sandbox_id": f"sandbox_{i % 5}",
                    "syscall": random.choice(syscalls),
                    "syscall_num": random.randint(0, 300),
                    "arch": "x86_64",
                    "pid": random.randint(1000, 65535),
                    "action": "KILL",
                }
                f.write(json.dumps(event) + "\n")
        generated["seccomp_log"] = seccomp_path

        # 2. 生成KVM VM-Exit事件
        kvm_path = os.path.join(output_dir, "kvm_vm_exit.jsonl")
        with open(kvm_path, 'w') as f:
            exit_reasons = ["IO_INSTRUCTION", "MSR_WRITE", "VMCALL", "CPUID", "HLT", "EXCEPTION_NMI", "TRIPLE_FAULT"]
            for i in range(num_events):
                event = {
                    "event_id": f"vmexit_{i:06d}",
                    "vm_id": f"vm_{i % 3}",
                    "exit_reason": random.choice(exit_reasons),
                    "timestamp": time.time() - (num_events - i) * 0.05,
                    "vcpu_id": random.randint(0, 3),
                    "guest_rip": f"0x{random.randint(0, 0xffffffff):08x}",
                }
                f.write(json.dumps(event) + "\n")
        generated["kvm_vm_exit"] = kvm_path

        # 3. 生成HMAC审计链（包含一些异常）
        audit_path = os.path.join(output_dir, "sandbox_audit.jsonl")
        secret = "photon-sandbox-audit-chain-default-key"
        prev_hash = hashlib.sha256(b"PHOTON_SANDBOX_CHAIN_GENESIS").hexdigest()
        with open(audit_path, 'w') as f:
            for i in range(num_events):
                payload = {
                    "event_id": f"audit_{i:06d}",
                    "event_type": random.choice(["EXEC", "SYSCALL", "NETWORK", "FILE_ACCESS"]),
                    "timestamp": time.time() - (num_events - i) * 0.1,
                    "sandbox_id": f"sandbox_{i % 5}",
                    "seq": i,
                    "prev_hash": prev_hash,
                }
                # 计算HMAC
                hmac_val = hmac.new(
                    secret.encode(),
                    (prev_hash + json.dumps({k: v for k, v in payload.items() if k not in ["seq", "prev_hash", "hmac"]}, sort_keys=True)).encode(),
                    hashlib.sha256
                ).hexdigest()
                payload["hmac"] = hmac_val

                # 每20条插入一个异常（哈希链断裂）
                if i > 0 and i % 20 == 0:
                    payload["prev_hash"] = "0" * 64  # 故意错误的prev_hash

                f.write(json.dumps(payload) + "\n")
                prev_hash = hashlib.sha256(json.dumps(payload).encode()).hexdigest()
        generated["audit_chain"] = audit_path

        return generated


import random
