"""
真实信号消费器（Real Signal Consumer）

将红蓝对抗框架的输入从"模拟攻击用例"替换为真实沙箱信号：
- LightPool 的 seccomp 违规日志
- StrongPool 的 KVM VM-Exit 事件统计
- HMAC 审计链异常事件

核心价值：将框架从"学术仿真"变为"真实数据驱动的攻防演进"。

设计原则：
1. 消费真实格式的日志文件（JSONL），不依赖模拟数据生成器
2. 实时消费，支持 tail -f 模式和批量模式
3. 事件去重，避免重复触发训练
4. 事件缓冲，支持批量训练和单事件触发
5. 与 RedBlueAdversaryTrainer 解耦，通过回调接口注入
"""

import json
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from evolution.real_data_adapter import (
    AnomalyType,
    EventSource,
    RealDataAdapter,
    SecurityEvent,
)


class SignalType(Enum):
    """真实信号类型"""
    SECCOMP_VIOLATION = "seccomp_violation"      # LightPool seccomp 违规
    KVM_VM_EXIT = "kvm_vm_exit"                    # StrongPool KVM VM-Exit
    AUDIT_CHAIN_ANOMALY = "audit_chain_anomaly"    # HMAC 审计链异常
    NETWORK_BLOCK = "network_block"                 # eBPF 网络拦截
    RESOURCE_EXCEED = "resource_exceed"             # 资源超限
    CAPABILITY_DROP = "capability_drop"             # 能力位删除


class ConsumeMode(Enum):
    """消费模式"""
    BATCH = "batch"              # 批量消费：读取全部历史日志后一次性训练
    REALTIME = "realtime"        # 实时消费：tail -f 模式，新事件触发训练
    THRESHOLD = "threshold"      # 阈值消费：积累 N 个事件或 M 秒后触发训练


@dataclass
class NetworkVector:
    """网络五元组"""
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = "tcp"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
        }


@dataclass
class EscapeEvent:
    """
    逃逸尝试事件（真实信号的统一表示）

    从 LightPool seccomp 违规、StrongPool VM-Exit、审计链异常等
    真实数据源转换而来，直接注入红蓝对抗框架。
    """
    event_id: str
    signal_type: SignalType
    timestamp: float
    sandbox_id: str
    severity: str  # "low", "medium", "high", "critical"
    description: str
    payload: Dict[str, Any] = field(default_factory=dict)
    network_vector: Optional[NetworkVector] = None
    syscall: Optional[str] = None
    vm_exit_reason: Optional[str] = None
    anomaly_type: Optional[AnomalyType] = None
    anomaly_score: float = 0.0
    raw_event: Optional[Dict[str, Any]] = None

    def to_security_event(self) -> SecurityEvent:
        """转换为 SecurityEvent（兼容 RealDataAdapter 格式）"""
        source_map = {
            SignalType.SECCOMP_VIOLATION: EventSource.SECCOMP_VIOLATION,
            SignalType.KVM_VM_EXIT: EventSource.KVM_VM_EXIT,
            SignalType.AUDIT_CHAIN_ANOMALY: EventSource.AUDIT_CHAIN_ANOMALY,
            SignalType.NETWORK_BLOCK: EventSource.NETWORK_BLOCK,
            SignalType.RESOURCE_EXCEED: EventSource.RESOURCE_EXCEED,
            SignalType.CAPABILITY_DROP: EventSource.CAPABILITY_DROP,
        }
        return SecurityEvent(
            event_id=self.event_id,
            source=source_map.get(self.signal_type, EventSource.SECCOMP_VIOLATION),
            timestamp=self.timestamp,
            sandbox_id=self.sandbox_id,
            severity=self.severity,
            description=self.description,
            payload=self.payload,
            anomaly_type=self.anomaly_type,
            anomaly_score=self.anomaly_score,
        )

    def to_attack_case_params(self) -> Dict[str, Any]:
        """转换为红蓝对抗框架的攻击用例参数"""
        params = {
            "event_id": self.event_id,
            "signal_type": self.signal_type.value,
            "severity": self.severity,
            "description": self.description,
            "payload": self.payload,
            "syscall": self.syscall,
            "vm_exit_reason": self.vm_exit_reason,
            "anomaly_score": self.anomaly_score,
        }
        if self.network_vector:
            params["network_vector"] = self.network_vector.to_dict()
        return params

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "signal_type": self.signal_type.value,
            "timestamp": self.timestamp,
            "sandbox_id": self.sandbox_id,
            "severity": self.severity,
            "description": self.description,
            "payload": self.payload,
            "network_vector": self.network_vector.to_dict() if self.network_vector else None,
            "syscall": self.syscall,
            "vm_exit_reason": self.vm_exit_reason,
            "anomaly_type": self.anomaly_type.value if self.anomaly_type else None,
            "anomaly_score": self.anomaly_score,
        }


class SeccompLogParser:
    """
    LightPool seccomp 违规日志解析器

    解析真实的 seccomp 违规日志（JSONL 格式），转换为 EscapeEvent。

    支持的日志字段：
    - event_id, timestamp, sandbox_id, syscall, syscall_num, pid, action
    - arch, comm (进程名), args (系统调用参数)
    """

    # 高危系统调用（逃逸尝试的强信号）
    HIGH_RISK_SYSCALLS = {
        "ptrace", "kexec_load", "kexec_file_load", "init_module",
        "finit_module", "delete_module", "reboot", "pivot_root",
        "mount", "umount2", "swapon", "swapoff", "sethostname",
        "setdomainname", "unshare", "setns", "clone", "execve",
        "execveat", "bpf", "perf_event_open", "quotactl",
    }

    # 严重程度映射
    CRITICAL_SYSCALLS = {"ptrace", "kexec_load", "init_module", "reboot", "pivot_root"}
    HIGH_SYSCALLS = {"mount", "unshare", "setns", "bpf", "execve", "clone"}

    def parse_line(self, line: str) -> Optional[EscapeEvent]:
        """解析单行 seccomp 违规日志"""
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        # 验证是否为 seccomp 违规事件
        if not self._is_seccomp_violation(data):
            return None

        return self._build_escape_event(data)

    def _is_seccomp_violation(self, data: Dict[str, Any]) -> bool:
        """判断是否为 seccomp 违规事件"""
        event_type = str(data.get("event_type", "")).upper()
        if "SECCOMP" in event_type or "VIOLATION" in event_type:
            return True
        if "syscall" in data and "action" in data:
            return True
        return False

    def _build_escape_event(self, data: Dict[str, Any]) -> EscapeEvent:
        """从原始数据构建 EscapeEvent"""
        syscall = str(data.get("syscall", data.get("syscall_num", "unknown")))
        sandbox_id = str(data.get("sandbox_id", data.get("instance_id", "unknown")))
        timestamp = float(data.get("timestamp", time.time()))
        event_id = str(data.get("event_id", f"seccomp_{int(timestamp * 1000)}"))
        action = str(data.get("action", "KILL"))
        pid = data.get("pid", 0)
        comm = str(data.get("comm", ""))

        # 严重程度判断
        severity = self._determine_severity(syscall, action)

        # 描述
        description = f"seccomp违规: syscall={syscall}, action={action}, pid={pid}, comm={comm}"

        # payload
        payload = {
            "syscall": syscall,
            "syscall_num": data.get("syscall_num"),
            "action": action,
            "pid": pid,
            "comm": comm,
            "arch": data.get("arch", "x86_64"),
            "args": data.get("args", []),
        }

        return EscapeEvent(
            event_id=event_id,
            signal_type=SignalType.SECCOMP_VIOLATION,
            timestamp=timestamp,
            sandbox_id=sandbox_id,
            severity=severity,
            description=description,
            payload=payload,
            syscall=syscall,
            raw_event=data,
        )

    def _determine_severity(self, syscall: str, action: str) -> str:
        """根据系统调用和动作确定严重程度"""
        if syscall in self.CRITICAL_SYSCALLS:
            return "critical"
        if syscall in self.HIGH_SYSCALLS:
            return "high"
        if action == "KILL":
            return "high"
        if action == "ERRNO":
            return "medium"
        return "low"

    def is_escape_attempt(self, event: EscapeEvent) -> bool:
        """判断是否为逃逸尝试（高危系统调用）"""
        return event.syscall in self.HIGH_RISK_SYSCALLS or event.severity in ("critical", "high")


class VMExitStatsParser:
    """
    StrongPool KVM VM-Exit 事件统计解析器

    解析真实的 KVM VM-Exit 事件日志（JSONL 格式），转换为 EscapeEvent。

    支持的日志字段：
    - event_id, timestamp, vm_id, vcpu_id, exit_reason, guest_rip
    - exit_qualification, instruction_length, instruction_info
    """

    # 可疑 VM-Exit 原因（可能表明逃逸尝试）
    SUSPICIOUS_EXIT_REASONS = {
        "VMCALL", "VMMCALL", "IO_INSTRUCTION", "MSR_WRITE",
        "EXCEPTION_NMI", "TRIPLE_FAULT", "SHUTDOWN",
        "EPT_VIOLATION", "EPT_MISCONFIG", "APIC_ACCESS",
    }

    # 严重程度映射
    CRITICAL_EXIT_REASONS = {"TRIPLE_FAULT", "SHUTDOWN", "VMCALL"}
    HIGH_EXIT_REASONS = {"MSR_WRITE", "IO_INSTRUCTION", "EPT_VIOLATION"}

    def parse_line(self, line: str) -> Optional[EscapeEvent]:
        """解析单行 VM-Exit 事件日志"""
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        if not self._is_vm_exit_event(data):
            return None

        return self._build_escape_event(data)

    def _is_vm_exit_event(self, data: Dict[str, Any]) -> bool:
        """判断是否为 VM-Exit 事件"""
        event_type = str(data.get("event_type", "")).upper()
        if "VM_EXIT" in event_type or "VMEXIT" in event_type:
            return True
        if "exit_reason" in data and "vm_id" in data:
            return True
        return False

    def _build_escape_event(self, data: Dict[str, Any]) -> EscapeEvent:
        """从原始数据构建 EscapeEvent"""
        exit_reason = str(data.get("exit_reason", "UNKNOWN"))
        vm_id = str(data.get("vm_id", data.get("sandbox_id", "unknown")))
        timestamp = float(data.get("timestamp", time.time()))
        event_id = str(data.get("event_id", f"vmexit_{int(timestamp * 1000)}"))
        vcpu_id = data.get("vcpu_id", 0)
        guest_rip = str(data.get("guest_rip", "0x0"))

        severity = self._determine_severity(exit_reason)
        description = f"KVM VM-Exit: reason={exit_reason}, vm={vm_id}, vcpu={vcpu_id}, rip={guest_rip}"

        payload = {
            "exit_reason": exit_reason,
            "vcpu_id": vcpu_id,
            "guest_rip": guest_rip,
            "exit_qualification": data.get("exit_qualification"),
            "instruction_length": data.get("instruction_length"),
            "instruction_info": data.get("instruction_info"),
        }

        return EscapeEvent(
            event_id=event_id,
            signal_type=SignalType.KVM_VM_EXIT,
            timestamp=timestamp,
            sandbox_id=vm_id,
            severity=severity,
            description=description,
            payload=payload,
            vm_exit_reason=exit_reason,
            raw_event=data,
        )

    def _determine_severity(self, exit_reason: str) -> str:
        """根据 VM-Exit 原因确定严重程度"""
        if exit_reason in self.CRITICAL_EXIT_REASONS:
            return "critical"
        if exit_reason in self.HIGH_EXIT_REASONS:
            return "high"
        if exit_reason in self.SUSPICIOUS_EXIT_REASONS:
            return "medium"
        return "low"

    def is_suspicious(self, event: EscapeEvent) -> bool:
        """判断是否为可疑 VM-Exit（可能表明逃逸尝试）"""
        return event.vm_exit_reason in self.SUSPICIOUS_EXIT_REASONS or event.severity in ("critical", "high")


class RealSignalConsumer:
    """
    真实信号消费器

    从真实沙箱日志文件消费 seccomp 违规、VM-Exit 等事件，
    转换为 EscapeEvent，注入红蓝对抗框架。

    三种消费模式：
    - BATCH: 批量消费历史日志
    - REALTIME: 实时 tail -f 消费
    - THRESHOLD: 积累 N 个事件或 M 秒后触发

    使用示例：
        consumer = RealSignalConsumer(mode=ConsumeMode.BATCH)
        consumer.register_callback(trainer.ingest_real_event)
        consumer.consume_file("/var/log/photon/seccomp_violations.jsonl")
    """

    def __init__(
        self,
        mode: ConsumeMode = ConsumeMode.BATCH,
        batch_size: int = 50,
        batch_interval_seconds: float = 30.0,
        dedup_enabled: bool = True,
        dedup_ttl_seconds: int = 86400,
        drift_monitor: Optional[Any] = None,
    ):
        """
        初始化真实信号消费器

        Args:
            mode: 消费模式（BATCH/REALTIME/THRESHOLD）
            batch_size: 批量训练的事件数量阈值
            batch_interval_seconds: 批量训练的时间间隔阈值
            dedup_enabled: 是否启用事件去重
            dedup_ttl_seconds: 去重缓存 TTL（秒）
            drift_monitor: 可选的进化漂移监控器（EvolutionDriftMonitor），
                           用于持续集成中监控红方权重变化，检测"只消费数据不学习"的停滞
        """
        self.mode = mode
        self.batch_size = batch_size
        self.batch_interval_seconds = batch_interval_seconds
        self.dedup_enabled = dedup_enabled
        self.dedup_ttl_seconds = dedup_ttl_seconds

        # 解析器
        self.seccomp_parser = SeccompLogParser()
        self.vmexit_parser = VMExitStatsParser()
        self.real_data_adapter = RealDataAdapter()

        # 回调函数列表（事件消费后调用）
        self._callbacks: List[Callable[[EscapeEvent], None]] = []

        # 批量回调（积累一批事件后调用）
        self._batch_callbacks: List[Callable[[List[EscapeEvent]], None]] = []

        # 事件缓冲
        self._event_buffer: List[EscapeEvent] = []
        self._last_batch_time: float = time.time()

        # 去重缓存
        self._seen_event_ids: Set[str] = set()
        self._seen_event_times: Dict[str, float] = {}

        # 统计
        self.stats = {
            "total_consumed": 0,
            "total_parsed": 0,
            "total_skipped": 0,
            "total_deduped": 0,
            "seccomp_events": 0,
            "vmexit_events": 0,
            "audit_events": 0,
            "escape_attempts": 0,
            "batch_triggers": 0,
            "errors": 0,
        }

        # 进化漂移监控（CI 必加项：检测"只消费数据不学习"的停滞）
        self.drift_monitor = drift_monitor
        self._drift_snapshot_count = 0
        self._last_red_weights: Dict[str, float] = {}

    def attach_drift_monitor(self, drift_monitor: Any) -> None:
        """
        挂载进化漂移监控器（持续集成必加项）

        在 RealSignalConsumer 消费真实事件的同时，监控红方权重分布的漂移。
        如果连续 N 轮真实事件流入后权重变化 < 阈值，触发停滞告警，
        说明框架只消费了数据却没真正学习——需要回查 train_round 逻辑。

        Args:
            drift_monitor: EvolutionDriftMonitor 实例
        """
        self.drift_monitor = drift_monitor

    def record_weight_snapshot(
        self,
        red_weights: Dict[str, float],
        blue_rule_count: int = 0,
        blue_avg_effectiveness: float = 0.0,
        attack_pattern_count: int = 0,
        total_events_consumed: Optional[int] = None,
    ) -> Optional[Any]:
        """
        记录一轮训练后的红方权重分布快照（漂移监控埋点）

        每轮 train_round 完成后调用此方法，将红方策略权重分布记录到漂移监控器。
        漂移监控器会自动计算相邻轮次的 KL 散度/变化率，检测停滞/突变/振荡。

        Args:
            red_weights: 红方策略权重分布（攻击类型 -> 权重）
            blue_rule_count: 蓝方防御规则数量
            blue_avg_effectiveness: 蓝方平均防御有效性
            attack_pattern_count: 攻击模式数量

        Returns:
            DriftSnapshot（如果挂载了漂移监控器），否则 None
        """
        self._last_red_weights = dict(red_weights)
        self._drift_snapshot_count += 1

        if self.drift_monitor is None:
            return None

        return self.drift_monitor.record_snapshot(
            round_idx=self._drift_snapshot_count,
            red_weights=red_weights,
            blue_rule_count=blue_rule_count,
            blue_avg_effectiveness=blue_avg_effectiveness,
            attack_pattern_count=attack_pattern_count,
            total_events_consumed=total_events_consumed if total_events_consumed is not None else self.stats["total_consumed"],
        )

    def get_drift_status(self) -> Dict[str, Any]:
        """
        获取漂移监控状态

        Returns:
            漂移监控状态（是否挂载、快照数、最近告警、学习有效性）
        """
        if self.drift_monitor is None:
            return {
                "drift_monitor_attached": False,
                "message": "未挂载漂移监控器。建议在CI中挂载EvolutionDriftMonitor，"
                           "检测'只消费数据不学习'的进化停滞。",
            }

        return {
            "drift_monitor_attached": True,
            "snapshots_recorded": self._drift_snapshot_count,
            "total_events_consumed": self.stats["total_consumed"],
            "learning_effectiveness": self.drift_monitor.get_learning_effectiveness(),
            "recent_alerts": self.drift_monitor.get_recent_alerts(limit=5),
            "consecutive_stagnation": getattr(self.drift_monitor, 'consecutive_stagnation', 0),
        }

    def register_callback(self, callback: Callable[[EscapeEvent], None]) -> None:
        """注册单事件回调（每个事件消费后调用）"""
        self._callbacks.append(callback)

    def register_batch_callback(self, callback: Callable[[List[EscapeEvent]], None]) -> None:
        """注册批量回调（积累一批事件后调用）"""
        self._batch_callbacks.append(callback)

    def consume_file(self, file_path: str, signal_type: Optional[SignalType] = None) -> int:
        """
        消费日志文件（BATCH 模式）

        Args:
            file_path: 日志文件路径（JSONL 格式）
            signal_type: 信号类型（None 则自动检测）

        Returns:
            成功消费的事件数量
        """
        if not os.path.exists(file_path):
            self.stats["errors"] += 1
            return 0

        consumed = 0
        with open(file_path, 'r') as f:
            for line in f:
                event = self._parse_line(line, signal_type)
                if event:
                    if self._process_event(event):
                        consumed += 1

        # BATCH 模式结束时触发批量回调
        if self._event_buffer:
            self._flush_batch()

        return consumed

    def consume_line(self, line: str, signal_type: Optional[SignalType] = None) -> Optional[EscapeEvent]:
        """
        消费单行日志（REALTIME 模式）

        Args:
            line: 日志行（JSON 格式）
            signal_type: 信号类型（None 则自动检测）

        Returns:
            解析出的 EscapeEvent（如果有效）
        """
        event = self._parse_line(line, signal_type)
        if event:
            if self._process_event(event):
                return event
        return None

    def consume_events(self, events: List[Dict[str, Any]], signal_type: SignalType) -> int:
        """
        消费事件字典列表（用于程序化注入）

        Args:
            events: 事件字典列表
            signal_type: 信号类型

        Returns:
            成功消费的事件数量
        """
        consumed = 0
        for data in events:
            line = json.dumps(data)
            event = self._parse_line(line, signal_type)
            if event and self._process_event(event):
                consumed += 1

        if self._event_buffer:
            self._flush_batch()

        return consumed

    def _parse_line(self, line: str, signal_type: Optional[SignalType] = None) -> Optional[EscapeEvent]:
        """解析单行日志，自动检测信号类型"""
        self.stats["total_consumed"] += 1

        if signal_type == SignalType.SECCOMP_VIOLATION:
            return self.seccomp_parser.parse_line(line)
        if signal_type == SignalType.KVM_VM_EXIT:
            return self.vmexit_parser.parse_line(line)

        # 自动检测：尝试所有解析器
        event = self.seccomp_parser.parse_line(line)
        if event:
            return event
        event = self.vmexit_parser.parse_line(line)
        if event:
            return event

        # 其他信号类型暂不支持自动解析
        self.stats["total_skipped"] += 1
        return None

    def _process_event(self, event: EscapeEvent) -> bool:
        """处理单个事件：去重、统计、回调、缓冲"""
        # 去重
        if self.dedup_enabled:
            if self._is_duplicate(event):
                self.stats["total_deduped"] += 1
                return False
            self._mark_seen(event)

        # 统计
        self.stats["total_parsed"] += 1
        if event.signal_type == SignalType.SECCOMP_VIOLATION:
            self.stats["seccomp_events"] += 1
            if self.seccomp_parser.is_escape_attempt(event):
                self.stats["escape_attempts"] += 1
        elif event.signal_type == SignalType.KVM_VM_EXIT:
            self.stats["vmexit_events"] += 1
            if self.vmexit_parser.is_suspicious(event):
                self.stats["escape_attempts"] += 1
        elif event.signal_type == SignalType.AUDIT_CHAIN_ANOMALY:
            self.stats["audit_events"] += 1

        # 单事件回调
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception:
                self.stats["errors"] += 1

        # 缓冲（用于批量回调）
        self._event_buffer.append(event)

        # THRESHOLD 模式：检查是否触发批量回调
        if self.mode == ConsumeMode.THRESHOLD:
            if (len(self._event_buffer) >= self.batch_size or
                    time.time() - self._last_batch_time >= self.batch_interval_seconds):
                self._flush_batch()

        return True

    def _flush_batch(self) -> None:
        """刷新事件缓冲，触发批量回调"""
        if not self._event_buffer:
            return

        batch = self._event_buffer.copy()
        self._event_buffer.clear()
        self._last_batch_time = time.time()
        self.stats["batch_triggers"] += 1

        for callback in self._batch_callbacks:
            try:
                callback(batch)
            except Exception:
                self.stats["errors"] += 1

    def _is_duplicate(self, event: EscapeEvent) -> bool:
        """检查事件是否重复（基于 event_id）"""
        if event.event_id in self._seen_event_ids:
            # 检查 TTL
            seen_time = self._seen_event_times.get(event.event_id, 0)
            if time.time() - seen_time < self.dedup_ttl_seconds:
                return True
        return False

    def _mark_seen(self, event: EscapeEvent) -> None:
        """标记事件为已见"""
        self._seen_event_ids.add(event.event_id)
        self._seen_event_times[event.event_id] = time.time()

        # 清理过期的去重缓存
        if len(self._seen_event_ids) > 100000:
            self._cleanup_dedup_cache()

    def _cleanup_dedup_cache(self) -> None:
        """清理过期的去重缓存"""
        now = time.time()
        expired = [
            eid for eid, t in self._seen_event_times.items()
            if now - t > self.dedup_ttl_seconds
        ]
        for eid in expired:
            self._seen_event_ids.discard(eid)
            self._seen_event_times.pop(eid, None)

    def _security_event_to_escape_event(self, security_event: SecurityEvent) -> EscapeEvent:
        """将 SecurityEvent 转换为 EscapeEvent"""
        signal_type_map = {
            EventSource.SECCOMP_VIOLATION: SignalType.SECCOMP_VIOLATION,
            EventSource.KVM_VM_EXIT: SignalType.KVM_VM_EXIT,
            EventSource.AUDIT_CHAIN_ANOMALY: SignalType.AUDIT_CHAIN_ANOMALY,
            EventSource.NETWORK_BLOCK: SignalType.NETWORK_BLOCK,
            EventSource.RESOURCE_EXCEED: SignalType.RESOURCE_EXCEED,
            EventSource.CAPABILITY_DROP: SignalType.CAPABILITY_DROP,
        }
        return EscapeEvent(
            event_id=security_event.event_id,
            signal_type=signal_type_map.get(security_event.source, SignalType.SECCOMP_VIOLATION),
            timestamp=security_event.timestamp,
            sandbox_id=security_event.sandbox_id,
            severity=security_event.severity,
            description=security_event.description,
            payload=security_event.payload,
            anomaly_type=security_event.anomaly_type,
            anomaly_score=security_event.anomaly_score,
        )

    def get_stats(self) -> Dict[str, Any]:
        """获取消费统计"""
        return self.stats.copy()

    def reset(self) -> None:
        """重置消费器状态"""
        self._event_buffer.clear()
        self._seen_event_ids.clear()
        self._seen_event_times.clear()
        self._last_batch_time = time.time()
        for key in self.stats:
            self.stats[key] = 0
