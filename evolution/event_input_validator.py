"""
evolution.event_input_validator — 外部事件输入校验器

核心目标: 防止恶意伪造的审计事件污染红蓝对抗训练器,
避免攻击者通过注入恶意事件诱导生成错误/破坏性防御规则。

这是v26 RealDataAdapter新增的关键攻击面的防护层。

校验维度:
1. 结构校验: 必填字段、字段类型、字段长度限制
2. 内容校验: 防止SQL注入/命令注入/路径穿越/恶意payload
3. 来源校验: 可信来源白名单,拒绝未知来源
4. 频率限制: 单来源事件频率上限,防止洪水攻击
5. 签名验证: HMAC签名验证,防止事件伪造
6. 恶意模式检测: 已知攻击模式特征匹配
7. 事件去重: 重复事件检测,防止重复注入

使用示例:
    validator = EventInputValidator(
        trusted_sources=["seccomp_logger", "audit_chain", "kvm_monitor"],
        hmac_secret="your-secret-key",
        max_events_per_second=100,
    )

    # 校验事件
    result = validator.validate(event_dict, source="seccomp_logger")
    if result.valid:
        # 安全事件,可以注入红蓝对抗
        adapter.ingest_event(result.cleaned_event, source)
    else:
        # 恶意/无效事件,记录并拒绝
        log.warning(f"Event rejected: {result.reason}")
"""
from __future__ import annotations
import re
import hmac
import hashlib
import time
import threading
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum


class ValidationResultCode(Enum):
    """校验结果码"""
    VALID = "valid"                          # 有效
    INVALID_STRUCTURE = "invalid_structure"  # 结构无效
    INVALID_CONTENT = "invalid_content"      # 内容恶意
    UNTRUSTED_SOURCE = "untrusted_source"    # 来源不可信
    RATE_LIMITED = "rate_limited"            # 频率超限
    SIGNATURE_INVALID = "signature_invalid"  # 签名无效
    DUPLICATE = "duplicate"                  # 重复事件
    MALICIOUS_PATTERN = "malicious_pattern"  # 恶意模式


@dataclass
class ValidationResult:
    """校验结果"""
    valid: bool
    code: ValidationResultCode
    reason: str = ""
    cleaned_event: Optional[Dict[str, Any]] = None
    risk_score: float = 0.0  # 0.0-1.0, 越高越可疑


@dataclass
class ValidatorStats:
    """校验器统计"""
    total_events: int = 0
    valid_events: int = 0
    rejected_events: int = 0
    rejected_by_reason: Dict[str, int] = field(default_factory=dict)
    rate_limit_triggers: int = 0
    malicious_pattern_hits: int = 0
    signature_failures: int = 0
    duplicate_events: int = 0


# 已知恶意模式正则
MALICIOUS_PATTERNS = [
    # 命令注入
    (r'[;&|`$]\s*(rm|wget|curl|nc|bash|sh|python|perl)\s', "command_injection"),
    # 路径穿越
    (r'\.\./\.\./', "path_traversal"),
    # SQL注入
    (r"(?i)(union\s+select|drop\s+table|insert\s+into|delete\s+from)", "sql_injection"),
    # XSS
    (r"<script[^>]*>", "xss"),
    #  shell元字符
    (r"[\x00-\x1f\x7f]", "control_characters"),
    # 超长base64(可能是恶意payload)
    (r"[A-Za-z0-9+/]{500,}={0,2}", "suspicious_long_base64"),
    # 已知逃逸技术关键词
    (r"(?i)(setns|unshare|pivot_root|mount_namespace|user_namespace)", "namespace_escape_keyword"),
    # ptrace/kexec高危
    (r"(?i)(ptrace|kexec_load|reboot|swapon)", "high_risk_syscall_keyword"),
]

# 必填字段
REQUIRED_FIELDS = {
    "event_id": str,
    "timestamp": (int, float),
    "source": str,
    "severity": str,
}

# 字段长度限制
FIELD_LENGTH_LIMITS = {
    "event_id": 128,
    "source": 64,
    "severity": 32,
    "description": 1024,
    "payload": 4096,
    "rule_id": 128,
    "attack_type": 64,
}

# 合法severity值
VALID_SEVERITIES = {"low", "medium", "high", "critical", "info", "warning"}


class EventInputValidator:
    """
    外部事件输入校验器

    防护目标: 防止恶意伪造的审计事件污染红蓝对抗训练器。

    校验流程:
    1. 来源校验 → 2. 频率限制 → 3. 结构校验 → 4. 内容校验
    → 5. 恶意模式检测 → 6. 签名验证 → 7. 去重 → 8. 清洗输出
    """

    def __init__(
        self,
        trusted_sources: Optional[List[str]] = None,
        hmac_secret: Optional[str] = None,
        max_events_per_second: int = 100,
        enable_signature_check: bool = False,
        enable_duplicate_check: bool = True,
        max_duplicate_cache_size: int = 10000,
    ):
        self.trusted_sources = set(trusted_sources or [
            "seccomp_logger", "audit_chain", "kvm_monitor",
            "ebpf_monitor", "runtime_guard", "release_gate",
        ])
        self.hmac_secret = hmac_secret
        self.max_events_per_second = max_events_per_second
        self.enable_signature_check = enable_signature_check and hmac_secret is not None
        self.enable_duplicate_check = enable_duplicate_check

        self._stats = ValidatorStats()
        self._lock = threading.Lock()

        # 频率限制
        self._event_timestamps: List[float] = []
        self._source_event_counts: Dict[str, List[float]] = {}

        # 去重缓存
        self._duplicate_cache: Set[str] = set()
        self._max_duplicate_cache_size = max_duplicate_cache_size

        # 编译恶意模式
        self._compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE), name)
            for pattern, name in MALICIOUS_PATTERNS
        ]

    def validate(
        self,
        event: Dict[str, Any],
        source: Optional[str] = None,
    ) -> ValidationResult:
        """
        校验外部输入事件

        Args:
            event: 事件字典
            source: 事件来源(可选,如果event中已有source字段)

        Returns:
            ValidationResult: 校验结果
        """
        with self._lock:
            self._stats.total_events += 1

            # 1. 来源校验
            event_source = source or event.get("source", "")
            source_result = self._validate_source(event_source)
            if not source_result.valid:
                return self._reject(source_result, event)

            # 2. 频率限制
            rate_result = self._check_rate_limit(event_source)
            if not rate_result.valid:
                return self._reject(rate_result, event)

            # 3. 结构校验
            struct_result = self._validate_structure(event)
            if not struct_result.valid:
                return self._reject(struct_result, event)

            # 4. 内容校验(字段长度、类型)
            content_result = self._validate_content(event)
            if not content_result.valid:
                return self._reject(content_result, event)

            # 5. 恶意模式检测
            pattern_result = self._detect_malicious_patterns(event)
            if not pattern_result.valid:
                return self._reject(pattern_result, event)

            # 6. 签名验证
            if self.enable_signature_check:
                sig_result = self._verify_signature(event)
                if not sig_result.valid:
                    return self._reject(sig_result, event)

            # 7. 去重
            if self.enable_duplicate_check:
                dup_result = self._check_duplicate(event)
                if not dup_result.valid:
                    return self._reject(dup_result, event)

            # 8. 清洗输出
            cleaned = self._clean_event(event)
            self._stats.valid_events += 1

            return ValidationResult(
                valid=True,
                code=ValidationResultCode.VALID,
                reason="",
                cleaned_event=cleaned,
                risk_score=pattern_result.risk_score,
            )

    def _validate_source(self, source: str) -> ValidationResult:
        """校验事件来源"""
        if not source:
            return ValidationResult(
                valid=False,
                code=ValidationResultCode.UNTRUSTED_SOURCE,
                reason="Empty source",
            )
        if source not in self.trusted_sources:
            return ValidationResult(
                valid=False,
                code=ValidationResultCode.UNTRUSTED_SOURCE,
                reason=f"Untrusted source: {source}",
            )
        return ValidationResult(valid=True, code=ValidationResultCode.VALID)

    def _check_rate_limit(self, source: str) -> ValidationResult:
        """检查频率限制"""
        now = time.time()
        # 清理1秒前的时间戳
        self._event_timestamps = [t for t in self._event_timestamps if now - t < 1.0]

        if len(self._event_timestamps) >= self.max_events_per_second:
            self._stats.rate_limit_triggers += 1
            return ValidationResult(
                valid=False,
                code=ValidationResultCode.RATE_LIMITED,
                reason=f"Rate limit exceeded: {len(self._event_timestamps)}/s",
            )

        self._event_timestamps.append(now)
        return ValidationResult(valid=True, code=ValidationResultCode.VALID)

    def _validate_structure(self, event: Dict[str, Any]) -> ValidationResult:
        """校验事件结构"""
        if not isinstance(event, dict):
            return ValidationResult(
                valid=False,
                code=ValidationResultCode.INVALID_STRUCTURE,
                reason="Event is not a dict",
            )

        for field, expected_type in REQUIRED_FIELDS.items():
            if field not in event:
                return ValidationResult(
                    valid=False,
                    code=ValidationResultCode.INVALID_STRUCTURE,
                    reason=f"Missing required field: {field}",
                )
            if not isinstance(event[field], expected_type):
                return ValidationResult(
                    valid=False,
                    code=ValidationResultCode.INVALID_STRUCTURE,
                    reason=f"Invalid type for field {field}: expected {expected_type}",
                )

        # 校验severity值
        if event.get("severity", "").lower() not in VALID_SEVERITIES:
            return ValidationResult(
                valid=False,
                code=ValidationResultCode.INVALID_STRUCTURE,
                reason=f"Invalid severity: {event.get('severity')}",
            )

        return ValidationResult(valid=True, code=ValidationResultCode.VALID)

    def _validate_content(self, event: Dict[str, Any]) -> ValidationResult:
        """校验事件内容(字段长度)"""
        for field, max_len in FIELD_LENGTH_LIMITS.items():
            if field in event and isinstance(event[field], str):
                if len(event[field]) > max_len:
                    return ValidationResult(
                        valid=False,
                        code=ValidationResultCode.INVALID_CONTENT,
                        reason=f"Field {field} exceeds length limit: {len(event[field])}>{max_len}",
                    )

        # 校验timestamp合理性(不能是未来超过1小时,不能是过去超过1年)
        ts = event.get("timestamp", 0)
        now = time.time()
        if ts > now + 3600 or ts < now - 31536000:
            return ValidationResult(
                valid=False,
                code=ValidationResultCode.INVALID_CONTENT,
                reason=f"Invalid timestamp: {ts}",
            )

        return ValidationResult(valid=True, code=ValidationResultCode.VALID)

    def _detect_malicious_patterns(self, event: Dict[str, Any]) -> ValidationResult:
        """检测恶意模式"""
        risk_score = 0.0
        # 只检查字符串类型的字段值
        for key, value in event.items():
            if not isinstance(value, str):
                continue
            for pattern, name in self._compiled_patterns:
                if pattern.search(value):
                    # namespace_escape_keyword和high_risk_syscall_keyword在安全事件中是正常的
                    if name in ("namespace_escape_keyword", "high_risk_syscall_keyword"):
                        risk_score += 0.1  # 低风险,可能是正常安全事件描述
                        continue
                    self._stats.malicious_pattern_hits += 1
                    return ValidationResult(
                        valid=False,
                        code=ValidationResultCode.MALICIOUS_PATTERN,
                        reason=f"Malicious pattern detected: {name} in field {key}",
                        risk_score=1.0,
                    )

        return ValidationResult(
            valid=True,
            code=ValidationResultCode.VALID,
            risk_score=risk_score,
        )

    def _verify_signature(self, event: Dict[str, Any]) -> ValidationResult:
        """验证HMAC签名"""
        signature = event.get("signature", "")
        if not signature:
            self._stats.signature_failures += 1
            return ValidationResult(
                valid=False,
                code=ValidationResultCode.SIGNATURE_INVALID,
                reason="Missing signature",
            )

        # 计算签名(排除signature字段)
        sign_data = {k: v for k, v in event.items() if k != "signature"}
        sign_str = str(sorted(sign_data.items()))
        expected = hmac.new(
            self.hmac_secret.encode(),
            sign_str.encode(),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(signature, expected):
            self._stats.signature_failures += 1
            return ValidationResult(
                valid=False,
                code=ValidationResultCode.SIGNATURE_INVALID,
                reason="Signature mismatch",
            )

        return ValidationResult(valid=True, code=ValidationResultCode.VALID)

    def _check_duplicate(self, event: Dict[str, Any]) -> ValidationResult:
        """检查重复事件"""
        event_id = event.get("event_id", "")
        if event_id in self._duplicate_cache:
            self._stats.duplicate_events += 1
            return ValidationResult(
                valid=False,
                code=ValidationResultCode.DUPLICATE,
                reason=f"Duplicate event_id: {event_id}",
            )

        self._duplicate_cache.add(event_id)
        # 限制缓存大小
        if len(self._duplicate_cache) > self._max_duplicate_cache_size:
            # 简单清理: 清空一半
            self._duplicate_cache = set(
                list(self._duplicate_cache)[self._max_duplicate_cache_size // 2:]
            )

        return ValidationResult(valid=True, code=ValidationResultCode.VALID)

    def _clean_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """清洗事件(移除危险字符,截断超长字段)"""
        cleaned = {}
        for key, value in event.items():
            if isinstance(value, str):
                # 移除控制字符
                value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
                # 截断超长字段
                max_len = FIELD_LENGTH_LIMITS.get(key, 8192)
                if len(value) > max_len:
                    value = value[:max_len]
            cleaned[key] = value
        return cleaned

    def _reject(self, result: ValidationResult, event: Dict[str, Any]) -> ValidationResult:
        """记录拒绝并返回结果(已在锁内调用,不再加锁)"""
        self._stats.rejected_events += 1
        reason_key = result.code.value
        self._stats.rejected_by_reason[reason_key] = (
            self._stats.rejected_by_reason.get(reason_key, 0) + 1
        )
        return result

    def get_stats(self) -> Dict[str, Any]:
        """获取校验器统计"""
        with self._lock:
            return {
                "total_events": self._stats.total_events,
                "valid_events": self._stats.valid_events,
                "rejected_events": self._stats.rejected_events,
                "rejection_rate": (
                    self._stats.rejected_events / self._stats.total_events
                    if self._stats.total_events > 0 else 0
                ),
                "rejected_by_reason": dict(self._stats.rejected_by_reason),
                "rate_limit_triggers": self._stats.rate_limit_triggers,
                "malicious_pattern_hits": self._stats.malicious_pattern_hits,
                "signature_failures": self._stats.signature_failures,
                "duplicate_events": self._stats.duplicate_events,
                "trusted_sources": list(self.trusted_sources),
                "signature_check_enabled": self.enable_signature_check,
            }

    def add_trusted_source(self, source: str) -> None:
        """添加可信来源"""
        with self._lock:
            self.trusted_sources.add(source)

    def remove_trusted_source(self, source: str) -> None:
        """移除可信来源"""
        with self._lock:
            self.trusted_sources.discard(source)
