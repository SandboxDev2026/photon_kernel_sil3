"""
evolution.secure_event_pipeline — 安全事件处理流水线

将EventInputValidator挂载到RealDataAdapter事件入口,
实现事件去重持久化,集成防御规则下发链路。

完整链路:
  日志消费层(LogConsumer/RealtimeLogStream)
    → EventInputValidator(8维校验+去重持久化)
    → RealDataAdapter(标准化安全事件)
    → RedBlueAdversaryTrainer(红蓝对抗推演)
    → DefenseRulePersistence(规则持久化+熔断+回滚)
    → DefenseRuleExecutor(规则部署到执行层)
"""
from __future__ import annotations
import os
import json
import time
import threading
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

from evolution.event_input_validator import (
    EventInputValidator, ValidationResult, ValidationResultCode
)
from evolution.real_data_adapter import RealDataAdapter, EventSource, SecurityEvent
from evolution.defense_rule_persistence import DefenseRulePersistence, RuleState
from evolution.defense_executor import DefenseRuleExecutor, ExecutionMode
from evolution.defense_enforcer import ConfigUpdate, ConfigTarget, ChangeAction
from evolution.defense_executor import ExecutionStatus


@dataclass
class PipelineStats:
    """流水线统计"""
    total_received: int = 0
    total_validated: int = 0
    total_rejected: int = 0
    total_ingested: int = 0
    total_rules_generated: int = 0
    total_rules_deployed: int = 0
    total_circuit_breaks: int = 0
    total_rollbacks: int = 0
    duplicate_cache_size: int = 0
    last_persist_time: float = 0.0


class SecureEventPipeline:
    """
    安全事件处理流水线

    将EventInputValidator挂载到RealDataAdapter事件入口,
    实现事件去重持久化,集成防御规则下发链路。

    使用示例:
        pipeline = SecureEventPipeline(
            validator_config={'max_events_per_second': 100},
            persistence_config={'config_dir': '/etc/photonbox/rules'},
            executor_config={'mode': ExecutionMode.DRY_RUN},
        )

        # 处理事件(自动校验+去重+标准化)
        event = pipeline.process_event(raw_event, source='seccomp_logger')

        # 部署防御规则(自动持久化+熔断+回滚)
        result = pipeline.deploy_defense_rule(
            rule_id='seccomp-ptrace-block',
            config={'action': 'KILL', 'syscall': 'ptrace'},
            deployed_by='adversary_loop',
        )

        # 持久化状态
        pipeline.persist_state()
    """

    def __init__(
        self,
        validator_config: Optional[Dict[str, Any]] = None,
        persistence_config: Optional[Dict[str, Any]] = None,
        executor_config: Optional[Dict[str, Any]] = None,
        state_dir: Optional[str] = None,
        auto_persist: bool = True,
        persist_interval_seconds: int = 60,
    ):
        self.auto_persist = auto_persist
        self.persist_interval_seconds = persist_interval_seconds
        self._last_persist_time = time.time()
        self._lock = threading.Lock()
        self._stats = PipelineStats()

        # 状态目录
        self.state_dir = state_dir or self._get_default_state_dir()
        os.makedirs(self.state_dir, exist_ok=True)

        # 1. EventInputValidator(事件入口校验)
        validator_config = validator_config or {}
        self.validator = EventInputValidator(**validator_config)

        # 2. RealDataAdapter(事件标准化)
        self.adapter = RealDataAdapter()

        # 3. DefenseRulePersistence(规则持久化+熔断+回滚)
        persistence_config = persistence_config or {}
        self.rule_persistence = DefenseRulePersistence(**persistence_config)
        self.rule_persistence.load()

        # 4. DefenseRuleExecutor(规则部署)
        executor_config = executor_config or {}
        self.rule_executor = DefenseRuleExecutor(**executor_config)

        # 加载去重缓存
        self._load_duplicate_cache()

    def _get_default_state_dir(self) -> str:
        """获取默认状态目录(带权限回退)"""
        import tempfile
        candidates = [
            "/etc/photonbox/state",
            os.path.expanduser("~/.photonbox/state"),
            tempfile.gettempdir() + "/photonbox_state",
        ]
        for candidate in candidates:
            try:
                os.makedirs(candidate, exist_ok=True)
                test_file = os.path.join(candidate, ".write_test")
                with open(test_file, 'w') as f:
                    f.write("test")
                os.remove(test_file)
                return candidate
            except (OSError, PermissionError):
                continue
        return tempfile.mkdtemp(prefix="photonbox_state_")

    def process_event(
        self,
        raw_event: Dict[str, Any],
        source: str,
        event_source_type: Optional[EventSource] = None,
    ) -> Tuple[Optional[SecurityEvent], ValidationResult]:
        """
        处理单个事件: 校验 → 去重 → 标准化

        Args:
            raw_event: 原始事件数据
            source: 事件来源名称(用于校验器白名单)
            event_source_type: 事件来源类型(用于适配器解析)

        Returns:
            (标准化安全事件, 校验结果)
        """
        with self._lock:
            self._stats.total_received += 1

            # 1. EventInputValidator校验(8维校验+去重)
            validation = self.validator.validate(raw_event, source=source)

            if not validation.valid:
                self._stats.total_rejected += 1
                self._maybe_persist()
                return None, validation

            self._stats.total_validated += 1

            # 2. RealDataAdapter标准化
            cleaned_event = validation.cleaned_event or raw_event
            if event_source_type:
                security_event = self.adapter.ingest_event(
                    cleaned_event, event_source_type
                )
            else:
                # 自动推断来源类型
                security_event = self._auto_ingest(cleaned_event, source)

            if security_event:
                self._stats.total_ingested += 1

            self._maybe_persist()
            return security_event, validation

    def _auto_ingest(
        self, event: Dict[str, Any], source: str
    ) -> Optional[SecurityEvent]:
        """自动推断来源类型并摄入事件"""
        source_lower = source.lower()
        if "seccomp" in source_lower:
            return self.adapter.ingest_event(event, EventSource.SECCOMP_VIOLATION)
        elif "kvm" in source_lower or "vm_exit" in source_lower:
            return self.adapter.ingest_event(event, EventSource.KVM_VM_EXIT)
        elif "audit" in source_lower or "hmac" in source_lower:
            return self.adapter.ingest_event(
                event, EventSource.AUDIT_CHAIN_ANOMALY_ANOMALY
            )
        return None

    def deploy_defense_rule(
        self,
        rule_id: str,
        config: Dict[str, Any],
        deployed_by: str = "manual",
        target: str = "LIGHTPOOL_SECCOMP",
    ) -> Dict[str, Any]:
        """
        部署防御规则: 持久化 → 熔断监控 → 部署到执行层

        Args:
            rule_id: 规则ID
            config: 规则配置
            deployed_by: 部署者
            target: 部署目标

        Returns:
            部署结果
        """
        with self._lock:
            # 1. 持久化规则(生成版本+状态管理)
            version = self.rule_persistence.deploy_rule(
                rule_id=rule_id,
                config=config,
                deployed_by=deployed_by,
            )
            self._stats.total_rules_generated += 1

            # 2. 检查是否已熔断
            if self.rule_persistence.is_circuit_broken(rule_id):
                self._stats.total_circuit_breaks += 1
                return {
                    "success": False,
                    "rule_id": rule_id,
                    "reason": "rule_circuit_broken",
                    "version_id": version.version_id,
                }

            # 3. 部署到执行层
            config_update = ConfigUpdate(
                update_id=f"{rule_id}-{int(time.time())}",
                target=self._parse_config_target(target),
                action=ChangeAction.ADD,
                description=f"Deploy defense rule: {rule_id}",
                config_key=rule_id,
                config_value=config,
                priority="high",
                reason=f"Deployed by {deployed_by}",
                defense_rule_id=rule_id,
            )
            exec_result = self.rule_executor.execute_update(config_update)
            deploy_result = {
                "success": exec_result.status == ExecutionStatus.SUCCESS,
                "error": exec_result.error,
                "update_id": exec_result.update_id,
                "status": exec_result.status.value,
            }

            if deploy_result.get("success"):
                self._stats.total_rules_deployed += 1
                # 记录规则触发(成功部署)
                self.rule_persistence.record_trigger(rule_id, blocked=True)
            else:
                # 部署失败,记录失败(可能触发熔断)
                broken = self.rule_persistence.record_failure(
                    rule_id, reason=deploy_result.get("error", "deploy_failed")
                )
                if broken:
                    self._stats.total_circuit_breaks += 1
                    # 自动回滚
                    rolled_back = self.rule_persistence.rollback_rule(rule_id)
                    if rolled_back:
                        self._stats.total_rollbacks += 1

            self._maybe_persist()
            return {
                "success": deploy_result.get("success", False),
                "rule_id": rule_id,
                "version_id": version.version_id,
                "rule_state": version.state.value,
                "circuit_state": version.circuit_state.value,
                "deploy_result": deploy_result,
            }

    def _parse_config_target(self, target):
        """解析配置目标(支持大小写)"""
        if isinstance(target, ConfigTarget):
            return target
        if isinstance(target, str):
            target_lower = target.lower()
            for ct in ConfigTarget:
                if ct.value == target_lower or ct.name.lower() == target_lower:
                    return ct
        return ConfigTarget.LIGHTPOOL_SECCOMP

    def record_rule_failure(self, rule_id: str, reason: str = "") -> bool:
        """
        记录规则失败,可能触发熔断和自动回滚

        Returns:
            是否触发了熔断
        """
        with self._lock:
            broken = self.rule_persistence.record_failure(rule_id, reason)
            if broken:
                self._stats.total_circuit_breaks += 1
                rolled_back = self.rule_persistence.rollback_rule(rule_id)
                if rolled_back:
                    self._stats.total_rollbacks += 1
            self._maybe_persist()
            return broken

    def persist_state(self) -> bool:
        """
        持久化全部状态: 去重缓存 + 规则状态

        Returns:
            是否成功
        """
        with self._lock:
            success = True
            # 1. 持久化去重缓存
            success &= self._save_duplicate_cache()
            # 2. 持久化规则状态
            success &= self.rule_persistence.persist()
            self._last_persist_time = time.time()
            self._stats.last_persist_time = time.time()
            return success

    def _maybe_persist(self) -> None:
        """可能触发自动持久化"""
        if (self.auto_persist and
            time.time() - self._last_persist_time >= self.persist_interval_seconds):
            self._save_duplicate_cache()
            self.rule_persistence.persist()
            self._last_persist_time = time.time()

    def _save_duplicate_cache(self) -> bool:
        """保存去重缓存到磁盘"""
        try:
            cache_file = os.path.join(self.state_dir, "duplicate_cache.json")
            # 只保存最近的10000条
            cache_list = list(self.validator._duplicate_cache)
            if len(cache_list) > 10000:
                cache_list = cache_list[-10000:]
            with open(cache_file, 'w') as f:
                json.dump({"event_ids": cache_list, "saved_at": time.time()}, f)
            self._stats.duplicate_cache_size = len(cache_list)
            return True
        except OSError:
            return False

    def _load_duplicate_cache(self) -> int:
        """从磁盘加载去重缓存

        Returns:
            加载的事件ID数量
        """
        cache_file = os.path.join(self.state_dir, "duplicate_cache.json")
        if not os.path.exists(cache_file):
            return 0
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            event_ids = data.get("event_ids", [])
            self.validator._duplicate_cache.update(event_ids)
            self._stats.duplicate_cache_size = len(event_ids)
            return len(event_ids)
        except (json.JSONDecodeError, OSError):
            return 0

    def get_stats(self) -> Dict[str, Any]:
        """获取流水线统计"""
        with self._lock:
            validator_stats = self.validator.get_stats()
            persistence_stats = self.rule_persistence.get_stats()
            return {
                "pipeline": {
                    "total_received": self._stats.total_received,
                    "total_validated": self._stats.total_validated,
                    "total_rejected": self._stats.total_rejected,
                    "total_ingested": self._stats.total_ingested,
                    "total_rules_generated": self._stats.total_rules_generated,
                    "total_rules_deployed": self._stats.total_rules_deployed,
                    "total_circuit_breaks": self._stats.total_circuit_breaks,
                    "total_rollbacks": self._stats.total_rollbacks,
                    "duplicate_cache_size": self._stats.duplicate_cache_size,
                    "state_dir": self.state_dir,
                },
                "validator": validator_stats,
                "rule_persistence": persistence_stats,
            }

    def get_active_rules(self) -> List[Dict[str, Any]]:
        """获取所有活跃规则"""
        return [v.to_dict() for v in self.rule_persistence.get_active_rules()]

    def shutdown(self) -> None:
        """关闭流水线,持久化状态"""
        self.persist_state()
