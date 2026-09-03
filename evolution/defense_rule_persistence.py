"""
evolution.defense_rule_persistence — 防御规则持久化与熔断机制

生产级闭环补齐:
1. 防御规则持久化: 规则状态写入磁盘,重启后恢复
2. 规则熔断: 部署后监控规则效果,异常触发熔断(自动禁用规则)
3. 自动回滚: 熔断后自动回滚到上一稳定版本
4. 规则版本管理: 支持多版本,可回滚到任意历史版本
5. 规则效果评估: 统计规则触发次数、拦截成功率、误报率

与现有模块集成:
- DefenseRuleExecutor: 执行规则部署
- AdversaryLoopOrchestrator: 编排推演+部署
- RealtimeLogStream: 消费日志评估规则效果
"""
from __future__ import annotations
import os
import json
import time
import hashlib
import threading
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class RuleState(Enum):
    """规则状态"""
    DRAFT = "draft"              # 草稿(推演生成,未部署)
    PENDING = "pending"          # 待部署
    DEPLOYED = "deployed"        # 已部署(生效中)
    MONITORING = "monitoring"    # 部署后监控期
    ACTIVE = "active"            # 稳定运行
    CIRCUIT_BROKEN = "broken"    # 熔断(异常触发,已禁用)
    ROLLED_BACK = "rolled_back"  # 已回滚
    DEPRECATED = "deprecated"    # 已废弃


class CircuitBreakerState(Enum):
    """熔断器状态"""
    CLOSED = "closed"        # 关闭(规则正常生效)
    OPEN = "open"            # 打开(规则被熔断禁用)
    HALF_OPEN = "half_open"  # 半开(尝试恢复,少量流量测试)


@dataclass
class RuleVersion:
    """规则版本"""
    version_id: str
    rule_id: str
    config: Dict[str, Any]
    deployed_at: float
    deployed_by: str
    state: RuleState = RuleState.DRAFT
    # 效果统计
    trigger_count: int = 0
    block_count: int = 0
    false_positive_count: int = 0
    # 熔断配置
    failure_threshold: int = 5          # 失败次数阈值
    success_threshold: int = 3           # 半开期成功次数阈值
    cooldown_seconds: int = 60           # 熔断冷却时间
    # 熔断状态
    circuit_state: CircuitBreakerState = CircuitBreakerState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: float = 0.0
    last_state_change: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version_id": self.version_id,
            "rule_id": self.rule_id,
            "config": self.config,
            "deployed_at": self.deployed_at,
            "deployed_by": self.deployed_by,
            "state": self.state.value,
            "trigger_count": self.trigger_count,
            "block_count": self.block_count,
            "false_positive_count": self.false_positive_count,
            "circuit_state": self.circuit_state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
        }


@dataclass
class PersistenceStats:
    """持久化统计"""
    total_rules: int = 0
    active_rules: int = 0
    broken_rules: int = 0
    rolled_back_rules: int = 0
    total_versions: int = 0
    total_triggers: int = 0
    total_blocks: int = 0
    total_false_positives: int = 0
    circuit_breaker_triggers: int = 0
    auto_rollbacks: int = 0
    last_persist_time: float = 0.0


class DefenseRulePersistence:
    """
    防御规则持久化与熔断机制

    核心能力:
    1. 规则持久化: 规则状态写入JSON文件,重启后恢复
    2. 规则版本管理: 每次部署生成新版本,支持回滚
    3. 熔断器: 部署后监控规则效果,失败次数超阈值自动熔断
    4. 自动回滚: 熔断后自动回滚到上一稳定版本
    5. 效果评估: 统计触发次数、拦截成功率、误报率
    6. 半开恢复: 熔断冷却后尝试恢复,少量流量测试

    使用示例:
        persistence = DefenseRulePersistence(config_dir="/etc/photonbox/rules")
        persistence.load()  # 加载持久化状态

        # 部署新规则
        version = persistence.deploy_rule(
            rule_id="seccomp-ptrace-block",
            config={"action": "KILL", "syscall": "ptrace"},
            deployed_by="adversary_loop",
        )

        # 记录规则触发
        persistence.record_trigger(rule_id="seccomp-ptrace-block", blocked=True)

        # 记录规则失败(可能触发熔断)
        persistence.record_failure(rule_id="seccomp-ptrace-block")

        # 检查熔断状态
        if persistence.is_circuit_broken("seccomp-ptrace-block"):
            # 自动回滚
            persistence.rollback_rule("seccomp-ptrace-block")

        persistence.persist()  # 保存状态到磁盘
    """

    def __init__(
        self,
        config_dir: str = "/etc/photonbox/rules",
        auto_persist: bool = True,
        auto_rollback_on_circuit_break: bool = True,
        circuit_breaker_enabled: bool = True,
    ):
        self.config_dir = config_dir
        self.auto_persist = auto_persist
        self.auto_rollback_on_circuit_break = auto_rollback_on_circuit_break
        self.circuit_breaker_enabled = circuit_breaker_enabled

        self._rules: Dict[str, List[RuleVersion]] = {}
        self._active_versions: Dict[str, RuleVersion] = {}
        self._stats = PersistenceStats()
        self._lock = threading.Lock()

        # 确保目录存在
        self._ensure_config_dir()

    def _ensure_config_dir(self) -> None:
        """确保配置目录存在(带权限回退)"""
        import tempfile
        candidates = [
            self.config_dir,
            os.path.expanduser("~/.photonbox/rules"),
            tempfile.gettempdir() + "/photonbox_rules",
        ]
        for candidate in candidates:
            try:
                os.makedirs(candidate, exist_ok=True)
                test_file = os.path.join(candidate, ".write_test")
                with open(test_file, 'w') as f:
                    f.write("test")
                os.remove(test_file)
                self.config_dir = candidate
                return
            except (OSError, PermissionError):
                continue
        self.config_dir = tempfile.mkdtemp(prefix="photonbox_rules_")

    def load(self) -> int:
        """
        从磁盘加载持久化状态

        Returns:
            加载的规则数量
        """
        state_file = os.path.join(self.config_dir, "rules_state.json")
        if not os.path.exists(state_file):
            return 0

        try:
            with open(state_file, 'r') as f:
                data = json.load(f)

            self._rules.clear()
            self._active_versions.clear()

            for rule_id, versions in data.get("rules", {}).items():
                self._rules[rule_id] = []
                for v_data in versions:
                    version = RuleVersion(
                        version_id=v_data["version_id"],
                        rule_id=v_data["rule_id"],
                        config=v_data["config"],
                        deployed_at=v_data["deployed_at"],
                        deployed_by=v_data.get("deployed_by", "unknown"),
                        state=RuleState(v_data.get("state", "draft")),
                        trigger_count=v_data.get("trigger_count", 0),
                        block_count=v_data.get("block_count", 0),
                        false_positive_count=v_data.get("false_positive_count", 0),
                        circuit_state=CircuitBreakerState(v_data.get("circuit_state", "closed")),
                        failure_count=v_data.get("failure_count", 0),
                        success_count=v_data.get("success_count", 0),
                    )
                    self._rules[rule_id].append(version)
                    if version.state in (RuleState.ACTIVE, RuleState.MONITORING):
                        self._active_versions[rule_id] = version

            self._stats.last_persist_time = data.get("last_persist_time", 0)
            return len(self._rules)

        except (json.JSONDecodeError, OSError, KeyError):
            return 0

    def persist(self) -> bool:
        """
        保存状态到磁盘

        Returns:
            是否保存成功
        """
        try:
            state_file = os.path.join(self.config_dir, "rules_state.json")
            data = {
                "rules": {
                    rule_id: [v.to_dict() for v in versions]
                    for rule_id, versions in self._rules.items()
                },
                "stats": {
                    "total_rules": self._stats.total_rules,
                    "active_rules": self._stats.active_rules,
                    "broken_rules": self._stats.broken_rules,
                    "circuit_breaker_triggers": self._stats.circuit_breaker_triggers,
                    "auto_rollbacks": self._stats.auto_rollbacks,
                },
                "last_persist_time": time.time(),
            }
            with open(state_file, 'w') as f:
                json.dump(data, f, indent=2)
            self._stats.last_persist_time = time.time()
            return True
        except OSError:
            return False

    def deploy_rule(
        self,
        rule_id: str,
        config: Dict[str, Any],
        deployed_by: str = "manual",
    ) -> RuleVersion:
        """
        部署新规则版本

        Args:
            rule_id: 规则ID
            config: 规则配置
            deployed_by: 部署者

        Returns:
            新规则版本
        """
        with self._lock:
            version_id = f"{rule_id}-v{int(time.time()*1000)}"
            version = RuleVersion(
                version_id=version_id,
                rule_id=rule_id,
                config=config,
                deployed_at=time.time(),
                deployed_by=deployed_by,
                state=RuleState.MONITORING,
            )

            if rule_id not in self._rules:
                self._rules[rule_id] = []
            self._rules[rule_id].append(version)
            self._active_versions[rule_id] = version

            self._stats.total_versions += 1
            self._update_stats()

            if self.auto_persist:
                self.persist()

            return version

    def record_trigger(self, rule_id: str, blocked: bool = True) -> None:
        """记录规则触发"""
        with self._lock:
            version = self._active_versions.get(rule_id)
            if not version:
                return

            version.trigger_count += 1
            if blocked:
                version.block_count += 1
            else:
                version.false_positive_count += 1

            # 监控期足够成功后转为ACTIVE
            if version.state == RuleState.MONITORING and version.trigger_count >= 10:
                success_rate = version.block_count / version.trigger_count
                if success_rate >= 0.8:
                    version.state = RuleState.ACTIVE
                    version.last_state_change = time.time()

            self._update_stats()
            if self.auto_persist:
                self.persist()

    def record_failure(self, rule_id: str, reason: str = "") -> bool:
        """
        记录规则失败,可能触发熔断

        Args:
            rule_id: 规则ID
            reason: 失败原因

        Returns:
            是否触发了熔断
        """
        with self._lock:
            version = self._active_versions.get(rule_id)
            if not version:
                return False

            version.failure_count += 1
            version.last_failure_time = time.time()

            # 检查是否触发熔断
            if (self.circuit_breaker_enabled and
                version.circuit_state == CircuitBreakerState.CLOSED and
                version.failure_count >= version.failure_threshold):
                self._trigger_circuit_break(version, reason)
                return True

            if self.auto_persist:
                self.persist()
            return False

    def _trigger_circuit_break(self, version: RuleVersion, reason: str) -> None:
        """触发熔断"""
        version.circuit_state = CircuitBreakerState.OPEN
        version.state = RuleState.CIRCUIT_BROKEN
        version.last_state_change = time.time()
        self._stats.circuit_breaker_triggers += 1

        # 从活跃版本中移除
        if version.rule_id in self._active_versions:
            del self._active_versions[version.rule_id]

        # 自动回滚
        if self.auto_rollback_on_circuit_break:
            self._rollback_to_previous(version.rule_id)

        self._update_stats()

    def _rollback_to_previous(self, rule_id: str) -> Optional[RuleVersion]:
        """回滚到上一稳定版本"""
        versions = self._rules.get(rule_id, [])
        # 找到上一个ACTIVE状态的版本
        for version in reversed(versions[:-1]):
            if version.state == RuleState.ACTIVE:
                version.state = RuleState.ROLLED_BACK
                # 恢复上一版本为ACTIVE
                version.state = RuleState.ACTIVE
                version.circuit_state = CircuitBreakerState.CLOSED
                version.failure_count = 0
                self._active_versions[rule_id] = version
                self._stats.auto_rollbacks += 1
                return version
        return None

    def rollback_rule(self, rule_id: str) -> Optional[RuleVersion]:
        """手动回滚规则"""
        with self._lock:
            result = self._rollback_to_previous(rule_id)
            if result and self.auto_persist:
                self.persist()
            return result

    def is_circuit_broken(self, rule_id: str) -> bool:
        """检查规则是否被熔断"""
        version = self._active_versions.get(rule_id)
        if not version:
            # 检查是否有熔断状态的版本
            for v in self._rules.get(rule_id, []):
                if v.state == RuleState.CIRCUIT_BROKEN:
                    return True
            return False
        return version.circuit_state == CircuitBreakerState.OPEN

    def attempt_half_open(self, rule_id: str) -> bool:
        """
        尝试半开恢复(熔断冷却后)

        Returns:
            是否进入半开状态
        """
        with self._lock:
            for version in self._rules.get(rule_id, []):
                if (version.state == RuleState.CIRCUIT_BROKEN and
                    version.circuit_state == CircuitBreakerState.OPEN and
                    time.time() - version.last_failure_time >= version.cooldown_seconds):
                    version.circuit_state = CircuitBreakerState.HALF_OPEN
                    version.success_count = 0
                    version.failure_count = 0
                    self._active_versions[rule_id] = version
                    if self.auto_persist:
                        self.persist()
                    return True
            return False

    def get_active_rules(self) -> List[RuleVersion]:
        """获取所有活跃规则"""
        return list(self._active_versions.values())

    def get_rule_versions(self, rule_id: str) -> List[RuleVersion]:
        """获取规则的所有版本"""
        return self._rules.get(rule_id, [])

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        self._update_stats()
        return {
            "total_rules": self._stats.total_rules,
            "active_rules": self._stats.active_rules,
            "broken_rules": self._stats.broken_rules,
            "rolled_back_rules": self._stats.rolled_back_rules,
            "total_versions": self._stats.total_versions,
            "total_triggers": self._stats.total_triggers,
            "total_blocks": self._stats.total_blocks,
            "total_false_positives": self._stats.total_false_positives,
            "circuit_breaker_triggers": self._stats.circuit_breaker_triggers,
            "auto_rollbacks": self._stats.auto_rollbacks,
            "last_persist_time": self._stats.last_persist_time,
            "config_dir": self.config_dir,
        }

    def _update_stats(self) -> None:
        """更新统计信息"""
        self._stats.total_rules = len(self._rules)
        self._stats.active_rules = sum(
            1 for v in self._active_versions.values()
            if v.state in (RuleState.ACTIVE, RuleState.MONITORING)
        )
        self._stats.broken_rules = sum(
            1 for versions in self._rules.values()
            for v in versions if v.state == RuleState.CIRCUIT_BROKEN
        )
        self._stats.rolled_back_rules = sum(
            1 for versions in self._rules.values()
            for v in versions if v.state == RuleState.ROLLED_BACK
        )
        self._stats.total_triggers = sum(
            v.trigger_count for versions in self._rules.values() for v in versions
        )
        self._stats.total_blocks = sum(
            v.block_count for versions in self._rules.values() for v in versions
        )
        self._stats.total_false_positives = sum(
            v.false_positive_count for versions in self._rules.values() for v in versions
        )
