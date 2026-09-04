"""
进化-防御桥接器（Evolution-Defense Bridge）

将红蓝对抗进化框架产出的防御规则，真正下发到 LightPool/seccomp、StrongPool 配置，
而非停留在模拟层。配套规则熔断器与自动回滚。

完整链路：
    红蓝对抗进化 → DefenseRule → ConfigUpdate → DefenseRuleEnforcer 下发
    → DefenseRuleExecutor 执行 → DefenseRulePersistence 版本管理
    → 规则效果监控 → 熔断器（误报率/失败率超阈值自动熔断）
    → 自动回滚到上一稳定版本

这是之前高优先级但未完成的项：
"将适配器输出事件对接底层沙盒风控，不再只是模拟红蓝推演，
实现真实的防御规则下发回写到LightPool/seccomp、StrongPool配置"
"配套熔断、回滚"
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from evolution.defense_enforcer import (
    ChangeAction,
    ConfigTarget,
    ConfigUpdate,
    DefenseRuleEnforcer,
)
from evolution.defense_executor import DefenseRuleExecutor
from evolution.defense_rule_persistence import (
    CircuitBreakerState,
    DefenseRulePersistence,
    RuleState,
)
from evolution.real_data_adapter import SecurityEvent
from evolution.red_blue_adversary import DefenseRule


class BridgePhase(Enum):
    """桥接器执行阶段"""
    IDLE = "idle"
    CONVERTING = "converting"       # 规则转换为配置更新
    ENQUEUING = "enqueuing"         # 排队等待下发
    APPLYING = "applying"           # 下发执行
    MONITORING = "monitoring"       # 监控规则效果
    CIRCUIT_BROKEN = "circuit_broken"  # 熔断器触发
    ROLLING_BACK = "rolling_back"   # 回滚中
    STABLE = "stable"               # 稳定运行


@dataclass
class RuleDeploymentRecord:
    """规则部署记录"""
    rule_id: str
    defense_type: str
    description: str
    config_updates: List[Dict[str, Any]] = field(default_factory=list)
    deployed_at: float = field(default_factory=time.time)
    deployment_status: str = "pending"  # pending/applied/failed/circuit_broken/rolled_back
    trigger_count: int = 0
    true_positive_count: int = 0
    false_positive_count: int = 0
    failure_count: int = 0
    rolled_back_at: Optional[float] = None
    rollback_reason: str = ""
    version: int = 1

    @property
    def precision(self) -> float:
        """精确率"""
        if self.trigger_count == 0:
            return 1.0
        return 1.0 - (self.false_positive_count / self.trigger_count)

    @property
    def failure_rate(self) -> float:
        """失败率"""
        if self.trigger_count == 0:
            return 0.0
        return self.failure_count / self.trigger_count

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "defense_type": self.defense_type,
            "description": self.description,
            "config_updates_count": len(self.config_updates),
            "deployed_at": self.deployed_at,
            "deployment_status": self.deployment_status,
            "trigger_count": self.trigger_count,
            "precision": self.precision,
            "failure_rate": self.failure_rate,
            "version": self.version,
            "rolled_back_at": self.rolled_back_at,
            "rollback_reason": self.rollback_reason,
        }


class EvolutionDefenseBridge:
    """
    进化-防御桥接器

    将红蓝对抗进化框架产出的防御规则，真正下发到底层沙盒配置：
    1. 接收进化出的 DefenseRule 列表
    2. 通过 DefenseRuleEnforcer 转换为 ConfigUpdate 并下发
    3. 通过 DefenseRulePersistence 管理规则版本
    4. 监控规则效果（精确率/失败率/性能影响）
    5. 熔断器：误报率或失败率超阈值自动熔断
    6. 自动回滚：熔断后回滚到上一稳定版本

    这是从"模拟红蓝推演"到"真实防御规则下发"的关键桥梁。
    """

    def __init__(
        self,
        enforcer: Optional[DefenseRuleEnforcer] = None,
        executor: Optional[DefenseRuleExecutor] = None,
        persistence: Optional[DefenseRulePersistence] = None,
        false_positive_threshold: float = 0.3,
        failure_rate_threshold: float = 0.2,
        min_triggers_before_monitoring: int = 5,
        circuit_breaker_cooldown_seconds: float = 60.0,
        auto_rollback_enabled: bool = True,
        dry_run: bool = False,
    ):
        """
        初始化进化-防御桥接器

        Args:
            enforcer: 防御规则强制执行器（转换规则为配置更新并下发）
            executor: 防御规则执行器（实际执行配置更新）
            persistence: 防御规则持久化（版本管理/熔断器/回滚）
            false_positive_threshold: 误报率阈值（超过则熔断）
            failure_rate_threshold: 失败率阈值（超过则熔断）
            min_triggers_before_monitoring: 开始监控前的最少触发次数（避免小样本误判）
            circuit_breaker_cooldown_seconds: 熔断器冷却时间（半开恢复前等待）
            auto_rollback_enabled: 是否启用自动回滚
            dry_run: 试运行模式（只生成配置更新，不实际下发）
        """
        self.enforcer = enforcer or DefenseRuleEnforcer()
        self.executor = executor or DefenseRuleExecutor()
        self.persistence = persistence or DefenseRulePersistence()

        self.false_positive_threshold = false_positive_threshold
        self.failure_rate_threshold = failure_rate_threshold
        self.min_triggers_before_monitoring = min_triggers_before_monitoring
        self.circuit_breaker_cooldown_seconds = circuit_breaker_cooldown_seconds
        self.auto_rollback_enabled = auto_rollback_enabled
        self.dry_run = dry_run

        # 规则部署记录
        self.deployment_records: Dict[str, RuleDeploymentRecord] = {}

        # 熔断状态
        self.circuit_broken_rules: Dict[str, float] = {}  # rule_id -> 熔断时间

        # 阶段
        self.current_phase = BridgePhase.IDLE

        # 统计
        self.stats = {
            "total_rules_received": 0,
            "total_rules_deployed": 0,
            "total_rules_failed": 0,
            "total_circuit_breaks": 0,
            "total_rollbacks": 0,
            "total_config_updates_generated": 0,
            "total_config_updates_applied": 0,
            "dry_run": self.dry_run,
        }

    def deploy_evolved_rules(
        self,
        rules: List[DefenseRule],
        source_event: Optional[SecurityEvent] = None,
        max_priority: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        部署进化出的防御规则（核心入口）

        将红蓝对抗进化出的 DefenseRule 列表，转换为 ConfigUpdate 并下发到底层沙盒配置。

        Args:
            rules: 进化出的防御规则列表
            source_event: 触发进化的源事件（可选，用于追溯）
            max_priority: 最大优先级过滤（只下发低于等于此优先级的规则）

        Returns:
            部署结果（包含每条规则的部署状态、生成的配置更新、熔断/回滚信息）
        """
        self.current_phase = BridgePhase.CONVERTING
        self.stats["total_rules_received"] += len(rules)

        deployment_results = []
        all_config_updates: List[ConfigUpdate] = []

        # 1. 将每条 DefenseRule 转换为 ConfigUpdate
        for rule in rules:
            # 跳过已熔断的规则
            if self._is_circuit_broken(rule.rule_id):
                deployment_results.append({
                    "rule_id": rule.rule_id,
                    "status": "skipped_circuit_broken",
                    "reason": "规则已熔断，等待冷却后半开恢复",
                })
                continue

            # 转换为配置更新
            updates = self.enforcer.generate_updates_from_rule(rule, source_event)
            self.stats["total_config_updates_generated"] += len(updates)

            # 创建部署记录
            record = RuleDeploymentRecord(
                rule_id=rule.rule_id,
                defense_type=str(rule.defense_type),
                description=rule.description,
                config_updates=[u.__dict__ if hasattr(u, '__dict__') else str(u) for u in updates],
                version=rule.trigger_count + 1,
            )
            self.deployment_records[rule.rule_id] = record

            if updates:
                all_config_updates.extend(updates)
                deployment_results.append({
                    "rule_id": rule.rule_id,
                    "status": "converted",
                    "config_updates_count": len(updates),
                    "targets": list(set(u.target.value for u in updates)),
                })
            else:
                record.deployment_status = "failed"
                self.stats["total_rules_failed"] += 1
                deployment_results.append({
                    "rule_id": rule.rule_id,
                    "status": "failed",
                    "reason": "无法生成配置更新（防御类型不支持或配置目标不可用）",
                })

        # 2. 排队并下发配置更新
        if all_config_updates and not self.dry_run:
            self.current_phase = BridgePhase.ENQUEUING
            self.enforcer.enqueue_updates(all_config_updates)

            self.current_phase = BridgePhase.APPLYING
            apply_result = self.enforcer.apply_pending(max_priority=max_priority)
            self.stats["total_config_updates_applied"] += apply_result.get("applied", 0)

            # 更新部署记录状态
            applied_ids = set(apply_result.get("applied_ids", []))
            for rule_id, record in self.deployment_records.items():
                if record.deployment_status == "pending":
                    record.deployment_status = "applied"
                    record.deployed_at = time.time()
                    self.stats["total_rules_deployed"] += 1

        elif all_config_updates and self.dry_run:
            # 试运行模式：只记录，不下发
            for record in self.deployment_records.values():
                if record.deployment_status == "pending":
                    record.deployment_status = "dry_run"

        self.current_phase = BridgePhase.MONITORING

        return {
            "phase": self.current_phase.value,
            "total_rules_received": len(rules),
            "total_rules_deployed": self.stats["total_rules_deployed"],
            "total_config_updates_generated": self.stats["total_config_updates_generated"],
            "total_config_updates_applied": self.stats["total_config_updates_applied"],
            "deployment_results": deployment_results,
            "dry_run": self.dry_run,
            "timestamp": time.time(),
        }

    def record_rule_trigger(
        self,
        rule_id: str,
        is_true_positive: bool,
        is_failure: bool = False,
        failure_reason: str = "",
    ) -> Dict[str, Any]:
        """
        记录规则触发事件，用于效果监控和熔断判断

        Args:
            rule_id: 规则 ID
            is_true_positive: 是否为真阳性（正确拦截）
            is_failure: 是否为执行失败
            failure_reason: 失败原因

        Returns:
            规则当前状态（包含是否触发熔断/回滚）
        """
        record = self.deployment_records.get(rule_id)
        if record is None:
            return {"error": f"规则 {rule_id} 未部署，无法记录触发"}

        # 已回滚或已熔断的规则不再记录触发（避免重复熔断/回滚）
        if record.deployment_status in ("rolled_back", "circuit_broken"):
            return {
                "rule_id": rule_id,
                "status": "skipped",
                "reason": f"规则已处于{record.deployment_status}状态，不再记录触发",
                "deployment_status": record.deployment_status,
            }

        record.trigger_count += 1
        if is_true_positive:
            record.true_positive_count += 1
        else:
            record.false_positive_count += 1

        if is_failure:
            record.failure_count += 1

        # 检查是否需要熔断
        circuit_result = self._check_circuit_breaker(record)

        result = {
            "rule_id": rule_id,
            "trigger_count": record.trigger_count,
            "precision": record.precision,
            "failure_rate": record.failure_rate,
            "deployment_status": record.deployment_status,
        }

        if circuit_result.get("circuit_broken"):
            result["circuit_broken"] = True
            result["circuit_break_reason"] = circuit_result["reason"]

            # 自动回滚
            if self.auto_rollback_enabled:
                rollback_result = self.rollback_rule(rule_id, circuit_result["reason"])
                result["auto_rollback"] = rollback_result

        return result

    def _check_circuit_breaker(self, record: RuleDeploymentRecord) -> Dict[str, Any]:
        """
        检查规则是否需要熔断

        熔断条件（满足任一）：
        1. 触发次数 >= 最小监控阈值 且 误报率 > 阈值
        2. 触发次数 >= 最小监控阈值 且 失败率 > 阈值
        """
        if record.trigger_count < self.min_triggers_before_monitoring:
            return {"circuit_broken": False}

        # 检查误报率
        if record.precision < (1.0 - self.false_positive_threshold):
            reason = (
                f"误报率过高：{1.0 - record.precision:.1%} > "
                f"阈值 {self.false_positive_threshold:.1%}"
            )
            self._trigger_circuit_break(record, reason)
            return {"circuit_broken": True, "reason": reason}

        # 检查失败率
        if record.failure_rate > self.failure_rate_threshold:
            reason = (
                f"失败率过高：{record.failure_rate:.1%} > "
                f"阈值 {self.failure_rate_threshold:.1%}"
            )
            self._trigger_circuit_break(record, reason)
            return {"circuit_broken": True, "reason": reason}

        return {"circuit_broken": False}

    def _trigger_circuit_break(self, record: RuleDeploymentRecord, reason: str) -> None:
        """触发熔断器"""
        record.deployment_status = "circuit_broken"
        self.circuit_broken_rules[record.rule_id] = time.time()
        self.stats["total_circuit_breaks"] += 1
        self.current_phase = BridgePhase.CIRCUIT_BROKEN

    def _is_circuit_broken(self, rule_id: str) -> bool:
        """检查规则是否处于熔断状态（含冷却期判断）"""
        if rule_id not in self.circuit_broken_rules:
            return False

        break_time = self.circuit_broken_rules[rule_id]
        elapsed = time.time() - break_time

        if elapsed >= self.circuit_breaker_cooldown_seconds:
            # 冷却期已过，可以尝试半开恢复
            return False

        return True

    def attempt_half_open(self, rule_id: str) -> Dict[str, Any]:
        """
        尝试半开恢复（熔断器冷却期过后，允许少量流量测试）

        Args:
            rule_id: 规则 ID

        Returns:
            半开恢复结果
        """
        if rule_id not in self.circuit_broken_rules:
            return {"status": "not_circuit_broken"}

        break_time = self.circuit_broken_rules[rule_id]
        elapsed = time.time() - break_time

        if elapsed < self.circuit_breaker_cooldown_seconds:
            return {
                "status": "cooldown",
                "remaining_seconds": self.circuit_breaker_cooldown_seconds - elapsed,
            }

        # 半开恢复：重置熔断状态，但标记为半开
        record = self.deployment_records.get(rule_id)
        if record:
            record.deployment_status = "half_open"
            record.trigger_count = 0  # 重置计数，重新监控
            record.false_positive_count = 0
            record.failure_count = 0

        del self.circuit_broken_rules[rule_id]

        return {
            "status": "half_open",
            "message": "熔断器冷却期已过，进入半开状态。允许少量流量测试，如再次超过阈值将重新熔断。",
            "rule_id": rule_id,
        }

    def rollback_rule(self, rule_id: str, reason: str = "") -> Dict[str, Any]:
        """
        回滚规则到上一稳定版本

        Args:
            rule_id: 规则 ID
            reason: 回滚原因

        Returns:
            回滚结果
        """
        self.current_phase = BridgePhase.ROLLING_BACK

        record = self.deployment_records.get(rule_id)
        if record is None:
            return {"error": f"规则 {rule_id} 不存在"}

        # 生成回滚配置更新（移除当前规则的配置）
        rollback_updates = []
        for update_info in record.config_updates:
            if isinstance(update_info, dict):
                rollback_update = ConfigUpdate(
                    update_id=f"rollback_{rule_id}_{int(time.time())}",
                    target=ConfigTarget(update_info.get("target", "lightpool_seccomp")),
                    action=ChangeAction.REMOVE,
                    description=f"回滚规则 {rule_id}: {reason}",
                    config_key=update_info.get("config_key", ""),
                    config_value=update_info.get("config_value"),
                    priority="high",
                    reason=f"自动回滚：{reason}",
                    defense_rule_id=rule_id,
                )
                rollback_updates.append(rollback_update)

        # 执行回滚（如果不是试运行）
        if rollback_updates and not self.dry_run:
            self.enforcer.enqueue_updates(rollback_updates)
            self.enforcer.apply_pending(max_priority="high")

        # 更新记录
        record.deployment_status = "rolled_back"
        record.rolled_back_at = time.time()
        record.rollback_reason = reason
        self.stats["total_rollbacks"] += 1

        self.current_phase = BridgePhase.IDLE

        return {
            "rule_id": rule_id,
            "status": "rolled_back",
            "reason": reason,
            "rollback_updates_count": len(rollback_updates),
            "rolled_back_at": record.rolled_back_at,
            "previous_version": record.version - 1 if record.version > 1 else 1,
        }

    def get_deployment_status(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """获取规则部署状态"""
        record = self.deployment_records.get(rule_id)
        if record is None:
            return None
        return record.to_dict()

    def get_all_deployments(self) -> List[Dict[str, Any]]:
        """获取所有规则部署状态"""
        return [r.to_dict() for r in self.deployment_records.values()]

    def get_circuit_broken_rules(self) -> List[Dict[str, Any]]:
        """获取当前熔断的规则列表"""
        result = []
        for rule_id, break_time in self.circuit_broken_rules.items():
            record = self.deployment_records.get(rule_id)
            result.append({
                "rule_id": rule_id,
                "broken_at": break_time,
                "elapsed_seconds": time.time() - break_time,
                "cooldown_remaining": max(0, self.circuit_breaker_cooldown_seconds - (time.time() - break_time)),
                "precision": record.precision if record else None,
                "failure_rate": record.failure_rate if record else None,
            })
        return result

    def get_stats(self) -> Dict[str, Any]:
        """获取桥接器统计"""
        return {
            **self.stats,
            "current_phase": self.current_phase.value,
            "total_rules_tracked": len(self.deployment_records),
            "circuit_broken_count": len(self.circuit_broken_rules),
            "false_positive_threshold": self.false_positive_threshold,
            "failure_rate_threshold": self.failure_rate_threshold,
            "auto_rollback_enabled": self.auto_rollback_enabled,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stats": self.get_stats(),
            "deployments": self.get_all_deployments(),
            "circuit_broken_rules": self.get_circuit_broken_rules(),
        }
