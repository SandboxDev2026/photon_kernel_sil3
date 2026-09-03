"""
evolution.defense_executor — 防御规则执行层

将红蓝对抗框架进化的防御规则，实际应用到底层沙盒执行层:
1. LightPool/seccomp配置更新（系统调用白名单/黑名单）
2. StrongPool配置更新（VM内存/CPU/TTL/并发限制）
3. RuntimeGuard安全策略更新（风险等级→后端映射）
4. eBPF网络规则更新（内网IP黑名单/域名白名单）
5. 审计配置更新（级别/采样率/HMAC开关）

与v27 DefenseRuleEnforcer的区别:
- v27: 生成配置更新指令，默认dry-run不实际修改
- v28: 实际执行配置更新，应用到运行中的沙盒实例

执行模式:
- DRY_RUN: 只生成指令，不实际修改（默认，安全）
- SIMULATE: 模拟执行，验证逻辑正确性
- APPLY: 实际应用到沙盒配置（生产环境，需验证）
"""
from __future__ import annotations
import os
import json
import time
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from evolution.defense_enforcer import (
    DefenseRuleEnforcer, ConfigUpdate, ConfigTarget, ChangeAction
)


class ExecutionMode(Enum):
    """执行模式"""
    DRY_RUN = "dry_run"          # 只生成指令，不实际修改
    SIMULATE = "simulate"        # 模拟执行，验证逻辑
    APPLY = "apply"              # 实际应用到沙盒配置


class ExecutionStatus(Enum):
    """执行状态"""
    PENDING = "pending"
    APPLYING = "applying"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    SKIPPED = "skipped"


@dataclass
class ExecutionResult:
    """执行结果"""
    update_id: str
    status: ExecutionStatus
    target: ConfigTarget
    action: ChangeAction
    config_key: str
    config_value: Any
    applied_at: float = 0.0
    duration_ms: float = 0.0
    error: str = ""
    rollback_snapshot: Optional[Dict[str, Any]] = None
    verification_passed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "update_id": self.update_id,
            "status": self.status.value,
            "target": self.target.value,
            "action": self.action.value,
            "config_key": self.config_key,
            "applied_at": self.applied_at,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "verification_passed": self.verification_passed,
        }


class DefenseRuleExecutor:
    """
    防御规则执行器

    将配置更新实际应用到底层沙盒执行层。
    支持执行前验证、执行后校验、自动回滚。

    安全设计:
    - 默认DRY_RUN模式，不会实际修改系统
    - 执行前备份配置，支持回滚
    - 执行后验证配置是否正确应用
    - 所有执行操作写入审计日志
    - 高危操作需要显式确认
    """

    # 高危操作（需要显式确认才能执行）
    HIGH_RISK_ACTIONS = {
        (ConfigTarget.LIGHTPOOL_SECCOMP, ChangeAction.REMOVE),  # 移除seccomp规则
        (ConfigTarget.RUNTIME_GUARD, ChangeAction.DISABLE),      # 禁用安全策略
        (ConfigTarget.AUDIT_CONFIG, ChangeAction.DISABLE),       # 禁用审计
    }

    def __init__(
        self,
        config_dir: str = "/etc/photonbox",
        mode: ExecutionMode = ExecutionMode.DRY_RUN,
        auto_verify: bool = True,
        auto_rollback_on_failure: bool = True,
        require_confirmation_for_high_risk: bool = True,
    ):
        self.config_dir = config_dir
        self.mode = mode
        self.auto_verify = auto_verify
        self.auto_rollback_on_failure = auto_rollback_on_failure
        self.require_confirmation_for_high_risk = require_confirmation_for_high_risk

        self.enforcer = DefenseRuleEnforcer(config_dir=config_dir, dry_run=(mode == ExecutionMode.DRY_RUN))
        self.execution_history: List[ExecutionResult] = []
        self._confirmed_updates: Set[str] = set()
        self._stats = {"total": 0, "success": 0, "failed": 0, "rolled_back": 0, "skipped": 0}

    def confirm_update(self, update_id: str) -> None:
        """确认高危操作"""
        self._confirmed_updates.add(update_id)

    def execute_update(self, update: ConfigUpdate) -> ExecutionResult:
        """
        执行单个配置更新

        Args:
            update: 配置更新指令

        Returns:
            执行结果
        """
        result = ExecutionResult(
            update_id=update.update_id,
            status=ExecutionStatus.PENDING,
            target=update.target,
            action=update.action,
            config_key=update.config_key,
            config_value=update.config_value,
        )

        # 1. 高危操作检查
        if self._is_high_risk(update) and self.require_confirmation_for_high_risk:
            if update.update_id not in self._confirmed_updates:
                result.status = ExecutionStatus.SKIPPED
                result.error = "高风险操作需要显式确认"
                self._stats["skipped"] += 1
                self.execution_history.append(result)
                return result

        # 2. 执行前备份
        snapshot = self._backup_config(update.target)
        result.rollback_snapshot = snapshot

        # 3. 执行更新
        start_time = time.time()
        result.status = ExecutionStatus.APPLYING

        try:
            if self.mode == ExecutionMode.DRY_RUN:
                # DRY_RUN: 只验证不实际修改
                self._verify_update_safe(update)
                result.status = ExecutionStatus.SUCCESS
                result.verification_passed = True

            elif self.mode == ExecutionMode.SIMULATE:
                # SIMULATE: 模拟执行
                self._simulate_apply(update, snapshot)
                result.status = ExecutionStatus.SUCCESS
                result.verification_passed = True

            else:  # APPLY
                # APPLY: 实际应用
                self._actual_apply(update)
                result.status = ExecutionStatus.SUCCESS

                # 4. 执行后验证
                if self.auto_verify:
                    result.verification_passed = self._verify_applied(update)
                    if not result.verification_passed:
                        raise RuntimeError("执行后验证失败")

        except Exception as e:
            result.status = ExecutionStatus.FAILED
            result.error = str(e)

            # 5. 失败自动回滚
            if self.auto_rollback_on_failure and snapshot:
                try:
                    self._rollback(update.target, snapshot)
                    result.status = ExecutionStatus.ROLLED_BACK
                    self._stats["rolled_back"] += 1
                except Exception as rollback_err:
                    result.error += f" | 回滚失败: {rollback_err}"

        result.applied_at = time.time()
        result.duration_ms = (time.time() - start_time) * 1000

        # 6. 记录审计
        self._log_audit(result)
        self._stats["total"] += 1
        if result.status == ExecutionStatus.SUCCESS:
            self._stats["success"] += 1
        elif result.status == ExecutionStatus.FAILED:
            self._stats["failed"] += 1

        self.execution_history.append(result)
        return result

    def execute_updates(self, updates: List[ConfigUpdate]) -> List[ExecutionResult]:
        """批量执行配置更新"""
        return [self.execute_update(update) for update in updates]

    def _is_high_risk(self, update: ConfigUpdate) -> bool:
        """检查是否为高危操作"""
        return (update.target, update.action) in self.HIGH_RISK_ACTIONS

    def _verify_update_safe(self, update: ConfigUpdate) -> bool:
        """验证更新是否安全（DRY_RUN模式）"""
        # 检查配置键是否存在
        if not update.config_key:
            raise ValueError("配置键不能为空")

        # 检查配置值类型
        if update.config_value is None and update.action != ChangeAction.REMOVE:
            raise ValueError("配置值不能为空（REMOVE操作除外）")

        return True

    def _backup_config(self, target: ConfigTarget) -> Optional[Dict[str, Any]]:
        """备份配置"""
        config_path = self.enforcer.config_paths.get(target)
        if not config_path or not os.path.exists(config_path):
            return None

        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

    def _simulate_apply(self, update: ConfigUpdate, snapshot: Optional[Dict[str, Any]]) -> None:
        """模拟应用更新"""
        # 在内存中模拟配置变更
        config = snapshot or {}
        self.enforcer._apply_to_config(config, update)
        # 验证模拟后的配置
        if not isinstance(config, dict):
            raise RuntimeError("模拟配置变更失败")

    def _actual_apply(self, update: ConfigUpdate) -> None:
        """实际应用更新"""
        config_path = self.enforcer.config_paths.get(update.target)
        if not config_path:
            raise RuntimeError(f"未知配置目标: {update.target}")

        # 确保目录存在
        os.makedirs(os.path.dirname(config_path), exist_ok=True)

        # 读取现有配置
        config = {}
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)

        # 应用更新
        self.enforcer._apply_to_config(config, update)

        # 写入配置
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

    def _verify_applied(self, update: ConfigUpdate) -> bool:
        """验证配置是否正确应用"""
        config_path = self.enforcer.config_paths.get(update.target)
        if not config_path or not os.path.exists(config_path):
            return False

        try:
            with open(config_path, 'r') as f:
                config = json.load(f)

            # 检查配置键是否存在/值是否正确
            keys = update.config_key.split('.')
            current = config
            for key in keys[:-1]:
                if key not in current:
                    if update.action == ChangeAction.REMOVE:
                        return True  # REMOVE操作，键不存在是正确的
                    return False
                current = current[key]

            if update.action == ChangeAction.REMOVE:
                return keys[-1] not in current
            elif update.action == ChangeAction.DISABLE:
                return current.get(keys[-1]) == False
            elif update.action == ChangeAction.ENABLE:
                return current.get(keys[-1]) == True
            else:
                return current.get(keys[-1]) == update.config_value

        except (json.JSONDecodeError, OSError):
            return False

    def _rollback(self, target: ConfigTarget, snapshot: Dict[str, Any]) -> None:
        """回滚配置"""
        config_path = self.enforcer.config_paths.get(target)
        if not config_path:
            return

        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(snapshot, f, indent=2)

    def _log_audit(self, result: ExecutionResult) -> None:
        """记录审计日志"""
        audit_entry = {
            "event_type": "DEFENSE_RULE_EXECUTION",
            "update_id": result.update_id,
            "status": result.status.value,
            "target": result.target.value,
            "action": result.action.value,
            "config_key": result.config_key,
            "duration_ms": result.duration_ms,
            "error": result.error,
            "verification_passed": result.verification_passed,
            "mode": self.mode.value,
            "timestamp": time.time(),
        }

        audit_path = os.path.join(self.config_dir, "defense_executor_audit.jsonl")
        os.makedirs(os.path.dirname(audit_path), exist_ok=True)
        with open(audit_path, 'a') as f:
            f.write(json.dumps(audit_entry) + "\n")

    def get_stats(self) -> Dict[str, Any]:
        """获取执行统计"""
        return {
            **self._stats,
            "mode": self.mode.value,
            "execution_history_count": len(self.execution_history),
            "success_rate": self._stats["success"] / self._stats["total"] if self._stats["total"] > 0 else 0,
        }

    def get_recent_executions(self, limit: int = 20) -> List[Dict[str, Any]]:
        """获取最近的执行记录"""
        return [r.to_dict() for r in self.execution_history[-limit:]]

    def rollback_last(self, count: int = 1) -> int:
        """回滚最近N次执行"""
        rolled_back = 0
        for result in reversed(self.execution_history[-count:]):
            if result.status == ExecutionStatus.SUCCESS and result.rollback_snapshot:
                try:
                    self._rollback(result.target, result.rollback_snapshot)
                    result.status = ExecutionStatus.ROLLED_BACK
                    rolled_back += 1
                except Exception:
                    pass
        return rolled_back
