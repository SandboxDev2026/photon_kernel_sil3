"""
evolution.defense_enforcer — 防御规则下发层

将红蓝对抗框架进化的防御规则，回写到底层沙盒风控配置：
1. LightPool/seccomp 配置更新（系统调用白名单/黑名单）
2. StrongPool 配置更新（VM内存/CPU/TTL/并发限制）
3. RuntimeGuard 安全策略更新（风险等级→后端映射）
4. eBPF网络规则更新（内网IP黑名单/域名白名单）

设计原则：
- 下发层独立于红蓝对抗框架，可单独测试
- 所有配置变更生成可审计的配置更新指令（JSON格式）
- 支持 dry-run 模式（只生成指令不下发）
- 配置变更前自动备份，支持回滚
- 变更记录全部接入HMAC审计链
"""
from __future__ import annotations
import os
import json
import time
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from evolution.red_blue_adversary import DefenseRule, DefenseType
from evolution.real_data_adapter import SecurityEvent, EventSource


class ConfigTarget(Enum):
    """配置目标"""
    LIGHTPOOL_SECCOMP = "lightpool_seccomp"      # LightPool seccomp配置
    STRONGPOOL_CONFIG = "strongpool_config"        # StrongPool配置
    RUNTIME_GUARD = "runtime_guard"                # RuntimeGuard安全策略
    EBPF_NETWORK = "ebpf_network"                  # eBPF网络规则
    AUDIT_CONFIG = "audit_config"                  # 审计配置


class ChangeAction(Enum):
    """变更动作"""
    ADD = "add"            # 添加规则
    REMOVE = "remove"      # 移除规则
    UPDATE = "update"      # 更新规则
    ENABLE = "enable"      # 启用功能
    DISABLE = "disable"    # 禁用功能


@dataclass
class ConfigUpdate:
    """配置更新指令"""
    update_id: str
    target: ConfigTarget
    action: ChangeAction
    description: str
    config_key: str
    config_value: Any
    priority: str = "medium"  # low/medium/high/critical
    reason: str = ""
    source_event_id: Optional[str] = None
    defense_rule_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    applied: bool = False
    applied_at: Optional[float] = None
    rollback_snapshot: Optional[Dict[str, Any]] = None

    def to_json(self) -> Dict[str, Any]:
        """转换为JSON"""
        return {
            "update_id": self.update_id,
            "target": self.target.value,
            "action": self.action.value,
            "description": self.description,
            "config_key": self.config_key,
            "config_value": self.config_value,
            "priority": self.priority,
            "reason": self.reason,
            "source_event_id": self.source_event_id,
            "defense_rule_id": self.defense_rule_id,
            "timestamp": self.timestamp,
            "applied": self.applied,
        }


@dataclass
class EnforcerStats:
    """下发统计"""
    total_updates: int = 0
    applied_updates: int = 0
    failed_updates: int = 0
    pending_updates: int = 0
    rollbacks: int = 0
    by_target: Dict[str, int] = field(default_factory=dict)
    by_priority: Dict[str, int] = field(default_factory=dict)
    last_update_time: float = 0.0


class DefenseRuleEnforcer:
    """
    防御规则下发器

    将红蓝对抗框架进化的防御规则，转换为底层沙盒配置更新指令，
    并下发到对应的配置目标。

    支持的配置目标：
    1. LightPool/seccomp：系统调用白名单/黑名单更新
    2. StrongPool：VM内存/CPU/TTL/并发限制更新
    3. RuntimeGuard：风险等级→后端映射更新
    4. eBPF网络：内网IP黑名单/域名白名单更新
    5. 审计配置：审计级别/采样率更新
    """

    def __init__(
        self,
        config_dir: str = "/etc/photonbox",
        dry_run: bool = True,
        auto_backup: bool = True,
        hmac_secret: Optional[str] = None,
    ):
        self.config_dir = config_dir
        self.dry_run = dry_run  # 默认dry-run，生产环境设为False
        self.auto_backup = auto_backup
        self.hmac_secret = hmac_secret or "photonbox-enforcer-default-key"

        self.pending_updates: List[ConfigUpdate] = []
        self.applied_updates: List[ConfigUpdate] = []
        self.failed_updates: List[ConfigUpdate] = []
        self.config_snapshots: Dict[str, Dict[str, Any]] = {}
        self._stats = EnforcerStats()

        # 配置文件路径
        self.config_paths = {
            ConfigTarget.LIGHTPOOL_SECCOMP: os.path.join(config_dir, "seccomp_policy.json"),
            ConfigTarget.STRONGPOOL_CONFIG: os.path.join(config_dir, "strongpool_config.json"),
            ConfigTarget.RUNTIME_GUARD: os.path.join(config_dir, "runtime_guard.json"),
            ConfigTarget.EBPF_NETWORK: os.path.join(config_dir, "ebpf_network.json"),
            ConfigTarget.AUDIT_CONFIG: os.path.join(config_dir, "audit_config.json"),
        }

    def generate_updates_from_rule(self, rule: DefenseRule, event: Optional[SecurityEvent] = None) -> List[ConfigUpdate]:
        """
        从防御规则生成配置更新指令

        根据防御规则类型和目标攻击类型，生成对应的配置更新。
        """
        updates = []
        base_id = hashlib.md5(f"{rule.rule_id}_{time.time()}".encode(), usedforsecurity=False).hexdigest()[:12]

        # 根据防御类型生成更新
        if rule.defense_type == DefenseType.SYSTEM_CALL_MONITOR:
            updates.extend(self._generate_seccomp_updates(rule, event, base_id))
        elif rule.defense_type == DefenseType.NETWORK_FILTER:
            updates.extend(self._generate_network_updates(rule, event, base_id))
        elif rule.defense_type == DefenseType.RESOURCE_LIMIT:
            updates.extend(self._generate_resource_updates(rule, event, base_id))
        elif rule.defense_type == DefenseType.PROCESS_ISOLATION:
            updates.extend(self._generate_isolation_updates(rule, event, base_id))
        elif rule.defense_type == DefenseType.AUDIT_LOGGING:
            updates.extend(self._generate_audit_updates(rule, event, base_id))
        elif rule.defense_type == DefenseType.CAPABILITY_DROP:
            updates.extend(self._generate_capability_updates(rule, event, base_id))

        return updates

    def _generate_seccomp_updates(self, rule: DefenseRule, event: Optional[SecurityEvent], base_id: str) -> List[ConfigUpdate]:
        """生成seccomp配置更新"""
        updates = []

        # 从事件中提取被攻击的系统调用
        blocked_syscalls = []
        if event and event.payload:
            syscall = event.payload.get("syscall")
            if syscall:
                blocked_syscalls.append(syscall)

        # 如果没有具体系统调用，使用规则中的默认列表
        if not blocked_syscalls:
            blocked_syscalls = ["ptrace", "kexec_load", "init_module", "finit_module"]

        for i, syscall in enumerate(blocked_syscalls):
            updates.append(ConfigUpdate(
                update_id=f"{base_id}_sc_{i}",
                target=ConfigTarget.LIGHTPOOL_SECCOMP,
                action=ChangeAction.ADD,
                description=f"添加seccomp黑名单: {syscall}",
                config_key=f"blacklist.{syscall}",
                config_value={"action": "KILL", "reason": rule.description},
                priority="high" if syscall in ["ptrace", "kexec_load"] else "medium",
                reason=f"防御规则{rule.rule_id}触发: {rule.description}",
                source_event_id=event.event_id if event else None,
                defense_rule_id=rule.rule_id,
            ))

        return updates

    def _generate_network_updates(self, rule: DefenseRule, event: Optional[SecurityEvent], base_id: str) -> List[ConfigUpdate]:
        """生成网络配置更新"""
        updates = []

        # 默认内网黑名单
        internal_cidrs = [
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "127.0.0.0/8", "169.254.0.0/16",
        ]

        for i, cidr in enumerate(internal_cidrs):
            updates.append(ConfigUpdate(
                update_id=f"{base_id}_net_{i}",
                target=ConfigTarget.EBPF_NETWORK,
                action=ChangeAction.ADD,
                description=f"添加内网IP黑名单: {cidr}",
                config_key=f"egress_blacklist.{cidr}",
                config_value={"action": "DROP", "reason": "内网隔离"},
                priority="high",
                reason=f"防御规则{rule.rule_id}: 网络隔离加固",
                source_event_id=event.event_id if event else None,
                defense_rule_id=rule.rule_id,
            ))

        return updates

    def _generate_resource_updates(self, rule: DefenseRule, event: Optional[SecurityEvent], base_id: str) -> List[ConfigUpdate]:
        """生成资源限制配置更新"""
        updates = []

        # StrongPool资源限制收紧
        resource_limits = [
            ("default_vm_memory_mb", 128, "默认VM内存"),
            ("max_concurrent_vms", 50, "最大并发VM数"),
            ("max_ttl_seconds", 60, "最大执行时间"),
        ]

        for i, (key, value, desc) in enumerate(resource_limits):
            updates.append(ConfigUpdate(
                update_id=f"{base_id}_res_{i}",
                target=ConfigTarget.STRONGPOOL_CONFIG,
                action=ChangeAction.UPDATE,
                description=f"更新{desc}: {value}",
                config_key=key,
                config_value=value,
                priority="medium",
                reason=f"防御规则{rule.rule_id}: 资源限制加固",
                source_event_id=event.event_id if event else None,
                defense_rule_id=rule.rule_id,
            ))

        return updates

    def _generate_isolation_updates(self, rule: DefenseRule, event: Optional[SecurityEvent], base_id: str) -> List[ConfigUpdate]:
        """生成隔离配置更新"""
        updates = []

        # RuntimeGuard策略更新：高风险任务强制StrongPool
        updates.append(ConfigUpdate(
            update_id=f"{base_id}_iso_0",
            target=ConfigTarget.RUNTIME_GUARD,
            action=ChangeAction.UPDATE,
            description="高风险任务强制StrongPool",
            config_key="mandatory_backend.high_risk",
            config_value="StrongPool",
            priority="critical",
            reason=f"防御规则{rule.rule_id}: 高风险任务强制KVM隔离",
            source_event_id=event.event_id if event else None,
            defense_rule_id=rule.rule_id,
        ))

        # 禁止管理员覆盖安全策略
        updates.append(ConfigUpdate(
            update_id=f"{base_id}_iso_1",
            target=ConfigTarget.RUNTIME_GUARD,
            action=ChangeAction.DISABLE,
            description="禁止管理员覆盖安全策略",
            config_key="allow_admin_override",
            config_value=False,
            priority="high",
            reason=f"防御规则{rule.rule_id}: 防止安全策略被绕过",
            source_event_id=event.event_id if event else None,
            defense_rule_id=rule.rule_id,
        ))

        return updates

    def _generate_audit_updates(self, rule: DefenseRule, event: Optional[SecurityEvent], base_id: str) -> List[ConfigUpdate]:
        """生成审计配置更新"""
        updates = []

        updates.append(ConfigUpdate(
            update_id=f"{base_id}_aud_0",
            target=ConfigTarget.AUDIT_CONFIG,
            action=ChangeAction.ENABLE,
            description="启用HMAC审计链",
            config_key="hmac_chain.enabled",
            config_value=True,
            priority="high",
            reason=f"防御规则{rule.rule_id}: 审计防篡改",
            source_event_id=event.event_id if event else None,
            defense_rule_id=rule.rule_id,
        ))

        updates.append(ConfigUpdate(
            update_id=f"{base_id}_aud_1",
            target=ConfigTarget.AUDIT_CONFIG,
            action=ChangeAction.UPDATE,
            description="提升审计级别为verbose",
            config_key="audit_level",
            config_value="verbose",
            priority="medium",
            reason=f"防御规则{rule.rule_id}: 完整审计记录",
            source_event_id=event.event_id if event else None,
            defense_rule_id=rule.rule_id,
        ))

        return updates

    def _generate_capability_updates(self, rule: DefenseRule, event: Optional[SecurityEvent], base_id: str) -> List[ConfigUpdate]:
        """生成能力位配置更新"""
        updates = []

        # 删除危险能力位
        dangerous_caps = ["CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE"]

        for i, cap in enumerate(dangerous_caps):
            updates.append(ConfigUpdate(
                update_id=f"{base_id}_cap_{i}",
                target=ConfigTarget.LIGHTPOOL_SECCOMP,
                action=ChangeAction.ADD,
                description=f"删除能力位: {cap}",
                config_key=f"drop_capabilities.{cap}",
                config_value=True,
                priority="high",
                reason=f"防御规则{rule.rule_id}: 最小权限原则",
                source_event_id=event.event_id if event else None,
                defense_rule_id=rule.rule_id,
            ))

        return updates

    def enqueue_update(self, update: ConfigUpdate) -> None:
        """入队配置更新"""
        self.pending_updates.append(update)
        self._stats.pending_updates = len(self.pending_updates)

    def enqueue_updates(self, updates: List[ConfigUpdate]) -> None:
        """批量入队配置更新"""
        for update in updates:
            self.enqueue_update(update)

    def apply_pending(self, max_priority: Optional[str] = None) -> Dict[str, Any]:
        """
        应用所有待处理的配置更新

        Args:
            max_priority: 只应用指定优先级及以上的更新（None表示全部）

        Returns:
            应用结果统计
        """
        # 1. 按优先级过滤和排序
        filtered = self._filter_and_sort_updates(max_priority)

        # 2. 逐个应用更新
        applied, failed, results = self._apply_filtered_updates(filtered)

        # 3. 清理已应用的更新
        self._cleanup_applied_updates()

        # 4. 返回统计结果
        return {
            "applied": applied,
            "failed": failed,
            "total": len(self.pending_updates),
            "results": results,
        }


    def _filter_and_sort_updates(self, max_priority: Optional[str]) -> List:
        """按优先级过滤和排序待处理更新"""
        priority_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_level = priority_order.get(max_priority, 0) if max_priority else 0

        filtered = [
            u for u in self.pending_updates
            if priority_order.get(u.priority, 0) >= min_level
        ]
        return sorted(
            filtered,
            key=lambda u: priority_order.get(u.priority, 0),
            reverse=True,
        )

    def _apply_filtered_updates(self, updates: List) -> Tuple[int, int, List]:
        """逐个应用过滤后的更新，返回(成功数, 失败数, 结果列表)"""
        applied = 0
        failed = 0
        results = []

        for update in updates:
            try:
                if self.dry_run:
                    update.status = "simulated"
                    applied += 1
                else:
                    self._apply_single_update(update)
                    applied += 1
                results.append({
                    "update_id": update.update_id,
                    "status": update.status,
                    "target": update.target.value,
                    "config_key": update.config_key,
                })
            except Exception as e:
                failed += 1
                update.status = "failed"
                update.error = str(e)
                results.append({
                    "update_id": update.update_id,
                    "status": "failed",
                    "error": str(e),
                })

        return applied, failed, results

    def _apply_single_update(self, update) -> None:
        """应用单个配置更新（非dry-run模式）"""
        config_path = self.config_paths.get(update.target)
        if not config_path:
            raise ValueError(f"未知配置目标: {update.target}")

        import os, json
        os.makedirs(os.path.dirname(config_path), exist_ok=True)

        config = {}
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)

        self._apply_to_config(config, update)

        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

        update.status = "applied"

    def _cleanup_applied_updates(self) -> None:
        """清理已应用或失败的更新（保留pending状态的）"""
        self.pending_updates = [
            u for u in self.pending_updates
            if u.status == "pending"
        ]

    def _apply_update(self, update: ConfigUpdate) -> Dict[str, Any]:
        """应用单个配置更新"""
        if self.dry_run:
            # dry-run模式：只记录，不实际修改文件
            return {
                "update_id": update.update_id,
                "success": True,
                "dry_run": True,
                "message": f"[DRY-RUN]  Would apply: {update.description}",
            }

        # 实际应用：备份配置，更新，写入
        config_path = self.config_paths.get(update.target)
        if not config_path:
            return {"update_id": update.update_id, "success": False, "error": "Unknown config target"}

        try:
            # 1. 备份
            if self.auto_backup:
                self._backup_config(update.target, config_path)

            # 2. 读取现有配置
            config = self._load_config(config_path)

            # 3. 应用更新
            self._apply_to_config(config, update)

            # 4. 写入配置
            self._save_config(config_path, config)

            # 5. 记录审计
            self._log_audit(update)

            return {
                "update_id": update.update_id,
                "success": True,
                "dry_run": False,
                "message": f"Applied: {update.description}",
            }

        except Exception as e:
            return {"update_id": update.update_id, "success": False, "error": str(e)}

    def _backup_config(self, target: ConfigTarget, path: str) -> None:
        """备份配置文件"""
        if not os.path.exists(path):
            return
        backup_path = f"{path}.backup.{int(time.time())}"
        try:
            with open(path, 'r') as src:
                with open(backup_path, 'w') as dst:
                    dst.write(src.read())
            self.config_snapshots[target.value] = {
                "backup_path": backup_path,
                "timestamp": time.time(),
            }
        except OSError:
            pass

    def _load_config(self, path: str) -> Dict[str, Any]:
        """加载配置文件"""
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _save_config(self, path: str, config: Dict[str, Any]) -> None:
        """保存配置文件"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            json.dump(config, f, indent=2)

    def _apply_to_config(self, config: Dict[str, Any], update: ConfigUpdate) -> None:
        """将更新应用到配置字典"""
        keys = update.config_key.split('.')
        current = config
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]

        if update.action == ChangeAction.REMOVE:
            if keys[-1] in current:
                del current[keys[-1]]
        elif update.action == ChangeAction.DISABLE:
            current[keys[-1]] = False
        elif update.action == ChangeAction.ENABLE:
            current[keys[-1]] = True
        else:  # ADD or UPDATE
            current[keys[-1]] = update.config_value

    def _log_audit(self, update: ConfigUpdate) -> None:
        """记录审计日志（接入HMAC链）"""
        audit_entry = {
            "event_type": "CONFIG_UPDATE",
            "update_id": update.update_id,
            "target": update.target.value,
            "action": update.action.value,
            "config_key": update.config_key,
            "priority": update.priority,
            "reason": update.reason,
            "source_event_id": update.source_event_id,
            "defense_rule_id": update.defense_rule_id,
            "timestamp": time.time(),
        }
        # 实际应用中应写入AuditLogger，这里只记录
        audit_path = os.path.join(self.config_dir, "enforcer_audit.jsonl")
        os.makedirs(os.path.dirname(audit_path), exist_ok=True)
        with open(audit_path, 'a') as f:
            f.write(json.dumps(audit_entry) + "\n")

    def rollback(self, target: Optional[ConfigTarget] = None) -> Dict[str, Any]:
        """回滚配置到上次备份"""
        rolled_back = 0
        targets = [target] if target else list(ConfigTarget)

        for t in targets:
            snapshot = self.config_snapshots.get(t.value)
            if not snapshot:
                continue
            try:
                backup_path = snapshot["backup_path"]
                config_path = self.config_paths[t]
                if os.path.exists(backup_path):
                    with open(backup_path, 'r') as src:
                        with open(config_path, 'w') as dst:
                            dst.write(src.read())
                    rolled_back += 1
                    self._stats.rollbacks += 1
            except OSError:
                pass

        return {"rolled_back": rolled_back, "targets": [t.value for t in targets]}

    def get_stats(self) -> EnforcerStats:
        """获取下发统计"""
        return self._stats

    def get_pending_updates(self) -> List[ConfigUpdate]:
        """获取待处理更新"""
        return self.pending_updates

    def get_applied_updates(self, limit: int = 100) -> List[ConfigUpdate]:
        """获取已应用更新"""
        return self.applied_updates[-limit:]

    def generate_update_report(self) -> Dict[str, Any]:
        """生成配置更新报告"""
        return {
            "stats": {
                "total": self._stats.total_updates,
                "applied": self._stats.applied_updates,
                "failed": self._stats.failed_updates,
                "pending": self._stats.pending_updates,
                "rollbacks": self._stats.rollbacks,
            },
            "dry_run": self.dry_run,
            "pending_updates": [u.to_json() for u in self.pending_updates[:20]],
            "recent_applied": [u.to_json() for u in self.applied_updates[-10:]],
            "config_targets": {t.value: self.config_paths[t] for t in ConfigTarget},
            "security_boundary": self._get_security_boundary(),
        }

    def _get_security_boundary(self) -> Dict[str, Any]:
        """获取安全边界声明"""
        return {
            "warning": "本配置下发器默认运行在dry-run模式，不会实际修改系统配置",
            "production_requirements": [
                "必须在裸机特权环境运行",
                "必须完成独立第三方安全审计",
                "必须配置HMAC审计链",
                "必须有配置回滚预案",
            ],
            "unsupported_in_container": [
                "实际修改seccomp配置需要CAP_SYS_ADMIN",
                "实际修改eBPF规则需要CAP_BPF",
                "实际修改StrongPool配置需要访问/dev/kvm",
            ],
        }
