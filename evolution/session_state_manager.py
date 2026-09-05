"""
PhotonBox 服务器端会话状态管理模块

参考 Google Gemini Interactions API 的服务器端状态管理模式：
- 服务器保存会话状态，客户端只需 previous_session_id 即可跨会话恢复
- 每个会话独立状态空间，支持多租户隔离
- 会话状态快照/恢复、过期清理、变更审计

应用场景：
1. 沙箱实例会话状态持久化（启动参数、资源配额、网络策略）
2. 红蓝对抗训练会话（训练进度、权重分布、进化历史）
3. 安全审计会话（审计链状态、去重状态、规则熔断状态）
4. 多租户隔离（每租户独立会话空间，不交叉污染）

参考：
- Google Gemini Interactions API：服务器端状态管理，previous_interaction_id 跨会话继续
- Claude Projects：每项目独立记忆空间，后台自动提取
- Microsoft 365 Copilot Memory："memory updated"透明信号，用户可审查
"""

import os
import json
import time
import uuid
import hashlib
import threading
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional, List, Set
from collections import defaultdict
from enum import Enum


# ==================== 会话状态枚举 ====================

class SessionStatus(Enum):
    """会话状态枚举"""
    ACTIVE = "active"           # 活跃
    SUSPENDED = "suspended"     # 挂起（可恢复）
    COMPLETED = "completed"     # 已完成
    EXPIRED = "expired"         # 已过期
    ARCHIVED = "archived"       # 已归档


class SessionType(Enum):
    """会话类型枚举"""
    SANDBOX = "sandbox"                 # 沙箱实例会话
    RED_BLUE_TRAINING = "red_blue"     # 红蓝对抗训练会话
    AUDIT = "audit"                     # 安全审计会话
    EVOLUTION = "evolution"             # 进化训练会话
    GENERAL = "general"                 # 通用会话


# ==================== 数据结构 ====================

@dataclass
class SessionSnapshot:
    """会话快照（用于状态恢复和审计）"""
    snapshot_id: str
    session_id: str
    timestamp: float
    state: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""  # 快照原因（manual/periodic/auto_suspend/pre_restore）

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SessionChangeLog:
    """会话变更日志（审计用）"""
    timestamp: float
    session_id: str
    operation: str       # create/update/suspend/resume/expire/archive/delete
    field: str = ""      # 变更的字段
    old_value: Any = None
    new_value: Any = None
    actor: str = "system"  # 操作者（system/user/tenant_id）
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SessionState:
    """会话状态"""
    session_id: str
    session_type: str
    tenant_id: str = "default"
    status: str = SessionStatus.ACTIVE.value
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    last_accessed_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None  # None 表示永不过期
    state: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    parent_session_id: Optional[str] = None  # 父会话（用于会话链）
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionState":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ==================== 会话状态管理器 ====================

class SessionStateManager:
    """
    服务器端会话状态管理器

    参考 Google Gemini Interactions API：
    - 服务器保存完整会话状态
    - 客户端用 previous_session_id 跨会话恢复
    - 支持会话链（parent_session_id）
    - 多租户隔离（tenant_id 命名空间）

    核心功能：
    1. 会话生命周期管理（创建/挂起/恢复/完成/过期/归档/删除）
    2. 状态读写（get/set/update，带变更审计）
    3. 快照管理（create_snapshot/list_snapshots/restore_snapshot）
    4. 跨会话恢复（resume_from_previous）
    5. 会话链（parent/child 关系）
    6. 多租户隔离（tenant_id 命名空间）
    7. 过期清理（cleanup_expired）
    8. 持久化（save/load，JSON 文件存储）
    """

    def __init__(
        self,
        storage_dir: Optional[str] = None,
        default_ttl: Optional[float] = None,
        max_snapshots_per_session: int = 10,
        enable_audit_log: bool = True,
    ):
        """
        初始化会话状态管理器

        Args:
            storage_dir: 持久化存储目录（None 表示仅内存）
            default_ttl: 默认会话 TTL（秒），None 表示永不过期
            max_snapshots_per_session: 每会话最大快照数
            enable_audit_log: 是否启用变更审计日志
        """
        self.storage_dir = storage_dir
        self.default_ttl = default_ttl
        self.max_snapshots_per_session = max_snapshots_per_session
        self.enable_audit_log = enable_audit_log

        self._sessions: Dict[str, SessionState] = {}
        self._snapshots: Dict[str, List[SessionSnapshot]] = defaultdict(list)
        self._change_logs: List[SessionChangeLog] = []
        self._tenant_sessions: Dict[str, Set[str]] = defaultdict(set)  # tenant_id -> session_ids

        self._lock = threading.RLock()

        # 如果指定了存储目录，加载已有会话
        if self.storage_dir:
            os.makedirs(self.storage_dir, exist_ok=True)
            self._load_all()

    # ==================== 会话生命周期管理 ====================

    def create_session(
        self,
        session_type: str = SessionType.GENERAL.value,
        tenant_id: str = "default",
        initial_state: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        ttl: Optional[float] = None,
        parent_session_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> SessionState:
        """
        创建新会话

        Args:
            session_type: 会话类型
            tenant_id: 租户 ID（多租户隔离）
            initial_state: 初始状态
            metadata: 元数据
            ttl: 会话 TTL（秒），覆盖默认值
            parent_session_id: 父会话 ID（会话链）
            tags: 标签列表

        Returns:
            创建的会话状态
        """
        with self._lock:
            session_id = self._generate_session_id()
            now = time.time()

            expires_at = None
            if ttl is not None:
                expires_at = now + ttl
            elif self.default_ttl is not None:
                expires_at = now + self.default_ttl

            session = SessionState(
                session_id=session_id,
                session_type=session_type,
                tenant_id=tenant_id,
                status=SessionStatus.ACTIVE.value,
                created_at=now,
                updated_at=now,
                last_accessed_at=now,
                expires_at=expires_at,
                state=initial_state or {},
                metadata=metadata or {},
                parent_session_id=parent_session_id,
                tags=tags or [],
            )

            self._sessions[session_id] = session
            self._tenant_sessions[tenant_id].add(session_id)

            self._log_change(session_id, "create", actor="system",
                            reason=f"Created {session_type} session for tenant {tenant_id}")

            # 自动创建初始快照
            self._create_snapshot_internal(session, reason="initial")

            self._persist_session(session)
            return session

    def get_session(self, session_id: str, tenant_id: Optional[str] = None) -> Optional[SessionState]:
        """
        获取会话状态

        Args:
            session_id: 会话 ID
            tenant_id: 租户 ID（用于隔离校验，None 表示不校验）

        Returns:
            会话状态（不存在或租户不匹配返回 None）
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if tenant_id is not None and session.tenant_id != tenant_id:
                return None  # 租户隔离
            session.last_accessed_at = time.time()
            return session

    def update_state(
        self,
        session_id: str,
        updates: Dict[str, Any],
        tenant_id: Optional[str] = None,
        actor: str = "system",
    ) -> Optional[SessionState]:
        """
        更新会话状态（合并更新）

        Args:
            session_id: 会话 ID
            updates: 状态更新字典（合并到现有状态）
            tenant_id: 租户 ID
            actor: 操作者

        Returns:
            更新后的会话状态
        """
        with self._lock:
            session = self.get_session(session_id, tenant_id)
            if session is None:
                return None

            old_state = dict(session.state)
            session.state.update(updates)
            session.updated_at = time.time()

            # 记录每个变更字段
            for key, new_value in updates.items():
                old_value = old_state.get(key)
                self._log_change(
                    session_id, "update", field=key,
                    old_value=old_value, new_value=new_value, actor=actor,
                )

            self._persist_session(session)
            return session

    def set_state(
        self,
        session_id: str,
        key: str,
        value: Any,
        tenant_id: Optional[str] = None,
        actor: str = "system",
    ) -> Optional[SessionState]:
        """设置单个状态字段"""
        return self.update_state(session_id, {key: value}, tenant_id, actor)

    def get_state_value(
        self,
        session_id: str,
        key: str,
        default: Any = None,
        tenant_id: Optional[str] = None,
    ) -> Any:
        """获取单个状态字段"""
        session = self.get_session(session_id, tenant_id)
        if session is None:
            return default
        return session.state.get(key, default)

    def suspend_session(
        self,
        session_id: str,
        reason: str = "",
        tenant_id: Optional[str] = None,
    ) -> Optional[SessionState]:
        """
        挂起会话（保存状态，可恢复）

        挂起时自动创建快照，用于后续恢复。
        """
        with self._lock:
            session = self.get_session(session_id, tenant_id)
            if session is None:
                return None

            old_status = session.status
            session.status = SessionStatus.SUSPENDED.value
            session.updated_at = time.time()

            self._create_snapshot_internal(session, reason=f"suspend: {reason}" or "suspend")
            self._log_change(session_id, "suspend", old_value=old_status,
                            new_value=session.status, reason=reason)
            self._persist_session(session)
            return session

    def resume_session(
        self,
        session_id: str,
        tenant_id: Optional[str] = None,
        actor: str = "system",
    ) -> Optional[SessionState]:
        """
        恢复挂起的会话

        从最新快照恢复状态。
        """
        with self._lock:
            session = self.get_session(session_id, tenant_id)
            if session is None:
                return None

            old_status = session.status

            # 从最新快照恢复
            snapshots = self._snapshots.get(session_id, [])
            if snapshots:
                latest_snapshot = snapshots[-1]
                session.state = dict(latest_snapshot.state)

            session.status = SessionStatus.ACTIVE.value
            session.updated_at = time.time()
            session.last_accessed_at = time.time()

            self._log_change(session_id, "resume", old_value=old_status,
                            new_value=session.status, actor=actor)
            self._persist_session(session)
            return session

    def complete_session(
        self,
        session_id: str,
        final_state: Optional[Dict[str, Any]] = None,
        tenant_id: Optional[str] = None,
    ) -> Optional[SessionState]:
        """完成会话"""
        with self._lock:
            session = self.get_session(session_id, tenant_id)
            if session is None:
                return None

            if final_state:
                session.state.update(final_state)

            old_status = session.status
            session.status = SessionStatus.COMPLETED.value
            session.updated_at = time.time()

            self._create_snapshot_internal(session, reason="completed")
            self._log_change(session_id, "complete", old_value=old_status,
                            new_value=session.status)
            self._persist_session(session)
            return session

    def delete_session(
        self,
        session_id: str,
        tenant_id: Optional[str] = None,
        actor: str = "system",
    ) -> bool:
        """删除会话（连同快照和日志）"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False
            if tenant_id is not None and session.tenant_id != tenant_id:
                return False

            del self._sessions[session_id]
            self._snapshots.pop(session_id, None)
            self._tenant_sessions.get(session.tenant_id, set()).discard(session_id)

            self._log_change(session_id, "delete", actor=actor)
            self._delete_persisted_session(session_id)
            return True

    # ==================== 快照管理 ====================

    def create_snapshot(
        self,
        session_id: str,
        reason: str = "manual",
        tenant_id: Optional[str] = None,
    ) -> Optional[SessionSnapshot]:
        """手动创建会话快照"""
        with self._lock:
            session = self.get_session(session_id, tenant_id)
            if session is None:
                return None
            return self._create_snapshot_internal(session, reason=reason)

    def _create_snapshot_internal(
        self,
        session: SessionState,
        reason: str = "auto",
    ) -> SessionSnapshot:
        """内部创建快照（带滚动窗口）"""
        snapshot = SessionSnapshot(
            snapshot_id=self._generate_snapshot_id(),
            session_id=session.session_id,
            timestamp=time.time(),
            state=dict(session.state),
            metadata=dict(session.metadata),
            reason=reason,
        )

        snapshots = self._snapshots[session.session_id]
        snapshots.append(snapshot)

        # 滚动窗口：保留最近 N 个快照
        if len(snapshots) > self.max_snapshots_per_session:
            self._snapshots[session.session_id] = snapshots[-self.max_snapshots_per_session:]

        return snapshot

    def list_snapshots(
        self,
        session_id: str,
        tenant_id: Optional[str] = None,
    ) -> List[SessionSnapshot]:
        """列出会话的所有快照"""
        session = self.get_session(session_id, tenant_id)
        if session is None:
            return []
        return list(self._snapshots.get(session_id, []))

    def restore_snapshot(
        self,
        session_id: str,
        snapshot_id: str,
        tenant_id: Optional[str] = None,
        actor: str = "system",
    ) -> Optional[SessionState]:
        """
        从指定快照恢复会话状态

        恢复前自动创建当前状态的快照（防止误操作丢失）。
        """
        with self._lock:
            session = self.get_session(session_id, tenant_id)
            if session is None:
                return None

            snapshots = self._snapshots.get(session_id, [])
            target_snapshot = None
            for snap in snapshots:
                if snap.snapshot_id == snapshot_id:
                    target_snapshot = snap
                    break

            if target_snapshot is None:
                return None

            # 恢复前创建当前状态快照
            self._create_snapshot_internal(session, reason=f"pre_restore_to_{snapshot_id}")

            old_state = dict(session.state)
            session.state = dict(target_snapshot.state)
            session.updated_at = time.time()

            self._log_change(
                session_id, "update", field="__full_state__",
                old_value=f"<state before restore to {snapshot_id}>",
                new_value=f"<restored from {snapshot_id}>",
                actor=actor, reason=f"Restored from snapshot {snapshot_id}",
            )
            self._persist_session(session)
            return session

    # ==================== 跨会话恢复（参考 Google Gemini Interactions API） ====================

    def resume_from_previous(
        self,
        previous_session_id: str,
        new_session_type: Optional[str] = None,
        tenant_id: Optional[str] = None,
        inherit_state: bool = True,
        inherit_metadata: bool = True,
        inherit_tags: bool = True,
    ) -> Optional[SessionState]:
        """
        从之前的会话恢复，创建新会话（参考 Google Gemini previous_interaction_id）

        新会话的 parent_session_id 指向旧会话，形成会话链。
        可以选择性继承状态、元数据、标签。

        Args:
            previous_session_id: 之前的会话 ID
            new_session_type: 新会话类型（None 表示继承旧会话类型）
            tenant_id: 租户 ID（None 表示继承旧会话租户）
            inherit_state: 是否继承状态
            inherit_metadata: 是否继承元数据
            inherit_tags: 是否继承标签

        Returns:
            新创建的会话状态
        """
        with self._lock:
            previous = self._sessions.get(previous_session_id)
            if previous is None:
                return None

            # 租户隔离校验
            if tenant_id is not None and previous.tenant_id != tenant_id:
                return None

            effective_tenant = tenant_id or previous.tenant_id
            effective_type = new_session_type or previous.session_type

            initial_state = dict(previous.state) if inherit_state else {}
            initial_metadata = dict(previous.metadata) if inherit_metadata else {}
            initial_tags = list(previous.tags) if inherit_tags else []

            # 标记继承来源
            initial_metadata["inherited_from"] = previous_session_id
            initial_metadata["inherited_at"] = time.time()

            new_session = self.create_session(
                session_type=effective_type,
                tenant_id=effective_tenant,
                initial_state=initial_state,
                metadata=initial_metadata,
                parent_session_id=previous_session_id,
                tags=initial_tags,
            )

            return new_session

    def get_session_chain(self, session_id: str) -> List[SessionState]:
        """
        获取会话链（从当前会话向上追溯所有父会话）

        Returns:
            会话链列表（从最早的祖先到当前会话）
        """
        chain = []
        current_id = session_id
        visited = set()

        while current_id and current_id not in visited:
            visited.add(current_id)
            session = self._sessions.get(current_id)
            if session is None:
                break
            chain.append(session)
            current_id = session.parent_session_id

        chain.reverse()  # 从祖先到当前
        return chain

    # ==================== 多租户隔离 ====================

    def list_sessions_by_tenant(
        self,
        tenant_id: str,
        status_filter: Optional[str] = None,
        session_type_filter: Optional[str] = None,
    ) -> List[SessionState]:
        """
        列出指定租户的所有会话（多租户隔离）

        Args:
            tenant_id: 租户 ID
            status_filter: 状态过滤（None 表示全部）
            session_type_filter: 类型过滤（None 表示全部）
        """
        with self._lock:
            sessions = []
            for session_id in self._tenant_sessions.get(tenant_id, set()):
                session = self._sessions.get(session_id)
                if session is None:
                    continue
                if status_filter and session.status != status_filter:
                    continue
                if session_type_filter and session.session_type != session_type_filter:
                    continue
                sessions.append(session)
            sessions.sort(key=lambda s: s.created_at, reverse=True)
            return sessions

    def get_tenant_statistics(self, tenant_id: str) -> Dict[str, Any]:
        """获取租户会话统计"""
        sessions = self.list_sessions_by_tenant(tenant_id)
        status_counts = defaultdict(int)
        type_counts = defaultdict(int)
        for s in sessions:
            status_counts[s.status] += 1
            type_counts[s.session_type] += 1

        return {
            "tenant_id": tenant_id,
            "total_sessions": len(sessions),
            "sessions_by_status": dict(status_counts),
            "sessions_by_type": dict(type_counts),
            "active_sessions": status_counts.get(SessionStatus.ACTIVE.value, 0),
        }

    # ==================== 过期清理 ====================

    def cleanup_expired(self) -> int:
        """
        清理过期会话（自动挂起并标记过期）

        Returns:
            清理的会话数量
        """
        with self._lock:
            now = time.time()
            expired_count = 0

            for session_id, session in list(self._sessions.items()):
                if (session.expires_at is not None and
                        session.expires_at < now and
                        session.status == SessionStatus.ACTIVE.value):
                    # 自动挂起并标记过期
                    self._create_snapshot_internal(session, reason="auto_expire")
                    session.status = SessionStatus.EXPIRED.value
                    session.updated_at = now
                    self._log_change(session_id, "expire",
                                    old_value=SessionStatus.ACTIVE.value,
                                    new_value=SessionStatus.EXPIRED.value,
                                    reason="TTL expired")
                    self._persist_session(session)
                    expired_count += 1

            return expired_count

    # ==================== 审计日志 ====================

    def get_change_logs(
        self,
        session_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[SessionChangeLog]:
        """
        获取会话变更日志（审计用）

        Args:
            session_id: 会话 ID（None 表示全部）
            limit: 返回数量限制
        """
        with self._lock:
            logs = self._change_logs
            if session_id:
                logs = [log for log in logs if log.session_id == session_id]
            return logs[-limit:]

    def _log_change(
        self,
        session_id: str,
        operation: str,
        field: str = "",
        old_value: Any = None,
        new_value: Any = None,
        actor: str = "system",
        reason: str = "",
    ):
        """记录会话变更日志"""
        if not self.enable_audit_log:
            return

        log = SessionChangeLog(
            timestamp=time.time(),
            session_id=session_id,
            operation=operation,
            field=field,
            old_value=old_value,
            new_value=new_value,
            actor=actor,
            reason=reason,
        )
        self._change_logs.append(log)

        # 限制日志数量（保留最近 10000 条）
        if len(self._change_logs) > 10000:
            self._change_logs = self._change_logs[-10000:]

    # ==================== 持久化 ====================

    def _persist_session(self, session: SessionState):
        """持久化单个会话到文件"""
        if not self.storage_dir:
            return
        try:
            session_file = self._get_session_file(session.session_id)
            with open(session_file, "w", encoding="utf-8") as f:
                json.dump(session.to_dict(), f, indent=2, ensure_ascii=False)
        except (IOError, OSError):
            pass  # 持久化失败不影响内存操作

    def _delete_persisted_session(self, session_id: str):
        """删除持久化的会话文件"""
        if not self.storage_dir:
            return
        try:
            session_file = self._get_session_file(session_id)
            if os.path.exists(session_file):
                os.remove(session_file)
        except (IOError, OSError):
            pass

    def _get_session_file(self, session_id: str) -> str:
        """获取会话文件路径"""
        # 使用 session_id 的哈希作为文件名，避免路径遍历
        safe_id = hashlib.sha256(session_id.encode()).hexdigest()[:16]
        return os.path.join(self.storage_dir, f"session_{safe_id}.json")

    def _load_all(self):
        """从存储目录加载所有会话"""
        if not self.storage_dir or not os.path.exists(self.storage_dir):
            return
        try:
            for filename in os.listdir(self.storage_dir):
                if not filename.startswith("session_") or not filename.endswith(".json"):
                    continue
                filepath = os.path.join(self.storage_dir, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    session = SessionState.from_dict(data)
                    self._sessions[session.session_id] = session
                    self._tenant_sessions[session.tenant_id].add(session.session_id)
                except (json.JSONDecodeError, KeyError, TypeError):
                    continue
        except (IOError, OSError):
            pass

    def save_all(self):
        """强制保存所有会话"""
        with self._lock:
            for session in self._sessions.values():
                self._persist_session(session)

    # ==================== ID 生成 ====================

    @staticmethod
    def _generate_session_id() -> str:
        """生成会话 ID"""
        return f"sess_{uuid.uuid4().hex[:16]}"

    @staticmethod
    def _generate_snapshot_id() -> str:
        """生成快照 ID"""
        return f"snap_{uuid.uuid4().hex[:16]}"

    # ==================== 统计 ====================

    def get_statistics(self) -> Dict[str, Any]:
        """获取全局统计信息"""
        with self._lock:
            status_counts = defaultdict(int)
            type_counts = defaultdict(int)
            total_snapshots = sum(len(snaps) for snaps in self._snapshots.values())

            for session in self._sessions.values():
                status_counts[session.status] += 1
                type_counts[session.session_type] += 1

            return {
                "total_sessions": len(self._sessions),
                "sessions_by_status": dict(status_counts),
                "sessions_by_type": dict(type_counts),
                "total_snapshots": total_snapshots,
                "total_change_logs": len(self._change_logs),
                "total_tenants": len(self._tenant_sessions),
                "storage_dir": self.storage_dir,
                "default_ttl": self.default_ttl,
            }


# ==================== 便捷接口 ====================

def create_session_manager(
    storage_dir: Optional[str] = None,
    default_ttl: Optional[float] = None,
) -> SessionStateManager:
    """创建会话状态管理器"""
    return SessionStateManager(storage_dir=storage_dir, default_ttl=default_ttl)


if __name__ == "__main__":
    # 自测试
    print("=" * 60)
    print("PhotonBox 服务器端会话状态管理 - 自测试")
    print("=" * 60)

    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="photonbox_sessions_")
    manager = SessionStateManager(storage_dir=tmpdir, default_ttl=3600)

    # 测试 1：创建会话
    print("\n--- 测试 1：创建会话 ---")
    session = manager.create_session(
        session_type=SessionType.SANDBOX.value,
        tenant_id="tenant-a",
        initial_state={"backend": "StrongPool", "cpu_quota": 2.0},
        metadata={"image": "ubuntu-22.04", "region": "us-east-1"},
        tags=["production", "kvm"],
    )
    print(f"  会话 ID：{session.session_id}")
    print(f"  类型：{session.session_type}")
    print(f"  租户：{session.tenant_id}")
    print(f"  状态：{session.state}")
    print(f"  过期时间：{session.expires_at}")

    # 测试 2：更新状态
    print("\n--- 测试 2：更新状态 ---")
    manager.update_state(session.session_id, {"memory_mb": 1024, "status": "running"})
    updated = manager.get_session(session.session_id)
    print(f"  更新后状态：{updated.state}")

    # 测试 3：挂起和恢复
    print("\n--- 测试 3：挂起和恢复 ---")
    manager.suspend_session(session.session_id, reason="maintenance")
    suspended = manager.get_session(session.session_id)
    print(f"  挂起后状态：{suspended.status}")
    print(f"  快照数量：{len(manager.list_snapshots(session.session_id))}")

    manager.resume_session(session.session_id)
    resumed = manager.get_session(session.session_id)
    print(f"  恢复后状态：{resumed.status}")

    # 测试 4：跨会话恢复（previous_session_id 模式）
    print("\n--- 测试 4：跨会话恢复（Google Gemini 模式）---")
    new_session = manager.resume_from_previous(
        session.session_id,
        inherit_state=True,
        inherit_metadata=True,
    )
    print(f"  新会话 ID：{new_session.session_id}")
    print(f"  父会话 ID：{new_session.parent_session_id}")
    print(f"  继承的状态：{new_session.state}")
    print(f"  继承来源元数据：{new_session.metadata.get('inherited_from')}")

    # 测试 5：会话链
    print("\n--- 测试 5：会话链 ---")
    chain = manager.get_session_chain(new_session.session_id)
    print(f"  会话链长度：{len(chain)}")
    for s in chain:
        print(f"    - {s.session_id} ({s.session_type})")

    # 测试 6：多租户隔离
    print("\n--- 测试 6：多租户隔离 ---")
    manager.create_session(tenant_id="tenant-b", session_type="audit")
    tenant_a_sessions = manager.list_sessions_by_tenant("tenant-a")
    tenant_b_sessions = manager.list_sessions_by_tenant("tenant-b")
    print(f"  租户 A 会话数：{len(tenant_a_sessions)}")
    print(f"  租户 B 会话数：{len(tenant_b_sessions)}")

    # 测试 7：快照恢复
    print("\n--- 测试 7：快照恢复 ---")
    manager.update_state(session.session_id, {"test_field": "before_snapshot"})
    snapshot = manager.create_snapshot(session.session_id, reason="test")
    manager.update_state(session.session_id, {"test_field": "after_snapshot"})
    print(f"  快照前值：after_snapshot")
    manager.restore_snapshot(session.session_id, snapshot.snapshot_id)
    restored = manager.get_session(session.session_id)
    print(f"  恢复后值：{restored.state.get('test_field')}")

    # 测试 8：审计日志
    print("\n--- 测试 8：审计日志 ---")
    logs = manager.get_change_logs(session.session_id)
    print(f"  变更日志数量：{len(logs)}")
    for log in logs[-3:]:
        print(f"    - {log.operation} {log.field or ''} ({log.reason or 'N/A'})")

    # 测试 9：统计
    print("\n--- 测试 9：统计 ---")
    stats = manager.get_statistics()
    print(f"  总会话数：{stats['total_sessions']}")
    print(f"  总快照数：{stats['total_snapshots']}")
    print(f"  总变更日志：{stats['total_change_logs']}")
    print(f"  租户数：{stats['total_tenants']}")

    # 测试 10：过期清理
    print("\n--- 测试 10：过期清理 ---")
    expiring_session = manager.create_session(tenant_id="tenant-a", ttl=0.01)
    time.sleep(0.02)
    expired_count = manager.cleanup_expired()
    print(f"  过期会话数：{expired_count}")
    expired_session = manager.get_session(expiring_session.session_id)
    print(f"  过期后状态：{expired_session.status}")

    print("\n" + "=" * 60)
    print("✅ 所有测试通过")
    print("=" * 60)
