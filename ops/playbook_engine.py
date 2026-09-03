"""
PlaybookEngine — 自动化剧本编排引擎

将合规引擎与熔断机制产品化：当触发法案合规违规或安全威胁时，
支持通过编排剧本进行自动处置（自动隔离容器、冻结账号、弹窗提醒等）。

设计原则：
1. 剧本可声明式定义（YAML/JSON），支持条件触发+动作序列
2. 动作可插拔（隔离/冻结/告警/通知/回滚/扩容）
3. 执行可审计（每次剧本执行记录完整审计日志）
4. 支持手动确认（高危动作需要人工审批）
5. 支持回滚（动作失败时自动回滚）

剧本结构：
- trigger: 触发条件（合规违规/安全威胁/指标阈值/事件类型）
- conditions: 附加条件（风险等级/租户/时间窗口）
- actions: 动作序列（按顺序执行）
- on_failure: 失败处理（回滚/告警/人工介入）
- audit: 审计配置（记录级别/通知渠道）
"""

import json
import time
import uuid
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
from enum import Enum

logger = logging.getLogger(__name__)


class TriggerType(Enum):
    """触发类型"""
    COMPLIANCE_VIOLATION = "compliance_violation"  # 法案合规违规
    SECURITY_THREAT = "security_threat"  # 安全威胁
    METRIC_THRESHOLD = "metric_threshold"  # 指标阈值
    ESCAPE_ATTEMPT = "escape_attempt"  # 逃逸尝试
    RESOURCE_EXHAUSTION = "resource_exhaustion"  # 资源耗尽
    AUDIT_FAILURE = "audit_failure"  # 审计失败
    MANUAL = "manual"  # 手动触发


class ActionType(Enum):
    """动作类型"""
    ISOLATE_CONTAINER = "isolate_container"  # 隔离容器
    FREEZE_ACCOUNT = "freeze_account"  # 冻结账号
    REVOKE_CAPABILITY = "revoke_capability"  # 撤销权限票据
    SHUTDOWN_SANDBOX = "shutdown_sandbox"  # 关闭沙盒
    SEND_ALERT = "send_alert"  # 发送告警
    POPUP_NOTIFICATION = "popup_notification"  # 弹窗提醒
    SCALE_UP = "scale_up"  # 扩容
    SCALE_DOWN = "scale_down"  # 缩容
    CREATE_TICKET = "create_ticket"  # 创建工单
    SNAPSHOT_EVIDENCE = "snapshot_evidence"  # 快照证据
    ROLLBACK = "rollback"  # 回滚
    NOTIFY_ADMIN = "notify_admin"  # 通知管理员


class RiskLevel(Enum):
    """风险等级"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PlaybookStatus(Enum):
    """剧本执行状态"""
    PENDING = "pending"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"


@dataclass
class Action:
    """动作定义"""
    type: ActionType
    params: Dict[str, Any] = field(default_factory=dict)
    require_approval: bool = False  # 是否需要人工审批
    timeout_seconds: int = 30  # 超时时间
    retry_count: int = 1  # 重试次数
    rollback_action: Optional[ActionType] = None  # 回滚动作


@dataclass
class Trigger:
    """触发器定义"""
    type: TriggerType
    event_pattern: str = ""  # 事件匹配模式（正则）
    metric_name: str = ""  # 指标名称（METRIC_THRESHOLD时）
    threshold: float = 0.0  # 阈值
    comparison: str = ">"  # 比较符：> >= < <= == !=
    risk_level: Optional[RiskLevel] = None  # 风险等级过滤


@dataclass
class Playbook:
    """剧本定义"""
    id: str
    name: str
    description: str = ""
    trigger: Trigger = None
    conditions: Dict[str, Any] = field(default_factory=dict)
    actions: List[Action] = field(default_factory=list)
    on_failure: str = "alert"  # alert/rollback/manual
    enabled: bool = True
    priority: int = 100  # 优先级，数字越小越优先
    created_at: float = field(default_factory=time.time)
    tags: List[str] = field(default_factory=list)


@dataclass
class ActionResult:
    """动作执行结果"""
    action_type: ActionType
    success: bool
    message: str = ""
    started_at: float = 0.0
    completed_at: float = 0.0
    duration_ms: float = 0.0
    output: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PlaybookExecution:
    """剧本执行记录"""
    execution_id: str
    playbook_id: str
    playbook_name: str
    trigger_event: Dict[str, Any]
    status: PlaybookStatus = PlaybookStatus.PENDING
    action_results: List[ActionResult] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    duration_ms: float = 0.0
    error: str = ""
    approver: str = ""
    audit_log: List[str] = field(default_factory=list)


class PlaybookEngine:
    """
    自动化剧本编排引擎

    使用示例：
        engine = PlaybookEngine()

        # 注册剧本
        playbook = Playbook(
            id="isolate-on-escape",
            name="逃逸尝试自动隔离",
            trigger=Trigger(type=TriggerType.ESCAPE_ATTEMPT),
            actions=[
                Action(type=ActionType.SNAPSHOT_EVIDENCE),
                Action(type=ActionType.ISOLATE_CONTAINER, params={"container_id": "{container_id}"}),
                Action(type=ActionType.FREEZE_ACCOUNT, params={"tenant_id": "{tenant_id}"}),
                Action(type=ActionType.CREATE_TICKET),
                Action(type=ActionType.NOTIFY_ADMIN),
            ],
        )
        engine.register_playbook(playbook)

        # 注册动作处理器
        engine.register_action_handler(ActionType.ISOLATE_CONTAINER, isolate_handler)

        # 触发事件
        engine.handle_event({"type": "escape_attempt", "container_id": "c123", "tenant_id": "t456"})
    """

    def __init__(self, audit_callback: Optional[Callable] = None):
        self.playbooks: Dict[str, Playbook] = {}
        self.action_handlers: Dict[ActionType, Callable] = {}
        self.executions: Dict[str, PlaybookExecution] = {}
        self.audit_callback = audit_callback
        self._pending_approvals: Dict[str, PlaybookExecution] = {}
        self._register_default_handlers()

    def _register_default_handlers(self):
        """注册默认动作处理器（模拟实现，生产环境替换为真实操作）"""
        self.action_handlers[ActionType.SEND_ALERT] = self._default_alert_handler
        self.action_handlers[ActionType.POPUP_NOTIFICATION] = self._default_popup_handler
        self.action_handlers[ActionType.NOTIFY_ADMIN] = self._default_notify_handler
        self.action_handlers[ActionType.CREATE_TICKET] = self._default_ticket_handler
        self.action_handlers[ActionType.SNAPSHOT_EVIDENCE] = self._default_snapshot_handler
        # 以下为模拟默认处理器（生产环境需替换为真实操作）
        self.action_handlers[ActionType.ISOLATE_CONTAINER] = self._default_isolate_handler
        self.action_handlers[ActionType.FREEZE_ACCOUNT] = self._default_freeze_handler
        self.action_handlers[ActionType.REVOKE_CAPABILITY] = self._default_revoke_handler
        self.action_handlers[ActionType.SHUTDOWN_SANDBOX] = self._default_shutdown_handler
        self.action_handlers[ActionType.SCALE_UP] = self._default_scale_handler
        self.action_handlers[ActionType.SCALE_DOWN] = self._default_scale_handler
        self.action_handlers[ActionType.ROLLBACK] = self._default_rollback_handler

    def register_playbook(self, playbook: Playbook) -> None:
        """注册剧本"""
        self.playbooks[playbook.id] = playbook
        logger.info(f"注册剧本: {playbook.id} - {playbook.name}")

    def unregister_playbook(self, playbook_id: str) -> None:
        """注销剧本"""
        if playbook_id in self.playbooks:
            del self.playbooks[playbook_id]
            logger.info(f"注销剧本: {playbook_id}")

    def register_action_handler(self, action_type: ActionType, handler: Callable) -> None:
        """注册动作处理器"""
        self.action_handlers[action_type] = handler

    def handle_event(self, event: Dict[str, Any]) -> List[PlaybookExecution]:
        """
        处理事件，触发匹配的剧本

        Args:
            event: 事件字典，必须包含 type 字段

        Returns:
            触发的剧本执行列表
        """
        event_type = event.get("type", "")
        logger.info(f"处理事件: {event_type}")

        triggered = []
        # 按优先级排序
        sorted_playbooks = sorted(
            [p for p in self.playbooks.values() if p.enabled],
            key=lambda p: p.priority
        )

        for playbook in sorted_playbooks:
            if self._match_trigger(playbook.trigger, event):
                if self._match_conditions(playbook.conditions, event):
                    execution = self._execute_playbook(playbook, event)
                    triggered.append(execution)

        return triggered

    def _match_trigger(self, trigger: Trigger, event: Dict[str, Any]) -> bool:
        """匹配触发器"""
        event_type = event.get("type", "")

        # 类型匹配
        if trigger.type.value != event_type:
            return False

        # 事件模式匹配（正则）
        if trigger.event_pattern:
            import re
            event_str = json.dumps(event)
            if not re.search(trigger.event_pattern, event_str):
                return False

        # 指标阈值匹配
        if trigger.type == TriggerType.METRIC_THRESHOLD and trigger.metric_name:
            metric_value = event.get("metrics", {}).get(trigger.metric_name)
            if metric_value is None:
                return False
            if not self._compare(metric_value, trigger.comparison, trigger.threshold):
                return False

        # 风险等级匹配
        if trigger.risk_level:
            event_risk = event.get("risk_level", "")
            if trigger.risk_level.value != event_risk:
                return False

        return True

    def _match_conditions(self, conditions: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """匹配附加条件"""
        for key, expected in conditions.items():
            actual = event.get(key)
            if actual != expected:
                return False
        return True

    def _compare(self, value: float, op: str, threshold: float) -> bool:
        """比较运算"""
        ops = {
            ">": lambda a, b: a > b,
            ">=": lambda a, b: a >= b,
            "<": lambda a, b: a < b,
            "<=": lambda a, b: a <= b,
            "==": lambda a, b: a == b,
            "!=": lambda a, b: a != b,
        }
        return ops.get(op, lambda a, b: False)(value, threshold)

    def _execute_playbook(self, playbook: Playbook, event: Dict[str, Any]) -> PlaybookExecution:
        """执行剧本"""
        execution_id = str(uuid.uuid4())[:8]
        execution = PlaybookExecution(
            execution_id=execution_id,
            playbook_id=playbook.id,
            playbook_name=playbook.name,
            trigger_event=event,
            status=PlaybookStatus.RUNNING,
        )
        self.executions[execution_id] = execution
        self._audit(execution, f"剧本开始执行: {playbook.name}")

        try:
            for action in playbook.actions:
                # 检查是否需要审批
                if action.require_approval:
                    execution.status = PlaybookStatus.WAITING_APPROVAL
                    self._pending_approvals[execution_id] = execution
                    self._audit(execution, f"等待人工审批: {action.type.value}")
                    return execution

                result = self._execute_action(action, event, execution)
                execution.action_results.append(result)

                if not result.success:
                    self._handle_failure(playbook, action, event, execution)
                    break

            if execution.status == PlaybookStatus.RUNNING:
                execution.status = PlaybookStatus.COMPLETED
                self._audit(execution, "剧本执行完成")

        except Exception as e:
            execution.status = PlaybookStatus.FAILED
            execution.error = str(e)
            self._audit(execution, f"剧本执行异常: {e}")

        execution.completed_at = time.time()
        execution.duration_ms = (execution.completed_at - execution.started_at) * 1000
        return execution

    def _execute_action(self, action: Action, event: Dict[str, Any],
                        execution: PlaybookExecution) -> ActionResult:
        """执行单个动作"""
        result = ActionResult(
            action_type=action.type,
            success=False,
            started_at=time.time(),
        )

        handler = self.action_handlers.get(action.type)
        if not handler:
            result.success = False
            result.message = f"未注册动作处理器: {action.type.value}"
            self._audit(execution, f"动作失败: {result.message}")
            return result

        # 参数模板替换
        resolved_params = self._resolve_params(action.params, event)

        try:
            output = handler(resolved_params, event)
            result.success = True
            result.message = f"动作执行成功: {action.type.value}"
            result.output = output if isinstance(output, dict) else {"result": str(output)}
        except Exception as e:
            result.success = False
            result.message = f"动作执行异常: {e}"
            self._audit(execution, f"动作异常: {action.type.value} - {e}")

        result.completed_at = time.time()
        result.duration_ms = (result.completed_at - result.started_at) * 1000
        return result

    def _resolve_params(self, params: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        """解析参数模板（{key} 替换为事件中的值）"""
        resolved = {}
        for key, value in params.items():
            if isinstance(value, str) and value.startswith("{") and value.endswith("}"):
                event_key = value[1:-1]
                resolved[key] = event.get(event_key, value)
            else:
                resolved[key] = value
        return resolved

    def _handle_failure(self, playbook: Playbook, failed_action: Action,
                        event: Dict[str, Any], execution: PlaybookExecution) -> None:
        """处理动作失败"""
        self._audit(execution, f"动作失败: {failed_action.type.value}")

        if playbook.on_failure == "rollback" and failed_action.rollback_action:
            self._audit(execution, "执行回滚")
            rollback_action = Action(type=failed_action.rollback_action)
            self._execute_action(rollback_action, event, execution)
            execution.status = PlaybookStatus.ROLLED_BACK
        elif playbook.on_failure == "manual":
            execution.status = PlaybookStatus.WAITING_APPROVAL
            self._audit(execution, "等待人工介入")
        else:
            # alert
            alert_action = Action(type=ActionType.SEND_ALERT)
            self._execute_action(alert_action, event, execution)
            execution.status = PlaybookStatus.FAILED

    def approve_execution(self, execution_id: str, approver: str = "admin") -> Optional[PlaybookExecution]:
        """人工审批通过，继续执行"""
        execution = self._pending_approvals.pop(execution_id, None)
        if not execution:
            return None

        execution.approver = approver
        execution.status = PlaybookStatus.RUNNING
        self._audit(execution, f"人工审批通过: {approver}")

        # 继续执行剩余动作（简化：重新执行整个剧本）
        playbook = self.playbooks.get(execution.playbook_id)
        if playbook:
            return self._execute_playbook(playbook, execution.trigger_event)
        return execution

    def reject_execution(self, execution_id: str, reason: str = "") -> Optional[PlaybookExecution]:
        """人工审批拒绝"""
        execution = self._pending_approvals.pop(execution_id, None)
        if not execution:
            return None
        execution.status = PlaybookStatus.CANCELLED
        execution.error = f"人工拒绝: {reason}"
        self._audit(execution, f"人工审批拒绝: {reason}")
        return execution

    def get_execution(self, execution_id: str) -> Optional[PlaybookExecution]:
        """获取执行记录"""
        return self.executions.get(execution_id)

    def list_executions(self, status: Optional[PlaybookStatus] = None,
                        limit: int = 50) -> List[PlaybookExecution]:
        """列出执行记录"""
        executions = list(self.executions.values())
        if status:
            executions = [e for e in executions if e.status == status]
        executions.sort(key=lambda e: e.started_at, reverse=True)
        return executions[:limit]

    def get_pending_approvals(self) -> List[PlaybookExecution]:
        """获取待审批列表"""
        return list(self._pending_approvals.values())

    def _audit(self, execution: PlaybookExecution, message: str) -> None:
        """记录审计日志"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{execution.execution_id}] {message}"
        execution.audit_log.append(log_entry)
        logger.info(log_entry)
        if self.audit_callback:
            try:
                self.audit_callback(execution, message)
            except Exception:
                pass

    # 默认动作处理器
    def _default_alert_handler(self, params: Dict, event: Dict) -> Dict:
        return {"alert_sent": True, "channel": params.get("channel", "default")}

    def _default_popup_handler(self, params: Dict, event: Dict) -> Dict:
        return {"popup_shown": True, "message": params.get("message", "安全告警")}

    def _default_notify_handler(self, params: Dict, event: Dict) -> Dict:
        return {"admin_notified": True, "admin": params.get("admin", "security-team")}

    def _default_ticket_handler(self, params: Dict, event: Dict) -> Dict:
        ticket_id = f"TICKET-{uuid.uuid4().hex[:8].upper()}"
        return {"ticket_created": True, "ticket_id": ticket_id, "priority": params.get("priority", "high")}

    def _default_snapshot_handler(self, params: Dict, event: Dict) -> Dict:
        snapshot_id = f"SNAP-{uuid.uuid4().hex[:8]}"
        return {"snapshot_created": True, "snapshot_id": snapshot_id, "evidence_type": params.get("type", "full")}

    def _default_isolate_handler(self, params: Dict, event: Dict) -> Dict:
        return {"isolated": True, "container_id": params.get("container_id", "unknown")}

    def _default_freeze_handler(self, params: Dict, event: Dict) -> Dict:
        return {"frozen": True, "tenant_id": params.get("tenant_id", "unknown")}

    def _default_revoke_handler(self, params: Dict, event: Dict) -> Dict:
        return {"revoked": True, "capability": params.get("capability", "unknown")}

    def _default_shutdown_handler(self, params: Dict, event: Dict) -> Dict:
        return {"shutdown": True, "sandbox_id": params.get("sandbox_id", "unknown")}

    def _default_scale_handler(self, params: Dict, event: Dict) -> Dict:
        return {"scaled": True, "replicas": params.get("replicas", 0)}

    def _default_rollback_handler(self, params: Dict, event: Dict) -> Dict:
        return {"rolled_back": True, "version": params.get("version", "previous")}

    def load_playbooks_from_json(self, filepath: str) -> int:
        """从JSON文件加载剧本"""
        with open(filepath, 'r') as f:
            data = json.load(f)

        count = 0
        for pb_data in data.get("playbooks", []):
            playbook = Playbook(
                id=pb_data["id"],
                name=pb_data["name"],
                description=pb_data.get("description", ""),
                trigger=Trigger(
                    type=TriggerType(pb_data["trigger"]["type"]),
                    event_pattern=pb_data["trigger"].get("event_pattern", ""),
                    metric_name=pb_data["trigger"].get("metric_name", ""),
                    threshold=pb_data["trigger"].get("threshold", 0.0),
                    comparison=pb_data["trigger"].get("comparison", ">"),
                    risk_level=RiskLevel(pb_data["trigger"]["risk_level"]) if pb_data["trigger"].get("risk_level") else None,
                ),
                conditions=pb_data.get("conditions", {}),
                actions=[
                    Action(
                        type=ActionType(a["type"]),
                        params=a.get("params", {}),
                        require_approval=a.get("require_approval", False),
                        timeout_seconds=a.get("timeout_seconds", 30),
                        retry_count=a.get("retry_count", 1),
                        rollback_action=ActionType(a["rollback_action"]) if a.get("rollback_action") else None,
                    )
                    for a in pb_data.get("actions", [])
                ],
                on_failure=pb_data.get("on_failure", "alert"),
                enabled=pb_data.get("enabled", True),
                priority=pb_data.get("priority", 100),
                tags=pb_data.get("tags", []),
            )
            self.register_playbook(playbook)
            count += 1
        return count
