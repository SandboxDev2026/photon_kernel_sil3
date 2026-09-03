"""
TicketSystem — 工单与通报流转系统

提供工单流转接口，将沙盒捕获的底层异常自动转化为运维工单，
形成"发现-告警-处置-复盘"的完整闭环。

工单生命周期：
  CREATED → TRIAGED → IN_PROGRESS → RESOLVED → CLOSED
                ↓            ↓
            ESCALATED    REOPENED

核心功能：
1. 自动创建工单（从异常/告警/合规违规事件）
2. 工单流转（状态变更、指派、优先级调整）
3. SLA管理（响应时间、解决时间、超时升级）
4. 通报通知（邮件/短信/IM/Webhook）
5. 复盘记录（根因分析、改进措施、预防措施）
6. 统计报表（按状态/优先级/类别/处理人统计）
"""

import json
import time
import uuid
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
from enum import Enum

logger = logging.getLogger(__name__)


class TicketStatus(Enum):
    """工单状态"""
    CREATED = "created"  # 已创建
    TRIAGED = "triaged"  # 已分诊
    IN_PROGRESS = "in_progress"  # 处理中
    RESOLVED = "resolved"  # 已解决
    CLOSED = "closed"  # 已关闭
    ESCALATED = "escalated"  # 已升级
    REOPENED = "reopened"  # 已重开


class TicketPriority(Enum):
    """工单优先级"""
    P1_CRITICAL = "P1_critical"  # 紧急（15分钟响应）
    P2_HIGH = "P2_high"  # 高（1小时响应）
    P3_MEDIUM = "P3_medium"  # 中（4小时响应）
    P4_LOW = "P4_low"  # 低（24小时响应）


class TicketCategory(Enum):
    """工单类别"""
    SECURITY_THREAT = "security_threat"  # 安全威胁
    COMPLIANCE_VIOLATION = "compliance_violation"  # 合规违规
    ESCAPE_ATTEMPT = "escape_attempt"  # 逃逸尝试
    RESOURCE_EXHAUSTION = "resource_exhaustion"  # 资源耗尽
    SYSTEM_ERROR = "system_error"  # 系统错误
    PERFORMANCE_DEGRADATION = "performance_degradation"  # 性能下降
    AUDIT_FAILURE = "audit_failure"  # 审计失败
    NETWORK_ISSUE = "network_issue"  # 网络问题
    OTHER = "other"  # 其他


class SLAStatus(Enum):
    """SLA状态"""
    OK = "ok"  # 正常
    WARNING = "warning"  # 警告（接近超时）
    BREACHED = "breached"  # 已超时


@dataclass
class TicketComment:
    """工单评论"""
    id: str
    author: str
    content: str
    created_at: float = field(default_factory=time.time)
    attachments: List[str] = field(default_factory=list)
    internal: bool = False  # 内部评论（不对用户可见）


@dataclass
class TicketHistory:
    """工单历史记录"""
    timestamp: float
    action: str
    author: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PostMortem:
    """复盘记录"""
    root_cause: str = ""
    impact: str = ""
    timeline: List[str] = field(default_factory=list)
    corrective_actions: List[str] = field(default_factory=list)
    preventive_actions: List[str] = field(default_factory=list)
    lessons_learned: str = ""
    author: str = ""
    completed_at: float = 0.0


@dataclass
class Ticket:
    """工单"""
    id: str
    title: str
    description: str
    category: TicketCategory
    priority: TicketPriority
    status: TicketStatus = TicketStatus.CREATED
    assignee: str = ""
    reporter: str = "system"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    resolved_at: float = 0.0
    closed_at: float = 0.0
    sla_response_deadline: float = 0.0
    sla_resolve_deadline: float = 0.0
    comments: List[TicketComment] = field(default_factory=list)
    history: List[TicketHistory] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    related_tickets: List[str] = field(default_factory=list)
    source_event: Dict[str, Any] = field(default_factory=dict)
    post_mortem: Optional[PostMortem] = None
    escalation_count: int = 0
    custom_fields: Dict[str, Any] = field(default_factory=dict)


class TicketSystem:
    """
    工单与通报流转系统

    使用示例：
        ts = TicketSystem()

        # 从事件自动创建工单
        ticket = ts.create_from_event({
            "type": "escape_attempt",
            "container_id": "c123",
            "risk_level": "critical",
        })

        # 工单流转
        ts.assign(ticket.id, "admin")
        ts.start_progress(ticket.id)
        ts.resolve(ticket.id, "已隔离容器并冻结账号")
        ts.close(ticket.id)

        # 复盘
        ts.add_post_mortem(ticket.id, PostMortem(
            root_cause="沙盒配置错误导致逃逸面",
            corrective_actions=["修复seccomp配置", "增加逃逸检测"],
        ))
    """

    # SLA响应时间（秒）
    SLA_RESPONSE = {
        TicketPriority.P1_CRITICAL: 15 * 60,  # 15分钟
        TicketPriority.P2_HIGH: 60 * 60,  # 1小时
        TicketPriority.P3_MEDIUM: 4 * 60 * 60,  # 4小时
        TicketPriority.P4_LOW: 24 * 60 * 60,  # 24小时
    }

    # SLA解决时间（秒）
    SLA_RESOLVE = {
        TicketPriority.P1_CRITICAL: 1 * 60 * 60,  # 1小时
        TicketPriority.P2_HIGH: 4 * 60 * 60,  # 4小时
        TicketPriority.P3_MEDIUM: 24 * 60 * 60,  # 24小时
        TicketPriority.P4_LOW: 72 * 60 * 60,  # 72小时
    }

    # 事件类型到工单类别的映射
    EVENT_CATEGORY_MAP = {
        "escape_attempt": TicketCategory.ESCAPE_ATTEMPT,
        "security_threat": TicketCategory.SECURITY_THREAT,
        "compliance_violation": TicketCategory.COMPLIANCE_VIOLATION,
        "resource_exhaustion": TicketCategory.RESOURCE_EXHAUSTION,
        "system_error": TicketCategory.SYSTEM_ERROR,
        "performance_degradation": TicketCategory.PERFORMANCE_DEGRADATION,
        "audit_failure": TicketCategory.AUDIT_FAILURE,
        "network_issue": TicketCategory.NETWORK_ISSUE,
    }

    # 风险等级到优先级的映射
    RISK_PRIORITY_MAP = {
        "critical": TicketPriority.P1_CRITICAL,
        "high": TicketPriority.P2_HIGH,
        "medium": TicketPriority.P3_MEDIUM,
        "low": TicketPriority.P4_LOW,
    }

    def __init__(self, notification_callback: Optional[Callable] = None):
        self.tickets: Dict[str, Ticket] = {}
        self.notification_callback = notification_callback
        self._auto_increment = 0

    def create(self, title: str, description: str, category: TicketCategory,
               priority: TicketPriority, reporter: str = "system",
               source_event: Dict[str, Any] = None) -> Ticket:
        """创建工单"""
        self._auto_increment += 1
        ticket_id = f"PHOTON-{self._auto_increment:06d}"

        now = time.time()
        ticket = Ticket(
            id=ticket_id,
            title=title,
            description=description,
            category=category,
            priority=priority,
            reporter=reporter,
            created_at=now,
            updated_at=now,
            sla_response_deadline=now + self.SLA_RESPONSE[priority],
            sla_resolve_deadline=now + self.SLA_RESOLVE[priority],
            source_event=source_event or {},
        )

        self.tickets[ticket_id] = ticket
        self._add_history(ticket, "created", reporter, {"priority": priority.value})
        self._notify(ticket, "工单已创建")
        logger.info(f"工单创建: {ticket_id} - {title}")
        return ticket

    def create_from_event(self, event: Dict[str, Any]) -> Ticket:
        """从事件自动创建工单"""
        event_type = event.get("type", "other")
        risk_level = event.get("risk_level", "medium")
        category = self.EVENT_CATEGORY_MAP.get(event_type, TicketCategory.OTHER)
        priority = self.RISK_PRIORITY_MAP.get(risk_level, TicketPriority.P3_MEDIUM)

        title = f"[{category.value}] {event_type} - {event.get('container_id', 'unknown')}"
        description = self._generate_description(event)

        return self.create(
            title=title,
            description=description,
            category=category,
            priority=priority,
            reporter="system-auto",
            source_event=event,
        )

    def _generate_description(self, event: Dict[str, Any]) -> str:
        """从事件生成工单描述"""
        lines = [
            "自动创建工单（来自沙盒事件）",
            "",
            "事件详情：",
        ]
        for key, value in event.items():
            if key not in ["type", "risk_level"]:
                lines.append(f"  - {key}: {value}")
        lines.append("")
        lines.append(f"事件类型: {event.get('type', 'unknown')}")
        lines.append(f"风险等级: {event.get('risk_level', 'unknown')}")
        return "\n".join(lines)

    def assign(self, ticket_id: str, assignee: str, comment: str = "") -> Optional[Ticket]:
        """指派工单"""
        ticket = self.tickets.get(ticket_id)
        if not ticket:
            return None
        old_assignee = ticket.assignee
        ticket.assignee = assignee
        ticket.status = TicketStatus.TRIAGED
        ticket.updated_at = time.time()
        self._add_history(ticket, "assigned", assignee, {"from": old_assignee, "to": assignee})
        if comment:
            self.add_comment(ticket_id, assignee, comment)
        self._notify(ticket, f"工单已指派给 {assignee}")
        return ticket

    def start_progress(self, ticket_id: str, comment: str = "") -> Optional[Ticket]:
        """开始处理"""
        ticket = self.tickets.get(ticket_id)
        if not ticket:
            return None
        ticket.status = TicketStatus.IN_PROGRESS
        ticket.updated_at = time.time()
        self._add_history(ticket, "start_progress", ticket.assignee or "system", {})
        if comment:
            self.add_comment(ticket_id, ticket.assignee or "system", comment)
        return ticket

    def resolve(self, ticket_id: str, resolution: str, resolver: str = "") -> Optional[Ticket]:
        """解决工单"""
        ticket = self.tickets.get(ticket_id)
        if not ticket:
            return None
        ticket.status = TicketStatus.RESOLVED
        ticket.resolved_at = time.time()
        ticket.updated_at = time.time()
        self._add_history(ticket, "resolved", resolver or ticket.assignee, {"resolution": resolution})
        self.add_comment(ticket_id, resolver or ticket.assignee, f"解决方案: {resolution}")
        self._notify(ticket, "工单已解决")
        return ticket

    def close(self, ticket_id: str, closer: str = "") -> Optional[Ticket]:
        """关闭工单"""
        ticket = self.tickets.get(ticket_id)
        if not ticket:
            return None
        if ticket.status != TicketStatus.RESOLVED and ticket.status != TicketStatus.REOPENED:
            # 只能关闭已解决的工单
            return None
        ticket.status = TicketStatus.CLOSED
        ticket.closed_at = time.time()
        ticket.updated_at = time.time()
        self._add_history(ticket, "closed", closer or ticket.assignee, {})
        self._notify(ticket, "工单已关闭")
        return ticket

    def reopen(self, ticket_id: str, reason: str, reopener: str = "") -> Optional[Ticket]:
        """重开工单"""
        ticket = self.tickets.get(ticket_id)
        if not ticket:
            return None
        ticket.status = TicketStatus.REOPENED
        ticket.closed_at = 0.0
        ticket.updated_at = time.time()
        self._add_history(ticket, "reopened", reopener or "system", {"reason": reason})
        self.add_comment(ticket_id, reopener or "system", f"重开原因: {reason}")
        self._notify(ticket, "工单已重开")
        return ticket

    def escalate(self, ticket_id: str, reason: str, escalator: str = "") -> Optional[Ticket]:
        """升级工单"""
        ticket = self.tickets.get(ticket_id)
        if not ticket:
            return None
        ticket.status = TicketStatus.ESCALATED
        ticket.escalation_count += 1
        ticket.updated_at = time.time()
        self._add_history(ticket, "escalated", escalator or "system",
                          {"reason": reason, "count": ticket.escalation_count})
        self._notify(ticket, f"工单已升级（第{ticket.escalation_count}次）: {reason}")
        return ticket

    def add_comment(self, ticket_id: str, author: str, content: str,
                    internal: bool = False) -> Optional[TicketComment]:
        """添加评论"""
        ticket = self.tickets.get(ticket_id)
        if not ticket:
            return None
        comment = TicketComment(
            id=str(uuid.uuid4())[:8],
            author=author,
            content=content,
            internal=internal,
        )
        ticket.comments.append(comment)
        ticket.updated_at = time.time()
        return comment

    def add_post_mortem(self, ticket_id: str, post_mortem: PostMortem) -> Optional[Ticket]:
        """添加复盘记录"""
        ticket = self.tickets.get(ticket_id)
        if not ticket:
            return None
        post_mortem.completed_at = time.time()
        ticket.post_mortem = post_mortem
        ticket.updated_at = time.time()
        self._add_history(ticket, "post_mortem_added", post_mortem.author or "system",
                          {"root_cause": post_mortem.root_cause})
        return ticket

    def get_sla_status(self, ticket: Ticket) -> Dict[str, SLAStatus]:
        """获取SLA状态"""
        now = time.time()
        result = {}

        # 响应SLA
        if ticket.status in [TicketStatus.CREATED]:
            if now > ticket.sla_response_deadline:
                result["response"] = SLAStatus.BREACHED
            else:
                remaining = ticket.sla_response_deadline - now
                total = ticket.sla_response_deadline - ticket.created_at
                if total > 0 and remaining < total * 0.2:  # 剩余时间不足20%
                    result["response"] = SLAStatus.WARNING
                else:
                    result["response"] = SLAStatus.OK
        else:
            result["response"] = SLAStatus.OK

        # 解决SLA
        if ticket.status not in [TicketStatus.RESOLVED, TicketStatus.CLOSED]:
            if now > ticket.sla_resolve_deadline:
                result["resolve"] = SLAStatus.BREACHED
            else:
                remaining = ticket.sla_resolve_deadline - now
                total = ticket.sla_resolve_deadline - ticket.created_at
                if total > 0 and remaining < total * 0.2:  # 剩余时间不足20%
                    result["resolve"] = SLAStatus.WARNING
                else:
                    result["resolve"] = SLAStatus.OK
        else:
            result["resolve"] = SLAStatus.OK

        return result

    def get_ticket(self, ticket_id: str) -> Optional[Ticket]:
        """获取工单"""
        return self.tickets.get(ticket_id)

    def list_tickets(self, status: Optional[TicketStatus] = None,
                     priority: Optional[TicketPriority] = None,
                     category: Optional[TicketCategory] = None,
                     assignee: str = "",
                     limit: int = 50) -> List[Ticket]:
        """列出工单"""
        tickets = list(self.tickets.values())
        if status:
            tickets = [t for t in tickets if t.status == status]
        if priority:
            tickets = [t for t in tickets if t.priority == priority]
        if category:
            tickets = [t for t in tickets if t.category == category]
        if assignee:
            tickets = [t for t in tickets if t.assignee == assignee]
        tickets.sort(key=lambda t: t.created_at, reverse=True)
        return tickets[:limit]

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        tickets = list(self.tickets.values())
        stats = {
            "total": len(tickets),
            "by_status": {},
            "by_priority": {},
            "by_category": {},
            "by_assignee": {},
            "sla_breached": 0,
            "avg_resolution_time_ms": 0.0,
            "escalated_count": 0,
            "post_mortem_count": 0,
        }

        for status in TicketStatus:
            count = sum(1 for t in tickets if t.status == status)
            if count > 0:
                stats["by_status"][status.value] = count

        for priority in TicketPriority:
            count = sum(1 for t in tickets if t.priority == priority)
            if count > 0:
                stats["by_priority"][priority.value] = count

        for category in TicketCategory:
            count = sum(1 for t in tickets if t.category == category)
            if count > 0:
                stats["by_category"][category.value] = count

        assignees = set(t.assignee for t in tickets if t.assignee)
        for assignee in assignees:
            stats["by_assignee"][assignee] = sum(1 for t in tickets if t.assignee == assignee)

        # SLA超时
        for t in tickets:
            sla = self.get_sla_status(t)
            if SLAStatus.BREACHED in sla.values():
                stats["sla_breached"] += 1
            if t.escalation_count > 0:
                stats["escalated_count"] += 1
            if t.post_mortem:
                stats["post_mortem_count"] += 1

        # 平均解决时间
        resolved = [t for t in tickets if t.resolved_at > 0]
        if resolved:
            avg_time = sum(t.resolved_at - t.created_at for t in resolved) / len(resolved)
            stats["avg_resolution_time_ms"] = avg_time * 1000

        return stats

    def _add_history(self, ticket: Ticket, action: str, author: str, details: Dict) -> None:
        """添加历史记录"""
        ticket.history.append(TicketHistory(
            timestamp=time.time(),
            action=action,
            author=author,
            details=details,
        ))

    def _notify(self, ticket: Ticket, message: str) -> None:
        """发送通知"""
        if self.notification_callback:
            try:
                self.notification_callback(ticket, message)
            except Exception:
                pass

    def export_ticket(self, ticket_id: str, filepath: str) -> bool:
        """导出工单为JSON"""
        ticket = self.tickets.get(ticket_id)
        if not ticket:
            return False
        data = {
            "id": ticket.id,
            "title": ticket.title,
            "description": ticket.description,
            "category": ticket.category.value,
            "priority": ticket.priority.value,
            "status": ticket.status.value,
            "assignee": ticket.assignee,
            "reporter": ticket.reporter,
            "created_at": ticket.created_at,
            "updated_at": ticket.updated_at,
            "resolved_at": ticket.resolved_at,
            "closed_at": ticket.closed_at,
            "comments": [{"author": c.author, "content": c.content, "created_at": c.created_at}
                        for c in ticket.comments],
            "history": [{"action": h.action, "author": h.author, "timestamp": h.timestamp}
                       for h in ticket.history],
            "source_event": ticket.source_event,
            "escalation_count": ticket.escalation_count,
        }
        if ticket.post_mortem:
            data["post_mortem"] = {
                "root_cause": ticket.post_mortem.root_cause,
                "corrective_actions": ticket.post_mortem.corrective_actions,
                "preventive_actions": ticket.post_mortem.preventive_actions,
                "lessons_learned": ticket.post_mortem.lessons_learned,
            }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
