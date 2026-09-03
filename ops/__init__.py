"""
PhotonBox 运维与产品化模块 (ops)

包含6大产品化增强模块：
1. PlaybookEngine - 自动化剧本编排（合规违规/安全威胁自动处置）
2. TicketSystem - 工单与通报流转（发现-告警-处置-复盘闭环）
3. InferenceMetrics - 推理指标监控（QPS/TTFT/Token速度/显存碎片率）
4. MonitorDashboard - 可视化监控大屏（深色主题+严格告警阈值）
5. HPA配置 - 弹性伸缩（QPS+GPU利用率驱动，70-85%目标）
6. 高可用架构 - 双实例+负载均衡+蓝绿部署+热切换
"""

from .playbook_engine import (
    PlaybookEngine, Playbook, PlaybookExecution, Action, Trigger,
    TriggerType, ActionType, RiskLevel, PlaybookStatus, ActionResult,
)
from .ticket_system import (
    TicketSystem, Ticket, TicketStatus, TicketPriority, TicketCategory,
    TicketComment, TicketHistory, PostMortem, SLAStatus,
)
from .inference_metrics import InferenceMetrics, MetricSnapshot, RequestRecord, MetricType
from .monitor_dashboard import MonitorDashboard

__all__ = [
    # PlaybookEngine
    "PlaybookEngine", "Playbook", "PlaybookExecution", "Action", "Trigger",
    "TriggerType", "ActionType", "RiskLevel", "PlaybookStatus", "ActionResult",
    # TicketSystem
    "TicketSystem", "Ticket", "TicketStatus", "TicketPriority", "TicketCategory",
    "TicketComment", "TicketHistory", "PostMortem", "SLAStatus",
    # InferenceMetrics
    "InferenceMetrics", "MetricSnapshot", "RequestRecord", "MetricType",
    # MonitorDashboard
    "MonitorDashboard",
]
