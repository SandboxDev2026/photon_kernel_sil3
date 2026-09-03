"""
MonitorDashboard — 可视化监控大屏生成器

参考业界安全感知平台，开发专属的监控大屏。
设定严格的告警阈值（P99延迟>500ms或错误率>1%时触发告警），
让运维人员能直观掌握沙盒集群的健康状态。

功能：
1. 生成HTML可视化大屏（纯前端，无外部依赖）
2. 实时指标展示（QPS/延迟/Token速度/显存/GPU）
3. 告警面板（当前告警列表+历史告警）
4. 集群拓扑（节点/沙盒实例/网络流量）
5. 趋势图表（最近1小时/24小时）
6. 深色主题（运维大屏标准）
"""

import json
import time
from typing import Dict, Any, List, Optional


class MonitorDashboard:
    """
    可视化监控大屏生成器

    使用示例：
        dashboard = MonitorDashboard()
        dashboard.add_metric("qps", 125.5)
        dashboard.add_alert({"level": "critical", "message": "P99延迟超标"})
        html = dashboard.render()
        with open("dashboard.html", "w") as f:
            f.write(html)
    """

    # 默认告警阈值
    DEFAULT_THRESHOLDS = {
        "p99_latency_ms": 500,
        "error_rate": 1.0,
        "vram_fragmentation_rate": 15,
        "gpu_utilization_high": 85,
        "gpu_utilization_low": 70,
        "queue_depth": 100,
    }

    def __init__(self, title: str = "PhotonBox 监控大屏",
                 thresholds: Dict[str, float] = None):
        self.title = title
        self.thresholds = thresholds or self.DEFAULT_THRESHOLDS
        self._metrics: Dict[str, Any] = {}
        self._alerts: List[Dict[str, Any]] = []
        self._nodes: List[Dict[str, Any]] = []
        self._sandboxes: List[Dict[str, Any]] = []
        self._history: Dict[str, List[float]] = {}

    def add_metric(self, name: str, value: Any, unit: str = "") -> None:
        """添加指标"""
        self._metrics[name] = {"value": value, "unit": unit}

    def add_metrics_batch(self, metrics: Dict[str, Any]) -> None:
        """批量添加指标"""
        for name, value in metrics.items():
            if isinstance(value, dict):
                self._metrics[name] = value
            else:
                self._metrics[name] = {"value": value, "unit": ""}

    def add_alert(self, alert: Dict[str, Any]) -> None:
        """添加告警"""
        alert["timestamp"] = time.time()
        alert["time_str"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self._alerts.insert(0, alert)
        # 只保留最近100条
        if len(self._alerts) > 100:
            self._alerts = self._alerts[:100]

    def add_node(self, node: Dict[str, Any]) -> None:
        """添加集群节点"""
        self._nodes.append(node)

    def add_sandbox(self, sandbox: Dict[str, Any]) -> None:
        """添加沙盒实例"""
        self._sandboxes.append(sandbox)

    def add_history(self, metric: str, value: float) -> None:
        """添加历史数据点"""
        if metric not in self._history:
            self._history[metric] = []
        self._history[metric].append(value)
        # 只保留最近60个点
        if len(self._history[metric]) > 60:
            self._history[metric] = self._history[metric][-60:]

    def get_alert_summary(self) -> Dict[str, int]:
        """获取告警统计"""
        summary = {"critical": 0, "warning": 0, "info": 0}
        for alert in self._alerts:
            level = alert.get("level", "info")
            if level in summary:
                summary[level] += 1
        return summary

    def get_health_status(self) -> str:
        """获取整体健康状态"""
        summary = self.get_alert_summary()
        if summary["critical"] > 0:
            return "critical"
        elif summary["warning"] > 0:
            return "warning"
        return "healthy"

    def _render_base_css(self) -> str:
        """渲染基础CSS样式（reset + body）"""
        return """
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif;
            background: #0a0e1a;
            color: #e0e6f0;
            min-height: 100vh;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #4b5563;
            font-size: 12px;
            border-top: 1px solid #1f2937;
        }}
        .full-width {{ grid-column: 1 / -1; }}
        """

    def _render_header_css(self) -> str:
        """渲染头部CSS样式（header + health-status + alert-summary）"""
        return """
        .header {{
            background: linear-gradient(135deg, #0d1526 0%, #1a2744 100%);
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #2a3f5f;
        }}
        .header h1 {{
            font-size: 28px;
            background: linear-gradient(90deg, #00d4ff, #00ff88);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .health-status {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .health-dot {{
            width: 16px;
            height: 16px;
            border-radius: 50%;
            background: {health_color};
            box-shadow: 0 0 20px {health_color};
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
        }}
        .health-text {{ font-size: 18px; color: {health_color}; }}
        .alert-summary {{
            display: flex;
            gap: 20px;
            font-size: 14px;
        }}
        .alert-summary span {{ padding: 4px 12px; border-radius: 4px; }}
        .alert-critical {{ background: rgba(255,68,68,0.2); color: #ff4444; }}
        .alert-warning {{ background: rgba(255,170,0,0.2); color: #ffaa00; }}
        .alert-info {{ background: rgba(68,170,255,0.2); color: #44aaff; }}
        """

    def _render_metrics_css(self) -> str:
        """渲染指标面板CSS样式（main + panel + metric-grid + metric-card）"""
        return """
        .main {{
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 20px;
            padding: 20px 40px;
        }}
        .panel {{
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 8px;
            padding: 20px;
        }}
        .panel-title {{
            font-size: 16px;
            color: #00d4ff;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #1f2937;
        }}
        .metric-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
        }}
        .metric-card {{
            background: #0d1526;
            border: 1px solid #1f2937;
            border-radius: 6px;
            padding: 12px;
            text-align: center;
        }}
        .metric-name {{ font-size: 12px; color: #6b7280; margin-bottom: 8px; }}
        .metric-value {{ font-size: 24px; font-weight: bold; color: #00ff88; }}
        .metric-unit {{ font-size: 12px; color: #6b7280; }}
        """

    def _render_alerts_css(self) -> str:
        """渲染告警和节点CSS样式（alert-list + alert-item + node-list + threshold-info）"""
        return """
        .alert-list {{ max-height: 400px; overflow-y: auto; }}
        .alert-item {{
            padding: 10px;
            margin-bottom: 8px;
            background: #0d1526;
            border-radius: 4px;
            border-left: 3px solid #333;
            font-size: 13px;
        }}
        .alert-critical {{ border-left-color: #ff4444; }}
        .alert-warning {{ border-left-color: #ffaa00; }}
        .alert-info {{ border-left-color: #44aaff; }}
        .alert-level {{ font-weight: bold; margin-right: 8px; }}
        .alert-time {{ color: #6b7280; margin-right: 8px; font-size: 11px; }}
        .no-alerts {{ color: #00ff88; text-align: center; padding: 40px; }}
        .node-list {{ max-height: 400px; overflow-y: auto; }}
        .node-item {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px;
            margin-bottom: 8px;
            background: #0d1526;
            border-radius: 4px;
            font-size: 13px;
        }}
        .node-status {{ width: 10px; height: 10px; border-radius: 50%; }}
        .node-name {{ font-weight: bold; color: #e0e6f0; }}
        .node-ip {{ color: #6b7280; }}
        .node-pods {{ margin-left: auto; color: #00d4ff; }}
        .threshold-info {{
            margin-top: 20px;
            padding: 15px;
            background: #0d1526;
            border-radius: 6px;
            font-size: 12px;
            color: #6b7280;
        }}
        .threshold-info h4 {{ color: #ffaa00; margin-bottom: 8px; }}
        .threshold-info ul {{ list-style: none; }}
        .threshold-info li {{ padding: 4px 0; }}
        """

    def _render_business_impact_base_css(self) -> str:
        """渲染业务影响面面板基础CSS"""
        return """
        .business-impact-panel {
            background: linear-gradient(135deg, #0d1526 0%, #131d33 100%);
            border: 1px solid #1e2d4a;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .business-impact-panel h3 {
            color: #00d4ff;
            margin-bottom: 15px;
            font-size: 16px;
        }
        .impact-compliance-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            margin-left: 10px;
        }
        .impact-compliance-badge.compliant {
            background: rgba(0, 255, 136, 0.15);
            color: #00ff88;
            border: 1px solid #00ff88;
        }
        .impact-compliance-badge.violation {
            background: rgba(255, 68, 68, 0.15);
            color: #ff4444;
            border: 1px solid #ff4444;
        }
        """

    def _render_business_impact_metrics_css(self) -> str:
        """渲染业务影响面指标卡片CSS"""
        return """
        .impact-metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }
        .impact-metric-card {
            background: #0a1220;
            border-radius: 6px;
            padding: 15px;
            text-align: center;
        }
        .impact-metric-label {
            font-size: 12px;
            color: #6b7280;
            margin-bottom: 8px;
        }
        .impact-metric-value {
            font-size: 28px;
            font-weight: bold;
            color: #00ff88;
        }
        .impact-metric-value.warning { color: #ffaa00; }
        .impact-metric-value.critical { color: #ff4444; }
        .impact-metric-unit {
            font-size: 14px;
            color: #6b7280;
        }
        """

    def _render_business_impact_progress_css(self) -> str:
        """渲染业务影响面进度条CSS"""
        return """
        .impact-progress-bar {
            height: 8px;
            background: #1a2540;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 10px;
        }
        .impact-progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #00ff88, #00d4ff);
            border-radius: 4px;
        }
        .impact-progress-fill.warning { background: linear-gradient(90deg, #ffaa00, #ff8800); }
        .impact-progress-fill.critical { background: linear-gradient(90deg, #ff4444, #ff0000); }
        """

    def _render_business_impact_details_css(self) -> str:
        """渲染业务影响面详情网格CSS"""
        return """
        .impact-details-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            margin-top: 15px;
        }
        .impact-detail-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 12px;
            background: #0a1220;
            border-radius: 4px;
            font-size: 12px;
        }
        .impact-detail-label { color: #6b7280; }
        .impact-detail-value { color: #e0e6f0; font-weight: 500; }
        """

    def _render_business_impact_css(self) -> str:
        """渲染业务影响面面板CSS（优化版：拆分为4个子函数组合）"""
        return (
            self._render_business_impact_base_css() +
            self._render_business_impact_metrics_css() +
            self._render_business_impact_progress_css() +
            self._render_business_impact_details_css()
        )


    def _render_css(self) -> str:
        """渲染CSS样式（优化版：拆分为4个子函数组合）"""
        return (
            self._render_base_css() +
            self._render_header_css() +
            self._render_metrics_css() +
            self._render_alerts_css() +
            self._render_business_impact_css()
        )

    def _render_header(self, health_color: str, health_text: str, alert_summary: Dict[str, int]) -> str:
        """渲染头部"""
        return f'''
    <div class="header">
        <h1>{self.title}</h1>
        <div class="health-status">
            <div class="health-dot"></div>
            <span class="health-text">{health_text}</span>
        </div>
        <div class="alert-summary">
            <span class="alert-critical">严重: {alert_summary["critical"]}</span>
            <span class="alert-warning">警告: {alert_summary["warning"]}</span>
            <span class="alert-info">信息: {alert_summary["info"]}</span>
        </div>
        '''

    def _render_metric_cards(self) -> str:
        """渲染指标卡片"""
        cards = ""
        for name, data in self._metrics.items():
            value = data.get("value", 0) if isinstance(data, dict) else data
            unit = data.get("unit", "") if isinstance(data, dict) else ""
            display_value = f"{value:.2f}" if isinstance(value, float) else str(value)
            cards += f'<div class="metric-card"><div class="metric-name">{name}</div><div class="metric-value">{display_value} <span class="metric-unit">{unit}</span></div></div>'
        return f'<div class="panel full-width"><div class="panel-title">核心指标</div><div class="metric-grid">{cards}</div></div>'

    def _render_alert_list(self) -> str:
        """渲染告警列表"""
        items = ""
        for alert in self._alerts[:20]:
            level = alert.get("level", "info")
            level_color = {"critical": "#ff4444", "warning": "#ffaa00", "info": "#44aaff"}.get(level, "#888")
            items += f'<div class="alert-item alert-{level}"><span class="alert-level" style="color:{level_color}">[{level.upper()}]</span><span class="alert-time">{alert.get("time_str", "")}</span><span class="alert-msg">{alert.get("message", "")}</span></div>'
        if not items:
            items = '<div class="no-alerts">暂无告警，系统运行正常</div>'
        return f'<div class="panel"><div class="panel-title">实时告警</div><div class="alert-list">{items}</div></div>'

    def _render_node_list(self) -> str:
        """渲染节点列表"""
        items = ""
        for node in self._nodes:
            status = node.get("status", "unknown")
            status_color = {"ready": "#00ff88", "notready": "#ff4444", "unknown": "#888"}.get(status, "#888")
            items += f'<div class="node-item"><span class="node-status" style="background:{status_color}"></span><span class="node-name">{node.get("name", "unknown")}</span><span class="node-ip">{node.get("ip", "")}</span><span class="node-pods">Pods: {node.get("pods", 0)}</span></div>'
        return f'<div class="panel"><div class="panel-title">集群节点</div><div class="node-list">{items}</div></div>'

    def _render_business_impact_header(self, impact_data: Dict[str, Any]) -> str:
        """渲染业务影响面面板标题区"""
        compliant = impact_data.get("compliant", True)
        badge_class = "compliant" if compliant else "violation"
        badge_text = "合规" if compliant else "违规"
        return f"""
        <h3>业务影响面监控（第十三条）
            <span class="impact-compliance-badge {badge_class}">{badge_text}</span>
        </h3>
"""

    def _render_business_impact_metric_cards(self, impact_data: Dict[str, Any]) -> str:
        """渲染业务影响面指标卡片（4个核心指标）"""
        current = impact_data.get("current_impact_percent", 0.0)
        threshold = impact_data.get("threshold_percent", 5.0)

        if current > threshold * 2:
            status_class = "critical"
        elif current > threshold:
            status_class = "warning"
        else:
            status_class = ""

        max_display = threshold * 2
        progress_width = min((current / max_display) * 100, 100)
        active_unrecovered = impact_data.get("active_unrecovered_events", 0)
        active_class = "critical" if active_unrecovered > 0 else ""

        return f"""
        <div class="impact-metrics-grid">
            <div class="impact-metric-card">
                <div class="impact-metric-label">当前业务影响面</div>
                <div class="impact-metric-value {status_class}">{current:.2f}<span class="impact-metric-unit">%</span></div>
                <div class="impact-progress-bar">
                    <div class="impact-progress-fill {status_class}" style="width: {progress_width:.1f}%"></div>
                </div>
            </div>
            <div class="impact-metric-card">
                <div class="impact-metric-label">LightPool 影响面</div>
                <div class="impact-metric-value">{impact_data.get("light_pool_impact_percent", 0):.2f}<span class="impact-metric-unit">%</span></div>
            </div>
            <div class="impact-metric-card">
                <div class="impact-metric-label">StrongPool 影响面</div>
                <div class="impact-metric-value">{impact_data.get("strong_pool_impact_percent", 0):.2f}<span class="impact-metric-unit">%</span></div>
            </div>
            <div class="impact-metric-card">
                <div class="impact-metric-label">未恢复事件</div>
                <div class="impact-metric-value {active_class}">{active_unrecovered}</div>
            </div>
        </div>
"""

    def _render_business_impact_details(self, impact_data: Dict[str, Any]) -> str:
        """渲染业务影响面详情网格（4项详情）"""
        alerts = impact_data.get("alerts", 0)
        alerts_class = "critical" if alerts > 0 else ""
        return f"""
        <div class="impact-details-grid">
            <div class="impact-detail-item">
                <span class="impact-detail-label">窗口内事件总数</span>
                <span class="impact-detail-value">{impact_data.get("total_events_window", 0)}</span>
            </div>
            <div class="impact-detail-item">
                <span class="impact-detail-label">受影响请求总数</span>
                <span class="impact-detail-value">{impact_data.get("total_affected_requests", 0)}</span>
            </div>
            <div class="impact-detail-item">
                <span class="impact-detail-label">平均恢复时间</span>
                <span class="impact-detail-value">{impact_data.get("avg_recovery_time_ms", 0):.0f} ms</span>
            </div>
            <div class="impact-detail-item">
                <span class="impact-detail-label">告警数</span>
                <span class="impact-detail-value {alerts_class}">{alerts}</span>
            </div>
        </div>
"""

    def _render_business_impact_panel(self) -> str:
        """渲染业务影响面面板（第十三条，优化版：拆分为3个子函数）"""
        impact_data = getattr(self, '_business_impact_data', None)
        if not impact_data:
            impact_data = {
                "current_impact_percent": 0.0,
                "threshold_percent": 5.0,
                "light_pool_impact_percent": 0.0,
                "strong_pool_impact_percent": 0.0,
                "total_events_window": 0,
                "active_unrecovered_events": 0,
                "total_affected_requests": 0,
                "avg_recovery_time_ms": 0,
                "alerts": 0,
                "compliant": True,
            }

        return f"""
    <div class="business-impact-panel">
        {self._render_business_impact_header(impact_data)}
        {self._render_business_impact_metric_cards(impact_data)}
        {self._render_business_impact_details(impact_data)}
    </div>
"""

    def set_business_impact_data(self, data: Dict[str, Any]) -> None:
        """设置业务影响面数据（由BusinessImpactTracker.get_impact_summary()提供）"""
        self._business_impact_data = data

    def _render_threshold_info(self) -> str:
        """渲染阈值信息"""
        return f'''
        <div class="panel">
            <div class="panel-title">告警阈值配置</div>
            <div class="threshold-info">
                <h4>严格告警阈值</h4>
                <ul>
                    <li>• P99延迟 > {self.thresholds.get("p99_latency_ms", 500)}ms → 严重告警</li>
                    <li>• 错误率 > {self.thresholds.get("error_rate", 1.0)}% → 严重告警</li>
                    <li>• 显存碎片率 > {self.thresholds.get("vram_fragmentation_rate", 15)}% → 警告</li>
                    <li>• GPU利用率 > {self.thresholds.get("gpu_utilization_high", 85)}% → 扩容建议</li>
                    <li>• GPU利用率 < {self.thresholds.get("gpu_utilization_low", 70)}% → 缩容建议</li>
                    <li>• 队列深度 > {self.thresholds.get("queue_depth", 100)} → 警告</li>
                </ul>
            </div>
        </div>
        '''

    def render(self) -> str:
        """渲染HTML大屏（优化版：拆分成多个子函数）"""
        health = self.get_health_status()
        alert_summary = self.get_alert_summary()
        health_color = {"healthy": "#00ff88", "warning": "#ffaa00", "critical": "#ff4444"}.get(health, "#888")
        health_text = {"healthy": "健康", "warning": "警告", "critical": "严重"}.get(health, "未知")
        css = self._render_css()
        header = self._render_header(health_color, health_text, alert_summary)
        metric_cards = self._render_metric_cards()
        business_impact = self._render_business_impact_panel()
        alert_list = self._render_alert_list()
        node_list = self._render_node_list()
        threshold_info = self._render_threshold_info()
        return f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.title}</title>
    <style>{css}</style>
</head>
<body>
    {header}
    <div class="main">
        {metric_cards}
        {business_impact}
        {alert_list}
        {node_list}
        {threshold_info}
    </div>
    <div class="footer">
        PhotonBox 监控大屏 | 生成时间: {time.strftime("%Y-%m-%d %H:%M:%S")} | 数据每5秒自动刷新
    </div>
    <script>
        setTimeout(function() {{ location.reload(); }}, 5000);
    </script>
</body>
</html>'''

    def render_json(self) -> Dict[str, Any]:
        """渲染JSON格式数据（用于API）"""
        return {
            "title": self.title,
            "timestamp": time.time(),
            "health_status": self.get_health_status(),
            "alert_summary": self.get_alert_summary(),
            "metrics": self._metrics,
            "alerts": self._alerts[:20],
            "nodes": self._nodes,
            "sandboxes": self._sandboxes,
            "thresholds": self.thresholds,
        }
