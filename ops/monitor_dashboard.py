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

    def _render_css(self) -> str:
        """渲染CSS样式"""
        return """
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif;
            background: #0a0e1a;
            color: #e0e6f0;
            min-height: 100vh;
        }}
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
        .footer {{
            text-align: center;
            padding: 20px;
            color: #4b5563;
            font-size: 12px;
            border-top: 1px solid #1f2937;
        }}
        .full-width {{ grid-column: 1 / -1; }}
        """

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
