"""
evolution.alert_integration — 告警平台接入模块

将规则熔断事件推送到监控告警平台,支持:
1. Prometheus metrics导出
2. Webhook告警推送(通用webhook,可对接Alertmanager/钉钉/企业微信/Slack)
3. 告警分级路由(CRITICAL→紧急通知,HIGH→邮件/IM,WARNING→日志)
4. 告警去重和聚合(相同规则的熔断告警聚合,避免告警风暴)
5. 告警静默和维护窗口

与CircuitBreakerAlertManager集成,熔断事件自动推送。
"""
from __future__ import annotations
import os
import json
import time
import threading
import urllib.request
import urllib.error
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from enum import Enum

from evolution.pipeline_enhancements import Alert, AlertSeverity, AlertStatus


class AlertChannel(Enum):
    """告警通道"""
    PROMETHEUS = "prometheus"    # Prometheus metrics
    WEBHOOK = "webhook"          # 通用Webhook
    EMAIL = "email"              # 邮件(需配置SMTP)
    LOG = "log"                  # 日志文件


@dataclass
class WebhookConfig:
    """Webhook配置"""
    url: str
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 5
    max_retries: int = 3
    retry_delay_seconds: float = 1.0
    # 钉钉/企业微信/Slack专用格式
    format: str = "generic"  # generic/dingtalk/wecom/slack/alertmanager


@dataclass
class AlertRoutingRule:
    """告警路由规则"""
    severity: AlertSeverity
    channels: List[AlertChannel]
    # 静默配置
    silent_hours: Optional[List[int]] = None  # 静默小时列表(0-23)
    # 聚合配置
    aggregate_seconds: int = 60  # 相同规则告警聚合窗口
    max_alerts_per_window: int = 5  # 聚合窗口内最大告警数


class PrometheusMetricsExporter:
    """
    Prometheus metrics导出器

    导出以下metrics:
    - photonbox_circuit_breaker_triggers_total: 熔断触发总数(按规则ID)
    - photonbox_circuit_breaker_active: 当前活跃熔断数(按规则ID)
    - photonbox_alerts_total: 告警总数(按严重等级/类型)
    - photonbox_alerts_pending: 待确认告警数
    - photonbox_rule_recoveries_total: 规则恢复总数
    - photonbox_duplicate_cache_size: 去重缓存大小
    - photonbox_duplicate_cache_usage_ratio: 去重缓存使用率

    使用方式:
        exporter = PrometheusMetricsExporter()
        exporter.record_circuit_break('rule-1')
        exporter.record_alert('circuit_breaker', 'high')
        metrics = exporter.render()  # 返回Prometheus格式文本
    """

    def __init__(self):
        self._metrics: Dict[str, Any] = {
            'circuit_breaker_triggers': {},  # rule_id -> count
            'circuit_breaker_active': {},    # rule_id -> 0/1
            'alerts_total': {},              # (severity, type) -> count
            'alerts_pending': 0,
            'rule_recoveries_total': {},     # rule_id -> count
            'duplicate_cache_size': 0,
            'duplicate_cache_usage_ratio': 0.0,
        }
        self._lock = threading.Lock()

    def record_circuit_break(self, rule_id: str) -> None:
        """记录熔断触发"""
        with self._lock:
            self._metrics['circuit_breaker_triggers'][rule_id] = (
                self._metrics['circuit_breaker_triggers'].get(rule_id, 0) + 1
            )
            self._metrics['circuit_breaker_active'][rule_id] = 1

    def record_rule_recovery(self, rule_id: str) -> None:
        """记录规则恢复"""
        with self._lock:
            self._metrics['rule_recoveries_total'][rule_id] = (
                self._metrics['rule_recoveries_total'].get(rule_id, 0) + 1
            )
            self._metrics['circuit_breaker_active'][rule_id] = 0

    def record_alert(self, alert_type: str, severity: str) -> None:
        """记录告警"""
        with self._lock:
            key = f"{severity}_{alert_type}"
            self._metrics['alerts_total'][key] = (
                self._metrics['alerts_total'].get(key, 0) + 1
            )

    def set_pending_alerts(self, count: int) -> None:
        """设置待确认告警数"""
        with self._lock:
            self._metrics['alerts_pending'] = count

    def set_duplicate_cache(self, size: int, max_size: int) -> None:
        """设置去重缓存状态"""
        with self._lock:
            self._metrics['duplicate_cache_size'] = size
            self._metrics['duplicate_cache_usage_ratio'] = (
                size / max_size if max_size > 0 else 0.0
            )

    def render(self) -> str:
        """渲染为Prometheus格式文本"""
        with self._lock:
            lines = []
            lines.append("# HELP photonbox_circuit_breaker_triggers_total Total circuit breaker triggers")
            lines.append("# TYPE photonbox_circuit_breaker_triggers_total counter")
            for rule_id, count in self._metrics['circuit_breaker_triggers'].items():
                lines.append(f'photonbox_circuit_breaker_triggers_total{{rule_id="{rule_id}"}} {count}')

            lines.append("# HELP photonbox_circuit_breaker_active Active circuit breakers")
            lines.append("# TYPE photonbox_circuit_breaker_active gauge")
            for rule_id, active in self._metrics['circuit_breaker_active'].items():
                lines.append(f'photonbox_circuit_breaker_active{{rule_id="{rule_id}"}} {active}')

            lines.append("# HELP photonbox_alerts_total Total alerts")
            lines.append("# TYPE photonbox_alerts_total counter")
            for key, count in self._metrics['alerts_total'].items():
                parts = key.split('_', 1)
                severity = parts[0] if parts else 'unknown'
                alert_type = parts[1] if len(parts) > 1 else 'unknown'
                lines.append(f'photonbox_alerts_total{{severity="{severity}",type="{alert_type}"}} {count}')

            lines.append("# HELP photonbox_alerts_pending Pending alerts")
            lines.append("# TYPE photonbox_alerts_pending gauge")
            lines.append(f"photonbox_alerts_pending {self._metrics['alerts_pending']}")

            lines.append("# HELP photonbox_rule_recoveries_total Total rule recoveries")
            lines.append("# TYPE photonbox_rule_recoveries_total counter")
            for rule_id, count in self._metrics['rule_recoveries_total'].items():
                lines.append(f'photonbox_rule_recoveries_total{{rule_id="{rule_id}"}} {count}')

            lines.append("# HELP photonbox_duplicate_cache_size Duplicate cache size")
            lines.append("# TYPE photonbox_duplicate_cache_size gauge")
            lines.append(f"photonbox_duplicate_cache_size {self._metrics['duplicate_cache_size']}")

            lines.append("# HELP photonbox_duplicate_cache_usage_ratio Duplicate cache usage ratio")
            lines.append("# TYPE photonbox_duplicate_cache_usage_ratio gauge")
            lines.append(f"photonbox_duplicate_cache_usage_ratio {self._metrics['duplicate_cache_usage_ratio']:.4f}")

            return '\n'.join(lines) + '\n'


class WebhookAlertSender:
    """
    Webhook告警推送器

    支持通用webhook格式,可对接:
    - Alertmanager (Prometheus告警管理器)
    - 钉钉机器人
    - 企业微信机器人
    - Slack Incoming Webhook
    - 自定义HTTP端点

    使用方式:
        config = WebhookConfig(url='https://hooks.slack.com/xxx', format='slack')
        sender = WebhookAlertSender(config)
        sender.send(alert)
    """

    def __init__(self, config: WebhookConfig):
        self.config = config
        self._send_history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def send(self, alert: Alert) -> bool:
        """
        发送告警到webhook

        Returns:
            是否发送成功
        """
        payload = self._build_payload(alert)
        return self._send_with_retry(payload)

    def _build_payload(self, alert: Alert) -> Dict[str, Any]:
        """根据格式构建payload(分发到各格式子函数)"""
        fmt = self.config.format.lower()
        builders = {
            'dingtalk': self._build_dingtalk_payload,
            'wecom': self._build_wecom_payload,
            'slack': self._build_slack_payload,
            'alertmanager': self._build_alertmanager_payload,
        }
        builder = builders.get(fmt, self._build_generic_payload)
        return builder(alert)

    def _build_dingtalk_payload(self, alert):
        """构建钉钉格式payload"""
        return {
            "msgtype": "markdown",
            "markdown": {
                "title": f"[PhotonBox] {alert.title}",
                "text": f"### {alert.title}\n\n"
                        f"**严重等级**: {alert.severity.value}\n\n"
                        f"**规则ID**: {alert.rule_id or 'N/A'}\n\n"
                        f"**描述**: {alert.description}\n\n"
                        f"**时间**: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert.created_at))}",
            },
        }

    def _build_wecom_payload(self, alert):
        """构建企业微信格式payload"""
        return {
            "msgtype": "markdown",
            "markdown": {
                "content": f"## [PhotonBox] {alert.title}\n"
                           f"> 严重等级: <font color=\"warning\">{alert.severity.value}</font>\n"
                           f"> 规则ID: {alert.rule_id or 'N/A'}\n"
                           f"> 描述: {alert.description}",
            },
        }

    def _build_slack_payload(self, alert):
        """构建Slack格式payload"""
        color = {
            'critical': '#FF0000', 'high': '#FFA500',
            'warning': '#FFFF00', 'info': '#00FF00',
        }.get(alert.severity.value, '#CCCCCC')
        return {
            "attachments": [{
                "color": color,
                "title": f"[PhotonBox] {alert.title}",
                "text": alert.description,
                "fields": [
                    {"title": "Severity", "value": alert.severity.value, "short": True},
                    {"title": "Rule ID", "value": alert.rule_id or 'N/A', "short": True},
                ],
                "ts": alert.created_at,
            }],
        }

    def _build_alertmanager_payload(self, alert):
        """构建Alertmanager格式payload"""
        return {
            "status": "firing",
            "labels": {
                "alertname": alert.alert_type,
                "severity": alert.severity.value,
                "rule_id": alert.rule_id or '',
                "source": alert.source,
            },
            "annotations": {
                "title": alert.title,
                "description": alert.description,
            },
            "startsAt": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(alert.created_at)),
        }

    def _build_generic_payload(self, alert):
        """构建通用格式payload"""
        return alert.to_dict()

    def _send_with_retry(self, payload: Dict[str, Any]) -> bool:
        """带重试的发送"""
        # URL scheme白名单校验,防止SSRF(只允许http/https)
        from urllib.parse import urlparse
        parsed = urlparse(self.config.url)
        if parsed.scheme not in ('http', 'https'):
            self._record_send(payload, success=False, attempt=0)
            return False
        # 禁止访问内网地址(SSRF防护)
        import ipaddress
        hostname = parsed.hostname or ''
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                # 开发环境允许localhost,生产环境应配置外部webhook地址
                if hostname not in ('127.0.0.1', 'localhost'):
                    self._record_send(payload, success=False, attempt=0)
                    return False
        except ValueError:
            pass  # 域名,跳过IP检查

        data = json.dumps(payload).encode('utf-8')
        headers = {'Content-Type': 'application/json', **self.config.headers}

        for attempt in range(self.config.max_retries):
            try:
                req = urllib.request.Request(
                    self.config.url, data=data, headers=headers, method=self.config.method
                )
                with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:  # nosec B310 - URL scheme已在_send_with_retry开头校验,只允许http/https,且已做SSRF内网地址防护
                    if 200 <= resp.status < 300:
                        self._record_send(payload, success=True, attempt=attempt)
                        return True
            except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
                pass

            if attempt < self.config.max_retries - 1:
                time.sleep(self.config.retry_delay_seconds * (attempt + 1))

        self._record_send(payload, success=False, attempt=self.config.max_retries)
        return False

    def _record_send(self, payload: Dict[str, Any], success: bool, attempt: int) -> None:
        """记录发送历史"""
        with self._lock:
            self._send_history.append({
                'timestamp': time.time(),
                'success': success,
                'attempt': attempt,
                'url': self.config.url,
            })
            # 限制历史长度
            if len(self._send_history) > 1000:
                self._send_history = self._send_history[-500:]

    def get_stats(self) -> Dict[str, Any]:
        """获取发送统计"""
        with self._lock:
            total = len(self._send_history)
            success = sum(1 for h in self._send_history if h['success'])
            return {
                'total_sent': total,
                'success_count': success,
                'failure_count': total - success,
                'success_rate': success / total if total > 0 else 0.0,
                'webhook_url': self.config.url,
                'format': self.config.format,
            }


class AlertRouter:
    """
    告警分级路由器

    根据告警严重等级路由到不同通道:
    - CRITICAL: Prometheus + Webhook + 紧急通知
    - HIGH: Prometheus + Webhook
    - WARNING: Prometheus + 日志
    - INFO: Prometheus

    支持告警聚合(相同规则的熔断告警在时间窗口内聚合)和静默窗口。

    使用方式:
        router = AlertRouter()
        router.add_webhook(WebhookConfig(url='https://hooks.slack.com/xxx', format='slack'))
        router.route(alert)
    """

    def __init__(
        self,
        prometheus_exporter: Optional[PrometheusMetricsExporter] = None,
        webhook_configs: Optional[List[WebhookConfig]] = None,
        routing_rules: Optional[Dict[AlertSeverity, AlertRoutingRule]] = None,
    ):
        self.prometheus = prometheus_exporter or PrometheusMetricsExporter()
        self.webhook_senders: List[WebhookAlertSender] = [
            WebhookAlertSender(c) for c in (webhook_configs or [])
        ]
        self.routing_rules = routing_rules or self._default_routing_rules()
        self._aggregate_cache: Dict[str, List[float]] = {}  # rule_id -> timestamps
        self._lock = threading.Lock()

    def _default_routing_rules(self) -> Dict[AlertSeverity, AlertRoutingRule]:
        """默认路由规则"""
        return {
            AlertSeverity.CRITICAL: AlertRoutingRule(
                severity=AlertSeverity.CRITICAL,
                channels=[AlertChannel.PROMETHEUS, AlertChannel.WEBHOOK],
                aggregate_seconds=30,
                max_alerts_per_window=3,
            ),
            AlertSeverity.HIGH: AlertRoutingRule(
                severity=AlertSeverity.HIGH,
                channels=[AlertChannel.PROMETHEUS, AlertChannel.WEBHOOK],
                aggregate_seconds=60,
                max_alerts_per_window=5,
            ),
            AlertSeverity.WARNING: AlertRoutingRule(
                severity=AlertSeverity.WARNING,
                channels=[AlertChannel.PROMETHEUS, AlertChannel.LOG],
                aggregate_seconds=120,
                max_alerts_per_window=10,
            ),
            AlertSeverity.INFO: AlertRoutingRule(
                severity=AlertSeverity.INFO,
                channels=[AlertChannel.PROMETHEUS],
                aggregate_seconds=300,
                max_alerts_per_window=20,
            ),
        }

    def add_webhook(self, config: WebhookConfig) -> None:
        """添加webhook通道"""
        self.webhook_senders.append(WebhookAlertSender(config))

    def route(self, alert: Alert) -> Dict[str, Any]:
        """
        路由告警到对应通道

        Returns:
            路由结果: {routed, channels, webhook_results, aggregated}
        """
        rule = self.routing_rules.get(alert.severity, self.routing_rules[AlertSeverity.WARNING])

        # 检查静默窗口
        if self._is_silent(rule):
            return {'routed': False, 'reason': 'silent_window', 'channels': []}

        # 检查聚合
        aggregated = self._check_aggregation(alert, rule)
        if aggregated:
            return {'routed': False, 'reason': 'aggregated', 'channels': []}

        results = {'routed': True, 'channels': [], 'webhook_results': [], 'aggregated': False}

        # Prometheus metrics(所有等级都记录)
        if AlertChannel.PROMETHEUS in rule.channels:
            self.prometheus.record_alert(alert.alert_type, alert.severity.value)
            if alert.rule_id:
                self.prometheus.record_circuit_break(alert.rule_id)
            results['channels'].append('prometheus')

        # Webhook推送
        if AlertChannel.WEBHOOK in rule.channels:
            for sender in self.webhook_senders:
                success = sender.send(alert)
                results['webhook_results'].append({
                    'url': sender.config.url,
                    'success': success,
                    'format': sender.config.format,
                })
            results['channels'].append('webhook')

        # 日志(WARNING及以下)
        if AlertChannel.LOG in rule.channels:
            results['channels'].append('log')

        return results

    def _is_silent(self, rule: AlertRoutingRule) -> bool:
        """检查是否在静默窗口"""
        if not rule.silent_hours:
            return False
        current_hour = time.localtime().tm_hour
        return current_hour in rule.silent_hours

    def _check_aggregation(self, alert: Alert, rule: AlertRoutingRule) -> bool:
        """检查是否需要聚合(返回True表示应聚合抑制)"""
        if not alert.rule_id:
            return False

        with self._lock:
            now = time.time()
            key = alert.rule_id
            # 清理过期时间戳
            self._aggregate_cache[key] = [
                t for t in self._aggregate_cache.get(key, [])
                if now - t < rule.aggregate_seconds
            ]
            # 检查是否超过窗口限制
            if len(self._aggregate_cache[key]) >= rule.max_alerts_per_window:
                return True
            self._aggregate_cache[key].append(now)
            return False

    def get_stats(self) -> Dict[str, Any]:
        """获取路由统计"""
        webhook_stats = [s.get_stats() for s in self.webhook_senders]
        return {
            'webhook_channels': len(self.webhook_senders),
            'webhook_stats': webhook_stats,
            'routing_rules': {
                sev.value: {'channels': [c.value for c in rule.channels]}
                for sev, rule in self.routing_rules.items()
            },
            'prometheus_metrics_available': True,
        }
