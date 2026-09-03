# PhotonBox 告警平台接入评估报告

**日期**: 2026-09-03
**范围**: AlertIntegration 告警平台接入模块 + 运维 Runbook

---

## 一、模块说明

针对用户提出的 P1 任务："完善告警接入，规则熔断事件推送监控告警平台，完善人工介入运维 runbook"。

实现 AlertIntegration 模块（463 行），包含三个核心组件：
1. PrometheusMetricsExporter — Prometheus metrics 导出
2. WebhookAlertSender — Webhook 告警推送（支持 5 种格式）
3. AlertRouter — 告警分级路由器（含聚合、静默窗口）

同时创建运维 Runbook 文档（253 行）。

## 二、PrometheusMetricsExporter

### 导出的 Metrics（7 种）

| Metric 名称 | 类型 | 说明 |
|-------------|------|------|
| photonbox_circuit_breaker_triggers_total | counter | 熔断触发总数（按规则 ID） |
| photonbox_circuit_breaker_active | gauge | 当前活跃熔断数（按规则 ID） |
| photonbox_alerts_total | counter | 告警总数（按严重等级/类型） |
| photonbox_alerts_pending | gauge | 待确认告警数 |
| photonbox_rule_recoveries_total | counter | 规则恢复总数 |
| photonbox_duplicate_cache_size | gauge | 去重缓存大小 |
| photonbox_duplicate_cache_usage_ratio | gauge | 去重缓存使用率 |

### 验证结果

- metrics 行数：24 行
- 包含全部 7 种 metrics
- 格式符合 Prometheus 文本格式规范

## 三、WebhookAlertSender

### 支持的格式（5 种）

| 格式 | 适用平台 | 验证结果 |
|------|---------|---------|
| generic | 通用 HTTP 端点 | 通过 |
| slack | Slack Incoming Webhook | 通过 |
| dingtalk | 钉钉机器人 | 通过 |
| wecom | 企业微信机器人 | 通过 |
| alertmanager | Prometheus Alertmanager | 通过 |

### 核心能力

- 发送重试（默认 3 次，指数退避）
- 超时控制（默认 5 秒）
- 发送历史记录（最多 1000 条）
- 发送统计（成功率、失败数）
- **SSRF 防护**：URL scheme 白名单（只允许 http/https）+ 内网地址拦截

### 验证结果

- Webhook 推送成功率：100%
- 5 种格式全部正确构建
- 模拟服务器收到告警标题和规则 ID

## 四、AlertRouter 告警分级路由

### 路由规则

| 严重等级 | 通道 | 聚合窗口 | 窗口上限 |
|---------|------|---------|---------|
| CRITICAL | Prometheus + Webhook | 30 秒 | 3 条 |
| HIGH | Prometheus + Webhook | 60 秒 | 5 条 |
| WARNING | Prometheus + 日志 | 120 秒 | 10 条 |
| INFO | Prometheus | 300 秒 | 20 条 |

### 核心能力

- 分级路由（不同严重等级走不同通道）
- 告警聚合（相同规则短时间内聚合，避免告警风暴）
- 静默窗口（可配置静默小时）
- 多 Webhook 通道冗余

### 验证结果

- HIGH 级别：routed=True, channels=['prometheus', 'webhook']
- WARNING 级别：routed=True, channels=['prometheus', 'log']
- 告警聚合：8 次相同规则告警，3 次被聚合抑制
- 路由规则：4 级全部配置

## 五、运维 Runbook

创建 `docs/ops/circuit_breaker_runbook.md`（253 行），包含：

1. 告警级别与响应矩阵（CRITICAL 30 分钟 / HIGH 2 小时）
2. 熔断事件应急处置流程（确认→评估→紧急处置→根因分析）
3. 人工确认恢复操作步骤（确认模式 / 自动模式）
4. 回滚操作指南（单规则回滚 / 批量回滚 / 回滚后验证）
5. 去重缓存容量告警处置（WARNING / CRITICAL）
6. 常见问题排查（4 个 FAQ）
7. 联系人与升级路径

## 六、SAST 静态扫描

| 严重等级 | 初始 | 修复后 |
|---------|------|--------|
| HIGH | 0 | 0 |
| MEDIUM | 1（B310 urllib SSRF） | 0 |
| LOW | 0 | 0 |
| **合计** | **1** | **0** |

修复内容：
- 添加 URL scheme 白名单校验（只允许 http/https）
- 添加 SSRF 内网地址拦截（禁止访问私网/回环/链路本地地址，开发环境例外 localhost）
- 添加 # nosec 注释说明已做安全校验

## 七、渗透测试（内部 POC）

| 指标 | 结果 |
|------|------|
| 通过 | 14 |
| 失败 | 0 |
| 逃逸检测 | 0 |
| 通过率 | 100% |

## 八、漏洞评估

| CVE | 严重等级 | 状态 |
|-----|---------|------|
| CVE-2022-3602 | HIGH | 系统侧待升级，Python侧已修复 |
| CVE-2023-44487 | HIGH | Python侧已修复，C++侧待安装 |

## 九、诚实声明

1. 所有安全验证为内部自评估，不代表第三方认证
2. 核心卖点 KVM StrongPool 尚未在真实环境验证
3. 6个关键模块因缺少必要条件尚未实测
4. 无独立第三方安全审计（前置材料已就绪7份）
5. 2个 HIGH CVE 为系统侧依赖问题，生产部署前必须在有 sudo 环境升级
6. 生产部署前必须完成官方要求的三件事：裸机 KVM 验证、第三方审计、依赖升级
7. Webhook SSRF 防护已添加，但生产环境建议配置网络策略限制出站访问
