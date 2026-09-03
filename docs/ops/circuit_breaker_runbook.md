# PhotonBox 规则熔断事件运维 Runbook

**适用范围**: DefenseRulePersistence 规则熔断、CircuitBreakerAlertManager 告警
**优先级**: P1（规则熔断可能导致安全防护降级）
**响应时间**: 工作时间 30 分钟，非工作时间 2 小时

---

## 一、告警级别与响应

| 告警级别 | 触发条件 | 响应时间 | 通知通道 |
|---------|---------|---------|---------|
| CRITICAL | 规则熔断后影响核心安全防护（seccomp/eBPF） | 30 分钟 | Webhook + 电话 + 短信 |
| HIGH | 规则熔断，影响非核心防护 | 2 小时 | Webhook + 邮件 |
| WARNING | 去重缓存容量预警 | 下一个工作日 | 日志 + 邮件 |
| INFO | 规则恢复、容量恢复 | 无需响应 | 日志 |

---

## 二、熔断事件应急处置流程

### 2.1 收到告警后

1. **确认告警真实性**
   - 查看告警详情：规则 ID、失败次数、最后失败原因
   - 检查是否为聚合告警（相同规则短时间内多次触发）
   - 确认是否在维护窗口内

2. **评估影响范围**
   - 规则类型：seccomp / eBPF / StrongPool / RuntimeGuard / 审计
   - 影响范围：单个规则 / 整个安全域
   - 是否有替代防护措施

### 2.2 紧急处置（CRITICAL 级别）

1. **立即检查规则状态**
   ```bash
   # 查看规则持久化状态
   cat /etc/photonbox/rules/rules_state.json | python3 -m json.tool
   
   # 查看活跃规则
   photonbox-ctl rules list --active
   
   # 查看熔断规则
   photonbox-ctl rules list --broken
   ```

2. **确认是否需要立即恢复**
   - 如果规则是核心安全防护（seccomp 黑名单、eBPF 内网拦截），需要立即恢复
   - 如果规则是优化类（资源限制收紧），可以等待人工分析

3. **临时恢复规则（需人工确认）**
   ```bash
   # 人工确认告警
   photonbox-ctl alerts acknowledge <alert_id> --by <operator>
   
   # 尝试恢复规则
   photonbox-ctl rules recover <rule_id>
   
   # 验证规则是否正常
   photonbox-ctl rules status <rule_id>
   ```

### 2.3 根因分析

1. **查看规则失败历史**
   ```bash
   photonbox-ctl rules history <rule_id> --limit 20
   ```

2. **常见失败原因及处理**

   | 失败原因 | 可能原因 | 处理方式 |
   |---------|---------|---------|
   | deploy_failed | 配置格式错误、目标不可达 | 检查规则配置，修正后重新部署 |
   | rule_effectiveness_low | 规则拦截率过低，误报率高 | 调整规则参数，或标记为 deprecated |
   | high_false_positive | 规则误杀正常业务 | 放宽规则条件，添加白名单 |
   | config_target_unavailable | LightPool/StrongPool 不可用 | 检查运行时状态，恢复后重新部署 |
   | verification_failed | 部署后验证失败 | 回滚到上一版本，检查配置兼容性 |

3. **检查是否为攻击导致**
   - 查看审计日志，是否有大量恶意事件触发规则
   - 检查红蓝对抗框架是否生成了异常规则
   - 确认 EventInputValidator 是否正常工作

---

## 三、人工确认恢复操作

### 3.1 确认模式（require_manual_ack=True）

当配置为需要人工确认时，熔断后的规则不能自动恢复，必须经过以下步骤：

1. **收到告警通知**
   - Webhook 推送（Slack/钉钉/企业微信）
   - Prometheus Alertmanager 告警
   - 邮件通知

2. **人工确认告警**
   ```bash
   photonbox-ctl alerts acknowledge <alert_id> --by <operator> --reason "已排查，规则配置有误"
   ```

3. **修复规则（如需要）**
   ```bash
   # 查看规则配置
   photonbox-ctl rules show <rule_id>
   
   # 修改规则配置
   photonbox-ctl rules update <rule_id> --config new_config.json
   ```

4. **恢复规则**
   ```bash
   photonbox-ctl rules recover <rule_id>
   ```

5. **验证恢复**
   ```bash
   photonbox-ctl rules status <rule_id>
   # 确认状态为 active，circuit_state 为 closed
   ```

6. **解决告警**
   ```bash
   photonbox-ctl alerts resolve <alert_id> --by <operator>
   ```

### 3.2 自动模式（require_manual_ack=False）

自动模式下，熔断后冷却期结束会自动尝试恢复。运维人员需要：

1. 收到告警后及时查看
2. 如果自动恢复失败，手动介入
3. 定期检查自动恢复的规则是否正常工作

---

## 四、回滚操作指南

### 4.1 单规则回滚

```bash
# 查看规则版本历史
photonbox-ctl rules versions <rule_id>

# 回滚到指定版本
photonbox-ctl rules rollback <rule_id> --version <version_id>

# 回滚到上一稳定版本
photonbox-ctl rules rollback <rule_id> --previous
```

### 4.2 批量回滚（紧急情况）

```bash
# 回滚所有熔断规则
photonbox-ctl rules rollback-all --broken-only

# 回滚最近1小时内部署的所有规则
photonbox-ctl rules rollback-all --since "1h"
```

### 4.3 回滚后验证

```bash
# 检查所有规则状态
photonbox-ctl rules list

# 确认无熔断规则
photonbox-ctl rules list --broken
# 预期输出: 空

# 检查安全防护是否正常
photonbox-ctl security status
```

---

## 五、去重缓存容量告警处置

### 5.1 WARNING 级别（80% 容量）

1. 检查缓存增长速度
   ```bash
   photonbox-ctl cache stats
   # 关注 cache_size 和 growth_rate
   ```

2. 检查是否有异常事件洪水
   - 查看 EventInputValidator 统计
   - 检查是否有恶意事件注入

3. 临时措施
   - 增加 max_entries 配置
   - 缩短 TTL（如从 24 小时改为 12 小时）

### 5.2 CRITICAL 级别（95% 容量）

1. 系统会自动淘汰最旧 10% 条目
2. 立即检查是否为攻击导致
3. 必要时重启流水线（会丢失未持久化的缓存）

---

## 六、常见问题排查

### Q1: 规则频繁熔断怎么办？

A: 
1. 检查规则配置是否合理
2. 查看失败原因，针对性修复
3. 如果是红蓝对抗自动生成的规则，考虑提高 min_rule_effectiveness 阈值
4. 检查 EventInputValidator 是否被绕过（恶意事件注入）

### Q2: 告警风暴（短时间大量告警）怎么办？

A:
1. 检查是否为聚合失效（aggregate_seconds 配置过小）
2. 临时启用静默窗口
3. 排查根因，通常是某个核心组件故障导致连锁反应

### Q3: Webhook 推送失败怎么办？

A:
1. 检查 Webhook URL 是否可达
2. 查看 WebhookAlertSender 统计（success_rate）
3. 检查网络连通性和防火墙规则
4. 配置多个 Webhook 通道作为冗余

### Q4: Prometheus metrics 不更新怎么办？

A:
1. 检查 /metrics 端点是否正常
2. 确认 AlertRouter 正常初始化
3. 查看 Prometheus 抓取配置

---

## 七、联系人与升级路径

| 角色 | 职责 | 升级条件 |
|------|------|---------|
| 一线运维 | 告警确认、简单恢复 | 30 分钟内无法恢复 |
| 安全工程师 | 规则分析、安全事件排查 | 确认是攻击导致 |
| 开发负责人 | 代码缺陷修复、架构调整 | 系统性问题 |
| 安全负责人 | 重大安全事件决策 | CRITICAL 级别影响核心业务 |

---

**文档版本**: 1.0
**最后更新**: 2026-09-03
**适用版本**: PhotonBox 4.14.0
