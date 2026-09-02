# 应急响应 Runbook

**适用系统**：PhotonBox 沙盒服务
**响应级别**：P0（安全事故）/ P1（服务中断）/ P2（性能降级）
**目标**：在安全事故发生时，提供标准化的人工处置流程，最小化影响范围和数据泄露。

---

## 一、通用响应流程

### 1.1 事故确认（0-5分钟）

1. **确认告警真实性**：
   - 检查 Prometheus 告警是否持续触发（非瞬时抖动）
   - 查看 Grafana 面板对应指标趋势
   - 检查审计日志是否有对应事件记录

2. **初步定级**：
   - **P0**：沙盒逃逸确认、数据泄露、元数据服务访问
   - **P1**：守护进程下线、高风险任务降级、审计队列溢出
   - **P2**：能力降级、延迟升高、僵尸实例

3. **通知相关人员**：
   - P0：立即电话通知安全负责人 + 运维负责人
   - P1：即时通讯群组通知
   - P2：工单系统记录

### 1.2 影响范围评估（5-15分钟）

1. **检查受影响租户**：
   ```bash
   # 查看最近1小时的审计日志，按租户统计
   grep "$(date -d '1 hour ago' '+%Y-%m-%dT%H')" /var/log/photon/audit.jsonl | \
     jq -r '.tenant_id' | sort | uniq -c | sort -rn
   ```

2. **检查受影响实例**：
   ```bash
   curl -s http://localhost:9090/pool/status | jq
   ```

3. **检查网络异常**：
   ```bash
   # 查看eBPF拦截日志
   journalctl -u photon-sandbox --since "1 hour ago" | grep -i "block\|deny"
   ```

---

## 二、专项处置流程

### 2.1 沙盒逃逸（P0）<a id="escape"></a>

**告警**：`SandboxEscapeAttempt` — 检测到 seccomp 绕过 / namespace 逃逸

**处置步骤**：

1. **立即隔离（0-5分钟）**：
   ```bash
   # 1. 暂停新任务接入
   curl -X POST http://localhost:9090/admin/pause -H "Content-Type: application/json" -d '{"reason":"escape_incident"}'
   
   # 2. 列出所有活跃沙盒实例
   curl -s http://localhost:9090/pool/status | jq '.active_instances'
   
   # 3. 销毁可疑实例（高风险租户的所有实例）
   curl -X POST http://localhost:9090/admin/destroy -d '{"tenant_id":"<可疑租户>"}'
   ```

2. **证据保全（5-15分钟）**：
   ```bash
   # 1. 导出审计日志（最近24小时）
   journalctl -u photon-sandbox --since "24 hours ago" > /tmp/escape_evidence_$(date +%s).log
   
   # 2. 校验审计链完整性
   python3 tools/audit_verify.py --file /var/log/photon/audit.jsonl
   
   # 3. 保存系统状态快照
   ps auxf > /tmp/process_snapshot.txt
   ss -tlnp > /tmp/network_snapshot.txt
   ```

3. **根因分析（15-60分钟）**：
   - 检查逃逸实例的任务代码（从审计日志获取 task_id）
   - 检查 seccomp 白名单是否有遗漏的 syscall
   - 检查 namespace 配置是否完整（mount/pid/net/user/uts/ipc）
   - 检查是否有内核漏洞利用（对照 CVE 监控结果）

4. **恢复服务（60分钟后）**：
   - 修复漏洞后，先在测试环境验证
   - 逐步恢复流量（10% → 50% → 100%）
   - 持续监控24小时

### 2.2 内网访问大量拦截（P1）<a id="network-block"></a>

**告警**：`InternalNetworkBlocked` — 1分钟内超过10次内网访问被拦截

**处置步骤**：

1. **判断是否为逃逸前兆**：
   ```bash
   # 查看拦截的目标地址
   journalctl -u photon-sandbox --since "5 minutes ago" | grep -i "blocked" | jq -r '.destination' | sort | uniq -c
   ```

2. **如果拦截目标包含业务内网网段（10.x/172.16-31.x/192.168.x）**：
   - 按 2.1 沙盒逃逸流程处置
   - 检查对应租户的任务代码

3. **如果只是正常业务被误拦**：
   - 检查 eBPF 白名单配置是否需要更新
   - 临时将该租户加入可信白名单（需审批）

### 2.3 云元数据服务访问（P0）<a id="metadata"></a>

**告警**：`MetadataServiceAccessAttempt` — 检测到访问 169.254.169.254

**处置步骤**：

1. **这是高危行为，立即按 2.1 沙盒逃逸流程处置**

2. **额外检查**：
   ```bash
   # 检查云凭证是否可能泄露
   # 1. 查看是否有成功的元数据请求（eBPF应该全部拦截）
   journalctl -u photon-sandbox | grep "169.254.169.254" | grep -i "allow\|success"
   
   # 2. 如果有成功请求，立即轮换云凭证
   # AWS: aws iam create-access-key ...
   # 阿里云: aliyun ram CreateAccessKey ...
   ```

3. **确认防护有效性**：
   - eBPF 规则应拦截所有到 169.254.0.0/16 的连接
   - 隔离网关应二次校验
   - 如果 eBPF 未生效（CAP_BPF 缺失），立即启用 iptables 兜底

### 2.4 高风险任务降级（P0）<a id="downgrade"></a>

**告警**：`HighRiskTaskDowngraded` — 高风险任务被降级到 LightPool

**处置步骤**：

1. **这是严重安全事故，立即暂停高风险任务**：
   ```bash
   curl -X POST http://localhost:9090/admin/pause-high-risk -d '{"reason":"kvm_unavailable"}'
   ```

2. **检查 KVM 状态**：
   ```bash
   ls -la /dev/kvm
   lsmod | grep kvm
   dmesg | grep -i kvm | tail -10
   ```

3. **恢复 KVM**：
   - 如果 /dev/kvm 不存在：加载内核模块 `modprobe kvm_intel` 或 `modprobe kvm_amd`
   - 如果权限问题：`chmod 660 /dev/kvm && chown root:kvm /dev/kvm`
   - 如果是云实例不支持 KVM：该节点只能运行 LightPool，高风险任务调度到其他 KVM 节点

4. **恢复高风险任务**：
   ```bash
   curl -X POST http://localhost:9090/admin/resume-high-risk
   ```

### 2.5 能力降级（P2）<a id="capability"></a>

**告警**：`CapabilityDowngrade` — KVM/CAP_BPF/CRIU 不可用

**处置步骤**：

1. **查看降级的具体能力**：
   ```bash
   curl -s http://localhost:9090/capabilities | jq
   ```

2. **根据降级能力处理**：
   - **KVM 降级**：高风险任务被拒绝（正常行为），无需紧急处理，但需评估是否需要扩容 KVM 节点
   - **CAP_BPF 降级**：eBPF 网络过滤失效，回退到 seccomp/iptables。检查是否需要授予 CAP_BPF
   - **CRIU 降级**：快照功能不可用，不影响基础沙盒运行

3. **如果是非预期降级**：
   - 检查内核版本是否满足要求
   - 检查 capabilities 是否被正确授予
   - 检查容器是否以 privileged 模式运行（或添加了必要的 cap）

### 2.6 审计队列溢出（P1）<a id="audit-spool"></a>

**告警**：`AuditSpoolOverflow` — 审计本地队列超过 10000 条

**处置步骤**：

1. **检查 gRPC 上报状态**：
   ```bash
   # 检查审计服务端是否可达
   curl -s http://<audit-server>:9091/health
   
   # 检查网络连通性
   telnet <audit-server> 50051
   ```

2. **如果审计服务端不可用**：
   - 启动备用审计服务端
   - 或临时切换到本地文件写入（确保磁盘空间充足）

3. **清理旧 spool 文件**：
   ```bash
   # 查看 spool 目录大小
   du -sh /var/spool/photon/audit/
   
   # 清理超过7天的旧文件（已成功上报的）
   find /var/spool/photon/audit/ -name "*.spool" -mtime +7 -delete
   ```

4. **检查磁盘水位**：
   ```bash
   df -h /var/log/photon/
   # 如果超过95%，立即清理旧审计日志（已归档的）
   ```

---

## 三、事后复盘

### 3.1 事故报告模板

每次 P0/P1 事故后 24 小时内完成：

```
## 事故概要
- 事故等级：P0/P1/P2
- 发生时间：YYYY-MM-DD HH:MM:SS
- 恢复时间：YYYY-MM-DD HH:MM:SS
- 持续时长：XX 分钟
- 影响范围：XX 租户 / XX 实例

## 时间线
- HH:MM 告警触发
- HH:MM 运维确认
- HH:MM 开始处置
- HH:MM 服务恢复

## 根因分析
- 直接原因：
- 根本原因：
-  contributing factors：

## 处置措施
- 已执行：
- 效果验证：

## 改进项
- [ ] 短期（1周内）：
- [ ] 中期（1月内）：
- [ ] 长期（3月内）：

## 经验教训
- 
```

### 3.2 定期演练

- **每月**：模拟一次沙盒逃逸告警，验证响应流程
- **每季度**：模拟一次 KVM 不可用场景，验证高风险任务拒绝逻辑
- **每半年**：完整的红蓝对抗测试，尝试逃逸沙盒

---

## 四、联系方式

| 角色 | 职责 | 联系方式 |
|------|------|---------|
| 安全负责人 | P0 事故决策 | （填写） |
| 运维负责人 | 服务恢复 | （填写） |
| 沙盒开发 | 根因分析 | （填写） |
| 审计团队 | 证据分析 | （填写） |

---

## 五、相关文档

- `docs/security/seccomp_audit_report.md` — seccomp 白名单审计
- `docs/security/escape_security_audit.md` — 逃逸风险审计
- `RISK_ASSESSMENT.md` — 风险评估清单
- `PRODUCTION_CHECKLIST.md` — 生产上线检查清单
- `deploy/monitoring/prometheus_alerts.yml` — 告警规则
- `deploy/monitoring/grafana_dashboard.json` — 监控面板
