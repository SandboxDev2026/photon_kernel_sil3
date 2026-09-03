# 业务影响面度量规范

**版本**: v1.0
**适用范围**: PhotonBox 沙盒集群（LightPool + StrongPool）
**规范依据**: 第十三条（业务影响面控制）

---

## 1. 定义

**业务影响面**：单个沙盒实例故障/逃逸/资源耗尽时，对业务系统造成的最大影响范围，以受影响请求占比（%）度量。

**起步上限**：生产环境部署时，单实例故障的业务影响面必须 ≤ 5%。

---

## 2. LightPool 业务影响面度量

### 2.1 度量指标

| 指标 | 定义 | 起步上限 | 计算方式 |
|------|------|---------|---------|
| 单实例并发上限 | 单个 LightPool worker 同时处理的请求数 | ≤ 5% 集群总并发 | `单实例并发 / 集群总并发 × 100%` |
| 单实例内存上限 | 单个 LightPool worker 的内存配额 | ≤ 5% 节点内存 | `单实例内存 / 节点总内存 × 100%` |
| 单实例 CPU 上限 | 单个 LightPool worker 的 CPU 配额 | ≤ 5% 节点 CPU | `单实例CPU / 节点总CPU × 100%` |
| 故障爆炸半径 | 单实例故障影响的请求数 | ≤ 5% 总 QPS | `受影响QPS / 集群总QPS × 100%` |

### 2.2 配置要求

```yaml
# LightPool 配置示例
light_pool:
  max_concurrent_per_worker: 10        # 单worker最大并发
  memory_limit_mb: 256                  # 单worker内存上限
  cpu_limit: 0.5                        # 单worker CPU上限（核）
  max_workers_per_node: 50              # 单节点最大worker数
  # 业务影响面校验：
  # 单worker并发(10) / 集群总并发(50*10=500) = 2% ≤ 5% ✓
  # 单worker内存(256MB) / 节点内存(32GB) = 0.8% ≤ 5% ✓
```

### 2.3 验证方法

1. **并发影响面验证**：杀掉单个 worker，监控受影响请求数
2. **内存影响面验证**：触发单 worker OOM，验证不影响其他 worker
3. **CPU 影响面验证**：单 worker CPU 打满，验证其他 worker 性能下降 ≤ 5%

---

## 3. StrongPool 业务影响面度量

### 3.1 度量指标

| 指标 | 定义 | 起步上限 | 计算方式 |
|------|------|---------|---------|
| 单 VM 并发上限 | 单个 MicroVM 同时处理的请求数 | ≤ 5% 集群总并发 | `单VM并发 / 集群总并发 × 100%` |
| 单 VM 内存上限 | 单个 MicroVM 的内存配额 | ≤ 5% 节点内存 | `单VM内存 / 节点总内存 × 100%` |
| 单 VM CPU 上限 | 单个 MicroVM 的 CPU 配额 | ≤ 5% 节点 CPU | `单VM CPU / 节点总CPU × 100%` |
| VM 逃逸影响面 | 单 VM 逃逸后可访问的资源范围 | ≤ 5% 集群资源 | `可访问资源 / 集群总资源 × 100%` |
| 快照克隆影响面 | 单快照损坏影响的 VM 数 | ≤ 5% 总 VM 数 | `受影响VM数 / 总VM数 × 100%` |

### 3.2 配置要求

```yaml
# StrongPool 配置示例
strong_pool:
  max_concurrent_per_vm: 5              # 单VM最大并发（比LightPool更保守）
  memory_limit_mb: 512                   # 单VM内存上限
  cpu_count: 1                           # 单VM CPU核数
  max_vms_per_node: 32                   # 单节点最大VM数
  # 业务影响面校验：
  # 单VM并发(5) / 集群总并发(32*5=160) = 3.1% ≤ 5% ✓
  # 单VM内存(512MB) / 节点内存(32GB) = 1.6% ≤ 5% ✓
  # 单VM CPU(1核) / 节点CPU(16核) = 6.25% > 5% ✗ → 需调整为0.5核或增加节点CPU
```

### 3.3 验证方法

1. **VM 逃逸影响面验证**：模拟 VM 逃逸，验证无法访问其他 VM 和宿主机资源
2. **快照损坏验证**：损坏单个快照，验证仅影响基于该快照的 VM（≤ 5%）
3. **网络隔离验证**：单 VM 网络异常，验证不影响其他 VM 网络

---

## 4. 集群级业务影响面度量

### 4.1 多活部署要求

| 指标 | 要求 | 说明 |
|------|------|------|
| 可用区数量 | ≥ 2 | 跨可用区部署 |
| 单可用区流量占比 | ≤ 50% | 避免单点 |
| 单节点故障影响 | ≤ 5% | 节点级冗余 |
| 单可用区故障影响 | ≤ 50% | 可用区级冗余 |

### 4.2 弹性伸缩要求

```yaml
# HPA 配置
hpa:
  min_replicas: 3                        # 最小副本数
  max_replicas: 50                       # 最大副本数
  target_cpu_utilization: 70             # CPU目标利用率（70-85%）
  target_qps_per_pod: 100                # 单Pod目标QPS
  # 业务影响面校验：
  # 单Pod故障影响 = 1/3 = 33%（最小3副本时）
  # 正常负载下（10副本）= 1/10 = 10%
  # 高负载下（50副本）= 1/50 = 2% ≤ 5% ✓
```

---

## 5. 监控与告警

### 5.1 业务影响面监控指标

| 指标名 | 类型 | 告警阈值 | 说明 |
|--------|------|---------|------|
| `sandbox_instance_failure_impact_ratio` | Gauge | > 5% | 单实例故障影响占比 |
| `sandbox_worker_oom_count` | Counter | > 0/min | Worker OOM 次数 |
| `sandbox_vm_escape_attempts` | Counter | > 0 | VM 逃逸尝试次数 |
| `sandbox_resource_exhaustion_events` | Counter | > 0/min | 资源耗尽事件 |
| `sandbox_business_impact_p99` | Histogram | > 5% | P99 业务影响面 |

### 5.2 告警规则

```yaml
# Prometheus 告警规则
groups:
  - name: sandbox_business_impact
    rules:
      - alert: SandboxInstanceFailureImpactExceeded
        expr: sandbox_instance_failure_impact_ratio > 0.05
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "沙盒实例故障影响面超过5%"
          description: "当前影响面 {{ $value | humanizePercentage }}，超过起步上限5%"

      - alert: SandboxVMEscapeAttemptDetected
        expr: increase(sandbox_vm_escape_attempts[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "检测到VM逃逸尝试"
          description: "StrongPool检测到逃逸尝试，立即隔离受影响VM"
```

---

## 6. 验收标准

### 6.1 LightPool 验收

- [ ] 单 worker 并发占比 ≤ 5%
- [ ] 单 worker 内存占比 ≤ 5%
- [ ] 单 worker CPU 占比 ≤ 5%
- [ ] 单 worker 故障影响请求数 ≤ 5% 总 QPS
- [ ] 单 worker OOM 不影响其他 worker

### 6.2 StrongPool 验收

- [ ] 单 VM 并发占比 ≤ 5%
- [ ] 单 VM 内存占比 ≤ 5%
- [ ] 单 VM CPU 占比 ≤ 5%
- [ ] 单 VM 逃逸无法访问其他 VM/宿主机
- [ ] 单快照损坏影响 VM 数 ≤ 5%

### 6.3 集群级验收

- [ ] 跨可用区部署（≥ 2 AZ）
- [ ] 单节点故障影响 ≤ 5%
- [ ] HPA 最小副本 ≥ 3
- [ ] 业务影响面监控告警已配置
- [ ] 故障演练通过（单实例/单节点/单可用区）

---

## 7. 持续优化

业务影响面度量不是一次性验收，而是持续优化过程：

1. **每周**：检查业务影响面监控指标，确认 ≤ 5%
2. **每月**：进行故障演练，验证实际影响面
3. **每季度**：重新评估配置参数，根据业务增长调整
4. **重大变更**：扩容/架构变更后重新验证业务影响面
