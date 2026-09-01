# SandboxPool Operator —— K8s 原生沙盒算子（任务4）

声明式管理沙盒预热池：定义 `SandboxPool` CR（期望副本数、风险等级、资源配额），
Operator 负责对账，确保运行中的 worker Deployment 副本数与期望一致，并回写状态。

## 架构

```
┌────────────────────────────────────────────────────┐
│  Control Plane（编排面）                            │
│  ┌──────────────┐   ┌──────────────────────────┐   │
│  │ SandboxPool  │──▶│ Operator (kopf)          │   │
│  │ CR (期望状态)│   │  对账: 期望副本数 vs 实际 │   │
│  └──────────────┘   │  扩缩容 Deployment       │   │
│                     │  回写 status             │   │
│                     └──────────────────────────┘   │
└────────────────────────────────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────┐
│  Data Plane（数据面）                               │
│  worker Deployment：N 个 sandbox-worker Pod         │
│  每个 Pod 内运行 photon_sandbox 预 fork 沙盒进程     │
│  （seccomp 已就绪，通过 gRPC/HTTP 接收任务）         │
└────────────────────────────────────────────────────┘
```

## 快速开始

```bash
# 1. 安装 CRD 与示例池
kubectl apply -f deploy/crd.yaml

# 2. 部署 operator
pip install kopf kubernetes
kubectl create deployment sandbox-pool-operator --image=<operator镜像>
# 或本地运行（需能访问集群）：
kopf run operator/operator.py

# 3. 查看池状态
kubectl get sandboxpools
kubectl get sbp python-agent-pool -o yaml

# 4. 扩缩容（声明式）
kubectl patch sbp python-agent-pool --type merge \
  -p '{"spec":{"replicas":20}}'
```

## 核心 Reconcile 循环（双通道）
1. **独立后台线程 `_reconcile_loop`**：进程启动即运行，按 `RECONCILE_INTERVAL_SEC`（30s）周期
   全量扫描集群中所有 SandboxPool CR，逐个执行 `_reconcile`（与 kopf 事件机制解耦，进程存活即持续对账）。
2. **kopf 事件驱动**：`on.create / on.update / on.timer / on.delete` 调用同一 `_reconcile`。
3. `_reconcile`：期望副本数 → 实际 Deployment 副本数对账；Deployment 不存在（404）时按
   Pod 模板创建；不一致时 `patch` 滚动扩缩容；最后回写 `status`（ready/total/phase）。

## Pod 模板（完整定义）
`_build_worker_pod_template` 生成 worker Pod：
- 容器 `sandbox-worker`：镜像（默认 `photon/sandbox-worker:4.14`）、启动参数（risk/task-timeout-ms/port）、
  gRPC 端口 50051。
- 探针：`readinessProbe`（tcpSocket:50051，就绪接任务）+ `livenessProbe`（exec 检查
  `/tmp/photon_worker_ready`，失活自愈）。
- 安全上下文：非 root（1000）、`readOnlyRootFilesystem: true`、`capabilities.drop: ALL`、
  `allowPrivilegeEscalation: false`、`seccompProfile: RuntimeDefault`。
- 资源配额（requests/limits 默认 256Mi/500m，可由 CR spec 覆盖）；env 注入 pool/risk/timeout/POD_IP。
- 卷：emptyDir `/tmp`；`ownerReference` 级联清理。

## 对账逻辑
| 事件 | 行为 |
|---|---|
| CR 创建 | 创建 `{name}-worker` Deployment，replicas=spec.replicas |
| CR 更新（replicas 变化）| 滚动扩缩容 Deployment |
| 定时（30s）/ 后台循环 | 自愈对账：实际副本数与期望不一致则修正 |
| CR 删除 | 由 ownerRef 级联清理 worker Deployment |
## 说明与边界

- 沙盒能力由容器内 `photon_sandbox` 预 fork 进程提供（本仓库 C++ 工程），
  worker 镜像需预置 python3/node 解释器与 `sandbox-server`（gRPC 服务端）。
- `status.idle/busy` 由 worker 上报（可扩展 worker 侧周期上报池状态），
  当前示例由 Operator 维护 total/ready 与 phase。
- 自动扩缩容（`scalePolicy.targetUtilization`）为扩展点，可对接 HPA。
- 本机无 K8s 集群，此目录为完整交付物，未在集群实测。
