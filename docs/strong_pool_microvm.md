# StrongPool (MicroVM) 工程落地 — 三大限制解决方案

## 概述

StrongPool 基于 Firecracker MicroVM，提供强隔离后端。针对三大工程限制，提供完整解决方案：

| 限制 | 核心对策 | 安全关键点 |
|------|---------|-----------|
| 无KVM硬件虚拟化 | 运行时探测；低风险允许降级LightPool；**高风险任务直接拒绝，禁止静默降级** | 防止安全等级偷偷下降 |
| 高并发内存开销大 | 风险分级调度，仅高风险走MicroVM；短任务执行完立刻销毁；单机并发上限；集群横向扩容 | 不要所有任务跑MicroVM，混合双后端 |
| VM销毁数据全部丢失 | VM无状态；执行结束前导出产物diff到外部存储；VM内只允许临时读写；持久化交给外部对象存储 | **禁止宿主机目录RW直通VM内部**，所有数据进出受控，纳入审计证据链 |

## 限制1：无KVM自动降级

### 运行时能力探测

`KvmDetector` 启动阶段检测三项：

1. `/dev/kvm` 存在且可打开
2. CPU 支持 VM-X / RV 虚拟化扩展（检查 `/proc/cpuinfo` 的 vmx/svm 标志）
3. `firecracker` 二进制在 PATH 中

检测结果写入能力矩阵、Prometheus 指标。

```cpp
KvmCapabilities caps = KvmDetector::detect(config);
// caps.kvm_available, caps.firecracker_available, caps.cpu_virtualization
```

### 调度策略（关键安全点）

`StrongPoolScheduler::schedule()` 根据风险等级决定：

| 风险等级 | KVM可用 | KVM不可用 |
|---------|---------|----------|
| LOW | 运行MicroVM | **允许降级**到LightPool（`allow_low_risk_fallback=true`） |
| MEDIUM | 运行MicroVM | **默认拒绝**（`allow_medium_risk_fallback=false`），可配置允许降级 |
| HIGH | 运行MicroVM | **直接拒绝，绝不降级**（`reject_high_risk_without_kvm=true`） |
| CRITICAL | 运行MicroVM | **直接拒绝，绝不降级** |

**核心安全原则**：不能把高风险不可信代码悄悄降级到进程沙盒，否则等于安全策略失效。

### 集群异构部署

- 一部分节点打开KVM专门跑StrongPool
- 普通节点跑LightPool
- 调度器根据TaskSpec安全标签选择节点

## 限制2：高并发内存开销

### 风险分级调度（核心）

`RiskScorer` 对代码静态扫描打分（0-100），自动推荐运行时：

- **低风险、内网可信Agent**：直接调度 LightPool 进程沙盒（亚ms，内存百KB级）
- **高风险、不可信代码**：才分配 StrongPool MicroVM

现实业务绝大多数任务是内网半可信，只有一小部分走MicroVM，大幅降低MicroVM并发峰值。

### 并发上限与排队

`StrongPoolConfig` 配置：

```cpp
size_t max_concurrent_vms = 100;        // 单机最大并发VM数
size_t max_queue_size = 1000;            // 排队任务上限
std::chrono::seconds max_ttl{300};       // 任务最大执行时间
std::chrono::seconds queue_timeout{60};   // 排队超时
```

- 超过并发上限 → 任务排队
- 队列满 → 拒绝任务
- TTL到期 → `enforce_ttl()` 自动终止僵死VM，防止内存泄漏

### 短生命周期

- 任务执行完成立刻销毁VM，不做常驻闲置VM
- 不为每个租户长期保留VM实例
- Agent任务是短任务模式：执行→销毁

### 内存控制

```cpp
size_t default_vm_memory_mb = 128;       // 默认VM内存
size_t max_vm_memory_mb = 1024;          // 单VM最大内存
size_t total_memory_limit_mb = 16384;     // 池总内存上限
```

### 集群横向扩容

- 单台物理机MicroVM一般控制在几百实例以内
- 上万并发依靠集群横向扩展，而不是单机堆VM
- MicroVM并发压力上涨 → 新增KVM节点水平扩容

### 误区提醒

不要试图把所有任务全部跑MicroVM，成本不可接受；必须双后端按风险分流。

## 限制3：只读rootfs数据丢失

### 任务结束产物导出（推荐）

`ArtifactExporter` 实现完整导出流程：

```
VM内部：业务写在内存盘/临时可写分区（临时，VM内可见）
    ↓ (任务执行完毕，VM销毁之前)
virtio-vsock 通道：主动拷贝出VM到宿主机侧存储
    ↓
宿主机侧：落盘到对象存储/本地磁盘
    ↓
计算文件SHA256哈希 → 记录进入 Evidence+Release 证据链
    ↓
拷贝完成之后，才销毁MicroVM
```

**关键**：VM只是执行载体，持久存储不在VM内部，VM不负责存业务数据。

### 只读rootfs + 独立临时可写磁盘

`EphemeralDisk` 为每个VM创建独立临时块设备：

- **rootfs**：系统镜像，只读
- **临时可写磁盘**：tmpfs-backed 块设备，用于任务读写
- 生命周期和VM绑定，VM销毁设备释放

适合任务中间临时读写，依然不能持久化，仅用于任务运行期中间数据。

### 外部工作区存储（跨任务持久化）

`WorkspaceManager` 实现输入注入+输出导出，VM本身无状态：

**启动前（输入注入）**：
- 宿主机把需要的文件打包成临时**只读镜像**
- 作为 virtio-block 设备挂载进VM
- VM只能读，不能写输入镜像

**执行结束（输出导出）**：
- VM把修改过的文件通过vsock通道传回宿主机
- 宿主机计算diff（modified_files / new_files / deleted_files）
- 更新外部工作区存储

类似函数计算：输入注入，输出导出，VM本身无状态。

### 安全禁令

**禁止**：直接RW挂载宿主机目录到VM内，virtio-fs读写直通会增大逃逸攻击面。

所有数据进出VM必须：
1. 通过受控通道（vsock）
2. 经过大小检查（`max_artifact_size`）
3. 计算哈希（SHA256）
4. 纳入审计证据链

### 快照恢复（有限制）

可以对VM做内存+磁盘快照，用于恢复任务状态：

- 快照会占用存储；高并发场景快照数量要做清理策略
- 快照属于该任务的证据，一并存入Evidence证据链
- 快照不做长期在线运行实例，只用于任务恢复，用完依旧销毁

## 模块清单

| 模块 | 文件 | 功能 |
|------|------|------|
| KVM探测 | `strong_pool.hpp/cpp` | `KvmDetector` 运行时能力探测 |
| 调度器 | `strong_pool.hpp/cpp` | `StrongPoolScheduler` 风险分级+并发控制+TTL+排队 |
| 产物导出 | `artifact_export.hpp/cpp` | `ArtifactExporter` vsock导出+SHA256+证据链 |
| 工作区 | `artifact_export.hpp/cpp` | `WorkspaceManager` 输入注入(只读)+输出diff导出 |
| 临时磁盘 | `artifact_export.hpp/cpp` | `EphemeralDisk` tmpfs-backed块设备 |
| vsock通道 | `artifact_export.hpp/cpp` | `VsockChannel` VM↔宿主机通信 |

## 测试覆盖

`test_strong_pool.cpp` 15个测试：

- KVM探测：3（能力检测/快速检查/CPU虚拟化）
- 调度器：6（高风险拒绝/低风险降级/中风险默认拒绝/并发上限/TTL/池状态）
- 产物导出：2（SHA256计算/本地文件导出）
- 工作区：2（创建清理/输入注入只读）
- 临时磁盘：1（创建销毁）
- 安全策略：1（高风险绝不静默降级验证）

## 与四层控制平面对应

| StrongPool功能 | 控制平面 |
|---------------|---------|
| 风险分级调度 | Control Plane (TaskSpec + RiskScorer) |
| KVM探测+降级策略 | Control Plane (RuntimeSelector) |
| 并发上限+TTL | Control Plane (BudgetSpec) |
| 产物导出+哈希 | Evidence + Release (EvidenceCollector) |
| 工作区注入导出 | Execution Plane (IRuntime) |
| vsock通道审计 | Evidence + Release (审计日志) |
