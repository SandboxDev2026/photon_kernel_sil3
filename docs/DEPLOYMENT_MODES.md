# PhotonBox 部署模式说明

PhotonBox 采用**双后端架构**，提供两种部署模式，适应不同安全等级和硬件条件的场景。

---

## 模式一：LightPool 模式（推荐 / 生产就绪）

### 概述

基于进程级隔离的轻量级沙盒，无需硬件虚拟化支持，可在任意 Linux 环境运行。

### 技术栈

| 组件 | 技术 |
|------|------|
| 进程隔离 | `fork()` + `clone()` 命名空间 |
| 系统调用过滤 | seccomp-BPF（双模式规则集） |
| 文件系统隔离 | Landlock LSM + 只读挂载 |
| 资源限制 | cgroup v2（CPU/内存/PID/磁盘 IO） |
| 网络隔离 | eBPF 网络过滤（可选，需 CAP_BPF） |
| 审计 | HMAC 链式审计日志 |

### 安全特性

- ✅ **seccomp-BPF 双模式规则集**
  - `default_mode`：常规业务，宽松基础白名单
  - `untrusted_code_mode`：不可信用户代码，严格最小权限
  - 禁用 8 类高危 syscall：`ptrace`、`kexec_load`、`mount`、`umount2`、`open_by_handle_at`、`init_module`、`finit_module`
  - 参数级 BPF 过滤：`clone` 禁止 namespace flag，`openat` 标记写访问
  - 兜底动作：`SECCOMP_RET_KILL_PROCESS`（不使用 TRAP，避免信号绕过）

- ✅ **制度性红蓝对抗测试**
  - 5 个红队 POC：ptrace 注入、fd 泄露、fork 炸弹、seccomp 绕过、mount 逃逸
  - PR 准入规则：沙盒修改必须附带对抗用例
  - 季度人工红蓝演练机制

- ✅ **20 项安全测试**（CI 持续验证）
  - seccomp 安全（8 项）
  - 资源隔离（4 项）
  - 逃逸路径（4 项）
  - 审计完整性（4 项）

- ✅ **SAST 扫描**：High=0, Medium=0

### 性能指标

| 指标 | 数值 |
|------|------|
| 启动延迟 | <2ms（预热池命中） |
| 内存开销 | 百 KB 级/实例 |
| 单机并发 | 数千实例（受内存限制） |

### 硬件要求

- 任意 x86_64 Linux 主机
- 内核 >= 4.15（seccomp-BPF + KILL_PROCESS）
- 内核 >= 5.13（Landlock，可选）
- **无需 KVM / 硬件虚拟化**

### 适用场景

- ✅ 内网可信/半可信 Agent 代码执行
- ✅ 遗传算法种群评估（大量并发短任务）
- ✅ CI/CD 构建环境
- ✅ 开发调试环境
- ✅ 普通云容器 / Serverless 平台部署
- ⚠️ 公网不可信用户代码（需额外加固 + 第三方审计）

### 配置示例

```python
from photon_kernel.sandbox import SandboxConfig, RuntimeSelector

config = SandboxConfig(
    backend="lightpool",           # 强制使用 LightPool
    seccomp_mode="untrusted_code",  # 严格模式
    memory_limit_mb=128,
    cpu_limit=1.0,
    timeout_seconds=10,
    network_policy="deny_all",
)
```

---

## 模式二：StrongPool 模式（预览 / 高性能强隔离）

### 概述

基于 KVM 硬件虚拟化的 MicroVM 沙盒，每个实例运行独立 Guest 内核，提供硬件级强隔离。

### 技术栈

| 组件 | 技术 |
|------|------|
| 虚拟化 | KVM（Kernel-based Virtual Machine） |
| VMM | Firecracker MicroVM |
| 内核 | 独立 Guest Linux 内核（裁剪版） |
| 设备模型 | 极简 virtio（block/net/vsock） |
| 通信 | virtio-vsock（无共享内存） |
| 快照 | CRIU（可选，需 root） |

### 安全特性

- ✅ **CPU 硬件隔离**：Intel VT-x / AMD-V，VMX non-root 模式
- ✅ **内存硬件隔离**：EPT/NPT 硬件级地址翻译
- ✅ **独立 Guest 内核**：宿主机内核漏洞不影响 Guest
- ✅ **极简设备模型**：仅 block/net/vsock，无 PCI 直通
- ✅ **高风险任务强制路由**：绝不静默降级到 LightPool
- 🟡 **裸机端到端验证**：代码完整，待物理 KVM 环境验证

### 性能指标

| 指标 | 目标值 | 验证状态 |
|------|--------|---------|
| 启动延迟 | <125ms | 🟡 待裸机验证 |
| 内存开销 | 5-15MB/实例 | 🟡 待裸机验证 |
| 单机并发 | 数十~数百实例 | 🟡 受内存限制 |
| VM-Exit 解析 | 支持 VMCALL/MSR_WRITE/TRIPLE_FAULT | ✅ 单元测试通过 |

### 硬件要求

- **物理裸机**（不建议嵌套虚拟化环境做安全验收）
- CPU 支持 Intel VT-x 或 AMD-V（BIOS 已启用）
- `/dev/kvm` 设备可用
- Firecracker 二进制已安装
- 内核 >= 5.0（KVM 支持完善）
- root 权限（或 KVM 组权限）

### 适用场景

- ✅ 公网不可信用户代码（需裸机验证 + 第三方审计后）
- ✅ 多租户 SaaS 平台
- ✅ 高安全要求的内部场景
- ✅ 对抗内核 0day 逃逸
- ⚠️ 普通云容器（通常无 /dev/kvm）
- ⚠️ 开发调试（可用嵌套虚拟化，但不作为安全验收）

### 配置示例

```python
from photon_kernel.sandbox import SandboxConfig, RuntimeSelector

config = SandboxConfig(
    backend="strongpool",          # 强制使用 StrongPool
    memory_limit_mb=128,
    vcpu_count=1,
    timeout_seconds=10,
    vm_ttl_seconds=10,             # TTL 超时强制销毁
    snapshot_pool_size=10,          # 快照预启动池
    network_policy="deny_all",
)
```

### 嵌套虚拟化开发环境

> ⚠️ **重要**：嵌套虚拟化环境仅用于开发调试，**不能作为生产安全验收依据**。

| 平台 | 开启方式 |
|------|---------|
| VMware Workstation | `.vmx` 添加 `vhv.enable = "TRUE"` |
| VirtualBox | 设置→系统→处理器→启用嵌套 VT-x/AMD-V |
| Hyper-V | `Set-VMProcessor -ExposeVirtualizationExtensions $true` |
| 云 ECS | 仅裸金属实例支持（阿里云裸金属、AWS metal） |

验证脚本会自动检测嵌套环境并标记 `RUNNING_IN_NESTED_VM=TRUE`，安全测试结果仅供调试。

---

## 模式对比总览

| 维度 | LightPool（生产就绪） | StrongPool（技术预览） |
|------|----------------------|----------------------|
| 隔离底座 | 进程级（共享宿主内核） | KVM 硬件虚拟化（独立 Guest 内核） |
| 启动延迟 | <2ms（预热池） | <125ms（目标） |
| 内存开销 | 百 KB 级 | 5-15MB/实例 |
| 单机并发 | 数千实例 | 数十~数百实例 |
| 内核 0day 防护 | ⚠️ 共享内核，依赖 seccomp | ✅ 独立内核，硬件隔离 |
| 硬件要求 | 任意 Linux 主机 | 裸机 + KVM + Firecracker |
| 测试验证 | ✅ 690+ CI 测试持续验证 | 🟡 单元测试通过，待裸机 E2E |
| 安全审计 | ✅ 内部自评估完成 | 🟡 待第三方审计 |
| 公网多租户 | ⚠️ 需额外加固 | ✅ 验证后推荐 |
| 部署难度 | 低 | 高（需特权环境） |

---

## 自动模式选择

PhotonBox 的 `RuntimeSelector` 支持根据任务风险等级自动选择后端：

| 风险等级 | 默认后端 | 说明 |
|---------|---------|------|
| LOW / MEDIUM | LightPool | 内网可信代码，低延迟 |
| HIGH / CRITICAL | StrongPool | 不可信代码，强隔离 |
| 用户强制指定 | 按用户配置 | 覆盖自动选择 |

> **安全原则**：KVM 不可用时，HIGH/CRITICAL 风险任务**直接拒绝执行**，绝不静默降级到 LightPool。

---

## 生产部署检查清单

### LightPool 模式（已就绪）

- [x] seccomp-BPF 双模式规则集
- [x] 制度性红蓝对抗测试库
- [x] 20 项安全测试 CI 验证
- [x] SAST 扫描 High=0/Medium=0
- [x] HMAC 链式审计日志
- [x] cgroup v2 资源限制
- [ ] 独立第三方安全审计（公网部署前必需）

### StrongPool 模式（待验证）

- [x] Firecracker MicroVM 代码实现
- [x] VM-Exit 事件解析（单元测试）
- [x] 高风险任务拒绝降级逻辑
- [x] 快照池框架
- [ ] 裸机 KVM 环境端到端验证（`scripts/verify_baremetal.sh`）
- [ ] 长时间压力测试（内存泄漏/fd 泄漏/僵尸 VM）
- [ ] 独立第三方安全审计

---

## 参考文档

- [安全自评估报告](audit/SECURITY_SELF_ASSESSMENT.md)
- [生产上线检查清单](../PRODUCTION_CHECKLIST.md)
- [裸机验证脚本使用指南](privileged_e2e_guide.md)
- [运行时安全态势检测](security_posture.md)
