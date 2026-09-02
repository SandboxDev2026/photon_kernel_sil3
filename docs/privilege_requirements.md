# 权限要求与特权环境说明 (PRIVILEGE_REQUIREMENTS)

> **核心结论**：不是全部模块都必须 root，但四项高级隔离能力必须对应特权；普通 Docker 容器、普通云实例拿不到，只能编译代码、跑单元测试，做不了端到端完整验证。
>
> 项目内部已实现**能力探测 + 优雅降级**：缺少对应权限，直接关闭该模块，不会崩溃。

---

## 一、四大模块权限要求详解

### 1. KVM（StrongPool Firecracker MicroVM）

**本质**：访问 `/dev/kvm` 设备文件，需要硬件虚拟化扩展（Intel VT-x / AMD-V）。

**最低权限**：
- 用户加入 `kvm` 用户组，给 `/dev/kvm` 读写权限 → **不需要完整 root**
- 或者给二进制打 `CAP_KVM` 能力位即可运行 firecracker 主进程

**额外权限**：
- 创建 tap 网卡、net-namespace、cgroup 需要 `CAP_NET_ADMIN`
- 这部分一般还是需要 root 或对应 capabilities

**云环境坑**：
- 很多云服务器实例没有开启硬件虚拟化，`/dev/kvm` 不存在 → StrongPool 直接禁用
- AWS 默认不开启嵌套虚拟化，需要 bare metal 实例
- GCP 需要开启 "nested virtualization"

**关键安全逻辑**：
> TaskSpec 标记高风险任务，如果探测不到 KVM，**直接拒绝任务，绝不自动切 LightPool 进程沙盒**（防止安全降级漏洞）。

**验证命令**：
```bash
# 检查 KVM 是否可用
ls -la /dev/kvm
egrep -c '(vmx|svm)' /proc/cpuinfo
# 检查当前用户是否在 kvm 组
groups | grep kvm
```

---

### 2. CAP_BPF（eBPF 网络过滤模块）

**内核要求**：内核版本 ≥ 5.8 才有独立 `CAP_BPF`；低于 5.8 需要 `CAP_SYS_ADMIN`。

**作用**：加载 eBPF 字节码，hook `connect` 系统调用，拦截内网 IP、云元数据地址访问，做实例级网络黑名单。

**最低权限**：`CAP_BPF` + `CAP_NET_ADMIN`，**不需要完整 root**，可以 `setcap` 给二进制授予能力位，不用跑 root 用户。

```bash
# 给二进制授予 eBPF 能力（不用 root）
sudo setcap cap_bpf,cap_net_admin+ep /path/to/photon_sandbox
```

**容器限制**：
- 容器内部的用户 namespace 里面 `CAP_BPF` 基本无效
- 必须是**宿主机初始命名空间**下的能力
- 普通 Docker 容器拿不到，只能关闭 eBPF，降级到 seccomp 粗粒度兜底过滤

**降级逻辑**：
> 拿不到 `CAP_BPF`，eBPF 模块直接关闭，上报 metrics 告警（`ebpf_degraded` 指标），使用 seccomp `connect` 拦截作为兜底。

**验证命令**：
```bash
# 检查内核版本
uname -r
# 检查 CAP_BPF 支持
cat /proc/sys/kernel/unprivileged_bpf_disabled
# 检查当前进程 capabilities
grep Cap /proc/self/status
```

---

### 3. CRIU（进程 checkpoint/restore 快照）

**用途**：LightPool 进程快照、冻结恢复进程状态，用于任务恢复、状态分叉。

**权限要求**：
- **Linux 5.9+ 最小权限**：`CAP_CHECKPOINT_RESTORE` + `CAP_SYS_PTRACE`，不需要完整 root
- **但非 root 模式有大量限制**：很多进程状态 dump 失败（复杂 namespace、cgroup、socket、管道）
- **传统方式**：直接 root 运行 CRIU 最稳，支持全部 namespace、cgroup、socket、管道等复杂上下文

**容器限制**：
- 用户命名空间几乎无法完整使用 CRIU
- 必须宿主机特权环境
- Docker `--privileged` 容器可能可以，但仍有大量限制

**项目定位**：
> CRIU 属于**可选高级特性**，关闭不影响基础沙盒运行。仅用于任务恢复、状态分叉等增强场景。

**验证命令**：
```bash
# 检查 CRIU 是否安装
which criu
criu --version
# 检查 CRIU 能力（root）
sudo criu check --all
# 非 root 检查（受限）
criu check
```

---

### 4. 基础 LightPool 进程沙盒（fork + namespace + seccomp + cgroup v2 + Landlock）

> **这是重点**：哪怕你不用 StrongPool/eBPF/CRIU，只要跑完整 LightPool 沙盒，也需要 root/特权 capabilities。

**必须的操作**：
- 创建 PID / NET / MNT / USER namespace
- 配置 cgroup v2（资源限制）
- 设置 rlimit
- drop capabilities
- 加载 seccomp-bpf 过滤器
- pivot_root / chroot
- Landlock 规则加载（需要 CAP_SYS_ADMIN）

**所需 capabilities**：
| Capability | 用途 |
|-----------|------|
| `CAP_SYS_ADMIN` | namespace 创建、cgroup 配置、pivot_root、Landlock |
| `CAP_NET_ADMIN` | net-namespace、网络配置、tap 设备 |
| `CAP_SYS_RESOURCE` | rlimit 设置 |
| `CAP_CHOWN` | 文件所有者修改（沙盒内 UID 映射） |
| `CAP_DAC_OVERRIDE` | 文件访问（沙盒根目录） |
| `CAP_MKNOD` | 设备节点创建（/dev/null 等） |
| `CAP_AUDIT_WRITE` | 审计日志写入 |

**普通非 root 用户**：无法创建完整隔离的沙盒 namespace。

---

## 二、权限总览表

| 模块 | 是否必须 root | 最低可行权限 | 容器环境可用性 |
|------|---------------|-------------|---------------|
| **基础 LightPool 沙盒**（namespace/seccomp/cgroup） | **是，必须特权** | `CAP_SYS_ADMIN` 等一堆 cap | 特权容器可以；普通容器不行 |
| **StrongPool Firecracker KVM** | 不需要完整 root | `CAP_KVM` + `CAP_NET_ADMIN` | 需要宿主机开启 KVM；多数云容器不可用 |
| **eBPF 网络过滤** | 不需要完整 root | `CAP_BPF` + `CAP_NET_ADMIN` | 必须初始用户命名空间；普通 Docker 容器不可用 |
| **CRIU 进程快照** | 推荐 root，非 root 受限 | `CAP_CHECKPOINT_RESTORE`（5.9+） | 普通容器几乎不可用 |

---

## 三、现实开发调试情况

### 环境分级

| 环境 | 能做什么 | 不能做什么 |
|------|---------|-----------|
| **普通 Docker 容器** | 编译代码、跑单元测试、逻辑验证 | namespace、kvm、ebpf、criu 全部用不了 |
| **特权 Docker 容器** (`--privileged`) | LightPool namespace、部分 cgroup | KVM（需宿主机开启）、eBPF（需初始 namespace）、CRIU（受限） |
| **物理裸机 / 虚拟机（开启虚拟化）** | **全部能力完整跑通**，端到端验证 | 无 |
| **云实例（开启嵌套虚拟化）** | StrongPool KVM、LightPool | 取决于云厂商支持 |

### 开发建议

1. **本地开发**：普通容器即可，跑单元测试和逻辑验证
2. **集成测试**：特权容器 + 模拟环境，验证 LightPool 基础功能
3. **端到端验证**：必须裸机/特权 VM，验证全部高级特性
4. **生产部署**：裸机 root 运行沙盒管理器（规避 capability 坑），或 `setcap` 授予最小能力集

---

## 四、降级策略（photon 已实现）

启动时逐项探测，缺少能力自动降级：

| 探测项 | 缺失时行为 | 安全影响 |
|--------|-----------|---------|
| KVM 不存在 | StrongPool 禁用；**高风险任务拒绝执行** | 高风险任务无法运行（安全，不降级） |
| 无 `CAP_BPF` | eBPF 关闭，使用 seccomp 兜底网络过滤 | 网络过滤粒度变粗（可接受降级） |
| CRIU 二进制缺失/权限不足 | 快照功能禁用 | 任务恢复/状态分叉不可用（功能降级） |
| 没有 namespace 创建权限 | **直接报错拒绝启动沙盒** | 无法运行（安全，不静默降级） |
| Landlock 不支持 | 回退到 seccomp 路径过滤 | 路径过滤粒度变粗 |
| gRPC C++ 库缺失 | 使用 Python gRPC 替代 | 功能完整，性能略低 |

**降级原则**：
- ✅ 功能降级可以（eBPF→seccomp、CRIU→无快照）
- ❌ **安全降级绝不允许**（高风险任务→LightPool、namespace→无隔离）

---

## 五、部署权限模型

### 方案 A：root 运行（推荐生产）

```bash
# 沙盒管理器以 root 运行，内部 drop 权限到 nobody 执行用户代码
sudo ./build/photon_sandbox --config /etc/photon/config.yaml
```

- 优点：简单稳定，规避 capability 坑
- 缺点：管理器进程有 root 权限（但内部已最小化）

### 方案 B：setcap 最小能力（安全加固）

```bash
# 给二进制授予所需 capabilities，不用 root 运行
sudo setcap cap_sys_admin,cap_net_admin,cap_sys_resource,cap_chown,cap_dac_override,cap_mknod,cap_audit_write+ep ./build/photon_sandbox
# eBPF 支持
sudo setcap cap_bpf+ep ./build/photon_sandbox
# KVM 支持（加入 kvm 组即可，不需要 cap）
sudo usermod -aG kvm photon-user
# 非 root 运行
./build/photon_sandbox
```

- 优点：最小权限原则，管理器进程无 root
- 缺点：部署运维复杂度上升，capability 组合容易遗漏

### 方案 C：systemd 服务（生产推荐）

```ini
# /etc/systemd/system/photon-sandbox.service
[Unit]
Description=Photon Kernel Sandbox Manager
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/photon_sandbox --config /etc/photon/config.yaml
Restart=on-failure
RestartSec=5
# 安全加固
NoNewPrivileges=false  # 需要 namespace 创建
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

---

## 六、常见误区澄清

### ❌ 误区 1：全部模块都必须 root 才能跑

**✅ 真相**：部分模块可以通过 Linux capabilities 不用 root：
- KVM：`CAP_KVM` + kvm 组
- eBPF：`CAP_BPF` + `CAP_NET_ADMIN`
- CRIU：`CAP_CHECKPOINT_RESTORE`（5.9+，但受限）

但是：**容器用户命名空间下大部分高级隔离能力会失效**；完整的沙盒隔离能力离不开特权环境。

### ❌ 误区 2：setcap 给 capabilities 就可以完全不用 root

**✅ 真相**：理论上可以，但生产部署依然普遍直接使用 root 运行沙盒管理器：
- capability 组合复杂，容易遗漏导致功能异常
- namespace 创建在非 root 下有大量限制（user namespace 映射）
- cgroup v2 配置在非 root 下需要 cgroup 所有权预先配置
- root 运行 + 内部 drop 权限是更稳妥的方案

### ❌ 误区 3：Docker 容器里可以跑完整沙盒

**✅ 真相**：普通 Docker 容器只能编译代码、跑单元测试：
- namespace：需要 `--privileged` 或大量 `--cap-add`
- KVM：需要宿主机开启虚拟化 + `--device /dev/kvm`
- eBPF：需要初始用户命名空间，容器内基本无效
- CRIU：用户命名空间几乎无法完整使用

**端到端完整验证必须裸机/特权 VM**。

### ❌ 误区 4：缺少权限会导致崩溃

**✅ 真相**：photon 已实现能力探测 + 优雅降级：
- 缺少 KVM → StrongPool 禁用，高风险任务拒绝
- 缺少 CAP_BPF → eBPF 关闭，seccomp 兜底
- 缺少 CRIU → 快照功能禁用
- 缺少 namespace → 直接报错（不静默降级）

**不会崩溃，但功能会受限**。

---

## 七、快速权限检查脚本

```bash
#!/bin/bash
# scripts/check_privileges.sh
echo "=== Photon Sandbox 权限环境检查 ==="
echo ""

echo "[1] 内核版本: $(uname -r)"
echo "    要求: >= 5.8 (CAP_BPF), >= 5.9 (CAP_CHECKPOINT_RESTORE), >= 5.10 (Landlock)"
echo ""

echo "[2] KVM 检查:"
if [ -e /dev/kvm ]; then
    echo "    /dev/kvm 存在: YES"
    echo "    当前用户可访问: $(test -r /dev/kvm && echo YES || echo NO)"
    echo "    CPU 虚拟化标志: $(egrep -c '(vmx|svm)' /proc/cpuinfo) 个"
else
    echo "    /dev/kvm 存在: NO (StrongPool 不可用)"
fi
echo ""

echo "[3] CAP_BPF 检查:"
echo "    unprivileged_bpf_disabled: $(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo 'unknown')"
echo "    当前进程 CapEff: $(grep CapEff /proc/self/status | awk '{print $2}')"
echo ""

echo "[4] CRIU 检查:"
if command -v criu &> /dev/null; then
    echo "    criu 已安装: $(criu --version 2>&1 | head -1)"
else
    echo "    criu 未安装 (快照功能不可用)"
fi
echo ""

echo "[5] Namespace 能力:"
echo "    用户 namespace: $(test -f /proc/sys/user/max_user_namespaces && echo 'supported' || echo 'unknown')"
echo "    max_user_namespaces: $(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo 'unknown')"
echo ""

echo "[6] cgroup v2:"
if mount | grep -q "cgroup2"; then
    echo "    cgroup v2: 已挂载"
    echo "    可写: $(test -w /sys/fs/cgroup && echo YES || echo NO)"
else
    echo "    cgroup v2: 未挂载 (使用 cgroup v1 或无 cgroup)"
fi
echo ""

echo "=== 检查完成 ==="
echo "结论: 普通容器环境只能编译+单元测试，端到端验证需要裸机/特权VM"
```

---

## 八、相关文档

- [PRODUCTION_CHECKLIST.md](../PRODUCTION_CHECKLIST.md) — 生产上线补齐任务清单
- [docs/strong_pool_microvm.md](strong_pool_microvm.md) — StrongPool MicroVM 三大限制解决方案
- [docs/network_defense_in_depth.md](network_defense_in_depth.md) — 网络三层防御
- [docs/microvm_advanced_features.md](microvm_advanced_features.md) — AgentENV 四大高级特性
- [SECURITY.md](../SECURITY.md) — 安全策略与已知边界

---

*最后更新：2026-09-02 | 基于 photon_kernel_sil3 v414*
