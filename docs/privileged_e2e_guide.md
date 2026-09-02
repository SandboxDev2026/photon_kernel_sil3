# 完整特权环境部署指南 (privileged_e2e_guide)

> 本指南用于启用全部高级沙盒能力：namespace、cgroup-v2、Landlock、eBPF网络过滤、StrongPool(Firecracker MicroVM)、CRIU快照。
>
> ⚠️ **警告**：整套组件需要 root/特定 Linux capabilities，仅部署于受控服务器，禁止在桌面日常环境直接运行；未做第三方安全审计，上线前自行安全测评。

---

## 1. 硬件 & 内核前置要求

### 最低硬件

- x86_64 CPU，支持 KVM 硬件虚拟化（Intel VT-x / AMD-V）
- 内存 ≥ 4GB；StrongPool 并发建议每实例预留 6-16MB 内存
- 磁盘：SSD 优先，MicroVM 镜像读写对 IO 敏感

### Linux 内核硬性要求

内核版本 **≥ 5.15**，推荐 **6.1 LTS / 6.6 LTS**

必须开启内核配置：

```
CONFIG_NAMESPACES=y
CONFIG_CGROUPS=y
CONFIG_CGROUP_BPF=y
CONFIG_CGROUP_FREEZER=y
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
CONFIG_LANDLOCK=y
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_KVM=y
CONFIG_KVM_INTEL / CONFIG_KVM_AMD=y
CONFIG_VSOCKETS=y
CONFIG_VHOST_VSOCK=y
```

### 检查命令

```bash
# 检查 KVM 支持
grep -E 'vmx|svm' /proc/cpuinfo
ls /dev/kvm

# 检查 cgroup v2
mount | grep cgroup2

# 检查 vsock
modprobe vsock
modprobe vhost_vsock
ls /dev/vsock

# 检查 Landlock
cat /sys/kernel/security/lsm | grep landlock

# 检查内核版本
uname -r
```

### 云服务商注意

多数公有云默认关闭 KVM，需要**裸金属/专用主机实例**；普通共享虚拟机无法启用 StrongPool。

| 云厂商 | 可用实例类型 |
|--------|-------------|
| AWS | bare metal (c5.metal, m5.metal) |
| GCP | 开启嵌套虚拟化的 n2 实例 |
| Azure | Dv5/Ev5 及以上 |
| 阿里云 | ecs.ebm 裸金属系列 |
| 腾讯云 | 标准型裸金属 |

### 操作系统发行版适配

| 发行版 | 备注 |
|--------|------|
| Ubuntu 22.04 / 24.04 | ✅ 推荐；内核可直接满足 cgroup v2、Landlock |
| Debian 12 | ✅ 默认 cgroup v2，需要手动安装 eBPF 工具链 |
| Rocky 9 / AlmaLinux 9 | ✅ 开启 cgroup v2，内核开启 Landlock 补丁 |
| CentOS 7、Ubuntu 20.04 | ❌ 不支持：内核过低无 Landlock，cgroup v1 兼容受限 |

> **必须启用 cgroup v2 unified hierarchy**，cgroup v1 不支持完整资源限制逻辑。

---

## 2. 需要的 Linux Capabilities

运行 photon-kernel 完整模式需要以下权限；两种运行模式：**直接 root 运行** / **非 root 授予 capabilities**。

### 完整能力集合

```
CAP_SYS_ADMIN      # namespace、pivot_root、mount 操作
CAP_SYS_RESOURCE   # rlimit、cgroup 设置
CAP_BPF            # 加载 eBPF 程序
CAP_PERFMON        # eBPF 监控
CAP_KVM            # Firecracker MicroVM
CAP_SETUID CAP_SETGID CAP_SETPCAP
CAP_MKNOD
CAP_NET_ADMIN      # iptables、网络命名空间、tun 设备
CAP_NET_RAW
CAP_SYS_PTRACE     # 调试/CRIU 快照（可选）
```

> ⚠️ 不建议直接放开全部 `CAP_SYS_ADMIN` 生产；生产尽量使用 capability 白名单，不要用 `privileged: true` 在 K8s。

### 非 root 授权方式示例（开发测试）

```bash
sudo setcap cap_sys_admin,cap_bpf,cap_kvm,cap_net_admin,cap_sys_resource=+ep \
  ./build/photon_sandbox_daemon
```

> **setcap 存在限制**：二进制不能 strip，不能放在 nosuid 挂载点；很多场景简单直接用 root 执行做 e2e 验证。

---

## 3. 系统依赖包安装

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y \
  g++ cmake libgtest-dev \
  libbpf-dev bpfcc-tools clang llvm \
  firecracker \
  criu \
  iproute2 iptables uidmap \
  libcap-dev libssl-dev \
  python3-protobuf python3-grpcio python3-pip
```

### Firecracker 安装

确认 firecracker 二进制在 PATH：

```bash
which firecracker
firecracker --version
```

也可以手动下载官方 release：

```bash
curl -L https://github.com/firecracker-microvm/firecracker/releases/download/v1.7.0/firecracker-v1.7.0-x86_64.tgz | tar xz
sudo cp release-v1.7.0-x86_64/firecracker-v1.7.0-x86_64 /usr/local/bin/firecracker
sudo chmod +x /usr/local/bin/firecracker
```

### CRIU 安装

CRIU 用于进程快照-恢复功能，可选模块，编译可开关 `PHOTON_ENABLE_CRIU=ON/OFF`。

```bash
sudo apt install -y criu
criu --version
sudo criu check --all  # 验证内核支持
```

---

## 4. 编译完整特权版本（开启全部高级模块）

```bash
git clone https://github.com/SandboxDev2026/PhotonBox.git
cd PhotonBox

cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DPHOTON_ENABLE_GRPC=ON \
  -DPHOTON_ENABLE_EBPF=ON \
  -DPHOTON_ENABLE_STRONGPOOL_FIRECRACKER=ON \
  -DPHOTON_ENABLE_CRIU=ON \
  -DPHOTON_ENABLE_LANDLOCK=ON

cmake --build build -j$(nproc)
```

### 编译开关说明

| 编译 Flag | 作用 | 依赖 |
|-----------|------|------|
| `PHOTON_ENABLE_EBPF` | 编译 eBPF 网络拦截程序 | libbpf-dev, clang |
| `PHOTON_ENABLE_STRONGPOOL_FIRECRACKER` | 启用 MicroVM 强隔离后端 | /dev/kvm, firecracker |
| `PHOTON_ENABLE_CRIU` | CRIU 快照恢复功能 | criu 二进制 |
| `PHOTON_ENABLE_LANDLOCK` | 文件系统 Landlock 访问控制 | 内核 ≥ 5.13 |
| `PHOTON_ENABLE_GRPC` | gRPC 服务端/客户端 | libgrpc++-dev, protobuf |

### 容器环境编译（无特权）

当前容器环境无 gRPC C++ 库，使用 Python gRPC 替代：

```bash
cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DPHOTON_ENABLE_GRPC=OFF \
  -DPHOTON_ENABLE_EBPF=ON \
  -DPHOTON_ENABLE_STRONGPOOL_FIRECRACKER=ON \
  -DPHOTON_ENABLE_CRIU=ON \
  -DPHOTON_ENABLE_LANDLOCK=ON

cmake --build build -j$(nproc)
```

---

## 5. 系统配置调优（必须）

### 5.1 sysctl 参数

写入 `/etc/sysctl.d/99-photon-sandbox.conf`：

```ini
# 允许 unprivileged userns（进程沙盒 namespace）
kernel.unprivileged_userns_clone = 1

# pid 最大数量，沙盒会创建大量临时进程
pid.max_pid = 4194304

# 网络调优，隔离网关大量短连接
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1

# vsock 内存
net.vsock.available_memory = 536870912
net.vsock.max_connections = 1024

# eBPF JIT
net.core.bpf_jit_enable = 1
net.core.bpf_jit_harden = 2
```

生效：

```bash
sudo sysctl -p /etc/sysctl.d/99-photon-sandbox.conf
```

### 5.2 cgroup v2 挂载确认

确认 `/sys/fs/cgroup` 是 cgroup2 挂载；如系统混合模式需要切换。

```bash
mount | grep cgroup2
# 预期输出: cgroup2 on /sys/fs/cgroup type cgroup2 (rw,nosuid,nodev,noexec,relatime)

sudo mkdir -p /sys/fs/cgroup/photon_pool
```

photon 守护进程会自动在该路径创建子 cgroup；也可以自定义 cgroup 根路径配置。

### 5.3 用户 ID 映射 uid/gid mapping

user namespace 需要充足的 subuid/subgid，编辑 `/etc/subuid` `/etc/subgid`：

```
root:100000:65536
```

---

## 6. 全套 E2E 验证脚本运行

必须 sudo/root 执行，普通用户只能跑基础单元测试，高级用例直接跳过。

```bash
# 全部特权端到端校验
sudo ./scripts/verify_baremetal.sh

# 分项执行
sudo ./build/test_network_isolation    # eBPF、netns 网络隔离
sudo ./build/test_strong_pool          # Firecracker MicroVM 创建、执行、销毁
sudo ./build/test_four_layer_arch      # 四层控制平面完整链路
sudo ./build/test_agent_orchestrator   # Agent DAG 编排特权链路
sudo ./build/test_microvm_advanced     # 内存气球/暂停恢复/状态分叉/分层镜像
sudo ./build/test_security_hardening   # TaskSpec 校验/密钥管理/解释器白名单
```

### 预期输出

全部用例 PASS；出现 SKIP 说明内核/权限缺失；出现 FAIL 代表环境不满足。

### 常见 SKIP 原因

| SKIP 信息 | 原因 | 解决 |
|-----------|------|------|
| KVM not available | /dev/kvm 缺失，无硬件虚拟化 | 使用裸金属/开启嵌套虚拟化 |
| eBPF load failed | CAP_BPF 缺失或内核 bpf 关闭 | sudo 运行或 setcap cap_bpf |
| Landlock not supported | 内核版本过低 | 升级内核 ≥ 5.13 |
| CRIU not found | criu 未安装 | sudo apt install criu |
| cgroup v2 not available | 系统使用 cgroup v1 | 切换到 cgroup v2 unified |

---

## 7. 特权模式启动守护进程

### 7.1 Sandbox gRPC Daemon（完整特权模式）

```bash
sudo ./build/photon_sandbox_daemon \
  --cgroup-root /sys/fs/cgroup/photon_pool \
  --enable-ebpf-filter true \
  --enable-strong-pool true \
  --firecracker-binary /usr/local/bin/firecracker \
  --max-strong-pool-vm 16 \
  --listen-grpc 0.0.0.0:50051
```

### 关键启动参数

| 参数 | 说明 |
|------|------|
| `--enable-ebpf-filter true` | 加载 eBPF 程序拦截 connect 系统调用，屏蔽内网、元数据地址 |
| `--enable-strong-pool true` | 开启 StrongPool MicroVM 后端；探测不到 KVM 则拒绝高危任务 |
| `--max-strong-pool-vm` | 并发 VM 上限，防止资源耗尽 |
| `--cgroup-root` | 指定 cgroup v2 根目录 |

### 7.2 隔离网关服务（特权）

隔离网关需要操作 netns、iptables，需要 root/CAP_NET_ADMIN：

```bash
sudo python3 server/gateway/isolation_gateway.py \
  --listen 0.0.0.0:8080 \
  --dns-listen 0.0.0.0:53 \
  --dns-server 223.5.5.5 \
  --max-conns 128 \
  --max-bandwidth 200
```

### 7.3 Python gRPC 服务端（容器环境替代 C++ gRPC）

```bash
python3 server/python/sandbox_grpc_server.py --port 50051 &
python3 server/python/sandbox_grpc_client.py --port 50051
```

### 7.4 客户端测试调用

```bash
python3 server/python/sandbox_grpc_client.py --port 50051
```

---

## 8. Kubernetes 部署特权约束

⚠️ **强烈不建议设置 `privileged: true`**，最小权限原则，只添加需要的 capabilities。

### Pod securityContext 示例

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: photon-sandbox
spec:
  containers:
  - name: sandbox
    image: photon-sandbox:latest
    securityContext:
      runAsUser: 0
      capabilities:
        add:
          - SYS_ADMIN
          - SYS_RESOURCE
          - BPF
          - KVM
          - NET_ADMIN
          - NET_RAW
          - SETUID
          - SETGID
    resources:
      limits:
        devices.kubevirt.io/kvm: "1"
    volumeMounts:
      - name: dev-kvm
        mountPath: /dev/kvm
      - name: cgroup
        mountPath: /sys/fs/cgroup
  volumes:
    - name: dev-kvm
      hostPath:
        path: /dev/kvm
    - name: cgroup
      hostPath:
        path: /sys/fs/cgroup
```

### 先决条件 K8s 节点

1. 节点内核满足上述内核配置
2. cgroup v2 开启
3. 节点开启 KVM 设备，`/dev/kvm` 以 hostPath 挂载进 pod
4. vsock 模块加载，`/dev/vsock` 挂载
5. 不兼容大多数托管 K8s，需要裸金属自建集群

CRD、NetworkPolicy 参考目录 `deploy/`。

---

## 9. 模块降级行为说明

当某项特权/内核能力缺失，系统不会崩溃，自动降级逻辑：

| 缺失能力 | 降级行为 | 安全影响 |
|---------|---------|---------|
| KVM 不可用 | StrongPool 完全禁用；高风险代码请求直接拒绝，不会静默降级到 LightPool | 高风险任务无法运行（安全，不降级） |
| CAP_BPF 缺失 | eBPF 网络过滤关闭，回退 iptables+seccomp 兜底策略 | 网络过滤粒度变粗（可接受降级） |
| Landlock 内核未支持 | 文件系统控制回退到 mount 挂载隔离方案 | 路径过滤粒度变粗 |
| CRIU 未编译/权限不足 | 快照功能直接禁用，相关 API 返回 Unavailable 错误 | 任务恢复/状态分叉不可用 |
| cgroup-v2 不可用 | 资源限制部分失效，告警输出日志 | 资源限制失效（需修复） |
| gRPC C++ 库缺失 | 使用 Python gRPC 替代 | 功能完整，性能略低 |

> **重点**：高危任务风险分数 > 70 分，必须 StrongPool；环境不具备则返回错误，不执行。

---

## 10. 安全风险与生产注意事项

1. **LightPool 进程沙盒共享宿主内核**；即使全套特权，LightPool 不能执行完全不可信公网代码；高危代码强制路由 StrongPool MicroVM
2. **Firecracker MicroVM 依旧存在 VM 逃逸攻击面**；定期升级 firecracker 二进制
3. **eBPF 程序在内核态运行**；内核 bug 可能导致逃逸，定期更新宿主 Linux 内核
4. **CAP_SYS_ADMIN 能力权限极高**；沙盒 daemon 进程一旦被攻陷，等同于主机 root 泄露
5. **项目无第三方安全审计报告**；生产上线必须完成：SAST 扫描、渗透测试、漏洞评估
6. **审计日志开启**，所有沙盒执行事件 HMAC 签名落盘；不要关闭审计模块
7. **设置资源硬上限**：CPU、内存、VM 最大数量、执行超时 TTL，防止 DoS 耗尽主机资源
8. **密钥管理**：HMAC 密钥通过环境变量/文件外部注入，禁止硬编码；生产启用密钥轮换
9. **Release-Gate 独立进程**：产物释放闸门必须独立进程运行，不与沙盒执行进程同权限

---

## 11. 常见排错清单

| 错误现象 | 原因 | 解决方案 |
|---------|------|---------|
| `/dev/kvm permission denied` | 没有 KVM 硬件虚拟化，云实例不支持；或者模块未加载 | 使用裸金属/开启嵌套虚拟化；`sudo modprobe kvm_intel` |
| eBPF 加载失败 | 缺少 CAP_BPF；内核 CONFIG_BPF_JIT 未开启 | sudo 运行或 setcap cap_bpf；检查内核配置 |
| Landlock create rules error | 内核版本低于 5.13 | 升级内核 ≥ 5.13 |
| pivot_root permission denied | 缺少 CAP_SYS_ADMIN；挂载目录不能为 nosuid/noexec 特殊挂载 | sudo 运行；检查挂载选项 |
| vsock connect timeout | vhost_vsock 内核模块未加载 | `sudo modprobe vhost_vsock`；检查 `/dev/vsock` |
| cgroup mkdir permission denied | 确认 cgroup v2，daemon 对 cgroup 根目录写权限 | `sudo chown` cgroup 目录或 root 运行 |
| StrongPool VM 启动超时 | 磁盘 IO 压力大；firecracker 二进制版本不匹配；vsock 异常 | 检查磁盘 IO；升级 firecracker；检查 vsock 模块 |
| CRIU dump failed | 非 root 模式限制太多；进程状态复杂 | root 运行 CRIU；简化进程状态 |
| gRPC 连接失败 | C++ gRPC 库未安装；服务端未启动 | 使用 Python gRPC 替代；检查服务端端口 |
| 审计哈希验证失败 | 密钥不一致；日志被篡改 | 确认使用相同 HMAC 密钥；运行 `tools/audit_verify` 检测 |

---

## 12. 相关文档跳转

- [docs/network_defense_in_depth.md](network_defense_in_depth.md) — 三层网络防御设计
- [docs/strong_pool_microvm.md](strong_pool_microvm.md) — StrongPool 安全约束与镜像管理
- [docs/escape_security_audit.md](escape_security_audit.md) — 逃逸风险审计清单
- [docs/four_layer_architecture.md](four_layer_architecture.md) — 四层控制平面架构
- [docs/privilege_requirements.md](privilege_requirements.md) — 权限要求与特权环境说明
- [docs/microvm_advanced_features.md](microvm_advanced_features.md) — AgentENV 四大高级特性
- [PRODUCTION_CHECKLIST.md](../PRODUCTION_CHECKLIST.md) — 生产上线补齐任务清单
- [SECURITY.md](../SECURITY.md) — 安全策略与漏洞响应

---

*最后更新：2026-09-02 | 基于 PhotonBox v414 | 内核要求 ≥ 5.15，推荐 6.1/6.6 LTS*
