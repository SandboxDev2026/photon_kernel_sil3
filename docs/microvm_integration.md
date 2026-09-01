# MicroVM 强隔离集成设计

## 问题：当前隔离等级有限

当前工程基于 `fork + seccomp + rlimit + cgroup` 的**进程级隔离**：
- 沙盒子进程与宿主共享同一内核
- 内核漏洞（如 Dirty Pipe、io_uring 漏洞）可导致沙盒逃逸
- 不适合直接运行公网完全不可信代码

**适用场景**：可信/半可信代码、内部工具、Agent 沙盒、CI/CD 隔离
**不适用场景**：公网多租户、完全不可信代码、需要强隔离的安全计算

## 解决方案：MicroVM 强隔离

集成 Firecracker（AWS Lambda 同款）或 cloud-hypervisor，实现：
- 每个沙盒 = 一个轻量虚拟机（独立内核）
- 启动时间 <125ms（Firecracker）
- 内存开销 <5MB（MicroVM 开销）
- 内核漏洞无法逃逸到宿主

## 架构设计

```
                    ┌─────────────────────────────┐
                    │     SandboxExecutor 接口      │
                    │  (execute / create / destroy) │
                    └───────────┬─────────────────┘
                                │
                 ┌──────────────┴──────────────┐
                 │                             │
        ┌────────▼────────┐          ┌────────▼────────┐
        │  ProcessSandbox  │          │   MicroVMSandbox │
        │  (fork+seccomp)  │          │  (Firecracker)   │
        │  启动 <2ms        │          │  启动 <125ms      │
        │  共享内核          │          │  独立内核          │
        └───────────────────┘          └───────────────────┘
```

## 适配层接口

```cpp
// include/photon_kernel/sandbox/sandbox_backend.hpp
enum class SandboxBackend {
    PROCESS,   // fork+seccomp（当前，轻量快速）
    MICROVM,   // Firecracker（强隔离，启动稍慢）
};

class ISandboxBackend {
public:
    virtual ~ISandboxBackend() = default;
    virtual SandboxResult execute(const CodeRunRequest& req) = 0;
    virtual SandboxHandle create(const SandboxConfig& cfg) = 0;
    virtual void destroy(SandboxHandle handle) = 0;
    virtual BackendStatus status() const = 0;
};
```

## Firecracker 集成要点

### 1. 依赖
```bash
# 下载 Firecracker
curl -L https://github.com/firecracker-microvm/firecracker/releases/download/v1.7.0/firecracker-v1.7.0-x86_64.tgz | tar xz
sudo mv firecracker-v1.7.0-x86_64 /usr/local/bin/firecracker

# 下载内核镜像（5.10+）
# 下载 rootfs（alpine 最小镜像）
```

### 2. 启动流程
1. 创建 TAP 网络设备（可选，无网络模式可跳过）
2. 启动 firecracker 进程（--api-sock /tmp/fc.sock）
3. 通过 REST API 配置：内核路径、rootfs 路径、内存大小、vCPU 数
4. 通过 API 启动虚拟机（InstanceStart）
5. 通过 vsock 或 serial console 传入代码执行
6. 执行完成后销毁虚拟机（kill firecracker 进程）

### 3. 代码执行方式
- **方式 A（推荐）**：通过 vsock  vsock 通道，虚拟机内运行 agent 接收代码并执行
- **方式 B（简单）**：将代码写入 rootfs，启动时自动执行，输出通过 serial console 捕获
- **方式 C（快速）**：使用 firecracker 的 `--config-file` 预配置，配合 init 脚本执行代码

## 性能对比

| 维度 | Process Sandbox | MicroVM (Firecracker) |
|---|---|---|
| 启动时间 | <2ms | <125ms |
| 内存开销 | ~100KB | ~5MB |
| 隔离等级 | 进程级（共享内核） | 硬件级（独立内核） |
| 内核漏洞逃逸 | 可能 | 极难 |
| 适合场景 | 可信/半可信代码 | 公网不可信代码 |
| 网络隔离 | seccomp 禁止 socket | TAP 设备 + iptables/nftables |
| 文件系统隔离 | Landlock/chroot | 独立 rootfs（只读） |

## 迁移路径

1. **Phase 1（当前）**：Process Sandbox，适合内部可信代码
2. **Phase 2**：实现 MicroVMSandbox 适配层，支持 Firecracker
3. **Phase 3**：根据风险等级自动选择后端（LOW→Process，HIGH→MicroVM）
4. **Phase 4**：MicroVM 快照恢复（Firecracker snapshot），进一步降低启动延迟

## 安全建议

- 公网多租户场景：**必须使用 MicroVM**，Process Sandbox 不够
- 内部可信场景：Process Sandbox 足够，性能更好
- 混合场景：按风险等级选择后端，高风险代码自动走 MicroVM
- 无论哪种后端，都应启用：审计日志、资源限制、超时 kill、监控告警

## 参考实现

- Firecracker: https://github.com/firecracker-microvm/firecracker
- cloud-hypervisor: https://github.com/cloud-hypervisor/cloud-hypervisor
- gVisor（用户态内核，另一种强隔离方案）: https://gvisor.dev/
- Kata Containers（OCI 兼容 MicroVM）: https://katacontainers.io/
