# PhotonBox — 基于 KVM 硬件虚拟化的安全隔离沙盒

轻量级、高性能、可审计的代码执行沙盒。**核心隔离底座为 KVM 硬件虚拟化**：每个 StrongPool 实例拥有独立的 Guest 内核，CPU 硬件级隔离内存（Intel VT-x / AMD-V + EPT/NPT），从根本上杜绝进程沙盒的内核逃逸风险。同时提供 LightPool 进程沙盒作为低延迟补充，支持双后端自动切换。

## 架构核心：KVM 硬件虚拟化

PhotonBox 的 StrongPool 后端基于 **KVM (Kernel-based Virtual Machine)** 构建，利用 CPU 硬件虚拟化扩展实现强隔离：

| 隔离维度 | 技术实现 | 安全保证 |
|---------|---------|---------|
| **CPU 隔离** | Intel VT-x / AMD-V，VMX root/non-root 模式 | Guest 代码运行在非根模式，无法直接访问宿主机硬件 |
| **内存隔离** | EPT (Extended Page Tables) / NPT (Nested Page Tables) | Guest 物理地址空间完全独立，硬件级地址翻译隔离 |
| **内核隔离** | 独立 Guest Linux 内核 | 宿主机内核漏洞不影响 Guest，反之亦然 |
| **设备隔离** | 极简 virtio 设备模型（仅 block/net/vsock） | 无 PCI 直通，攻击面极小 |
| **I/O 隔离** | virtio-vsock 通信，无共享内存 | 宿主-Guest 通信经过设备模拟层 |

> **与进程沙盒的本质区别**：LightPool (fork+seccomp) 共享宿主机内核，内核 0day 可逃逸；StrongPool (KVM) 运行独立 Guest 内核，即使 Guest 内核被攻破，仍需突破 KVM + 硬件虚拟化隔离才能到达宿主机。

## 隔离等级与适用场景

| 后端 | 隔离底座 | 启动延迟 | 内存开销 | 适用场景 |
|------|---------|---------|---------|---------|
| **StrongPool** (KVM MicroVM) | **KVM 硬件虚拟化 + 独立 Guest 内核** | <125ms | 5-15MB/实例 | 公网不可信用户代码、多租户、强隔离需求 |
| **LightPool** (fork+seccomp) | 进程级（共享宿主内核） | <2ms（预热池） | 百KB级 | 内网可信/半可信 Agent 代码、低延迟高吞吐 |

> **安全原则**：高风险任务绝不静默降级到进程沙盒。KVM 不可用时，HIGH/CRITICAL 风险任务直接拒绝执行。

## 快速开始

### 构建

```bash
# 依赖：g++ >=9, cmake >=3.14, googletest
cmake -B build -DCMAKE_BUILD_TYPE=Release -DPHOTON_ENABLE_GRPC=OFF
cmake --build build -j$(nproc)
```

### 运行测试

```bash
./build/test_sandbox              # 基础沙盒
./build/test_enhanced             # 增强模块（含 CRIU 跳过用例）
./build/test_new_modules          # 新模块
./build/test_agent_orchestrator   # 多智能体编排
./build/test_four_layer_arch      # 四层控制平面
./build/test_network_isolation    # 网络防御
./build/test_strong_pool          # StrongPool (KVM) 调度
python3 tests/test_operator.py    # K8s Operator
```

### 一键全量验证

```bash
./scripts/verify_all.sh                # 当前环境验证
sudo ./scripts/verify_baremetal.sh     # 裸机特权环境（含 KVM）端到端验证
```

### KVM 环境检查

```bash
# 检查 CPU 硬件虚拟化支持
grep -E 'vmx|svm' /proc/cpuinfo

# 检查 KVM 设备
ls -la /dev/kvm

# 检查 KVM 内核模块
lsmod | grep kvm

# 检查嵌套虚拟化（云环境）
cat /sys/module/kvm_intel/parameters/nested 2>/dev/null || echo "nested not available"
```

### gRPC 服务（Python 实现，已端到端实测）

```bash
pip install grpcio grpcio-tools protobuf
python3 server/python/sandbox_grpc_server.py --port 50051 &
python3 server/python/sandbox_grpc_client.py --port 50051
```

> C++ gRPC 服务端代码已完整实现，但需安装 `libgrpc++-dev` 后编译验证。当前环境使用 Python gRPC 作为生产替代方案。

### 隔离网关服务

```bash
sudo python3 server/gateway/isolation_gateway.py \
  --listen 0.0.0.0:8080 --dns-listen 0.0.0.0:53 \
  --dns-server 8.8.8.8 --max-conns 64 --max-bandwidth 100
```

## 核心特性

### KVM 硬件虚拟化引擎 (StrongPool)
- **独立 Guest 内核**：每个 MicroVM 运行完整的 Linux 内核，与宿主机内核完全隔离
- **CPU 硬件隔离**：Intel VT-x / AMD-V，VMX non-root 模式执行 Guest 代码
- **EPT/NPT 内存隔离**：硬件级二级地址翻译，Guest 无法访问宿主机物理内存
- **极简设备模型**：仅 virtio-block / virtio-net / virtio-vsock，无 PCI 直通
- **KVM 探测**：运行时检测 /dev/kvm + CPU vmx/svm + firecracker
- **高风险拒绝**：KVM 不可用时 HIGH/CRITICAL 直接拒绝，绝不静默降级
- **并发上限**：max_concurrent_vms + 排队 + TTL 强制终止
- **产物导出**：vsock 通道 + SHA256 + Evidence 证据链
- **工作区管理**：输入只读镜像注入 + 输出 diff 导出
- **临时磁盘**：tmpfs-backed 块设备，VM 销毁即释放

### 执行引擎 (LightPool)
- **预 fork 预热池**：p99 < 2ms，seccomp-ready worker 复用
- **任意代码执行**：Python/Node 解释器预置，stdin 传入执行
- **8 项 rlimit**：CPU/内存/文件数/进程数/CORE/NOFILE/SIGPENDING/MSGQUEUE
- **cgroup v2**：CPU/内存/IO 资源限制

### 隔离与安全
- **6 种 namespace**：mount+pivot_root+pid+net+uts+ipc+user（CLONE_NEWUSER+uid/gid 映射）
- **seccomp-bpf**：系统调用白名单，PR_SET_NO_NEW_PRIVS，非法调用直接 KILL_PROCESS
- **Landlock**：文件路径白名单（内核 >=5.13）
- **CapabilityToken**：票据式动态权限，HMAC-SHA256 签名防篡改，运行时可撤销
- **ResourceProxy**：CredentialVault 密钥保险箱 + 空白通行证（无权限返回虚拟数据）
- **ReleaseGate**：独立低权限进程（setuid nobody + seccomp-bpf），产物释放前强制校验

### 网络三层防御
- **网段隔离**：K8s NetworkPolicy，沙盒池独立子网
- **网关隔离**：独立可运行网关服务，域名白名单+限流+DNS劫持+HMAC审计
- **内网隔离**：eBPF cgroup/connect4 内置 RFC1918+云元数据黑名单，seccomp/iptables 兜底

### 审计与合规
- **HMAC 哈希链**：审计记录防篡改，SHA256 纯 C++ 实现（零外部依赖）
- **gRPC ClientStreaming**：批量异步上报，失败本地落盘重试
- **法案合规引擎**：22 条合规规则检查
- **Evidence+Release**：证据收集 + 独立发布闸门（5 项检查）
- **磁盘水位守卫**：4 级水位监控（NORMAL/WARNING/CRITICAL/EMERGENCY），spool 队列溢出保护

### 可插拔运行时
- **4 种运行时**：Container / gVisor / MicroVM(KVM) / Wasm
- **RuntimeSelector**：评分矩阵 + 加权评分 + 硬约束
- **RiskScorer**：15+ 危险模式静态扫描，0-100 分，自动推荐安全域
- **RiskEnforcer**：6 种任务来源分类，不可信输入强制 StrongPool，业务层二次校验

### 多智能体编排
- **Supervisor 总控**：任务拆解/分配/汇总
- **Actor 消息总线**：所有消息接入 HMAC 审计链
- **Environment 代理层**：工具调用经过 CapabilityToken 校验
- **TaskDAG**：任务依赖图调度

### 遗传算法与自进化
- **GA 主循环**：种群初始化→评估→锦标赛选择→变异交叉→精英保留→更新
- **三种变异模式**：rewrite 完整重写 / patch 局部 diff / nl_feedback 失败驱动
- **LLM 语义交叉**：不是字符串拼接，由大模型吸收两份代码优点
- **岛屿 GA**：多子种群独立演化 + 定期迁移，防止局部最优
- **自进化闭环**：执行层→反思层→生成层→评测层→版本快照
- **Skill 技能库**：版本管理 + 进化 + 回滚 + 评分历史
- **安全约束**：所有代码执行通过沙盒，禁止本地 exec/eval，适应度含安全惩罚

## 模块验证状态矩阵

| 模块 | 单元测试 | 端到端实测 | 环境要求 | 状态 |
|------|---------|-----------|---------|------|
| StrongPool (KVM MicroVM) | 通过 | 需 KVM | /dev/kvm + firecracker | 代码完整，待 KVM 验证 |
| 基础沙盒 (fork+seccomp) | 通过 | 已实测 | 无 | 生产可用 |
| 预热池 | - | 已实测 <2ms | 无 | 生产可用 |
| namespace 隔离 | 通过 | 需 root | CAP_SYS_ADMIN | 代码完整，待特权验证 |
| cgroup v2 | - | 需可写 cgroup | cgroup v2 | 代码完整 |
| Landlock | - | 已实测 (kernel 6.6) | 内核 >=5.13 | 生产可用 |
| eBPF 网络管控 | 编译通过 | 需 CAP_BPF | libbpf + CAP_BPF | 代码完整，待特权验证 |
| CRIU 快照 | 逻辑通过 | 需 criu+root | criu 二进制 | 代码完整，待特权验证 |
| gRPC (Python) | - | 8 项端到端 | grpcio | 生产可用 |
| gRPC (C++) | 编译通过 | 需 libgrpc++-dev | gRPC C++ 库 | 代码完整，Python 已替代 |
| K8s Operator | 通过 | 需 K8s 集群 | kind/minikube | 代码完整，待集群验证 |
| E2B 网关 | - | 已实测 | Python | 生产可用 |
| Prometheus metrics | - | 已实测 | 无 | 生产可用 |
| 隔离网关服务 | 通过 | 可运行 | Python | 生产可用 |
| 审计 HMAC 链 | - | 已实测 | 无 | 生产可用 |
| ReleaseGate 独立进程 | 通过 | 已实测 | 无 | 生产可用 |
| 遗传算法+自进化 | 通过 (42项) | 需沙盒服务 | PhotonBox HTTP API | 代码完整，测试通过 |
| Fuzz 测试 | - | 38 cases 通过 | clang/libFuzzer | 手动模式已通过 |

> 完整 KVM 验证步骤见 `docs/privileged_e2e_guide.md` 和 `scripts/verify_baremetal.sh`。

## KVM 硬件虚拟化深度解析

### CPU 虚拟化：VMX root / non-root 模式

```
┌─────────────────────────────────────────────────┐
│                   宿主机 (VMX root)               │
│  ┌─────────────────────────────────────────────┐ │
│  │            KVM 内核模块                       │ │
│  │  - VMCS (Virtual Machine Control Structure) │ │
│  │  - EPT 页表管理                              │ │
│  │  - 中断注入                                  │ │
│  └─────────────────────────────────────────────┘ │
│         │ VM exit / VM entry                      │
│  ┌──────▼──────────────────────────────────────┐ │
│  │          Guest (VMX non-root)                │ │
│  │  ┌────────────────────────────────────────┐ │ │
│  │  │          Guest Linux 内核               │ │ │
│  │  │  - 独立进程调度                          │ │ │
│  │  │  - 独立内存管理                          │ │ │
│  │  │  - 独立系统调用表                        │ │ │
│  │  └────────────────────────────────────────┘ │ │
│  │  ┌────────────────────────────────────────┐ │ │
│  │  │          用户代码 (沙盒内)              │ │ │
│  │  └────────────────────────────────────────┘ │ │
│  └─────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
```

### 内存隔离：EPT (Extended Page Tables)

传统进程沙盒依赖页表权限位（NX/只读）隔离内存，但共享同一物理地址空间。KVM 使用 EPT 实现**硬件级二级地址翻译**：

1. **Guest 虚拟地址** → (Guest 页表) → **Guest 物理地址**
2. **Guest 物理地址** → (EPT 页表，CPU 硬件遍历) → **宿主机物理地址**

Guest 内核只能管理 Guest 物理地址空间，无法直接访问宿主机物理内存。即使 Guest 内核被攻破，EPT 隔离仍然有效。

### 为什么 KVM 比进程沙盒安全

| 攻击面 | 进程沙盒 (fork+seccomp) | KVM MicroVM |
|--------|------------------------|-------------|
| 内核漏洞 | 共享宿主内核，直接逃逸 | Guest 内核独立，需先破 Guest 再破 KVM |
| 内存隔离 | 页表权限位（软件） | EPT/NPT（硬件） |
| CPU 隔离 | 同一内核调度 | VMX non-root 模式 |
| 系统调用 | seccomp 过滤（可绕过） | Guest 独立 syscall 表 |
| 设备访问 | 共享 /dev | 极简 virtio 设备 |
| 逃逸难度 | 内核 0day 即可 | 需 Guest 内核 0day + KVM 0day + 硬件漏洞 |

## 目录结构

```
PhotonBox/
├── include/photon_kernel/sandbox/   # 头文件
│   ├── sandbox.hpp                   # 核心沙盒
│   ├── sandbox_pool_v2.hpp           # 预热池
│   ├── namespace_isolation.hpp       # namespace 隔离
│   ├── seccomp_filter.hpp            # seccomp
│   ├── landlock.hpp                  # Landlock
│   ├── cgroup_manager.hpp            # cgroup v2
│   ├── capability_token.hpp          # 票据权限
│   ├── resource_proxy.hpp            # 资源代理
│   ├── risk_scorer.hpp               # 风险打分
│   ├── risk_enforcer.hpp             # 风险强制
│   ├── network_isolation.hpp         # 内网隔离
│   ├── isolation_gateway.hpp         # 隔离网关(C++库)
│   ├── strong_pool.hpp               # StrongPool (KVM) 调度
│   ├── artifact_export.hpp           # 产物导出/工作区
│   ├── sandbox_backend.hpp           # 后端抽象
│   ├── runtime_interface.hpp         # 4种运行时
│   ├── runtime_selector.hpp          # 运行时选型
│   ├── task_spec.hpp                 # 任务规范
│   ├── policy_engine.hpp             # 策略引擎
│   ├── evidence_release.hpp          # 证据/发布闸门
│   ├── audit_logger.hpp              # 审计日志
│   ├── audit_disk_guard.hpp          # 磁盘水位守卫
│   └── risk_level.hpp                # 风险等级统一
├── src/sandbox/                       # 实现
├── tests/                             # 测试
├── evolution/                         # 遗传算法+自进化Agent
├── agent/                             # 多智能体编排
├── server/
│   ├── python/                        # Python gRPC 服务端(已实测)
│   ├── gateway/                       # 隔离网关服务(可运行)
│   └── e2b_gateway.cpp                # E2B 兼容网关
├── ebpf/                              # eBPF 程序(内置内网黑名单)
├── operator/                          # K8s Operator (kopf)
├── deploy/                            # K8s 部署 + 监控配置
│   └── monitoring/                    # Grafana dashboard + Prometheus alerts
├── scripts/                           # 构建/验证/CVE监控
├── docs/                              # 设计文档
│   ├── security/                      # 安全审计报告
│   └── operations/                    # 运维文档(应急响应runbook)
├── reports/                           # 安全报告/SBOM
└── CMakeLists.txt
```

## 安全声明

### 已知安全边界
- **LightPool 进程后端共享宿主内核**：基于 namespace/seccomp/Landlock，共享宿主机 Linux 内核。内核漏洞可能导致沙盒逃逸。**公网不可信代码必须使用 StrongPool (KVM MicroVM)**，LightPool 仅限内网可信/半可信场景。
- **StrongPool KVM 后端仍有攻击面**：包含 Firecracker VMM、KVM 内核模块、virtio 设备驱动。存在漏洞可能性，需定期升级。但攻击面远小于进程沙盒。
- **高级特性需特权环境**：CRIU/eBPF/K8s/Firecracker 需对应权限，无权限时自动降级并上报告警。高风险任务在 KVM 不可用时直接拒绝，不静默降级。
- **单人维护项目**：无第三方安全审计，建议在生产环境前进行独立安全评估（SAST 扫描、渗透测试、漏洞评估）。

### 安全响应
- 漏洞报告：见 `SECURITY.md`
- CVE 监控：`python3 scripts/cve_monitor.py`（持续监控内核及依赖相关 CVE）
- SBOM：`reports/sbom.cyclonedx.json`（CycloneDX 1.5 格式）
- 风险评估：`RISK_ASSESSMENT.md`（22 项风险，P0/P1/P2 等级追踪）
- 生产检查清单：`PRODUCTION_CHECKLIST.md`（上线前自检）
- seccomp 审计：`docs/security/seccomp_audit_report.md`
- 应急响应：`docs/operations/incident_response_runbook.md`

## 文档索引

| 文档 | 内容 |
|------|------|
| `docs/network_defense_in_depth.md` | 网络三层防御完整设计 |
| `docs/strong_pool_microvm.md` | StrongPool (KVM) 三大限制解决方案 |
| `docs/four_layer_architecture.md` | 四层控制平面架构 |
| `docs/microvm_integration.md` | Firecracker/KVM 集成设计 |
| `docs/escape_security_audit.md` | 逃逸安全审计报告 |
| `docs/privileged_e2e_guide.md` | 特权环境（含 KVM）端到端验证指南 |
| `docs/privilege_requirements.md` | 权限要求与特权环境说明 |
| `docs/microvm_advanced_features.md` | MicroVM 高级特性 |
| `docs/security/seccomp_audit_report.md` | seccomp 白名单人工审计报告 |
| `docs/operations/incident_response_runbook.md` | 应急响应 Runbook |
| `deploy/monitoring/grafana_dashboard.json` | Grafana 监控面板 |
| `deploy/monitoring/prometheus_alerts.yml` | Prometheus 告警规则 |
| `docs/CHANGELOG.md` | 版本变更历史 |
| `SECURITY.md` | 安全策略与漏洞响应 |
| `CONTRIBUTING.md` | 贡献指南 |

## 许可证

Apache-2.0
