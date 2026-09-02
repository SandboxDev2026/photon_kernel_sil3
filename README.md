# photon_kernel_sil3 — C++17 安全隔离沙盒

轻量级、高性能、可审计的代码执行沙盒。基于 `fork + seccomp-bpf + namespace + eBPF`，支持双后端（进程沙盒 / Firecracker MicroVM），提供完整的网络三层防御和审计证据链。

## 隔离等级与适用场景

| 后端 | 隔离强度 | 启动延迟 | 内存开销 | 适用场景 |
|------|---------|---------|---------|---------|
| **LightPool** (fork+seccomp) | 进程级（共享内核） | <2ms（预热池） | 百KB级 | 内网可信/半可信 Agent 代码 |
| **StrongPool** (Firecracker MicroVM) | 内核级（独立内核） | <125ms | 5-15MB/实例 | 公网不可信用户代码 |

> **安全原则**：高风险任务绝不静默降级到进程沙盒。KVM 不可用时，HIGH/CRITICAL 风险任务直接拒绝。

## 快速开始

### 构建

```bash
# 依赖：g++ >=9, cmake >=3.14, googletest
cmake -B build -DCMAKE_BUILD_TYPE=Release -DPHOTON_ENABLE_GRPC=OFF
cmake --build build -j$(nproc)
```

### 运行测试

```bash
./build/test_sandbox              # 基础沙盒 8 测试
./build/test_enhanced             # 增强模块 77 测试 (+2 跳过 CRIU)
./build/test_new_modules          # 新模块 23 测试
./build/test_agent_orchestrator   # 多智能体 11 测试
./build/test_four_layer_arch      # 四层架构 23 测试
./build/test_network_isolation    # 网络防御 22 测试
./build/test_strong_pool          # StrongPool 15 测试
python3 tests/test_operator.py    # K8s Operator 14 测试
```

### 一键全量验证

```bash
./scripts/verify_all.sh                # 当前环境验证
sudo ./scripts/verify_baremetal.sh     # 裸机特权环境 10 模块端到端
```

### gRPC 服务端（Python，已端到端实测）

```bash
pip install grpcio grpcio-tools protobuf
python3 server/python/sandbox_grpc_server.py --port 50051 &
python3 server/python/sandbox_grpc_client.py --port 50051
```

### 隔离网关服务

```bash
sudo python3 server/gateway/isolation_gateway.py \
  --listen 0.0.0.0:8080 --dns-listen 0.0.0.0:53 \
  --dns-server 8.8.8.8 --max-conns 64 --max-bandwidth 100
```

## 核心特性

### 执行引擎
- **预 fork 预热池**：p99 < 2ms，seccomp-ready worker 复用
- **任意代码执行**：Python/Node 解释器预置，stdin 传入执行
- **8 项 rlimit**：CPU/内存/文件数/进程数/CORE/NOFILE/SIGPENDING/MSGQUEUE
- **cgroup v2**：CPU/内存/IO 资源限制

### 隔离与安全
- **6 种 namespace**：mount+pivot_root+pid+net+uts+ipc+user（CLONE_NEWUSER+uid/gid 映射）
- **seccomp-bpf**：系统调用白名单，PR_SET_NO_NEW_PRIVS
- **Landlock**：文件路径白名单
- **CapabilityToken**：票据式动态权限，HMAC-SHA256 签名防篡改，运行时可撤销
- **ResourceProxy**：CredentialVault 密钥保险箱 + 空白通行证（无权限返回 sk-dummy）

### 网络三层防御
- **网段隔离**：K8s NetworkPolicy，沙盒池独立子网
- **网关隔离**：独立可运行网关服务，域名白名单+限流+DNS劫持+HMAC审计
- **内网隔离**：eBPF cgroup/connect4 内置 RFC1918+云元数据黑名单，seccomp/iptables 兜底

### 审计与合规
- **HMAC 哈希链**：审计记录防篡改，SHA256 纯 C++ 实现（零外部依赖）
- **gRPC ClientStreaming**：批量异步上报，失败本地落盘重试
- **法案合规引擎**：22 条合规规则检查
- **Evidence+Release**：证据收集 + 独立发布闸门（5 项检查）

### 可插拔运行时
- **4 种运行时**：Container / gVisor / MicroVM / Wasm
- **RuntimeSelector**：评分矩阵 + 加权评分 + 硬约束
- **RiskScorer**：15+ 危险模式静态扫描，0-100 分，自动推荐安全域

### 多智能体编排
- **Supervisor 总控**：任务拆解/分配/汇总
- **Actor 消息总线**：所有消息接入 HMAC 审计链
- **Environment 代理层**：工具调用经过 CapabilityToken 校验
- **TaskDAG**：任务依赖图调度

### StrongPool (MicroVM)
- **KVM 探测**：运行时检测 /dev/kvm + CPU vmx/svm + firecracker
- **高风险拒绝**：KVM 不可用时 HIGH/CRITICAL 直接拒绝，绝不静默降级
- **并发上限**：max_concurrent_vms + 排队 + TTL 强制终止
- **产物导出**：vsock 通道 + SHA256 + Evidence 证据链
- **工作区管理**：输入只读镜像注入 + 输出 diff 导出
- **临时磁盘**：tmpfs-backed 块设备，VM 销毁即释放

## 模块验证状态矩阵

| 模块 | 单元测试 | 端到端实测 | 环境要求 | 状态 |
|------|---------|-----------|---------|------|
| 基础沙盒 (fork+seccomp) | 8 | 已实测 | 无 | 生产可用 |
| 预热池 | - | 已实测 <2ms | 无 | 生产可用 |
| namespace 隔离 | 6 | 需 root | CAP_SYS_ADMIN | 代码完整，待特权验证 |
| cgroup v2 | - | 需可写 cgroup | cgroup v2 | 代码完整 |
| Landlock | - | 已实测 (kernel 6.6) | 内核 >=5.13 | 生产可用 |
| eBPF 网络管控 | 编译通过 | 需 CAP_BPF | libbpf + CAP_BPF | 代码完整，待特权验证 |
| CRIU 快照 | 逻辑通过 | 需 criu+root | criu 二进制 | 代码完整，待特权验证 |
| gRPC (Python) | - | 8 项端到端 | grpcio | 生产可用 |
| gRPC (C++) | 编译通过 | 需 libgrpc++-dev | gRPC C++ 库 | 代码完整，Python 已替代 |
| K8s Operator | 14 | 需 K8s 集群 | kind/minikube | 代码完整，待集群验证 |
| Firecracker MicroVM | 15 | 需 KVM | /dev/kvm + firecracker | 代码完整，待 KVM 验证 |
| E2B 网关 | - | 已实测 | Python | 生产可用 |
| Prometheus metrics | - | 已实测 | 无 | 生产可用 |
| 隔离网关服务 | 7 | 可运行 | Python | 生产可用 |
| 审计 HMAC 链 | - | 已实测 | 无 | 生产可用 |

> 完整验证步骤见 `docs/privileged_e2e_guide.md` 和 `scripts/verify_baremetal.sh`。

## 目录结构

```
photon_kernel_sil3_v414/
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
│   ├── network_isolation.hpp         # 内网隔离
│   ├── isolation_gateway.hpp         # 隔离网关(C++库)
│   ├── strong_pool.hpp               # StrongPool 调度
│   ├── artifact_export.hpp           # 产物导出/工作区
│   ├── sandbox_backend.hpp           # 后端抽象
│   ├── runtime_interface.hpp         # 4种运行时
│   ├── runtime_selector.hpp          # 运行时选型
│   ├── task_spec.hpp                 # 任务规范
│   ├── policy_engine.hpp             # 策略引擎
│   ├── evidence_release.hpp          # 证据/发布闸门
│   └── audit_logger.hpp              # 审计日志
├── src/sandbox/                       # 实现
├── tests/                             # 测试 (179 通过 + 2 跳过)
├── agent/                             # 多智能体编排
├── server/
│   ├── python/                        # Python gRPC 服务端(已实测)
│   ├── gateway/                       # 隔离网关服务(可运行)
│   └── e2b_gateway.cpp                # E2B 兼容网关
├── ebpf/                              # eBPF 程序(内置内网黑名单)
├── operator/                          # K8s Operator (kopf)
├── deploy/                            # K8s 部署 (NetworkPolicy/CRD)
├── scripts/                           # 构建/验证/CVE监控
├── docs/                              # 设计文档
├── reports/                           # 安全报告/SBOM
└── CMakeLists.txt
```

## 安全声明

### 已知安全边界
- **进程后端共享宿主内核**：不适合直接跑公网完全不可信代码，公网高危代码必须使用 StrongPool (MicroVM)
- **高级特性需特权环境**：CRIU/eBPF/K8s/Firecracker 需对应权限，无权限时自动降级
- **单人维护项目**：无第三方安全审计，建议在生产环境前进行独立安全评估

### 安全响应
- 漏洞报告：见 `SECURITY.md`
- CVE 监控：`python3 scripts/cve_monitor.py`（10 个已知相关 CVE，含影响分析）
- SBOM：`reports/sbom.cyclonedx.json`（12 个组件，CycloneDX 1.5）

## 文档索引

| 文档 | 内容 |
|------|------|
| `docs/network_defense_in_depth.md` | 网络三层防御完整设计 |
| `docs/strong_pool_microvm.md` | StrongPool 三大限制解决方案 |
| `docs/four_layer_architecture.md` | 四层控制平面架构 |
| `docs/microvm_integration.md` | Firecracker 集成设计 |
| `docs/escape_security_audit.md` | 逃逸安全审计报告 |
| `docs/privileged_e2e_guide.md` | 特权环境端到端验证指南 |
| `docs/privilege_requirements.md` | 权限要求与特权环境说明（KVM/CAP_BPF/CRIU/LightPool） |
| `docs/microvm_advanced_features.md` | AgentENV 四大高级特性（内存气球/暂停恢复/状态分叉/分层镜像） |
| `docs/CHANGELOG_full.md` | 完整变更历史 |
| `SECURITY.md` | 安全策略与漏洞响应 |
| `CONTRIBUTING.md` | 贡献指南 |

## 许可证

Apache-2.0
