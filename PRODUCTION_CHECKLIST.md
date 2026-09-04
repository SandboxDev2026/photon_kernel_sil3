# 生产上线补齐任务清单 (PRODUCTION_CHECKLIST)

> **[2026-09-05 更新] LightPool 安全加固四项任务已完成**：
> - ✅ seccomp-BPF 双模式规则集（default_mode / untrusted_code_mode，8类高危syscall禁用 + clone namespace参数过滤 + KILL_PROCESS兜底 + 审计埋点）
> - ✅ 制度性红蓝对抗测试库（tests/redblue/，5个红队POC + 报告模板 + 一键执行脚本 + PR准入规则）
> - ✅ 安全测试用例集（tests/test_lightpool_security.cpp，20个测试：seccomp安全8 + 资源隔离4 + 逃逸路径4 + 审计完整性4）
> - ✅ strace syscall采集工具（scripts/strace_syscall_collector.sh，用于裁剪白名单）
> - ✅ GitHub Actions 定时合规收集 workflow（docs/compliance-collect-workflow.yml，需手动放置）
> - 测试：20/20 LightPool安全测试通过 | Python 690/690通过 | SAST 0问题
>
> **[2026-09-02 更新] P0 代码层安全加固已完成**：
> - ✅ TaskSpec 严格校验器、Release-Gate独立进程、CapabilityToken密钥轮换、解释器白名单seccomp内核强制
>
> **剩余 P0（需裸机/特权环境）**：StrongPool+eBPF裸机验证、内网拦截对抗测试、CRIU快照验证

---

# 生产上线补齐任务清单 (PRODUCTION_CHECKLIST)

> **前提**：Modified MIT 许可证原型，不能直接对公网跑不可信代码。本清单全部为补齐项。
>
> **五大块**：特权模块验证 → 安全加固 → 可靠性与压测 → 运维可观测 → 业务适配
>
> **状态标记**：⬜ 待完成 | 🔄 进行中 | ✅ 已完成 | ⚠️ 部分完成 | ❌ 阻塞

---

## 一、特权模块端到端验证（最高优先级）

> 当前状态：代码写完、单元测试过，缺少裸机真实环境跑通。

### 1.1 StrongPool Firecracker MicroVM

| 项 | 验证内容 | 状态 |
|----|---------|------|
| 全链路 | KVM环境完整跑通：创建→执行→产物导出→销毁 | ⬜ |
| 安全降级 | 无KVM时，高风险TaskSpec直接拒绝任务，禁止静默降级到LightPool | ⚠️ 代码已实现，待裸机验证 |
| 快照池稳定性 | 反复快照-克隆，检查内存泄漏、fd泄漏、僵尸VM残留 | ⬜ |
| 安全验证 | 禁止宿主机RW目录直通VM；只允许只读镜像 + vsock导出产物 | ⚠️ 代码已实现，待验证 |
| 压力测试 | 并发几百VM长时间运行，检查内存、句柄、僵尸实例泄漏 | ⬜ |

### 1.2 eBPF 网络过滤模块

| 项 | 验证内容 | 状态 |
|----|---------|------|
| 基础拦截 | CAP_BPF环境加载eBPF钩子，验证拦截内网CIDR、169.254元地址 | ⚠️ 代码已实现（内置16条黑名单），待CAP_BPF验证 |
| 降级逻辑 | 没有CAP_BPF，关闭eBPF，切seccomp兜底，指标上报降级 | ⚠️ 代码已实现，待验证 |
| 边界测试 | ipv4/ipv6、DNS隧道、各种畸形connect参数 | ⬜ |
| 审计集成 | 网络五元组完整送入审计链 | ⚠️ 代码已实现（target_ip/target_port字段） |

### 1.3 CRIU 快照/恢复

| 项 | 验证内容 | 状态 |
|----|---------|------|
| 状态还原 | 验证进程快照恢复完整，资源限制、namespace上下文是否正确还原 | ⬜ 需criu二进制+root |
| 安全排除 | 快照不能泄露上一个任务内存残留信息 | ⬜ |
| 使用边界 | 仅用于任务恢复，禁止租户长期持有快照实例 | ⬜ 需文档+代码约束 |

### 1.4 C++ gRPC 服务端 + 流式审计上报

| 项 | 验证内容 | 状态 |
|----|---------|------|
| 流式上报 | gRPC流式审计上报跑通 | ⚠️ Python版已端到端，C++版需libgrpc++-dev |
| 失败落盘 | 上报失败本地spool文件落盘、重试、旧文件轮转清理 | ⚠️ 代码已实现，待验证 |
| 溢出保护 | spool队列溢出保护，防止磁盘被审计日志打满 | ⚠️ 代码已实现（max_artifact_size模式），待审计spool专项 |

---

## 二、安全加固（沙盒类组件重中之重）

### 2.1 LightPool 进程沙盒加固

| 项 | 验证内容 | 状态 |
|----|---------|------|
| seccomp双模式 | default_mode / untrusted_code_mode 双模式规则集，untrusted禁用8类高危syscall | ✅ 已完成 (seccomp_policy.hpp/cpp) |
| seccomp参数过滤 | clone禁止CLONE_NEWNS/NEWUSER/NEWPID/NEWNET，openat标记写访问配合eBPF/Landlock | ✅ 已完成 |
| seccomp兜底 | 白名单之外全部SECCOMP_RET_KILL_PROCESS（不使用TRAP避免信号绕过） | ✅ 已完成 |
| seccomp审计埋点 | SeccompViolationEvent记录pid/syscall号/参数/时间戳，log_violation()上报 | ✅ 已完成 |
| seccomp规则快照 | generate_snapshot_json() + SHA256哈希，用于合规证据收集 | ✅ 已完成 |
| 高危调用 | 拒绝 ptrace、kexec_load、mount、init_module、open_by_handle_at 等 | ✅ untrusted_mode已禁用 |
| 白名单裁剪 | strace_syscall_collector.sh采集真实业务syscall，移除冗余允许项 | 🔄 工具已就绪，需真实负载运行 |
| Landlock校验 | Landlock路径规则严格校验 | ⚠️ 代码已实现，待裸机验证 |
| 解释器白名单 | 解释器路径白名单内核强制（BPF map + execve拦截） | ✅ 已完成 |
| 提权防护 | capabilities全部drop，确认没有残留能力位 | ⚠️ 代码已实现，待验证 |
| 逃逸对抗 | 红蓝对抗测试库：5个红队POC（ptrace注入/fd泄露/fork炸弹/seccomp绕过/mount逃逸） | ✅ tests/redblue/ 已建立 |
| 制度性测试 | PR准入规则（沙盒修改必须附带对抗用例）+ 季度人工红蓝演练机制 | ✅ 文档已定义 |
| 安全测试用例 | 20个测试：seccomp安全(8) + 资源隔离(4) + 逃逸路径(4) + 审计完整性(4) | ✅ 20/20通过 |

### 2.3 运行时安全态势检测（深层威胁防护）

> 覆盖三类深层威胁：内核 0day 逃逸、侧信道攻击（Spectre/Meltdown）、硬件级攻击（Rowhammer）。
> 模块：include/photon_kernel/sandbox/security_posture.hpp + src/sandbox/security_posture.cpp
> 测试：tests/test_security_posture.cpp（27个测试，全部通过）

| 项 | 检测内容 | 状态 |
|----|---------|------|
| 内核版本与CVE | 检测内核版本，评估已知 0day/CVE 风险 | ✅ 已实现（KERNEL-001） |
| 内核命令行安全参数 | slab_nomerge/init_on_alloc/init_on_free/page_poison/pti | ✅ 已实现（KERNEL-002） |
| 已加载模块审计 | 禁用高风险文件系统和网络模块 | ✅ 已实现（KERNEL-003） |
| 内核热补丁 | kpatch/canonical-livepatch 检测 | ✅ 已实现（KERNEL-004） |
| seccomp-BPF支持 | KILL_PROCESS 动作支持检测 | ✅ 已实现（KERNEL-005） |
| Landlock支持 | 非特权文件系统访问控制 | ✅ 已实现（KERNEL-006） |
| 命名空间隔离 | 7种命名空间支持检测 | ✅ 已实现（KERNEL-007） |
| 模块签名强制 | CONFIG_MODULE_SIG_FORCE 检测 | ✅ 已实现（KERNEL-008） |
| Spectre v1/v2/v4 | 推测执行漏洞防护状态 | ✅ 已实现（SIDE-001/002/003） |
| Meltdown | 内核内存读取漏洞（KPTI） | ✅ 已实现（SIDE-004，CRITICAL级） |
| L1TF/Foreshadow | L1缓存终端故障 | ✅ 已实现（SIDE-005） |
| MDS/ZombieLoad | 微架构数据采样 | ✅ 已实现（SIDE-006） |
| SwapGS/SRSO/GDS | 其他侧信道漏洞 | ✅ 已实现（SIDE-007/008/009） |
| CPU微码版本 | 最新微码更新检测 | ✅ 已实现（SIDE-010） |
| SMT/超线程状态 | 侧信道攻击重要因素 | ✅ 已实现（SIDE-011） |
| KPTI/Retpoline | 内核页表隔离和间接分支防护 | ✅ 已实现（SIDE-012/013） |
| perf_event限制 | 防止perf侧信道（Prime+Probe） | ✅ 已实现（SIDE-014） |
| ECC内存 | 纠错码内存检测（Rowhammer防护） | ✅ 已实现（HW-001） |
| Rowhammer/TRR | 目标行刷新防护检测 | ✅ 已实现（HW-002） |
| HugePages使用 | 大页内存增加Rowhammer攻击面 | ✅ 已实现（HW-003） |
| 内存清零 | init_on_alloc/init_on_free | ✅ 已实现（HW-004） |
| cgroup内存隔离 | 沙盒间内存隔离和限制 | ✅ 已实现（HW-005） |
| IOMMU/DMA防护 | Intel VT-d / AMD-Vi | ✅ 已实现（HW-006） |
| Secure Boot | UEFI安全启动（防bootkit） | ✅ 已实现（HW-007） |
| TPM可信平台模块 | 密钥存储和远程证明 | ✅ 已实现（HW-008） |
| 总体评分与报告 | JSON/Markdown双格式输出，0-100评分 | ✅ 已实现 |
| 宿主机加固脚本生成 | 自动生成shell加固脚本 | ✅ 已实现 |
| 额外seccomp限制建议 | 根据防护状态动态建议 | ✅ 已实现 |

**使用方式**：
```cpp
#include "photon_kernel/sandbox/security_posture.hpp"
using namespace photon_kernel::sandbox;

auto report = SecurityPostureEvaluator::evaluate();
std::cout << "总体安全评分: " << report.overall_score << "/100" << std::endl;
std::cout << report.to_markdown() << std::endl;

// 生成加固脚本
std::string script = SecurityPostureEvaluator::generate_hardening_script(report);
```

### 2.2 CapabilityToken / ResourceProxy

| 项 | 验证内容 | 状态 |
|----|---------|------|
| 密钥管理 | HMAC密钥支持密钥轮换，密钥不能硬编码进二进制；密钥外部注入 | ⬜ 当前硬编码 |
| 子票据 | 子票据、部分撤销逻辑完整测试 | ⬜ |
| 过期处理 | 过期票据直接拒绝 | ⚠️ 代码已实现，待测试 |
| ResourceProxy | 确认密钥永远不会拷贝进入沙盒内存；各种异常路径处理 | ⬜ |

### 2.3 四层平面安全边界复核

| 项 | 验证内容 | 状态 |
|----|---------|------|
| 职责分离 | Execution平面只负责隔离执行；业务鉴权、审批逻辑上移Policy-Identity网关 | ⚠️ 架构已分层，待代码复核 |
| TaskSpec校验 | 严格校验，防止恶意spec绕过限制（资源溢出、TTL为0、网络策略篡改） | ⬜ |
| Release-Gate | Evidence+Release闸门独立进程运行，不和沙盒执行进程同权限；产物必须经过闸门才流出 | ⬜ 当前闸门与执行进程同权限 |

### 2.4 网络纵深防御落地验证

| 项 | 验证内容 | 状态 |
|----|---------|------|
| 三层验证 | 网段隔离 + 隔离网关 + 实例eBPF内网黑名单三层全部验证 | ⚠️ 代码已实现（三层），待端到端 |
| DNS劫持 | 沙盒无法自定义DNS绕过域名白名单 | ⚠️ 代码已实现（iptables DNAT + resolv.conf 0444），待root验证 |
| 逃逸对抗 | 假设沙盒被攻破，验证无法访问内网业务、元数据服务 | ⬜ |

### 2.5 第三方安全审计（硬性要求）

> **没有审计不建议对公开放不可信代码**

| 项 | 验证内容 | 状态 |
|----|---------|------|
| 静态审计 | 内存越界、use-after-free、命令注入、权限绕过（C++高危） | ⬜ 无第三方审计 |
| 动态fuzz | fuzz TaskSpec解析、eBPF配置、gRPC入参、E2B http接口 | ⚠️ 4个harness代码已写，待clang+libFuzzer运行 |
| 渗透测试 | 尝试逃逸LightPool、尝试越权访问其他沙盒实例 | ⬜ |

---

## 三、压力测试 & 稳定性

### 3.1 LightPool 预热池压测

| 项 | 验证内容 | 状态 |
|----|---------|------|
| 高QPS压测 | 高QPS短任务长时间压测，验证fd泄漏、内存泄漏、worker泄漏 | ⬜ |
| 缩容shutdown | 池缩容、shutdown逻辑；僵死worker回收；队列堆积保护 | ⚠️ 代码已实现，待压测 |

### 3.2 混合负载压测

| 项 | 验证内容 | 状态 |
|----|---------|------|
| 混合调度 | 大量低风险跑LightPool + 少量高风险跑StrongPool | ⬜ |
| 分流逻辑 | RiskScorer调度分流逻辑；集群异构节点调度；限流排队 | ⚠️ 代码已实现，待验证 |
| 资源耗尽 | CPU打满、内存打满、磁盘打满，系统不雪崩，任务优雅失败 | ⬜ |

### 3.3 故障注入测试

| 项 | 验证内容 | 状态 |
|----|---------|------|
| worker被杀 | 任务中途杀掉沙盒worker进程 | ⬜ |
| firecracker被杀 | 杀掉firecracker子进程 | ⬜ |
| OOM注入 | 模拟OOM杀死VM | ⬜ |
| 审计完整性 | 保证审计链依然完整记录事件，不会丢失证据；资源全部回收无残留 | ⬜ |

---

## 四、可观测、运维、告警

### 4.1 Metrics 完善

| 指标 | 说明 | 状态 |
|------|------|------|
| 沙盒创建成功/失败数 | 按池维度 | ⚠️ 基础指标已有 |
| 降级事件 | LightPool↔StrongPool降级次数 | ⬜ |
| 逃逸拦截事件 | eBPF/seccomp拦截计数 | ⚠️ eBPF统计已有（BLOCK_INTERNAL等） |
| 队列长度 | 各池等待队列长度 | ⬜ |
| 各池活跃实例数 | LightPool/StrongPool当前活跃数 | ⚠️ StrongPool已有 |
| eBPF降级 | eBPF不可用降级指标 | ⬜ |
| KVM不可用 | KVM检测失败指标 | ⚠️ KvmDetector已有 |
| 审计spool堆积 | 本地spool队列长度 | ⬜ |
| TaskSpec维度 | 风险分数、使用后端、执行时长 | ⬜ |

### 4.2 审计日志

| 项 | 说明 | 状态 |
|----|------|------|
| 格式标准化 | 每条记录：租户ID、token_id、五元组、时间戳、产物哈希 | ⚠️ HMAC链已有，五元组待补全 |
| 完整性校验 | HMAC哈希链完整性校验工具常态化可用 | ⚠️ 校验工具已有，待常态化 |
| 事后校验 | 支持事后校验日志没有被篡改 | ⬜ |

### 4.3 告警清单

| 告警 | 触发条件 | 状态 |
|------|---------|------|
| 能力降级 | KVM/CAP_BPF能力降级 | ⬜ |
| 内网拦截 | 检测到内网访问拦截事件（大概率逃逸尝试） | ⬜ |
| spool堆积 | 审计spool队列堆积、磁盘水位 | ⬜ |
| 僵尸实例 | 僵尸沙盒/僵尸VM数量 | ⬜ |

### 4.4 部署运维

| 项 | 说明 | 状态 |
|----|------|------|
| K8s Operator | 完整端到端测试；CRD校验，防止错误spec下发 | ⚠️ Python代码+14纯函数测试通过，无K8s集群 |
| 容器化部署 | 运行时权限模型，哪些cap必须，哪些cap绝对不能给 | ⬜ |
| 版本升级 | 滚动升级方案 | ⬜ |
| 旧数据清理 | 旧快照、旧spool文件清理策略 | ⬜ |

---

## 五、业务适配与边界文档

### 5.1 明确能力边界文档

| 项 | 说明 | 状态 |
|----|------|------|
| LightPool边界 | 写明天然存在内核逃逸风险，适用场景；什么情况必须强制StrongPool | ⚠️ README有安全声明，待专项文档 |
| 不支持场景 | 写明不支持的场景 | ⬜ |
| 已知风险 | 已知风险列表 | ⚠️ SECURITY.md有部分 |
| 降级行为 | 安全降级发生后的业务行为 | ⬜ |

### 5.2 E2B 兼容网关契约测试

| 项 | 说明 | 状态 |
|----|------|------|
| 契约测试 | 对标E2B接口做完整契约测试，方便上层Agent业务无缝切换 | ⚠️ 网关代码+nc模拟测试通过，待真实E2B SDK |

### 5.3 多Agent编排模块打磨

| 项 | 说明 | 状态 |
|----|------|------|
| 异常处理 | Supervisor/Actor/DAG异常处理 | ⚠️ 基础框架已有 |
| 死循环保护 | 最大步数限制 | ⬜ |
| 审计集成 | 编排事件全部接入审计链 | ⬜ |
| 资源保护 | 防止DAG逻辑造成资源耗尽 | ⬜ |

---

## 优先级极简版

### P0（不做不能对公跑不可信代码）

| # | 任务 | 状态 |
|---|------|------|
| 1 | StrongPool + eBPF裸机完整验证，高风险任务禁止静默降级 | ⚠️ 代码已实现，待裸机 |
| 2 | seccomp/cap/Landlock安全复核 + fuzz测试 | ⚠️ 解释器白名单已内核强制，fuzz待运行 |
| 3 | TaskSpec严格校验；Release-Gate独立校验产物与证据 | ✅ 代码完成 |
| 4 | 内网拦截对抗测试 | ⬜ |

### P1（大规模生产必备）

| # | 任务 | 状态 |
|---|------|------|
| 1 | 泄漏压测、故障注入 | ⬜ |
| 2 | Metrics、告警、审计完整性 | ⚠️ 部分已有 |
| 3 | K8s Operator端到端验证 | ⚠️ 代码已有，无集群 |

### P2（优化增强）

| # | 任务 | 状态 |
|---|------|------|
| 1 | CRIU快照完善 | ⬜ 需criu+root |
| 2 | 密钥轮换 | ⬜ |
| 3 | 多Agent编排业务打磨 | ⚠️ 基础框架已有 |

---

## 当前完成度总览

| 大块 | 总项数 | 已完成 | 部分完成 | 待完成 | 完成度 |
|------|--------|--------|---------|--------|--------|
| 一、特权模块验证 | 17 | 0 | 8 | 9 | ~24% |
| 二、安全加固 | 22 | 0 | 6 | 16 | ~14% |
| 三、压测稳定性 | 8 | 0 | 2 | 6 | ~12% |
| 四、可观测运维 | 20 | 0 | 7 | 13 | ~18% |
| 五、业务适配 | 9 | 0 | 4 | 5 | ~22% |
| **合计** | **76** | **0** | **27** | **49** | **~18%** |

> **说明**：代码层面已实现大量功能（标记为 ⚠️ 部分完成），但缺少裸机/特权环境的端到端验证。当前容器环境限制：无sudo、无CAP_BPF、无KVM、无K8s集群、无criu、无libbpf、gRPC C++库未安装。
>
> **验证环境要求**：
> - 裸机 Linux（内核 ≥ 5.10，推荐 6.x）
> - sudo / root 权限
> - KVM 硬件虚拟化（/dev/kvm）
> - CAP_BPF + libbpf-dev
> - criu 二进制
> - libgrpc++-dev + protobuf-compiler-grpc
> - kind/minikube K8s 集群
> - clang + libFuzzer（fuzz测试）

---

*最后更新：2026-09-02 | 基于 PhotonBox v414*
