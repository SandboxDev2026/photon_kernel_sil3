# PhotonBox 第三方安全审计输入包

**版本**: 2026-09-05
**项目**: PhotonBox（原 photon_kernel_sil3）
**审计状态**: 待独立第三方审计
**代码提交**: 见 git log（main 分支最新 commit）

---

## 一、项目概述

PhotonBox 是一个 C++17 安全隔离沙盒引擎，为不可信代码执行提供多层隔离：
- **StrongPool**: Firecracker MicroVM（KVM 硬件虚拟化，强隔离）
- **LightPool**: namespace + seccomp + Landlock + cgroup v2（进程级隔离）
- **eBPF 网络过滤**: 内核态网络黑名单
- **红蓝对抗自进化框架**: 真实数据驱动的攻防策略进化
- **进化-防御桥接器**: 进化规则自动下发到底层沙盒配置

**重要声明**: 本项目尚未经过完整独立第三方安全审计。仅建议内网研究/半可信负载。请勿直接部署在面向公网处理不可信用户代码的多租户场景。

---

## 二、审计范围（必须明确写进合同）

### 2.1 底层沙盒（C++）

| 模块 | 审计重点 | 关键文件 |
|------|---------|---------|
| LightPool | namespace/seccomp-bpf/Landlock/cgroupv2、ReleaseGate IPC、fd泄露、权限绕过、TOCTOU、DoS | `src/sandbox/` |
| StrongPool | Firecracker jailer配置、vsock报文解析、Guest镜像校验、VM-Exit异常处理、CRIU快照风险 | `src/strong_pool/` |
| eBPF网络模块 | 字节码安全、map越界、过滤逻辑绕过、IPv6遗漏 | `src/ebpf/` |
| 控制平面 | gRPC接口鉴权、mTLS、CapabilityToken票据逻辑 | `src/grpc/` |

### 2.2 上层进化框架（Python）

| 模块 | 审计重点 | 关键文件 |
|------|---------|---------|
| 红蓝对抗框架 | 攻击用例生成、防御规则进化、权重更新逻辑 | `evolution/red_blue_adversary.py` |
| 真实信号消费器 | REALTIME文件监听循环、事件解析、去重、回调注入 | `evolution/real_signal_consumer.py` |
| 实时训练循环 | 事件积累触发训练、超时处理、资源泄漏 | `evolution/red_blue_adversary.py::train_from_real_signals` |
| 进化-防御桥接器 | 规则下发、熔断器、自动回滚、配置更新注入 | `evolution/evolution_defense_bridge.py` |
| 进化验证套件 | 漂移监控、A/B测试、统计显著性 | `evolution/evolution_validation.py` |
| 策略优化器 | 攻击/防御策略优化、进化触发 | `evolution/adversarial_strategy_optimizer.py` |

### 2.3 量子启发安全模块（Python）

| 模块 | 审计重点 | 关键文件 |
|------|---------|---------|
| QAOA异常检测 | 哈密顿量构造、优化收敛、异常判定 | `evolution/quantum_inspired_security.py` |
| VQE资源优化 | 资源分配逻辑、梯度计算、参数更新 | `evolution/quantum_inspired_enhancements.py` |
| 量子核聚类 | 特征映射、核矩阵计算、异常检测 | `evolution/quantum_inspired_enhancements.py` |
| 量子纠错容错 | 多副本校验、错误纠正、中位数逻辑 | `evolution/quantum_inspired_enhancements.py` |
| QRNG熵源 | 随机数生成、熵池管理、健康检查 | `evolution/quantum_inspired_enhancements.py` |
| STDP SNN | 神经元模型、STDP学习、权重更新 | `evolution/quantum_inspired_enhancements.py` |

### 2.4 审计链与安全控制

| 模块 | 审计重点 |
|------|---------|
| HMAC审计链 | 哈希篡改、状态复位、日志伪造 |
| CapabilityToken | 撤销、过期、伪造、密钥管理 |
| ReleaseGate | 进程隔离、IPC安全、权限校验 |
| ResourceProxy | 密钥不进入沙盒、异常路径泄漏 |

---

## 三、v26+ 新增模块特别审计提醒

### 3.1 RealDataAdapter 输入污染（高危）

`RealDataAdapter` 接收外部事件输入，攻击者若可以伪造审计日志，有可能注入恶意事件污染红蓝对抗训练，导致生成错误/破坏性防御规则。这是关键攻击面。

**审计重点**:
- 事件输入校验（EventInputValidator）是否完备
- 恶意事件能否诱导生成毁灭性 seccomp/Landlock 规则
- 事件去重逻辑能否被绕过（重复事件放大影响）
- HMAC链状态重启持久化逻辑漏洞

### 3.2 进化-防御桥接器规则下发（高危）

进化出的防御规则通过桥接器自动下发到底层沙盒配置（LightPool/seccomp、StrongPool）。如果进化逻辑被污染，可能下发危险规则。

**审计重点**:
- 规则转换为 ConfigUpdate 的逻辑是否安全
- 熔断器（误报率>30%/失败率>20%）是否可靠触发
- 自动回滚是否能正确撤销危险配置
- 试运行模式（dry_run）是否真的不下发
- 已熔断规则是否真的跳过部署

### 3.3 REALTIME 文件监听循环（中危）

`RealSignalConsumer` 的 REALTIME 模式通过后台线程持续监控日志文件（tail -f）。

**审计重点**:
- 文件路径遍历（symlink 攻击）
- 文件旋转/截断处理是否正确
- 后台线程资源泄漏（未正确停止）
- 大文件/快速写入时的内存占用
- 异常恢复逻辑是否可能丢失事件

### 3.4 实时训练循环（中危）

`train_from_real_signals` 每积累 N 个事件触发一轮红蓝对抗训练。

**审计重点**:
- 事件积累计数是否准确
- 超时处理是否正确退出
- 训练过程中资源占用（CPU/内存）
- 与桥接器集成时，自动下发规则的频率控制
- 并发安全（多线程访问 real_event_history）

---

## 四、威胁模型（信任边界）

### 4.1 完全不可信

- 沙盒内执行的用户代码（StrongPool/LightPool 内部）
- 外部输入的审计事件（RealDataAdapter/RealSignalConsumer 输入）
- 进化框架生成的攻击用例和防御规则（需桥接器校验后才能下发）

### 4.2 可信

- 沙盒管理器守护进程（root/CAP_SYS_ADMIN）
- 控制平面 gRPC 服务（需 mTLS 鉴权）
- ReleaseGate 发布闸门（应独立低权限进程）
- 审计链 HMAC 签名密钥（应外部注入，不硬编码）

### 4.3 攻击面清单

- 系统调用（seccomp 过滤）
- vsock 报文（StrongPool 通信）
- gRPC 接口（控制平面）
- eBPF 程序（内核态网络过滤）
- 日志文件输入（RealSignalConsumer REALTIME）
- 外部事件输入（RealDataAdapter）
- 进化规则下发（EvolutionDefenseBridge → ConfigUpdate）

---

## 五、编译与复现环境

### 5.1 系统要求

- Linux 内核 ≥ 5.15（推荐 6.1 LTS / 6.6 LTS）
- 必须开启: CONFIG_NAMESPACES, CONFIG_CGROUPS, CONFIG_SECCOMP, CONFIG_SECCOMP_FILTER, CONFIG_LANDLOCK, CONFIG_BPF, CONFIG_BPF_SYSCALL, CONFIG_KVM
- cgroup v2 unified hierarchy

### 5.2 编译命令

```bash
# C++ 部分（注意：build/ 目录有 virtiofs 写入问题，必须用 build2/）
cmake -B build2 \
  -DGTEST_DIR=/path/to/gtest/install/lib/cmake/GTest \
  -DCMAKE_BUILD_TYPE=Release \
  -DPHOTON_ENABLE_GRPC=OFF \
  -DBUILD_TESTING=ON
cmake --build build2 -j$(nproc)

# Python 部分测试
python3 -m unittest discover -s evolution/tests -p "test_*.py"
```

### 5.3 特权环境验证（生产必须）

```bash
# 裸机 KVM 环境完整验证
sudo ./scripts/verify_baremetal.sh

# 预期输出：全部模块 PASS
# SKIP = 内核/权限缺失
# FAIL = 环境不满足
```

---

## 六、已知风险清单（诚实告知审计方）

### 6.1 P0 高危（不解决禁止对公运行不可信代码）

1. **LightPool 公网使用**: 共享宿主机内核，内核漏洞可逃逸
2. **高风险任务静默降级**: KVM 消失时，代码逻辑设计为高风险任务拒绝，但如果逻辑 bug，可能降级到 LightPool
3. **Release-Gate 同权限**: 当前 Release-Gate 与沙盒管理器同进程/同权限，管理器被攻破可篡改审计
4. **TaskSpec 未 fuzz**: 入参解析缺少完整模糊测试
5. **eBPF/MicroVM 裸机未验证**: 代码完整，待 KVM 环境验证
6. **密钥硬编码**: CapabilityToken 密钥早期版本硬编码，需外部注入+轮换

### 6.2 P1 中风险（大规模生产必须补齐）

1. seccomp 白名单未逐行审计
2. 逃逸 POC 对抗测试未完成
3. 泄漏压测、故障注入未完成
4. 审计日志完整性（C++ gRPC 流式上报仅 Python 版本实测）
5. K8s Operator 端到端集群验证未完成
6. 规则熔断后的人工确认机制（自动回滚很好，但熔断事件应有告警）

### 6.3 P2 低风险（优化增强）

1. CRIU 快照加固
2. 密钥轮换机制
3. Agent 编排死循环防护
4. 去重持久化的 TTL 和容量上限

### 6.4 环境限制（当前容器无法验证）

- 无 sudo；gRPC C++ 库未安装；无 KVM（/dev/kvm 不存在）；无 CAP_BPF；无 CRIU；无 K8s 集群；cgroup v2 只读
- 系统侧 OpenSSL 3.0.2 和 gRPC C++ 因无 sudo 无法升级（2 个 HIGH CVE）
- 生产部署前必须在有 sudo 权限的裸机环境完成系统级依赖升级

---

## 七、内部自评估结果（不能替代独立审计）

### 7.1 SAST 扫描

- 工具: Bandit（Python）+ 人工代码审查
- 结果: 0 High / 0 Medium / 0 Low（最新扫描）
- 覆盖: 全部 Python 模块（evolution/ 下 30+ 模块）

### 7.2 渗透测试

- 方法: 边界条件测试、异常输入测试、权限绕过尝试
- 结果: 全部通过（每轮 10/10）
- 覆盖: 桥接器熔断器、REALTIME 监听、实时训练循环、量子启发模块

### 7.3 单元测试

- 总数: 587 个测试全部通过
- 覆盖: 红蓝对抗、真实信号消费、进化验证、桥接器、量子启发模块、REALTIME、实时训练

### 7.4 局限性声明

以上为内部自评估，**不能替代独立第三方安全审计**。内部测试无法发现：
- 逻辑漏洞（如静默降级 bug）
- 内核级逃逸路径
- 侧信道攻击
- 复杂攻击链组合

---

## 八、审计交付物要求

审计完成后，第三方机构应提供：

1. **正式审计报告**: 风险分级 Critical/High/Medium/Low/Info；复现步骤；POC；修复建议
2. **每一条漏洞必须可复现**
3. **修复后再确认**: 修复完成后提供复核验证
4. **公开审计报告**: 经项目方同意后可公开放到 `docs/audit/report-xxx.pdf`

---

## 九、联系方式

- 仓库: https://github.com/SandboxDev2026/photon_kernel_sil3
- 安全公告: 见仓库 SECURITY.md
- 漏洞报告: GitHub Security Advisories（私下报告）

---

**最后更新**: 2026-09-05
**代码状态**: main 分支最新 commit（含 REALTIME 监听、实时训练循环、进化-防御桥接器、量子启发增强模块）
