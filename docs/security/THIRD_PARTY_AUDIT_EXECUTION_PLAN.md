# PhotonBox 第三方安全审计执行计划模板

**版本**: v1.0
**日期**: 2026-09-03
**用途**: 交付给独立第三方安全审计机构的执行计划模板
**前置条件**: 审计必须在 x86_64 真实裸金属环境执行，`RUNNING_IN_NESTED_VM=FALSE`

---

## 一、审计环境要求

### 1.1 硬件环境（必须）

| 项目 | 要求 | 验证方法 |
|------|------|---------|
| CPU | x86_64，支持 Intel VT-x / AMD-V | `grep -E 'vmx\|svm' /proc/cpuinfo` |
| 内存 | ≥16GB（StrongPool 压测需要） | `free -h` |
| 磁盘 | ≥100GB SSD | `df -h` |
| KVM | `/dev/kvm` 存在且可读写 | `ls -la /dev/kvm` |
| 嵌套虚拟化 | **必须关闭**，`RUNNING_IN_NESTED_VM=FALSE` | `cpuid -1 \| grep hypervisor` 应为空 |

### 1.2 软件环境（必须）

| 项目 | 要求 | 验证方法 |
|------|------|---------|
| 操作系统 | Ubuntu 22.04 / 24.04 LTS 或 Debian 12 | `lsb_release -a` |
| 内核版本 | ≥5.15，推荐 6.1 LTS / 6.6 LTS | `uname -r` |
| cgroup | cgroup v2 unified hierarchy | `mount \| grep cgroup2` |
| 编译器 | GCC ≥11.2 / Clang ≥14 | `gcc --version` |
| CMake | ≥3.14 | `cmake --version` |
| gRPC C++ | libgrpc++-dev 已安装 | `pkg-config --modversion grpc++` |
| eBPF | libbpf-dev 已安装，内核开启 CONFIG_BPF | `dpkg -l libbpf-dev` |
| CRIU | criu 二进制已安装 | `criu --version` |
| Firecracker | firecracker 二进制在 PATH | `firecracker --version` |

### 1.3 权限要求（必须）

| 能力 | 要求 | 验证方法 |
|------|------|---------|
| root / sudo | 审计执行用户必须有 root 权限 | `id` |
| CAP_SYS_ADMIN | namespace、pivot_root、mount 操作 | `capsh --print` |
| CAP_BPF | eBPF 程序加载 | `capsh --print \| grep BPF` |
| CAP_NET_ADMIN | 网络命名空间、iptables | `capsh --print \| grep NET_ADMIN` |
| CAP_KVM | KVM 设备访问（或加入 kvm 组） | `groups \| grep kvm` |
| CAP_SYS_PTRACE | CRIU 快照调试 | `capsh --print \| grep PTRACE` |

---

## 二、审计范围

### 2.1 必审模块（P0，全部必须完成）

| 序号 | 模块 | 审计重点 | 预计工时 |
|------|------|---------|---------|
| 1 | StrongPool (Firecracker MicroVM) | VM 逃逸面、virtio 设备攻击面、快照安全、rootfs 篡改 | 3-4 人天 |
| 2 | LightPool (fork+seccomp) | seccomp 白名单绕过、namespace 逃逸、预热池 worker 复用污染 | 2-3 人天 |
| 3 | eBPF 网络管控 | eBPF 程序漏洞、内网 IP 黑名单绕过、DNS 隧道、连接劫持 | 2 人天 |
| 4 | CRIU 快照/恢复 | 快照内存泄露、快照篡改、恢复时权限提升 | 1-2 人天 |
| 5 | namespace/cgroup v2 隔离 | mount/pid/net/user namespace 逃逸、cgroup 资源限制绕过 | 2 人天 |
| 6 | gRPC C++ 沙盒服务端 | 认证绕过、消息越界、DoS、序列化漏洞 | 2 人天 |
| 7 | 审计 HMAC 哈希链 | 哈希链篡改、日志丢失、密钥泄露、重放攻击 | 1-2 人天 |
| 8 | CapabilityToken 权限模型 | 票据伪造、权限越界、票据撤销不生效、HMAC 密钥管理 | 1-2 人天 |
| 9 | Gang-Scheduler / Leader-Teammate | 多 Agent 权限越权、任务劫持、资源分配拒绝服务 | 1 人天 |
| 10 | E2B 兼容 HTTP 网关 | HTTP 注入、路径穿越、认证绕过、API 滥用 | 1 人天 |

**P0 合计**: 18-21 人天

### 2.2 选审模块（P1，建议完成）

| 序号 | 模块 | 审计重点 | 预计工时 |
|------|------|---------|---------|
| 1 | K8s Operator Reconcile | CRD 校验绕过、Operator 权限过大、容器逃逸 | 2 人天 |
| 2 | Landlock 路径白名单 | 规则绕过、TOCTOU 竞争、路径解析差异 | 1 人天 |
| 3 | ReleaseGate 发布闸门 | 闸门绕过、产物篡改、证据伪造 | 1 人天 |
| 4 | M2 检测网关 | 语义动量过滤绕过、对抗样本、阈值绕过 | 1 人天 |
| 5 | WikiSkill 三层架构 | 记忆污染、技能注入、知识库篡改 | 1 人天 |

**P1 合计**: 6 人天

### 2.3 审计总工时估算

| 级别 | 工时 | 说明 |
|------|------|------|
| P0 必审 | 18-21 人天 | 不完成不能输出生产安全验收报告 |
| P1 选审 | 6 人天 | 建议完成，增强审计覆盖度 |
| **总计** | **24-27 人天** | 按 2 名审计师并行约 12-14 个工作日 |

---

## 三、审计方法

### 3.1 静态代码审计（SAST）

| 工具 | 用途 | 覆盖范围 |
|------|------|---------|
| Clang Static Analyzer | C++ 内存安全、未初始化变量、空指针 | 全部 C++ 源码 |
| Clang-Tidy | C++ 代码质量、安全编码规范 | 全部 C++ 源码 |
| CodeQL | 语义代码分析、漏洞模式匹配 | C++ + Python |
| Bandit | Python 安全问题 | 全部 Python 源码 |
| Semgrep | 自定义规则、漏洞模式 | C++ + Python |
| 人工代码审计 | 逻辑漏洞、业务逻辑缺陷 | 核心隔离模块 |

**交付物**: SAST 报告，包含每个漏洞的位置、严重等级、修复建议、可利用性分析

### 3.2 动态渗透测试

| 测试类型 | 方法 | 目标 |
|---------|------|------|
| 沙盒逃逸测试 | 公开 POC + 自定义 EXP | StrongPool / LightPool 逃逸面 |
| 内核漏洞利用 | 已知内核 CVE POC | 验证 cgroup/namespace/seccomp 防护有效性 |
| 网络攻击 | 内网扫描、DNS 隧道、端口扫描 | eBPF 网络管控有效性 |
| 权限提升 | 提权 POC、capabilities 滥用 | 沙盒内提权防护 |
| 拒绝服务 | 资源耗尽、fork bomb、内存炸弹 | cgroup 资源限制有效性 |
| API 攻击 | SQL 注入、路径穿越、认证绕过 | gRPC / HTTP 网关 |
| 模糊测试 | libFuzzer / AFL++ | 输入解析、序列化、协议处理 |

**交付物**: 渗透测试报告，包含每个漏洞的复现步骤、影响范围、修复建议、PoC 代码

### 3.3 配置审计

| 审计项 | 检查内容 |
|--------|---------|
| seccomp 白名单 | 逐行审计 syscall 白名单，删除不必要 syscall |
| capabilities | 确认所有不必要 capabilities 已 drop |
| cgroup 限制 | 验证 CPU/内存/PID/IO 限制是否生效 |
| 文件系统 | 验证 pivot_root/chroot、只读挂载、敏感路径屏蔽 |
| 网络 | 验证网络隔离、内网黑名单、DNS 劫持 |
| 审计日志 | 验证 HMAC 哈希链完整性、日志不可篡改 |
| 密钥管理 | 验证 HMAC 密钥不硬编码、支持轮换、权限保护 |

**交付物**: 配置审计报告，包含每项配置的当前值、期望值、差距分析、修复建议

### 3.4 供应链安全审计

| 审计项 | 检查内容 |
|--------|---------|
| SBOM 完整性 | 验证所有依赖已记录，无未声明依赖 |
| 依赖漏洞扫描 | 使用 osv-scanner / trivy 扫描所有依赖 CVE |
| 许可证合规 | 验证所有依赖许可证兼容，无 GPL 污染 |
| 构建可重现 | 验证构建过程可重现，无供应链投毒 |
| 签名验证 | 验证 release 二进制签名、镜像签名 |

**交付物**: 供应链安全报告，包含 SBOM、漏洞清单、许可证清单、修复建议

---

## 四、审计证据收集模板

### 4.1 环境证据

审计开始前必须收集并记录：

```
【环境证据】
审计日期: YYYY-MM-DD
审计机构: [机构名称]
审计师: [姓名/资质]
目标版本: PhotonBox vX.Y.Z (commit: <hash>)
硬件: CPU型号 / 内存 / 磁盘
操作系统: 发行版 / 内核版本
KVM状态: /dev/kvm 存在 / 权限
嵌套虚拟化: RUNNING_IN_NESTED_VM=FALSE (必须)
权限: root / capabilities 列表
依赖版本: gRPC / libbpf / criu / firecracker 版本
```

### 4.2 漏洞证据模板

每个发现的漏洞必须记录：

```
【漏洞证据】
漏洞ID: PHOTON-YYYY-NNN
漏洞名称: [简短描述]
严重等级: CRITICAL / HIGH / MEDIUM / LOW
模块: [模块名称]
文件: [文件路径:行号]
发现方法: SAST / 渗透测试 / 配置审计 / 人工审计
可利用性: 可利用 / 需条件 / 理论可行 / 不可利用
影响范围: [描述影响]
复现步骤:
  1. [步骤1]
  2. [步骤2]
  3. [步骤3]
PoC代码: [附 PoC 或截图]
修复建议: [具体修复方案]
审计师确认: [签名/日期]
```

### 4.3 测试用例执行证据

每个审计测试用例必须记录：

```
【测试用例证据】
用例ID: TC-NNN
用例名称: [名称]
对应模块: [模块]
测试方法: [方法]
预期结果: [预期]
实际结果: [实际]
测试状态: PASS / FAIL / SKIP
证据: [日志/截图/抓包]
执行时间: YYYY-MM-DD HH:MM
审计师: [姓名]
```

---

## 五、审计交付物清单

审计完成后，第三方机构必须交付：

| 序号 | 交付物 | 格式 | 说明 |
|------|--------|------|------|
| 1 | 审计总结报告 | PDF（签名） | 总体结论、风险评级、关键发现 |
| 2 | SAST 详细报告 | PDF + 原始数据 | 所有静态分析发现 |
| 3 | 渗透测试报告 | PDF + PoC 代码 | 所有动态测试发现 |
| 4 | 配置审计报告 | PDF | 所有配置项检查结果 |
| 5 | 供应链安全报告 | PDF + SBOM | 依赖漏洞、许可证 |
| 6 | 漏洞修复建议 | Excel/CSV | 每个漏洞的修复方案、优先级 |
| 7 | 复测报告 | PDF（签名） | 修复后复测结果 |
| 8 | 审计师资质证明 | PDF | 审计师资格证书 |

---

## 六、审计通过标准

### 6.1 必须满足（不满足则审计不通过）

1. **无 CRITICAL 漏洞**：所有 CRITICAL 漏洞必须修复并复测通过
2. **HIGH 漏洞修复率 ≥95%**：剩余 HIGH 漏洞必须有明确的缓解措施和风险接受声明
3. **沙盒逃逸测试全部拦截**：所有公开 POC 和自定义 EXP 必须被沙盒拦截
4. **资源限制全部生效**：CPU/内存/PID/IO/网络限制必须全部验证生效
5. **审计日志完整**：HMAC 哈希链必须完整，无丢失、无可篡改
6. **嵌套虚拟化环境标记**：审计必须在真实裸机执行，`RUNNING_IN_NESTED_VM=FALSE`

### 6.2 建议满足（增强审计质量）

1. MEDIUM 漏洞修复率 ≥80%
2. 模糊测试覆盖核心输入解析模块
3. 供应链无 HIGH 级别依赖漏洞
4. 所有配置项符合安全基线
5. 代码符合安全编码规范

---

## 七、审计后修复与复测

1. **修复期限**: CRITICAL 7 天内，HIGH 30 天内，MEDIUM 90 天内
2. **复测要求**: 所有修复必须经过第三方机构复测确认
3. **回归测试**: 修复后必须运行全量单元测试 + 集成测试
4. **持续监控**: 修复后建立 CVE 监控机制，定期重新审计

---

## 八、免责声明

1. 本审计仅覆盖审计时的代码版本和环境，不代表未来版本的安全性
2. 审计不能保证绝对安全，只能降低安全风险
3. 审计结论仅代表审计机构的专业判断，不构成法律担保
4. 生产部署前还需考虑业务逻辑安全、运维安全、人员安全等非技术因素

---

**模板版本**: v1.0
**最后更新**: 2026-09-03
**适用项目**: PhotonBox (原 photon_kernel_sil3)
