# 威胁建模报告（STRIDE）— PhotonBox

> 依据《人工智能工程约束法案》V4.14 Final 第九条（需求阶段：威胁建模）补强交付。
> 审查日期：2026-09-01 · 审查版本：4.14.0 · 对象：安全隔离沙盒

## 1. 系统边界与信任域

```
┌────────────────────────────────────────────────────────────────┐
│ 信任域 A：编排面（Operator / 控制平面）                          │
│   - SandboxPool CRD / kopf 算子 / gRPC 服务端（Fast-Path）       │
└───────────────┬────────────────────────────────────────────────┘
                │ 受控接口：gRPC Execute / ExecuteAsync / GetPoolStatus
┌───────────────▼────────────────────────────────────────────────┐
│ 信任域 B：沙盒执行面（SandboxedExecutor / SandboxPoolV2 /        │
│             CodeRunner / PrewarmedWorker）                      │
│   - 父进程（特权侧：fork、seccomp 安装、rlimit、看门狗、审计）    │
└───────────────┬────────────────────────────────────────────────┘
                │ 隔离边界：fork + seccomp-bpf + rlimit + PR_SET_NO_NEW_PRIVS
┌───────────────▼────────────────────────────────────────────────┐
│ 信任域 C：任务进程（不可信用户代码 / 解释器子进程）              │
│   - python3 / node / dash，stdin 传码，stdout/stderr 捕获       │
└────────────────────────────────────────────────────────────────┘
```

- **威胁源**：提交任务的客户端、不可信用户代码、被攻破的解释器、外部网络（若开网络）、运维侧误操作。
- **资产**：宿主机完整性、审计日志完整性、任务资源配额、解释器进程隔离、敏感数据（用户代码/密钥/路径）。

## 2. STRIDE 威胁清单与缓解映射

| # | 威胁类别 | 具体威胁场景 | 影响 | 现有/补强控制 | 风险 |
|---|---|---|---|---|---|
| S1 | **Spoofing 仿冒** | 客户端伪造身份提交任务，冒充合法调用方 | 越权执行 | gRPC Fast-Path 接口 + 服务端校验（生产需补 mTLS/鉴权）；审计记录 HMAC 哈希链防伪造 | 中 |
| S2 | Spoofing | 攻击者伪造审计记录以掩盖攻击 | 证据失效 | `AuditChain` HMAC-SHA256 封链 + `verify_chain_file` 逐条校验 | 已控制 |
| T1 | **Tampering 篡改** | 篡改审计日志文件（改/删/插记录） | 抵赖/取证失效 | 哈希链 seq 连续 + prev_hash 衔接 + hmac 重算，任何改动即校验失败 | 已控制 |
| T2 | Tampering | 篡改沙盒配置（rlimit/seccomp 白名单/风险等级） | 削弱隔离 | 快照 save/load 往返校验；`SandboxConfig::validate()`；风险等级变更审计备案 | 已控制 |
| T3 | Tampering | 篡改用户代码/解释器路径 | 任意执行 | 解释器路径源头硬编码白名单（`/usr/bin/python3`、`/usr/bin/node`、`/bin/sh`） | 已控制 |
| R1 | **Repudiation 抵赖** | 无日志抵赖"未执行过某任务" | 责任不清 | 每次执行 JSON Lines 审计（时间戳/任务/结果/资源/信号）+ 责任主体登记（`act_governance`） | 已控制 |
| I1 | **Information Disclosure** | 用户代码/密钥/路径明文落入审计或上报 | 敏感信息泄露 | `AuditSanitizer` 敏感字段脱敏（code/token/secret/password/api_key/path...）；哈希链仅存摘要 | 已控制 |
| I2 | Information Disclosure | 任务进程读取宿主机敏感文件 | 数据泄露 | MEDIUM 只读 + 路径白名单；HIGH 禁文件操作；seccomp 白名单 | 已控制 |
| I3 | Information Disclosure | 跨任务数据泄露（并发任务共享状态） | 数据泄露 | 每任务独立 fork 进程 + 独立文件描述符；BatchIsolation 测试 | 已控制 |
| D1 | **DoS 拒绝服务** | fork 炸弹 / 无限 fork 耗尽进程 | 宿主机瘫痪 | `RLIMIT_NPROC` 任务进程内收紧（防 fork 炸弹）+ `RLIMIT_AS/CPU/FSIZE` | 已控制 |
| D2 | DoS | 死循环 / 恶意长任务挂死 | 资源占用 | 看门狗超时 `SIGKILL`（TIMEOUT_EXPIRED）；`RLIMIT_CPU` | 已控制 |
| D3 | DoS | 高并发请求压垮服务 | 服务不可用 | `CircuitBreaker` 逻辑熔断：延迟/错误率/资源水位动态基线 + 超硬限制拒绝新任务返回错误码 | 已控制 |
| D4 | DoS | 解释器进程启动抖动/资源水位过高 | 服务降级 | `HardwareSelfDiagnosis` 容器资源节流/内存水位检查（cgroup v2） | 已控制 |
| E1 | **Elevation of Privilege 提权** | 沙箱逃逸：任务进程突破 seccomp 执行宿主操作 | 宿主机沦陷 | seccomp-bpf 白名单（默认 `KILL_PROCESS`）+ `PR_SET_NO_NEW_PRIVS` + 非 root + 只读根文件系统 + drop ALL capabilities（K8s 模板） | 已控制 |
| E2 | Elevation of Privilege | 通过未白名单 syscall 逃逸（openat/getdents64 等） | 文件系统越权 | MEDIUM 白名单补齐 openat/readlinkat/getdents64；HIGH 显式移除文件操作 | 已控制 |
| E3 | Elevation of Privilege | NPROC 收紧被绕过（共享 uid 线程计数） | 进程耗尽 | worker 自身不收紧 NPROC，任务进程内单独设置（避免 EAGAIN 误伤） | 已控制 |

## 3. 高风险项与残余风险

| 风险 | 描述 | 缓解建议 |
|---|---|---|
| gRPC 通道无鉴权 | 当前 Fast-Path 为占位实现，未做 mTLS/Token | 生产部署启用 TLS + 服务端鉴权（N/A 本机无 gRPC 环境） |
| seccomp 无法按路径过滤 | 解释器路径白名单为源头硬编码，非内核级 | 可叠加 Landlock LSM（内核 5.15+），未集成 |
| 非 Linux 容器降级 | cgroup v2 仅 Linux 有效 | 已补：非 Linux/无 cgroup 时走软件模拟降级路径（`act_self_diagnosis`），见补强 3 |

## 4. 结论

本工程针对 STRIDE 六类威胁均有对应控制，核心隔离（seccomp + rlimit + 看门狗 + 审计哈希链 + 逻辑熔断 + 脱敏）已落地并经测试验证。残余风险集中在生产化网络鉴权与内核级路径过滤，属部署环境增强项，不影响 SIL-3 合规引擎（设计目标）的路径合规判定。
