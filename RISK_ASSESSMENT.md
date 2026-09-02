# Photon Kernel Sandbox v4.14-Final 风险评估清单

> **用途**：安全评审、上线评估、内部风险台账
> **分类**：设计固有风险、代码待验证风险、权限部署风险、业务使用风险、项目生命周期风险
> **配套文档**：[PRODUCTION_CHECKLIST.md](PRODUCTION_CHECKLIST.md) | [SECURITY.md](SECURITY.md) | [docs/privileged_e2e_guide.md](docs/privileged_e2e_guide.md)

---

## 风险等级速览

| 等级 | 含义 | 处置要求 |
|------|------|---------|
| 🔴 P0 高危 | 不解决禁止对公运行不可信代码 | 必须完成验证/修复后才能上线 |
| 🟠 P1 中风险 | 大规模生产必须补齐 | 上线后30天内补齐 |
| 🟡 P2 低风险 | 优化增强 | 按迭代计划推进 |

---

## 一、设计固有风险（架构本身无法彻底消除，只能约束使用场景）

### 1.1 LightPool 进程沙盒内核逃逸风险 🔴 P0

- **风险**：LightPool 基于 namespace/seccomp/Landlock，共享宿主机 Linux 内核。一旦内核存在漏洞，沙盒内代码可逃逸到宿主机。
- **影响**：破坏宿主机、横向访问其他沙盒实例、窃取数据。
- **管控措施**：
  - ✅ 公网不可信代码禁止使用 LightPool，必须调度 StrongPool(MicroVM)
  - ✅ LightPool 仅限内网可信/半可信 Agent
  - ✅ 高风险任务(score>70)无 KVM 时直接拒绝，不静默降级
- **状态**：⚠️ 代码已实现，待裸机验证

### 1.2 StrongPool（Firecracker MicroVM）并非绝对安全 🟠 P1

- **风险**：攻击面包含 Firecracker 二进制、KVM 内核模块、virtio 设备驱动。存在漏洞可能性。
- **影响**：客户机逃逸至宿主机。
- **管控措施**：
  - 不要信任 VM 内部任何代码
  - ✅ 三层网络防御（网段隔离+隔离网关+实例eBPF）
  - 定期升级 Firecracker、内核
- **状态**：⚠️ 设计已完成，待长期运行验证

### 1.3 MicroVM 高并发内存成本压力 🟡 P2

- **风险**：每个 MicroVM 拥有独立内核，单机大量并发 VM 会耗尽内存。
- **管控措施**：
  - ✅ 单机设置 VM 最大并发上限 (`--max-strong-pool-vm`)
  - ✅ 风险分级调度，只有高风险任务才上 MicroVM
  - ✅ 短任务执行完立刻销毁 VM，不常驻
  - ✅ MemoryBalloon 闲置放气回收内存（AgentENV 技术）
- **状态**：✅ 已实现

### 1.4 沙盒是执行载体，不会解决业务逻辑风险 🟠 P1

- **风险**：即使隔离做得再好，Agent 依然可以执行消耗大量 CPU、写满临时盘、发起大量对外网络请求；可以输出恶意业务内容。
- **管控措施**：
  - ✅ TTL 超时（`task_timeout`）
  - ✅ CPU/磁盘/网络限额（cgroup v2）
  - 上层业务做内容安全
- **状态**：⚠️ 部分实现，业务层内容安全需上层负责

---

## 二、代码待验证风险（代码逻辑已实现，缺少裸机特权环境实测、fuzz、逃逸对抗）

> 这些是 P0 级生产阻碍，没有完成验证前不建议对公跑不可信代码。

### 2.1 eBPF 网络过滤模块未完成完整对抗测试 🔴 P0

- **风险**：eBPF 拦截内网、云元数据；普通容器无法使用，降级 seccomp 粗粒度兜底。可能存在绕过、IPv6 遗漏、畸形数据包绕过。
- **管控措施**：
  - 裸机做逃逸模拟测试
  - ✅ 开启告警"eBPF 能力降级事件"（Metrics `photon_sandbox_degradation_total`）
  - ✅ 内网 IP 黑名单完整规则集（RFC1918 + 169.254 元数据 + 127 回环）
- **状态**：⚠️ 代码已实现，待裸机对抗测试
- **验证方式**：`sudo ./build/test_network_isolation` + `scripts/escape_poc_tester.sh`

### 2.2 StrongPool Firecracker 链路端到端验证缺失 🔴 P0

- **风险**：KVM 探测、高风险任务拒绝降级、快照克隆、VM 资源回收、vsock 产物导出，缺少长时间压力测试。可能出现僵尸 VM、fd 泄漏、内存泄漏；高危任务发生静默降级到 LightPool 是严重安全事故。
- **管控措施**：
  - 裸机 KVM 环境完整压测
  - ✅ 监控僵尸 VM 数量指标（Metrics `photon_sandbox_zombie_instances`）
  - ✅ 告警 KVM 不可用
  - ✅ NoSilentDowngradeForHighRisk 单元测试通过
- **状态**：⚠️ 代码已实现，待裸机压测
- **验证方式**：`sudo ./build/test_strong_pool` + 长时间并发压测

### 2.3 CRIU 快照恢复风险 🟡 P2

- **风险**：dump/restore 可能泄露上一个任务内存残留信息；非 root 权限下大量场景 dump 失败。
- **管控措施**：
  - 默认不开启
  - 仅用于任务恢复，禁止租户长期持有快照
  - 快照纳入审计证据
- **状态**：⚠️ 可选高级功能，代码已实现
- **验证方式**：`sudo criu dump -t <pid> → criu restore`

### 2.4 Release-Gate 发布闸门进程权限问题 🔴 P0

- **风险**：早期 Release-Gate 与沙盒管理器同进程/同权限，如果管理器被攻破，产物校验、审计证据可被篡改。
- **管控措施**：
  - ✅ **已修复**：改为独立低权限进程运行（`security_hardening.hpp` 中的 `ReleaseGateService`）
  - ✅ fork 独立进程 + Unix socket 通信 + 降权 nobody + seccomp 最小化 + 只读 rootfs
  - ✅ ReleaseGateClient 沙盒进程通过 socket 连接，产物必须经过闸门才流出
- **状态**：✅ 已完成（真正的独立低权限进程）
- **实现**：fork独立进程 + Unix socket + **真正setuid/setgid到nobody** + **真正seccomp-bpf最小化白名单(45个syscall)** + rlimit限制(64fd/16proc/64MB) + 清除LD_PRELOAD等环境变量 + 验证无法恢复root
- **测试**：`./build/test_security_hardening --gtest_filter="*ReleaseGate*"`

### 2.5 TaskSpec 参数解析缺少完整模糊测试(fuzz) 🔴 P0

- **风险**：恶意构造 TaskSpec，可能绕过资源限制、篡改网络策略、越权配置沙盒参数。
- **管控措施**：
  - ✅ TaskSpecValidator 严格校验器（资源溢出/TTL/网络策略/路径遍历/注入攻击/身份认证）
  - ✅ `validate_and_sanitize()` 自动清理可修复字段
  - ⚠️ libFuzzer 模糊测试 harness 已添加，待实际运行
- **状态**：⚠️ 校验器已实现，fuzz 待运行
- **验证方式**：`./build/fuzz_task_spec -max_total_time=60`

### 2.6 seccomp 系统调用白名单没有逐行安全审计 🔴 P0

- **风险**：多余 syscall 开放，存在逃逸利用点。
- **管控措施**：
  - 逐行复核 seccomp 白名单
  - 跑公开 namespace/seccomp 逃逸 POC 对抗测试
  - ✅ 拒绝 ptrace、kexec 等高危调用
- **状态**：⚠️ 待逐行审计
- **工具**：`scripts/escape_poc_tester.sh`

### 2.7 C++ gRPC 流式审计上报未完整实测 🟠 P1

- **风险**：C++ 路径下审计事件丢失、spool 本地队列溢出打满磁盘。
- **管控措施**：
  - ✅ 优先使用 Python-gRPC 网关（容器环境替代方案）
  - ⚠️ 补齐 C++ 流式上报完整测试
  - ✅ 磁盘水位告警（`audit_disk_guard`）
- **状态**：⚠️ Python 版本已验证，C++ 版本待测试

### 2.8 解释器路径校验早期为应用层校验 🔴 P0

- **风险**：应用层校验存在被绕过可能性。
- **管控措施**：
  - ✅ **已修复**：使用 seccomp-bpf 在内核层强制限制可执行解释器（`InterpreterWhitelist`）
  - ✅ BPF map 存白名单路径 + execve/execveat 拦截 + KILL_PROCESS 内核强制杀死
  - ✅ eBPF LSM 程序（lsm/bprm_check）作为更灵活方案
  - ✅ 动态添加/移除路径；allow_sh/allow_bash 配置开关
- **状态**：✅ 已修复（P0 加固项）
- **测试**：`./build/test_security_hardening --gtest_filter="*Interpreter*"`

---

## 三、权限与部署运维风险（部署配置不当直接造成安全失效）

### 3.1 特权依赖风险 🟠 P1

- **风险**：完整沙盒需要 root / CAP_SYS_ADMIN / CAP_BPF / CAP_KVM / CAP_NET_ADMIN。在普通 Docker 容器内大部分隔离能力直接失效。
- **管控措施**：
  - 只在裸机/开启虚拟化的虚拟机部署
  - 禁止普通容器运行完整沙盒
  - ✅ 监控各项能力降级指标并告警（Metrics + 能力矩阵 API）
  - ✅ `scripts/check_privileges.sh` 自动检查 8 项权限
- **状态**：✅ 能力探测+降级已实现
- **参考**：[docs/privilege_requirements.md](docs/privilege_requirements.md) | [docs/privileged_e2e_guide.md](docs/privileged_e2e_guide.md)

### 3.2 CapabilityToken 密钥管理风险 🔴 P0

- **风险**：早期版本密钥硬编码；如果密钥泄露，可以伪造权限票据。
- **管控措施**：
  - ✅ **已修复**：密钥外部注入（环境变量 `PHOTON_HMAC_KEY` > 密钥文件 `/etc/photon/hmac.key` > KMS > 临时生成）
  - ✅ `enforce_external_key=true` 时无外部密钥直接拒绝启动
  - ✅ 主动 `rotate_key()` + 定时 `rotate_interval` + 宽限期 `grace_period`
  - ✅ 常量时间比较防时序攻击
  - ✅ 禁止密钥写进二进制、配置文件明文
- **状态**：✅ 已修复（P0 加固项）
- **测试**：`./build/test_security_hardening --gtest_filter="*KeyManager*"`

### 3.3 ResourceProxy 密钥保险箱风险 🟠 P1

- **风险**：逻辑设计密钥不进入沙盒内存；异常路径下如果逻辑 bug 密钥泄漏进沙盒上下文。
- **管控措施**：
  - 单元+集成测试覆盖异常路径
  - 密钥流转全部记入审计链
- **状态**：⚠️ 待补充异常路径测试

### 3.4 K8s Operator / CRD 风险 🟠 P1

- **风险**：CRD 如果没有严格校验，恶意 CRD 可以下发危险沙盒配置；Operator 权限过高。
- **管控措施**：
  - CRD 开启 validation
  - 最小权限运行 operator
  - ⚠️ 尚未完成集群端到端测试
- **状态**：⚠️ 代码已实现，待 K8s 集群验证
- **验证方式**：`kind create cluster → kubectl apply -f deploy/crd.yaml → python operator/operator.py`

### 3.5 审计链本身风险 🟠 P1

- **风险**：本地 spool 磁盘耗尽会丢失审计记录；HMAC 链只能防篡改，不能防止事件不产生。
- **管控措施**：
  - ✅ 磁盘水位告警（`audit_disk_guard`）
  - ✅ spool 轮转清理
  - ✅ 告警上报堆积（Metrics `photon_sandbox_audit_spool_size`）
  - ✅ `tools/audit_verify` 事后校验日志没有被篡改
- **状态**：✅ 已实现

---

## 四、业务使用风险（上层调用方容易踩坑）

### 4.1 风险分数信任问题 🔴 P0

- **风险**：RiskScorer 是静态扫描，只能识别明显危险模式；复杂混淆代码可以绕过风险评分，导致高风险代码被调度到 LightPool。
- **管控措施**：
  - RiskScorer 结果只作为调度参考，不能作为唯一安全判定
  - ✅ **risk_enforcer**：用户不可信输入，直接强制走 StrongPool，不要依赖打分
  - ✅ 业务层二次校验后端类型
- **状态**：✅ 已实现 `risk_enforcer` 模块

### 4.2 高风险任务静默降级（高危）🔴 P0

- **风险**：KVM 消失，代码逻辑设计为高风险任务拒绝，但如果逻辑 bug，降级到 LightPool。
- **管控措施**：
  - ✅ 业务层二次校验后端类型
  - ✅ 告警高风险任务被分配 LightPool（Metrics + 审计日志）
  - ✅ NoSilentDowngradeForHighRisk 单元测试
- **状态**：✅ 代码已实现，待裸机验证

### 4.3 文件数据流转风险 🟠 P1

- **风险**：MicroVM 禁止宿主机 RW 目录直通；只能只读镜像注入 + vsock 导出产物。配置错误挂载 RW 目录会创建巨大逃逸面。
- **管控措施**：
  - 部署审查挂载配置
  - ✅ 禁止 RW 直通宿主机目录给 VM（代码层面强制）
  - ✅ 只允许只读镜像 + vsock 导出产物
- **状态**：✅ 已实现

### 4.4 网络纵深防御配置遗漏 🟠 P1

- **风险**：只依靠沙盒内部 eBPF，忘记配置外部网段隔离、隔离网关。沙盒一旦逃逸直接访问内网业务。
- **管控措施**：
  - ✅ 三层网络防御必须全套部署，不可省略任意一层
  - 第一层：网段隔离（沙盒池独立子网）
  - 第二层：网关隔离（所有流量强制经过代理网关）
  - 第三层：沙盒实例内网隔离（eBPF/seccomp 拦截 RFC1918）
- **状态**：✅ 设计已完成，部署时需确保三层齐全
- **参考**：[docs/network_defense_in_depth.md](docs/network_defense_in_depth.md)

---

## 五、项目生命周期风险

### 5.1 单人维护项目，没有大规模线上实战，无第三方安全审计 🟠 P1

- **风险**：存在未知漏洞；issue、漏洞响应能力有限。
- **管控措施**：
  - 适合学习、内网半可信场景
  - 对公使用必须自行安全审计
  - ✅ 关注仓库安全公告 [SECURITY.md](SECURITY.md)
  - ✅ CVE 监控脚本（`scripts/cve_monitor.py`，当前检测到 10 个 CVE，critical=0, high=2）
  - ✅ SBOM 清单（`reports/sbom.cyclonedx.json`，12 个直接依赖）
- **状态**：⚠️ 无第三方审计，使用方需自行评估

---

## P0 高危项汇总（不解决禁止对公运行不可信代码）

| # | 风险项 | 状态 | 缓解措施 |
|---|--------|------|---------|
| 1 | LightPool 公网使用 | ⚠️ 代码已实现 | 高风险任务强制 StrongPool，无 KVM 拒绝 |
| 2 | 高风险任务静默降级 | ✅ 已修复 | NoSilentDowngradeForHighRisk 测试 + 业务层二次校验 |
| 3 | Release-Gate 同权限 | ✅ 已完成 | 真正setuid nobody + seccomp-bpf 45 syscall + rlimit + 环境清除 |
| 4 | TaskSpec 未 fuzz | ⚠️ harness 已添加 | TaskSpecValidator 严格校验 + libFuzzer |
| 5 | eBPF/MicroVM 裸机未验证 | ⚠️ 待环境 | 代码已完成，需裸机 KVM/CAP_BPF 实测 |
| 6 | 密钥硬编码 | ✅ 已修复 | 外部注入 + 轮换 + 常量时间比较 |
| 7 | 解释器白名单应用层校验 | ✅ 已修复 | seccomp-bpf 内核强制 KILL_PROCESS |
| 8 | 风险分数信任问题 | ✅ 已修复 | risk_enforcer 不可信输入强制 StrongPool |
| 9 | seccomp 白名单未逐行审计 | ⚠️ 待审计 | escape_poc_tester.sh 对抗测试 |

---

## 完成度统计

| 类别 | 总数 | ✅ 已完成 | ⚠️ 部分完成/待验证 | 🔴 未开始 |
|------|------|----------|-------------------|----------|
| 设计固有风险 | 4 | 2 | 2 | 0 |
| 代码待验证风险 | 8 | 4 | 4 | 0 |
| 权限部署风险 | 5 | 3 | 2 | 0 |
| 业务使用风险 | 4 | 3 | 1 | 0 |
| 项目生命周期 | 1 | 0 | 1 | 0 |
| **合计** | **22** | **12 (55%)** | **10 (45%)** | **0 (0%)** |

---

*最后更新：2026-09-02 | 基于 photon_kernel_sil3 v4.14-Final | 配套 PRODUCTION_CHECKLIST.md*
