# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added
- 遗传算法与自进化 Agent 模块（`evolution/`）：GA 主循环、三种变异模式（rewrite/patch/nl_feedback）、LLM 语义交叉、锦标赛选择、岛屿 GA、自进化闭环（执行-反思-生成-评测-快照）、Skill 技能库、档案库、LLM 模型适配器。所有代码执行通过沙盒，禁止本地 exec/eval。
- ReleaseGate 独立低权限进程加固：setuid nobody + seccomp-bpf（45 个 syscall 最小白名单），产物释放前强制校验。
- RiskEnforcer 风险强制模块：6 种任务来源分类，不可信输入强制 StrongPool，业务层二次校验后端类型。
- AuditDiskGuard 磁盘水位守卫：4 级水位监控（NORMAL/WARNING/CRITICAL/EMERGENCY），spool 队列溢出保护，旧文件轮转清理。
- TaskSpec 模糊测试 harness（libFuzzer + NO_FUZZER 手动模式）：8 个手动测试全部通过。
- 逃逸 POC 对抗测试框架（`scripts/escape_poc_tester.sh`）：5 大类 16 项测试。
- photon_sandbox_daemon 统一守护进程：HTTP API（/health, /capabilities, /pool/status, /execute, /metrics），10 项能力探测矩阵，HMAC 审计哈希链，优雅降级。
- RiskLevel 统一定义（`include/photon_kernel/sandbox/risk_level.hpp`）：解决多文件重复定义冲突。

### Changed
- seccomp 默认动作由 `SECCOMP_RET_ERRNO` 改为 `SECCOMP_RET_KILL_PROCESS`，非法 syscall 直接杀死进程。
- 预热池 shutdown 由 `sleep_for(60s)` 改为条件变量 `wait_for`，秒级返回。
- 解释器路径白名单由应用层判断改为 seccomp-bpf 内核强制（KILL_PROCESS）。
- CapabilityToken 密钥由硬编码改为外部注入 + 密钥轮换支持。

### Fixed
- 管道 READY/DONE 合并 bug：子进程执行过快时 READY 与 DONE 被管道一次合并读出，改为精确读取 5 字节。
- 看门狗超时计算 bug：`std::chrono::milliseconds(cpu_time_limit) * 1000` 把 2 秒算成 2000 秒，改用 `duration_cast<milliseconds>`。
- MEDIUM 等级 syscall 白名单矛盾：基础白名单缺少 `openat/readlinkat/getdents64`，已补入。
- HIGH 等级空操作：原代码对不在白名单中的 syscall 执行 erase（无效），现在移除真实存在的条目。
- 测试用例 braced-init 参数：GCC 对成员函数直接传聚合临时对象报错，改为显式构造。

## [v4.14]

### Added
- 法案合规引擎：22 条合规规则检查，覆盖《人工智能工程安全管理法案》核心条款。
- 四层控制平面架构：Control Plane / Execution Plane / Policy+Identity / Evidence+Release。
- 网络三层防御：网段隔离 + 网关隔离 + 内网隔离（eBPF RFC1918+云元数据黑名单）。
- StrongPool Firecracker MicroVM 后端：KVM 探测、高风险拒绝、并发上限、产物导出、工作区管理。
- CapabilityToken 票据式动态权限：HMAC-SHA256 签名，运行时可撤销。
- ResourceProxy 资源代理：CredentialVault 密钥保险箱 + 空白通行证。
- 6 种 namespace 隔离：mount+pivot_root+pid+net+uts+ipc+user。
- Landlock 文件路径白名单。
- cgroup v2 资源限制。
- 多智能体编排：Supervisor 总控 + Actor 消息总线 + Environment 代理层 + TaskDAG。
- 可插拔运行时：Container / gVisor / MicroVM / Wasm 四种后端。
- RiskScorer 风险打分：15+ 危险模式静态扫描。
- E2B 兼容 HTTP 网关。
- Prometheus metrics 导出。
- 隔离网关服务：域名白名单 + 限流 + DNS 劫持 + HMAC 审计。
- K8s Operator（kopf）：CRD + Reconcile 循环。
- CRIU 进程级快照接口。
- eBPF 网络管控程序。
- HMAC 审计哈希链（SHA256 纯 C++ 实现）。
- gRPC ClientStreaming 批量异步上报。
- Python gRPC 服务端/客户端（已端到端实测，8 项全过）。
- CVE 监控脚本。
- SBOM 生成（CycloneDX 1.5）。

### Known Limitations
- C++ gRPC 服务端代码完整，但需安装 `libgrpc++-dev` 后编译验证；当前使用 Python gRPC 作为生产替代。
- eBPF 网络管控、CRIU 快照、Firecracker MicroVM、K8s Operator 需特权环境（CAP_BPF / criu / KVM / 集群），代码完整但端到端实测需对应环境。
- LightPool 进程沙盒共享宿主内核，不适合直接跑公网完全不可信代码；公网高危代码必须使用 StrongPool。

## [v4.0]

### Added
- 基础沙盒：fork + seccomp-bpf + rlimit。
- 预 fork 预热池：p99 < 2ms。
- 任意代码执行：Python/Node 解释器预置。
- 8 项 rlimit 资源限制。
- gRPC Fast-Path 服务框架。

[Unreleased]: https://github.com/SandboxDev2026/PhotonBox/compare/v4.14...HEAD
[v4.14]: https://github.com/SandboxDev2026/PhotonBox/releases/tag/v4.14
[v4.0]: https://github.com/SandboxDev2026/PhotonBox/releases/tag/v4.0
