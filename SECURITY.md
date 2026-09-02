# Security Policy

## 支持版本

| 版本 | 安全支持 |
|------|---------|
| v4.14.x | ✅ 完全支持 |
| < v4.14 | ❌ 不再支持 |

## 报告安全漏洞

**请勿在 GitHub Issues 中公开报告安全漏洞。**

请通过以下方式私密报告：

1. **GitHub Security Advisory**（推荐）：
   - 进入仓库 → Security → Advisories → New draft security advisory
   - 我们会在 24 小时内确认，72 小时内给出初步评估

2. **加密邮件**：
   - 发送至安全团队邮箱（在仓库 About 中查看）
   - 可使用 PGP 公钥加密（在 SECURITY.md 末尾获取）

## 漏洞响应 SLA

| 严重等级 | 确认时间 | 修复时间 | 披露时间 |
|---------|---------|---------|---------|
| Critical（远程代码执行/沙盒逃逸） | 24 小时 | 7 天 | 修复后 30 天 |
| High（权限提升/数据泄露） | 48 小时 | 14 天 | 修复后 30 天 |
| Medium（DoS/信息泄露） | 72 小时 | 30 天 | 修复后 60 天 |
| Low（理论风险） | 7 天 | 90 天 | 随版本发布 |

## 安全开发生命周期（SDL）

### 代码审查
- 所有 PR 必须经过至少 1 名安全审查员批准
- 涉及 seccomp/eBPF/cgroup/命名空间的 PR 需要 2 名审查员
- 安全敏感代码必须附带威胁建模说明

### 自动化安全扫描（CI）
- **静态分析**：clang-tidy + cppcheck（每次 PR）
- **依赖审计**：OSV-Scanner（每周）
- **模糊测试**：libFuzzer（4 个 harness，每日运行）
- **容器扫描**：Trivy（每次 Docker 构建）
- **密钥扫描**：gitleaks（每次 PR，防止密钥泄露）

### 内核漏洞监控
- `scripts/cve_monitor.py`：监控 Linux kernel、OpenSSL、gRPC、Firecracker 等依赖 CVE
- 监控范围：Linux kernel、seccomp、Landlock、eBPF、cgroup、glibc、OpenSSL、gRPC、Firecracker
- 高危 CVE 触发飞书 webhook 告警
- 输出格式：文本报告 / JSON / CycloneDX SBOM
- 运行：`python3 scripts/cve_monitor.py`（文本）/ `--json` / `--sbom` / `--report`

**已知相关 CVE（10 个，含影响分析）**：

| CVE | 组件 | 严重度 | 影响 | 缓解 |
|-----|------|--------|------|------|
| CVE-2024-1086 | Linux Kernel | Critical | nf_tables 双重释放，沙盒逃逸 | 升级内核 >=6.6.11；seccomp 拦截 nf_tables |
| CVE-2022-0185 | Linux Kernel | High | fs/configfs 堆溢出 | 升级内核 >=5.16.2 |
| CVE-2022-25840 | Linux Kernel | High | io_uring 引用计数 | seccomp 白名单不含 io_uring（已拦截） |
| CVE-2023-0386 | Linux Kernel | High | OverlayFS 提权 | pivot_root+独立 mount namespace，不依赖 overlayfs |
| CVE-2023-32233 | Linux Kernel | High | nf_tables 提权 | seccomp 拦截 nf_tables |
| CVE-2024-22252 | Linux Kernel | High | USB 子系统提权 | 沙盒默认不挂载 USB |
| CVE-2022-3602 | OpenSSL | High | X.509 缓冲区溢出 | 升级 >=3.0.7；项目有纯C++ crypto fallback |
| CVE-2023-44487 | gRPC/HTTP2 | High | Rapid Reset DoS | 升级 gRPC >=1.59；网关有限流保护 |
| CVE-2024-24762 | gRPC Python | Medium | Python gRPC DoS | 升级 grpcio >=1.62.0 |
| CVE-2023-41051 | Firecracker | Medium | virtio-vsock 信息泄露 | 升级 Firecracker >=1.5.0 |

**软件物料清单 (SBOM)**：
- 格式：CycloneDX 1.5
- 位置：`reports/sbom.cyclonedx.json`
- 组件：12 个直接依赖（含版本、许可证、关键度）
- 生成：`python3 scripts/cve_monitor.py --sbom > reports/sbom.cyclonedx.json`

## 已知安全边界（诚实声明）

### 已实现的防护
- ✅ seccomp-bpf 系统调用白名单
- ✅ rlimit 资源限制（8 项：CPU/内存/进程/fd/文件/core/信号/消息队列）
- ✅ cgroup v2 硬隔离（memory.max/cpu.max/pids.max）
- ✅ Landlock 文件路径白名单（kernel 6.6+）
- ✅ CapabilityToken 票据式动态权限（HMAC 签名，运行时可撤销）
- ✅ ResourceProxy 资源代理（密钥不落入沙盒内存，空白通行证）
- ✅ 审计日志 HMAC 哈希链（防篡改，文件权限 0600）
- ✅ 审计日志异步批量 gRPC 上报（失败本地落盘重试）
- ✅ oom_score_adj=1000（沙盒优先被 OOM kill）
- ✅ PR_SET_NO_NEW_PRIVS（防 setuid 提权）
- ✅ PR_SET_DUMPABLE=0（防 ptrace/dump）

### 已知限制（不适合的场景）
- ⚠️ **Process 后端共享宿主内核**：内核漏洞可能导致逃逸。公网多租户必须用 MicroVM 后端
- ⚠️ **MicroVM 后端需要裸机 + KVM**：容器环境自动降级为 Process 后端
- ⚠️ **eBPF 需要 CAP_BPF**：无权限时自动降级为 seccomp
- ⚠️ **CRIU 需要 root**：无权限时快照功能跳过
- ⚠️ **gRPC C++ 服务端需要 libgrpc++-dev**：无库时可用 Python gRPC 服务端替代

### 不承诺的安全属性
- ❌ 不防内核 0day 逃逸（Process 后端）
- ❌ 不防侧信道攻击（Spectre/Meltdown 等）
- ❌ 不防硬件级攻击（Rowhammer 等）
- ❌ 不防恶意管理员（root 可绕过所有隔离）

## 安全审计

- `docs/security_audit.md`：完整 STRIDE 威胁建模 + 已修复问题清单
- `docs/privileged_e2e_guide.md`：特权环境端到端验证手册
- 每次大版本发布前执行完整安全审计

## 致谢

感谢以下安全研究者的报告（按时间倒序）：
- （暂无，期待第一位报告者）

---

**PGP 公钥**（用于加密漏洞报告）：
```
-----BEGIN PGP PUBLIC KEY BLOCK-----
（请在此处粘贴安全团队 PGP 公钥）
-----END PGP PUBLIC KEY BLOCK-----
```
