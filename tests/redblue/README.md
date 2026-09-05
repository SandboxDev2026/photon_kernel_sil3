# LightPool 红蓝对抗测试制度

## 概述

制度性红蓝对抗测试：把渗透测试变成常态化流程，产出可归档报告。
不是单次人工渗透，而是可重复、可自动化、有准入规则的测试体系。

## 目录结构

```
tests/redblue/
├── README.md                    # 本文档（制度流程）
├── REPORT_TEMPLATE.md           # 对抗测试报告模板
├── run_redblue.sh               # 一键执行全部红队 POC
├── redteam_poc_ptrace.cpp          # POC-001: ptrace 注入父进程
├── redteam_poc_fd_leak.cpp         # POC-002: fd 泄露逃逸
├── redteam_poc_fork_bomb.cpp       # POC-003: fork 炸弹 DoS
├── redteam_poc_seccomp_bypass.cpp  # POC-004: seccomp 绕过尝试
├── redteam_poc_mount_escape.cpp    # POC-005: mount 逃逸
├── redteam_poc_toctou_race.cpp     # POC-006: TOCTOU 竞争条件逃逸
├── redteam_poc_32bit_seccomp_bypass.cpp # POC-007: 32位兼容模式 seccomp 绕过
├── redteam_poc_signal_race.cpp     # POC-008: 信号竞争条件逃逸
├── redteam_poc_proc_escape.cpp     # POC-009: /proc 接口突破限制
├── redteam_poc_memory_oom.cpp      # POC-010: 内存耗尽 OOM 拒绝服务
├── redteam_poc_landlock_bypass.cpp  # POC-011: Landlock 路径遍历与符号链接绕过
├── redteam_poc_cgroup_escape.cpp    # POC-012: cgroup 逃逸与资源限制绕过
├── redteam_poc_namespace_escape.cpp # POC-013: 命名空间逃逸与 setns 攻击
├── redteam_poc_kernel_info_leak.cpp # POC-014: 内核信息泄露与侦察
├── redteam_poc_sidechannel.cpp      # POC-015: 侧信道攻击（缓存时序+Spectre）
└── reports/                         # 对抗测试报告归档目录
    └── .gitkeep
```

## 红队对抗用例集（Red Team）

| ID | 用例 | 攻击技术 | 预期行为 | 风险等级 |
|----|------|---------|---------|---------|
| POC-001 | ptrace 注入 | 沙盒内尝试 ptrace 附加父进程 | 进程被 KILL，审计记录 | Critical |
| POC-002 | fd 泄露逃逸 | 继承未关闭特权 fd，尝试读写宿主文件 | 访问被拒绝，fd 已关闭 | High |
| POC-003 | fork 炸弹 | 疯狂 fork 耗尽 PID/资源 | cgroup pid 限制生效，进程被终止 | High |
| POC-004 | seccomp 绕过 | 尝试多种 seccomp-bpf 绕过技术 | 所有绕过被阻止，进程被 KILL | Critical |
| POC-005 | mount 逃逸 | 尝试 mount 特殊文件系统突破隔离 | mount 被拒绝，Landlock 生效 | High |
| POC-006 | TOCTOU 竞争 | access()/open() 之间切换符号链接 | 竞争条件未成功，路径验证有效 | High |
| POC-007 | 32位兼容绕过 | int 0x80 触发 32位系统调用 | arch 字段验证有效，进程被 KILL | Critical |
| POC-008 | 信号竞争 | SIGSYS/SIGSTOP 信号处理绕过 | KILL_PROCESS 无信号处理机会 | High |
| POC-009 | /proc 突破 | /proc/self/mem、sysrq、kcore 等 | Landlock 限制敏感路径访问 | High |
| POC-010 | 内存 OOM | malloc/mmap/COW/共享内存耗尽 | cgroup memory.max 限制生效 | High |
| POC-011 | cgroup 绕过 | 尝试修改 cgroup 限制、释放资源限制 | cgroup 文件系统只读，修改被拒 | High |
| POC-012 | namespace 逃逸 | 尝试突破 mount/pid/network/user namespace | namespace 隔离生效，无法访问宿主 | Critical |
| POC-013 | Landlock 绕过 | 尝试通过文件描述符继承、/proc 绕过 Landlock | Landlock 规则生效，访问被拒 | High |
| POC-014 | 内核信息泄露 | 读取 /proc/kallsyms、/boot/config、内核指针 | 内核指针被清零，敏感信息不可读 | Medium |
| POC-015 | 侧信道攻击 | Spectre/Meltdown 推测执行漏洞利用 | 内核页表隔离(KPTI)、微码更新生效 | High |
| POC-011 | Landlock绕过 | 路径遍历/符号链接/proc/self/fd | Landlock 限制所有路径访问 | High |
| POC-012 | cgroup逃逸 | 写入cgroup.procs/创建子cgroup/tmpfs绕过 | cgroup文件系统只读，资源限制生效 | High |
| POC-013 | 命名空间逃逸 | unshare user/setns/pivot_root | seccomp拦截，user namespace禁用 | Critical |
| POC-014 | 内核信息泄露 | /proc/kallsyms/dmesg/kcore/iomem | 敏感路径不可访问 | Medium |
| POC-015 | 侧信道攻击 | Flush+Reload/Spectre/高分辨率计时器 | 侧信道缓解已启用 | High |
| POC-004 | seccomp 绕过 | 32 位兼容模式/syscall 混淆 | 全部被拦截，无绕过 | Critical |
| POC-005 | mount 逃逸 | 尝试 mount procfs/sysfs 突破隔离 | mount 被 KILL | Critical |
| POC-006 | 内存炸弹 | 大量 mmap 耗尽内存 | cgroup 内存限制触发 OOM | Medium |
| POC-007 | fd 耗尽 | 打开海量文件耗尽 fd | rlimit NOFILE 拦截 | Medium |
| POC-008 | 信号竞争 | SIGSTOP/race condition 突破沙盒 | 进程被终止，无逃逸 | High |
| POC-009 | /proc 篡改 | 修改 /proc/self 下接口突破限制 | Landlock/seccomp 拦截 | High |
| POC-010 | 恶意网络 | 连接内网 IP/云元数据地址 | eBPF 网络过滤拦截 | High |

## 蓝方验证（防御侧）

每一次红队用例运行后，必须校验：

1. **进程终止**：恶意进程是否被 `SECCOMP_RET_KILL_PROCESS` 或 cgroup OOM 终止
2. **审计完整**：审计日志是否完整记录（pid、syscall号、参数、时间戳）
3. **资源配额**：cgroup/pid/rlimit 是否生效，没有耗尽宿主资源
4. **宿主完整性**：宿主没有文件被篡改、没有进程被注入、没有网络异常连接
5. **无横向移动**：其他沙盒实例未受影响

## 制度流程

### 1. PR 准入规则（强制）

**新增或修改沙盒功能的 PR，必须附带至少 1 条红队对抗用例，否则不允许合并。**

CI 检查项：
- PR 修改了 `include/photon_kernel/sandbox/` 下的文件
- PR 必须新增或修改 `tests/redblue/` 下的至少 1 个 POC
- 新增的 POC 必须在 CI 中运行通过（预期被拦截，不是预期成功）

### 2. 季度人工红蓝演练

- 每季度执行一次完整人工红蓝演练
- 红队：安全工程师尝试发现新的逃逸路径
- 蓝队：验证现有防御是否有效
- 输出：季度对抗报告 + 问题 issue 清单
- 发现的漏洞必须在 72 小时内修复（逃逸类 SLA）

### 3. 漏洞回归用例

**每发现一个逃逸漏洞，必须新增对应的回归安全用例。**

流程：
1. 漏洞报告 → 创建 issue
2. 修复漏洞 → 新增 `tests/redblue/redteam_poc_<vuln_id>.cpp`
3. 回归测试 → POC 在修复后必须被拦截
4. PR 合并 → 回归用例纳入 CI 持续运行

### 4. 报告归档

每次对抗测试后，使用 `REPORT_TEMPLATE.md` 生成报告，归档到 `tests/redblue/reports/` 目录。

报告命名：`redblue_report_YYYYMMDD_<version>.md`

## 执行方式

```bash
# 一键执行全部红队 POC（在沙盒内运行，预期全部被拦截）
cd tests/redblue
./run_redblue.sh

# 单独执行某个 POC
./redteam_poc_ptrace

# 生成报告
cp REPORT_TEMPLATE.md reports/redblue_report_$(date +%Y%m%d).md
```

## 覆盖率指标

- 安全相关分支覆盖率 ≥ 85%
- 每发现一个逃逸漏洞，必须新增对应回归用例
- 红队 POC 数量 ≥ 沙盒功能模块数 × 2
- 季度人工演练发现的问题，100% 有回归用例
