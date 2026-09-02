# Seccomp 白名单人工审计报告

**审计日期**：2026-09-02
**审计范围**：`src/sandbox/sandbox_policy.cpp` — `get_base_whitelist()` / `get_whitelist_for_risk()` / `get_whitelist_for_code_runner()` / `install_seccomp_filter()`
**审计方法**：逐行人工复核 + 与 NsJail / bubblewrap 参考实现对比

## 一、审计结论

整体设计合理，参考了 NsJail 的多策略白名单架构，默认动作为 `SECCOMP_RET_KILL_PROCESS`（非法调用直接杀死进程，而非返回 EPERM），这是正确的安全选择。

但发现 **3 个需关注项** 和 **2 个建议优化项**，详见下文。

## 二、已确认正确的设计

| 项 | 状态 | 说明 |
|---|---|---|
| 默认动作 KILL_PROCESS | ✅ | 非法 syscall 直接杀死，比 EPERM 更安全（防止攻击者利用返回值探测） |
| PR_SET_NO_NEW_PRIVS | ✅ | 安装 seccomp 前设置，防止 setuid 提权 |
| BPF 架构校验 | ✅ | 检查 `arch == x86_64`，防止 32 位 syscall 绕过 |
| HIGH 等级移除文件操作 | ✅ | 显式移除 openat/open/readlinkat/getdents64 等 |
| MEDIUM 等级无网络 | ✅ | 基础白名单不含 socket/connect，天然禁止网络 |
| 去重逻辑 | ✅ | sort + unique 防止重复 syscall |
| 解释器路径限制说明 | ✅ | 注释明确说明 seccomp 无法按路径过滤，由调用方硬编码 |

## 三、需关注项（按风险排序）

### 3.1 HIGH 等级未移除 fork/clone（中风险）

**位置**：`get_whitelist_for_risk()` — HIGH 分支的 `remove_list`

**问题**：基础白名单包含 `__NR_fork`, `__NR_vfork`, `__NR_clone`, `__NR_clone3`，HIGH 等级的 `remove_list` 未包含这些。高风险代码可以 fork 子进程，可能被用于：
- fork 炸弹（虽有 rlimit NPROC 限制）
- 子进程逃逸尝试（子进程可能继承不同的 seccomp 状态）
- 资源耗尽攻击

**建议**：HIGH 等级的 `remove_list` 中添加 `__NR_fork`, `__NR_vfork`, `__NR_clone`, `__NR_clone3`。如果代码执行确实需要 fork（如 shell 解释器），应在 code_runner 白名单中单独添加，而不是基础白名单。

**当前缓解**：rlimit `RLIMIT_NPROC` 限制进程数；任务进程有 TTL 超时。

### 3.2 基础白名单包含 socketpair/pipe（低风险）

**位置**：`get_base_whitelist()` — fd 操作部分

**问题**：`__NR_socketpair`, `__NR_pipe`, `__NR_pipe2` 在基础白名单中。这些不是网络 socket，是本地进程间通信，但可能被用于：
- fd 传递攻击（通过 UNIX domain socket 传递文件描述符）
- 与其他沙盒实例通信（如果 somehow 能拿到对方的 fd）

**建议**：HIGH 等级考虑移除 `__NR_socketpair`。pipe 保留（解释器需要管道）。

**当前缓解**：namespace 隔离（不同沙盒实例有独立的 fd 空间）；seccomp 禁止 socket/connect（无法建立网络连接）。

### 3.3 prctl 未限制子操作（低风险）

**位置**：`get_base_whitelist()` — 沙盒自省部分

**问题**：`__NR_prctl` 在基础白名单中。prctl 可以用于多种操作，包括：
- `PR_SET_SECCOMP`（安装 seccomp，正常需要）
- `PR_SET_DUMPABLE`（可能影响 core dump）
- `PR_SET_PDEATHSIG`（设置父进程死亡信号）
- `PR_SET_NO_NEW_PRIVS`（正常需要）

seccomp 无法过滤 prctl 的子操作号（option 参数），所以一旦允许 prctl，所有子操作都被允许。

**建议**：这是 seccomp 的固有局限，无法在 bpf 层面过滤。可接受风险。定期审查是否有新的危险 prctl 子操作。

## 四、建议优化项

### 4.1 考虑使用 libseccomp 替代手写 BPF

当前 `install_seccomp_filter()` 手写 BPF 指令，优点是零依赖，缺点是：
- 容易出错（BPF 指令手工构造）
- 不支持多架构（当前只校验 x86_64）
- 不支持 syscall 参数过滤（如限制 openat 的 flag）

**建议**：长期考虑引入 libseccomp-dev，支持参数级过滤。当前手写实现可接受，但需保持测试覆盖。

### 4.2 添加 seccomp 加载后的自检

**建议**：安装 seccomp 后，尝试调用一个不在白名单中的 syscall（如 `__NR_ptrace`），验证确实被 KILL_PROCESS。这可以在测试中完成，确保 seccomp 真正生效。

## 五、与参考实现对比

| 特性 | photon_kernel_sil3 | NsJail | bubblewrap |
|---|---|---|---|
| 默认动作 | KILL_PROCESS | KILL_PROCESS | EPERM (可配置) |
| 多策略 | LOW/MEDIUM/HIGH + code_runner | 多 profile | 单策略 |
| 参数过滤 | 不支持 | 支持(libseccomp) | 不支持 |
| 架构校验 | x86_64 | 多架构 | 多架构 |
| fork 控制 | 基础允许 | 可配置 | 允许 |

## 六、审计总结

| 等级 | 数量 | 说明 |
|---|---|---|
| 高风险 | 0 | 无 |
| 中风险 | 1 | HIGH 等级未移除 fork/clone |
| 低风险 | 2 | socketpair/prctl 固有局限 |
| 建议优化 | 2 | libseccomp/加载后自检 |

**总体评价**：seccomp 实现质量良好，默认动作和架构校验正确。主要改进空间是 HIGH 等级应更严格地移除 fork/clone。当前实现适合内网可信/半可信场景，公网不可信代码应配合 StrongPool (MicroVM) 使用。

**后续行动**：
1. [ ] HIGH 等级 remove_list 添加 fork/clone/vfork/clone3
2. [ ] 添加 seccomp 加载后自检测试
3. [ ] 长期评估 libseccomp 引入可行性
