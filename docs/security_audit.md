# 安全审计报告

## 审计范围
- `src/sandbox/sandboxed_executor.cpp` — fork+seccomp 沙盒执行器
- `src/sandbox/prewarmed_worker.cpp` — 预 fork 预热 worker
- `src/sandbox/code_runner.cpp` — 代码运行器（Python/Node/Shell）
- `src/sandbox/http_server.cpp` — 轻量 HTTP 服务器
- `server/e2b_gateway.cpp` — E2B 兼容网关（JSON 解析）
- `src/sandbox/sandbox_service.cpp` — gRPC 服务端

## 已发现并修复的问题

### 1. 【高危】子进程未关闭继承的文件描述符
**位置**：`sandboxed_executor.cpp:child_process_entry`、`prewarmed_worker.cpp:worker_main`
**风险**：沙盒子进程继承父进程所有打开的 fd，可通过 `/proc/self/fd` 访问父进程的文件、socket、管道，导致沙盒逃逸和信息泄露。
**修复**：子进程入口添加 `close_unneeded_fds()`，使用 `close_range`（Linux 5.9+）或遍历 `/proc/self/fd` 关闭所有 fd >= 3（保留通信 pipe）。

### 2. 【中危】子进程 stdin 未重定向
**位置**：同上
**风险**：用户代码可通过 stdin 读取父进程的输入数据。
**修复**：子进程将 stdin 重定向到 `/dev/null`。

### 3. 【中危】gRPC ExecuteAsync use-after-free
**位置**：`sandbox_service.cpp:ExecuteAsync`
**风险**：detach 线程捕获 gRPC `request` 指针，gRPC 在 RPC 返回后可能释放该指针，导致 use-after-free。
**修复**：在创建线程前将 request 拷贝为值类型 `CodeRunRequest`，线程只捕获值拷贝。

### 4. 【中危】gRPC 并发计数器只增不减
**位置**：`sandbox_service.cpp:Execute`
**风险**：`concurrent_tasks_.fetch_sub(1)` 在所有 return 之后，永远不会执行，导致并发计数器泄漏，最终所有请求被拒绝。
**修复**：使用 RAII `ConcurrentGuard`，析构时自动 -1。

### 5. 【低危】gRPC 缺少请求验证
**位置**：`sandbox_service.cpp`
**风险**：空代码、超大代码（>1MB）、超时溢出、非法 runner 值未验证。
**修复**：添加 `validate_request()`，验证 code 非空、大小上限 1MB、超时 0-60s、runner 范围。

### 6. 【低危】gRPC 缺少审计和 metrics
**位置**：`sandbox_service.cpp`
**风险**：代码执行无审计日志，无 metrics 统计。
**修复**：Execute 记录结构化 JSON 审计日志，更新 Metrics（任务数、执行时间）。

## 已验证的安全机制

| 机制 | 位置 | 状态 |
|---|---|---|
| seccomp 系统调用白名单 | `sandbox_policy.cpp` | 已验证（测试通过） |
| rlimit 资源限制 | `sandbox_policy.cpp` | 已验证 |
| 预 fork 子进程隔离 | `prewarmed_worker.cpp` | 已验证（p99<2ms） |
| Landlock 路径白名单 | `landlock.cpp` | 已验证（kernel 6.6 applied=yes） |
| cgroup v2 硬隔离 | `cgroup_manager.cpp` | 容器内 degraded，生产环境可用 |
| 审计日志 HMAC 哈希链 | `audit_security.cpp` | 已验证 |
| 子进程 fd 关闭 | 已实现 | 已验证（测试通过） |
| 子进程 stdin 重定向 | 已实现 | 已验证 |

## 仍存在的限制（需生产环境验证）

1. **eBPF 网络管控**：当前容器无 CAP_BPF，自动降级为 seccomp 全拦截；生产环境需验证 eBPF 程序加载和规则匹配。
2. **CRIU 快照**：当前容器无 criu，无法验证 dump/restore 的真实行为。
3. **命名空间隔离**：当前使用 seccomp + rlimit，未使用 user namespace / pid namespace / mount namespace。生产环境建议增加 namespace 隔离（参考 NsJail）。
4. **模糊测试**：已提供 libFuzzer harness，需在支持 ASan/UBSan 的环境运行。

## 模糊测试

见 `tests/fuzz/` 目录：
- `fuzz_code_runner.cpp` — 对代码执行器输入任意字节
- `fuzz_audit_logger.cpp` — 对审计日志输入任意字节
- `fuzz_json_parser.cpp` — 对 JSON 解析输入任意字节
- `fuzz_http_request.cpp` — 对 HTTP 请求解析输入任意字节

编译运行（需 clang + libFuzzer）：
```bash
clang++ -std=c++17 -fsanitize=fuzzer,address,undefined \
  -I include tests/fuzz/fuzz_code_runner.cpp \
  src/sandbox/code_runner.cpp -o fuzz_code_runner
./fuzz_code_runner -max_total_time=60
```
