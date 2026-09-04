# PhotonBox 安全编码规范

**版本**: 1.0
**生效日期**: 2026-09-05
**适用范围**: PhotonBox 项目全部 C++ 和 Python 代码
**文档负责人**: 项目维护团队

---

## 1. 目的

本规范定义 PhotonBox 项目的安全编码标准，确保：
- 代码从源头避免常见安全漏洞
- 沙盒隔离机制的实现正确且安全
- 输入验证、输出编码、错误处理符合安全要求
- 代码审查有明确的安全检查清单
- CI/CD 流水线有自动化安全检查

---

## 2. 通用安全原则

### 2.1 输入验证
- **所有外部输入必须验证**: 包括用户代码、配置文件、网络请求、审计日志、gRPC 消息
- **白名单优先**: 使用白名单验证（允许什么），而非黑名单（禁止什么）
- **类型安全**: 验证输入类型、长度、范围、格式
- **拒绝默认**: 验证失败时拒绝处理，而非尝试修复
- **多层验证**: 关键输入在多个层级验证（入口、业务逻辑、沙盒边界）

### 2.2 输出编码
- **上下文相关编码**: 根据输出上下文选择正确的编码方式
- **Shell 命令**: 禁止字符串拼接，使用参数数组
- **SQL 查询**: 使用参数化查询，禁止字符串拼接
- **HTML/XML**: 对特殊字符进行实体编码
- **JSON**: 使用标准库序列化，禁止手动拼接

### 2.3 错误处理
- **不泄露敏感信息**: 错误消息不得包含堆栈跟踪、文件路径、内部配置
- **优雅降级**: 失败时进入安全状态，而非继续执行
- **日志记录**: 记录错误详情到内部日志，但不返回给调用方
- **资源清理**: 错误路径必须正确清理资源（文件描述符、内存、锁）
- **不静默吞错**: 不得忽略错误返回值

### 2.4 资源管理
- **自动清理**: 使用 RAII（C++）/ context manager（Python）确保资源释放
- **文件描述符**: 沙盒内进程必须限制 fd 数量，exec 前关闭所有非必要 fd
- **内存**: 设置内存上限，防止 OOM
- **CPU**: 设置 CPU 时间限制，防止死循环
- **超时**: 所有外部操作必须设置超时

---

## 3. C++ 安全编码规范

### 3.1 内存安全

#### 3.1.1 禁止使用的危险函数

| 函数 | 替代方案 | 原因 |
|------|---------|------|
| `strcpy`, `strcat` | `strncpy_s`, `std::string` | 缓冲区溢出 |
| `sprintf`, `vsprintf` | `snprintf`, `std::format` | 缓冲区溢出 |
| `gets` | `fgets`, `std::getline` | 缓冲区溢出 |
| `scanf` 无宽度限制 | `scanf` 带宽度限制 | 缓冲区溢出 |
| `malloc`/`free` 手动管理 | `std::unique_ptr`, `std::shared_ptr` | 内存泄漏、UAF |
| `new`/`delete` 手动管理 | RAII 智能指针 | 内存泄漏、UAF |
| `reinterpret_cast` | 避免使用，或加注释说明 | 类型混淆 |
| `const_cast` | 避免使用 | 常量篡改 |

#### 3.1.2 缓冲区操作
- 所有缓冲区操作必须检查边界
- 使用 `std::string`, `std::vector`, `std::array` 替代原始数组
- 必须使用带长度参数的函数（`strnlen`, `strncmp`, `memcmp`）
- 从不可信源读取数据时，必须验证长度不超过缓冲区大小
- 网络字节序转换必须使用标准函数（`ntohl`, `htonl`）

#### 3.1.3 指针安全
- 禁止使用裸指针拥有资源，使用智能指针
- 指针使用前必须检查非空
- 禁止解引用已释放的指针（UAF）
- 禁止越界访问数组
- 函数返回指针时，必须明确所有权语义

### 3.2 输入验证

#### 3.2.1 gRPC 消息验证
- 所有 gRPC 请求字段必须验证
- 字符串字段验证长度上限
- 数字字段验证范围
- 枚举字段验证有效值
- 嵌套消息递归验证

```cpp
// 正确示例
Status ExecuteTask(ServerContext* context,
                   const TaskSpec* request,
                   TaskResult* response) {
    // 验证必填字段
    if (request->task_id().empty()) {
        return Status(StatusCode::INVALID_ARGUMENT, "task_id is required");
    }
    // 验证长度上限
    if (request->code().size() > MAX_CODE_SIZE) {
        return Status(StatusCode::INVALID_ARGUMENT, "code exceeds max size");
    }
    // 验证枚举范围
    if (request->runtime() < Runtime_MIN || request->runtime() > Runtime_MAX) {
        return Status(StatusCode::INVALID_ARGUMENT, "invalid runtime");
    }
    // ... 处理
}
```

#### 3.2.2 TaskSpec 严格校验
- `task_id`: 非空，长度 ≤ 256，字符集 `[a-zA-Z0-9_-]`
- `code`: 非空，大小 ≤ 1MB（可配置）
- `runtime`: 有效枚举值
- `timeout`: 范围 1s - 3600s
- `memory_limit`: 范围 16MB - 4GB
- `cpu_limit`: 范围 0.1 - 16 核
- `network_policy`: 有效枚举值
- `env_vars`: 数量 ≤ 64，每个 key/value 长度 ≤ 4096
- 禁止字段包含控制字符或 NUL 字节

### 3.3 系统调用安全

#### 3.3.1 seccomp 白名单
- seccomp 白名单必须逐行审计
- 仅允许沙盒内进程执行任务所需的最小系统调用集合
- 禁止允许 `ptrace`, `mount`, `unshare`, `setns`, `clone` 带 CLONE_NEWNS 等危险系统调用
- 系统调用参数必须过滤（不仅是系统调用号）
- 使用 `SECCOMP_RET_KILL_PROCESS` 作为默认动作

#### 3.3.2 fork/exec 安全
- fork 后子进程必须立即执行 exec，不得在中间执行复杂逻辑
- exec 前必须关闭所有非必要文件描述符（使用 `O_CLOEXEC` 或遍历 `/proc/self/fd`）
- exec 前必须重置信号处理
- exec 前必须清除环境变量，仅保留必要的
- 使用 `execve` 而非 `system`/`popen`
- 禁止使用 `shell=True` 风格的调用

```cpp
// 正确示例：安全的 fork/exec
pid_t pid = fork();
if (pid == 0) {
    // 子进程：立即清理并 exec
    // 1. 关闭所有非必要 fd
    for (int fd = 3; fd < FD_SETSIZE; fd++) {
        close(fd);
    }
    // 2. 重置信号
    for (int sig = 1; sig < NSIG; sig++) {
        signal(sig, SIG_DFL);
    }
    // 3. 清除环境
    clearenv();
    // 4. 设置必要环境
    setenv("PATH", "/usr/bin:/bin", 1);
    // 5. exec（使用参数数组，不通过 shell）
    execve("/usr/bin/python3", args, environ);
    // exec 失败必须立即退出
    _exit(127);
}
```

#### 3.3.3 文件操作安全
- 使用 `openat` 而非 `open`，避免 TOCTOU
- 禁止跟随符号链接（使用 `O_NOFOLLOW`）
- 文件权限必须显式设置（`umask` + `chmod`）
- 临时文件使用 `mkstemp`，创建后立即 `unlink`
- 禁止在沙盒内可写目录中创建 setuid 文件
- 挂载操作必须验证源和目标路径，禁止路径遍历

### 3.4 并发安全

#### 3.4.1 竞态条件
- 共享数据访问必须加锁
- 使用 `std::mutex`, `std::shared_mutex`, `std::atomic`
- 禁止在持有锁的情况下执行可能阻塞的操作
- 双检锁（DCL）必须使用原子操作和内存屏障
- 文件操作必须考虑 TOCTOU（检查时间 vs 使用时间）

#### 3.4.2 死锁预防
- 按固定顺序获取多把锁
- 使用 `std::lock` 同时获取多把锁
- 避免在回调中获取锁
- 设置锁超时（`try_lock_for`）
- 定期检查死锁（使用 `std::deadlock_detector` 或 valgrind helgrind）

### 3.5 加密安全

#### 3.5.1 随机数
- 安全场景必须使用密码学安全随机数（`/dev/urandom`, `getrandom`, `RAND_bytes`）
- 禁止使用 `rand`, `random`, `mt19937` 用于安全场景
- 随机数生成器必须正确播种
- 密钥、盐值、nonce、会话 ID 必须使用 CSPRNG

#### 3.5.2 哈希与签名
- 使用标准库实现（OpenSSL, libsodium），禁止自行实现
- 密码哈希使用 `bcrypt`, `scrypt`, `Argon2`，禁止 MD5/SHA1
- HMAC 使用 SHA-256 或更高
- 审计链使用 HMAC-SHA256 链式签名
- 密钥长度：对称加密 ≥ 128 位，非对称 ≥ 2048 位（RSA）或 256 位（ECC）

#### 3.5.3 TLS/SSL
- 使用 TLS 1.2 或更高（推荐 TLS 1.3）
- 禁止 SSLv2, SSLv3, TLS 1.0, TLS 1.1
- 禁用弱密码套件（RC4, MD5, SHA1, 3DES, 导出级）
- 验证证书链和主机名
- gRPC 控制平面使用 mTLS 双向认证

### 3.6 编译安全

#### 3.6.1 编译选项
- 必须启用：`-Wall -Wextra -Werror -pedantic`
- 安全加固：`-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie`
- 控制流保护：`-fcf-protection=full -mshstk`（如支持）
- 地址空间布局随机化：运行时 ASLR 必须开启
- 调试符号：生产构建剥离调试符号（`strip`）

#### 3.6.2 静态分析
- CI 必须运行：`clang-tidy`, `cppcheck`, `coverity`（如可用）
- 禁止引入新的 High/Critical 级别警告
- 内存错误检测：ASAN（AddressSanitizer）, UBSAN（UndefinedBehaviorSanitizer）
- 测试构建必须启用 ASAN/UBSAN
- 模糊测试：使用 libFuzzer/AFL++ 对关键输入解析模块做 fuzz

---

## 4. Python 安全编码规范

### 4.1 禁止使用的危险函数

| 函数/模块 | 替代方案 | 原因 |
|----------|---------|------|
| `eval()` | `ast.literal_eval()`, 显式解析 | 任意代码执行 |
| `exec()` | 避免使用，或在沙盒中执行 | 任意代码执行 |
| `os.system()` | `subprocess.run([...], shell=False)` | 命令注入 |
| `os.popen()` | `subprocess.run()` | 命令注入 |
| `subprocess.run(shell=True)` | `shell=False` + 参数列表 | 命令注入 |
| `pickle.loads()` | `json`, `msgpack` | 任意代码执行 |
| `yaml.load()` | `yaml.safe_load()` | 任意代码执行 |
| `marshal.loads()` | 避免使用 | 任意代码执行 |
| `input()` (Python 2) | `raw_input()` | 任意代码执行 |
| `tempfile.mktemp()` | `tempfile.mkstemp()` | 竞态条件 |

### 4.2 输入验证

#### 4.2.1 类型验证
- 使用类型注解（`typing` 模块）
- 运行时验证关键输入类型
- 使用 `pydantic` 或 `dataclasses` 进行数据验证
- 禁止信任外部输入的类型声明

```python
# 正确示例
from pydantic import BaseModel, Field, validator

class TaskSpec(BaseModel):
    task_id: str = Field(..., min_length=1, max_length=256)
    code: str = Field(..., max_length=1024*1024)  # 1MB
    timeout: int = Field(..., ge=1, le=3600)
    memory_limit: int = Field(..., ge=16, le=4096)  # MB

    @validator('task_id')
    def validate_task_id(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('task_id contains invalid characters')
        return v
```

#### 4.2.2 路径安全
- 禁止用户输入直接用于文件路径
- 使用 `os.path.realpath` 解析后验证是否在允许目录内
- 禁止路径遍历（`../`）
- 禁止符号链接跟随（使用 `os.path.islink` 检查）
- 临时文件使用 `tempfile` 模块

```python
# 正确示例：安全路径验证
def safe_join(base_dir: str, user_path: str) -> str:
    # 解析真实路径
    real_base = os.path.realpath(base_dir)
    full_path = os.path.realpath(os.path.join(real_base, user_path))
    # 验证在基础目录内
    if not full_path.startswith(real_base + os.sep) and full_path != real_base:
        raise ValueError("Path traversal detected")
    return full_path
```

### 4.3 子进程安全

#### 4.3.1 命令执行
- 必须使用 `subprocess.run([...], shell=False)`
- 禁止字符串拼接命令
- 必须设置 `timeout`
- 必须限制 `env`（仅传递必要环境变量）
- 必须设置 `cwd`（沙盒工作目录）
- 输出大小必须限制（防止内存耗尽）

```python
# 正确示例
import subprocess

def run_sandboxed_command(args: list[str], timeout: int = 30):
    result = subprocess.run(
        args,
        shell=False,           # 禁止 shell
        timeout=timeout,       # 超时
        capture_output=True,   # 捕获输出
        text=True,
        env={"PATH": "/usr/bin:/bin"},  # 最小环境
        cwd="/sandbox/work",   # 沙盒目录
    )
    # 限制输出大小
    if len(result.stdout) > 1024*1024:
        result.stdout = result.stdout[:1024*1024] + "...[truncated]"
    return result
```

### 4.4 网络安全

#### 4.4.1 HTTP 请求
- 必须验证 URL（禁止内网 IP、元数据地址）
- 必须设置超时
- 必须验证 SSL 证书（`verify=True`）
- 禁止跟随重定向到内网地址
- 限制响应大小

```python
# 正确示例：安全 HTTP 请求
import requests
from urllib.parse import urlparse

def safe_http_get(url: str, timeout: int = 10):
    # 验证 URL
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("Invalid scheme")
    # 禁止内网地址（需要 DNS 解析后验证）
    # ...
    # 安全请求
    response = requests.get(
        url,
        timeout=timeout,
        verify=True,            # 验证 SSL
        allow_redirects=False,  # 禁止自动重定向
        stream=True,            # 流式读取，限制大小
    )
    # 限制响应大小
    content = response.raw.read(10*1024*1024)  # 最多 10MB
    return content
```

### 4.5 序列化安全

#### 4.5.1 禁止反序列化不可信数据
- 禁止使用 `pickle.loads()` 处理不可信数据
- 使用 `json`, `msgpack`, `protobuf` 等安全格式
- YAML 使用 `yaml.safe_load()`
- 自定义反序列化必须验证类型和字段

### 4.6 日志安全

#### 4.6.1 日志注入
- 禁止直接将用户输入写入日志（可能注入伪造日志行）
- 对用户输入进行转义（换行符、控制字符）
- 使用结构化日志（JSON 格式）
- 日志中不得包含密钥、密码、Token

```python
# 正确示例：安全日志
import logging
import json

def safe_log(event: dict):
    # 序列化时转义特殊字符
    sanitized = json.dumps(event, ensure_ascii=True)
    logging.info("sandbox_event: %s", sanitized)
```

---

## 5. 沙盒特定安全规范

### 5.1 命名空间隔离
- 必须创建独立的 PID、NET、MNT、USER、IPC、UTS namespace
- USER namespace 必须配置 uid/gid 映射
- MNT namespace 必须 pivot_root，禁止共享宿主挂载
- NET namespace 必须配置独立网络栈，禁止共享宿主网络
- 禁止沙盒内进程访问宿主 `/proc`, `/sys`

### 5.2 cgroup 资源限制
- 必须设置 CPU 上限（`cpu.max`）
- 必须设置内存上限（`memory.max`）
- 必须设置进程数上限（`pids.max`）
- 必须设置磁盘 IO 上限（`io.max`）
- 必须设置设备访问白名单（`devices.allow`）

### 5.3 Landlock 文件系统限制
- 必须使用 Landlock 限制文件系统访问
- 沙盒内仅允许访问工作目录和必要的系统库
- 禁止访问 `/etc/passwd`, `/etc/shadow`, `/root`, `/home`
- 禁止写系统目录
- 禁止执行非白名单路径的二进制

### 5.4 能力删除
- 沙盒内进程必须删除所有 capabilities
- 使用 `prctl(PR_SET_NO_NEW_PRIVS, 1)` 防止 setuid 提权
- 禁止 `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_MODULE` 等危险能力
- 守护进程使用最小 capabilities 集合，不使用完整 root

---

## 6. 代码审查安全检查清单

### 6.1 输入验证
- [ ] 所有外部输入是否验证？
- [ ] 是否使用白名单而非黑名单？
- [ ] 字符串长度是否有限制？
- [ ] 数字范围是否验证？
- [ ] 枚举值是否验证？
- [ ] 路径是否验证（防遍历）？

### 6.2 内存安全（C++）
- [ ] 是否使用智能指针而非裸指针？
- [ ] 缓冲区操作是否检查边界？
- [ ] 是否禁止使用危险函数（strcpy, sprintf 等）？
- [ ] 错误路径是否正确释放资源？
- [ ] 是否有潜在的 UAF/双重释放？

### 6.3 命令执行
- [ ] 是否禁止 shell=True？
- [ ] 是否使用参数数组而非字符串拼接？
- [ ] 是否设置超时？
- [ ] 是否限制环境变量？
- [ ] 是否限制输出大小？

### 6.4 加密安全
- [ ] 是否使用密码学安全随机数？
- [ ] 是否使用标准加密库而非自行实现？
- [ ] 密钥是否外部注入（不硬编码）？
- [ ] TLS 是否使用 1.2+？
- [ ] 是否验证证书？

### 6.5 并发安全
- [ ] 共享数据是否加锁？
- [ ] 是否有潜在死锁？
- [ ] 是否有竞态条件（TOCTOU）？
- [ ] 锁的粒度是否合理？
- [ ] 是否在持有锁时执行阻塞操作？

### 6.6 错误处理
- [ ] 是否检查所有错误返回值？
- [ ] 错误消息是否泄露敏感信息？
- [ ] 失败时是否进入安全状态？
- [ ] 资源是否正确清理？
- [ ] 是否有日志记录？

### 6.7 沙盒安全
- [ ] 是否创建所有必要 namespace？
- [ ] seccomp 白名单是否最小化？
- [ ] cgroup 资源限制是否设置？
- [ ] Landlock 规则是否正确？
- [ ] capabilities 是否删除？
- [ ] 文件描述符是否关闭？
- [ ] 环境变量是否清理？

---

## 7. CI/CD 安全检查

### 7.1 必须通过的检查
- [ ] 全量单元测试通过
- [ ] SAST 扫描（bandit for Python, clang-tidy/cppcheck for C++）0 High
- [ ] 代码覆盖率不低于 80%
- [ ] 代码审查至少 1 人批准（安全相关 2 人）
- [ ] 依赖漏洞扫描（pip-audit, safety）0 High
- [ ] 许可证合规检查

### 7.2 定期运行的检查
- [ ] 模糊测试（libFuzzer/AFL++）每周运行
- [ ] ASAN/UBSAN 构建每周运行
- [ ] 渗透测试每月运行
- [ ] 依赖更新检查每周运行
- [ ] SBOM 生成每月更新

---

## 8. 违规处理

### 8.1 违规等级
- **Critical**: 引入可直接利用的安全漏洞（如沙盒逃逸、命令注入）
- **High**: 引入可能被利用的安全漏洞（如信息泄露、DoS）
- **Medium**: 违反安全编码规范但无直接漏洞
- **Low**: 代码风格、文档问题

### 8.2 处理措施
- Critical/High: 立即修复，代码不得合并
- Medium: 必须在合并前修复或记录豁免
- Low: 记录在 issue 中，择机修复
- 重复违规：加强代码审查，可能限制提交权限

---

## 附录

### 附录 A：参考标准
- OWASP Secure Coding Practices
- CERT C++ Coding Standard
- CWE Top 25 Most Dangerous Software Weaknesses
- MITRE ATT&CK Framework
- NIST SP 800-53 Security and Privacy Controls

### 附录 B：工具清单
- **SAST**: bandit (Python), clang-tidy, cppcheck (C++)
- **依赖扫描**: pip-audit, safety, syft (SBOM)
- **模糊测试**: libFuzzer, AFL++
- **内存检测**: ASAN, UBSAN, valgrind
- **代码覆盖率**: gcov, lcov, coverage.py

---

**最后更新**: 2026-09-05
**下次审查**: 2027-09-05
