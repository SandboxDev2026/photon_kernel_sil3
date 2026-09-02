# 贡献指南

感谢你对 Photon Kernel Sandbox 的关注！我们欢迎各种形式的贡献。

## 快速开始

### 环境要求
- C++17 编译器（g++ 9+ / clang 10+）
- CMake 3.16+
- Python 3.8+（用于 gRPC 服务端、Operator、测试）
- Linux kernel 5.10+（推荐 6.6+，支持 Landlock、eBPF、cgroup v2）

### 构建
```bash
# 非 gRPC 模式（默认，适合无 gRPC 环境）
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# gRPC 模式（需要 libgrpc++-dev）
cmake -B build -DCMAKE_BUILD_TYPE=Release -DPHOTON_ENABLE_GRPC=ON
cmake --build build -j$(nproc)

# 一键构建脚本
./scripts/build.sh --test
```

### 运行测试
```bash
# C++ 单元测试
./build/test_sandbox       # 基础沙盒 8 测试
./build/test_enhanced      # 增强测试 77+2
./build/test_new_modules   # 新架构模块 23 测试

# Python 测试
python3 tests/test_operator.py

# gRPC 端到端实测
python3 server/python/sandbox_grpc_server.py --port 50051 &
python3 server/python/sandbox_grpc_client.py --port 50051

# 全量验证
./scripts/verify_all.sh
```

## 贡献流程

### 1. 找到要做的事
- 查看 [Issues](https://github.com/SandboxDev2026/photon_kernel_sil3/issues) 中的 open issues
- 查看 `docs/` 下的设计文档，了解架构
- 运行 `./scripts/verify_all.sh`，找到 SKIP 的项，这些是需要特权环境验证的

### 2. Fork & 分支
```bash
git fork https://github.com/SandboxDev2026/photon_kernel_sil3
git checkout -b feature/your-feature-name
```

分支命名规范：
- `feature/xxx` — 新功能
- `fix/xxx` — Bug 修复
- `security/xxx` — 安全修复
- `docs/xxx` — 文档更新
- `test/xxx` — 测试补充

### 3. 编码规范

#### C++
- 遵循 C++17 标准
- 命名空间：`photon_kernel::sandbox`
- 类名：`PascalCase`，函数/变量：`snake_case`，常量：`kPascalCase`
- 头文件保护：`#pragma once`
- 每个公共 API 必须有 Doxygen 注释
- 安全敏感代码（seccomp/eBPF/namespace/审计）必须有威胁建模注释

#### Python
- 遵循 PEP 8
- 类型注解（type hints）
- gRPC 服务端必须支持优雅退出

#### 安全编码
- 所有用户输入必须验证（代码、路径、网络地址）
- 禁止使用 `system()`，用 `execve()` 或 `fork()+exec()`
- 禁止硬编码密钥，用环境变量或配置文件
- 新隔离机制必须有降级路径（无权限时不崩溃）

### 4. 提交 PR
- PR 标题格式：`[类型] 简短描述`，类型：feat/fix/security/docs/test/refactor
- PR 描述必须包含：
  - 做了什么（What）
  - 为什么做（Why）
  - 怎么验证的（How tested）
  - 是否有破坏性变更（Breaking changes）
- 安全相关 PR 必须标签 `security`，并在描述中说明威胁模型
- 所有 CI 检查必须通过

### 5. 代码审查
- 至少 1 名审查员批准
- 安全敏感代码（seccomp/eBPF/namespace/审计/加密）需要 2 名审查员
- 审查关注点：
  - 安全性：是否引入新的攻击面
  - 正确性：边界条件、错误处理
  - 性能：是否影响预热池延迟
  - 可维护性：命名、注释、复杂度

## 安全贡献

### 报告漏洞
**请勿在公开 Issues 中报告安全漏洞。** 请通过 [GitHub Security Advisories](https://github.com/SandboxDev2026/photon_kernel_sil3/security/advisories) 私密报告。

详见 [SECURITY.md](./SECURITY.md)。

### 安全修复
- 安全修复 PR 必须标签 `security`
- 必须包含：漏洞描述、影响范围、修复方案、验证方法
- 修复后必须添加回归测试
- CVE 分配后更新 `docs/security_audit.md`

## 特权环境验证

以下功能需要 root/特权环境，贡献者可在本地验证：

| 功能 | 依赖 | 验证命令 |
|------|------|---------|
| Namespace 隔离 | root | `sudo ./build/test_enhanced --gtest_filter=*Namespace*` |
| CRIU 快照 | criu + root | `sudo ./scripts/verify_e2e.sh --criu` |
| eBPF 网络管控 | libbpf + CAP_BPF | `cd ebpf && make verify` |
| K8s Operator | kind/k3s | `kind create cluster && ./scripts/verify_e2e.sh --k8s` |
| Firecracker MicroVM | /dev/kvm + firecracker | `./scripts/verify_e2e.sh --privileged` |
| gRPC C++ 服务端 | libgrpc++-dev | `cmake -DPHOTON_ENABLE_GRPC=ON && ./build/sandbox_server` |

## 社区行为准则

- 尊重他人，友善讨论
- 接受建设性批评
- 关注技术，不进行人身攻击
- 遇到问题先搜索，再提问
- 帮助新贡献者

## 获得帮助

- Issues: https://github.com/SandboxDev2026/photon_kernel_sil3/issues
- 设计文档: `docs/`
- 安全问题: 见 SECURITY.md

---

再次感谢你的贡献！每一个 PR 都让这个沙盒更安全、更可靠。
