# Photon Kernel Sandbox — 四层架构设计

## 概述

现代 Agent Sandbox 运行时没有绝对的优劣顺序。真正的运行时选型，需要同时考虑：
- 代码与租户可信度
- Linux 工具兼容性
- 冷启动延迟
- 并发密度
- 状态恢复
- 基础设施成本

本工程实现完整的四层架构，系统拆解四个控制平面：

```
┌─────────────────────────────────────────────────────────┐
│                   Control Plane                          │
│  目标编译 → TaskSpec(资源/网络/身份/工具/预算/TTL)      │
│  + RuntimeSelector 自动选型(4种运行时评分矩阵)          │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│                  Execution Plane                         │
│  统一 IRuntime 接口 + 4种运行时后端                      │
│  Container | gVisor | MicroVM(Firecracker) | Wasm      │
│  + 私有工作区管理 + 快照/恢复                            │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│                 Policy + Identity                        │
│  网络出口策略(白名单/黑名单/审批)                         │
│  + 凭证保险箱(不落入沙盒,空白通行证)                      │
│  + 工具调用逐次允许/拒绝/审批                             │
│  + 审批管理器(人工审批流程)                               │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│                Evidence + Release                        │
│  证据收集(diff/测试/轨迹/产物哈希)                        │
│  + 独立发布闸门(5项检查重新验证)                          │
│  + 决策: RELEASE / REJECT / REQUIRE_REVIEW              │
└─────────────────────────────────────────────────────────┘
```

## 一、Control Plane — 控制平面

### 1.1 TaskSpec 任务规范

把用户目标编译成结构化任务规范，定义：

| 维度 | 字段 | 说明 |
|------|------|------|
| 资源 | ResourceSpec | CPU核数/内存/磁盘/最大进程数/最大文件数/GPU |
| 网络 | NetworkSpec | 启用/DNS/出口CIDR白名单/端口/代理/并发连接/带宽 |
| 身份 | IdentitySpec | 主体/租户ID/角色/能力列表/凭证注入/CapabilityToken |
| 工具 | ToolSpec | 工具名/启用/允许参数/最大调用次数/限流/审批 |
| 预算 | BudgetSpec | TTL/执行超时/最大重试/CPU时间/网络流量/成本预算 |
| 工作区 | workspace_path | 私有工作区路径/是否持久化 |

### 1.2 TaskCompiler 任务编译器

- `compile(goal, workload, tenant_id)`: 通用任务编译
- `compile_code_execution(code, language, workload)`: 代码执行任务（短TTL）
- `compile_agent_task(goal, allowed_tools, workload)`: Agent任务（长TTL，多工具）
- `validate(spec, error)`: 验证任务规范完整性
- `apply_defaults(spec)`: 应用默认值

### 1.3 RuntimeSelector 运行时选型器

四种运行时评分矩阵（0-100分）：

| 维度 | Container | gVisor | MicroVM | Wasm |
|------|-----------|--------|---------|------|
| 隔离强度 | 30 | 60 | 95 | 90 |
| 冷启动速度 | 70 | 50 | 65 | 100 |
| 并发密度 | 85 | 65 | 35 | 100 |
| Linux兼容性 | 100 | 80 | 100 | 30 |
| 状态恢复 | 60 | 50 | 85 | 95 |
| 成本效率 | 90 | 70 | 40 | 100 |
| 典型冷启动 | ~100ms | ~200ms | ~125ms | <1ms |
| 典型内存 | ~10MB | ~30MB | ~50MB | ~1MB |

**选型逻辑**：
- 加权评分：隔离强度(权重=100-trust) + Linux兼容(需要时80/不需要20) + 冷启动 + 并发 + 恢复 + 成本
- 硬约束：需要完整Linux工具但运行时兼容性<50，扣150分（排除Wasm）
- 自动降级：首选不可用时降级到备选

**典型选型结果**：
- 低可信度+需要Linux工具 → MicroVM（独立内核）
- 高可信+高并发+无状态 → Wasm（<1ms冷启动）
- 高可信+需要Linux工具+成本敏感 → Container
- 半可信多租户+无KVM → gVisor

## 二、Execution Plane — 执行平面

### 2.1 IRuntime 统一接口

```cpp
class IRuntime {
    virtual std::string create(const TaskSpec& spec) = 0;
    virtual void destroy(const std::string& instance_id) = 0;
    virtual RuntimeExecResult exec(const std::string& id, const std::string& code,
                                     const std::string& language) = 0;
    virtual bool snapshot(const std::string& id, const std::string& path) = 0;
    virtual std::string restore(const std::string& snapshot_path) = 0;
    virtual RuntimeStatus status() const = 0;
    virtual bool available() const = 0;
    virtual std::string workspace_path(const std::string& id) const = 0;
};
```

### 2.2 四种运行时实现

| 运行时 | 实现方式 | 隔离机制 | 状态恢复 | 环境要求 |
|--------|----------|----------|----------|----------|
| ContainerRuntime | fork+namespace+cgroup | 共享内核 | CRIU | root/userns |
| GVisorRuntime | runsc create/exec | 用户态内核 | checkpoint | runsc二进制 |
| MicroVMRuntime | Firecracker REST API | 独立内核(KVM) | 快照API | firecracker+/dev/kvm+root |
| WasmRuntime | wasmtime/wasmer run | WASI沙箱 | 原生(小) | wasmtime/wasmer二进制 |

### 2.3 RuntimeFactory 工厂

- `create(type)`: 按类型创建
- `create_by_workload(workload)`: 按工作负载自动选型+降级

## 三、Policy + Identity — 策略与身份平面

### 3.1 NetworkPolicy 网络策略

- 默认拒绝（只允许本地回环 127.0.0.1/32, ::1/128）
- CIDR 白名单/黑名单
- 端口白名单
- DNS 单独控制
- 决策：ALLOW / DENY / REQUIRE_APPROVAL

### 3.2 PolicyCredentialVault 凭证保险箱

借鉴 OpenSandbox Credential Vault + 澎湃OS空白通行证：

- 凭证加密存储（XOR，生产环境应用AES-256-GCM+KMS）
- 凭证永不落入沙盒内存，代理中转
- 调用方权限校验（allowed_callers 列表）
- **空白通行证**：无权限时返回虚拟替身数据（sk-dummy-xxx/dummy_password_12345）
- 按租户隔离

### 3.3 ToolPolicy 工具策略

- 未注册工具默认拒绝
- 启用/禁用控制
- 最大调用次数限制（按调用方）
- 限流（每分钟调用次数）
- 需要审批的工具标记

### 3.4 ApprovalManager 审批管理器

- 创建审批请求（带TTL）
- 审批通过/拒绝
- 待审批列表
- 过期自动清理

### 3.5 PolicyEngine 统一决策点

- `evaluate_network(req)`: 网络请求决策
- `evaluate_tool(req)`: 工具调用决策（含调用计数）
- `evaluate_credential(req)`: 凭证请求决策
- 统计：总决策数/允许/拒绝/审批

## 四、Evidence + Release — 证据与发布平面

### 4.1 EvidenceCollector 证据收集器

收集执行过程中的所有证据：

| 证据类型 | 内容 |
|----------|------|
| FileDiff | 路径/类型(ADDED/MODIFIED/DELETED)/旧哈希/新哈希/是否敏感 |
| TestResult | 名称/通过/输出/耗时/断言数 |
| TraceEntry | 时间戳/类型(syscall/network/tool/exec/file)/详情/审计哈希 |
| Artifact | 路径/SHA256/大小/描述 |

- 轨迹哈希链（HMAC-SHA256，防篡改）
- syscall/network/tool 分类计数
- `finish()` 生成 EvidencePackage（含 root_hash）

### 4.2 ReleaseGate 独立发布闸门

5项检查，独立重新验证：

| 检查项 | 验证内容 | 失败后果 |
|--------|----------|----------|
| test_results | 所有测试通过 | REJECT（可配置） |
| sensitive_files | 无敏感文件修改（/etc/passwd等） | REJECT/REVIEW |
| network_activity | 网络调用不超限 | REVIEW |
| evidence_integrity | root_hash存在/轨迹哈希链完整 | REJECT（可配置） |
| artifact_hashes | 所有产物有有效SHA256(64字符) | REVIEW |

**决策**：
- `RELEASE`: 所有关键检查通过
- `REJECT`: 关键检查失败（测试失败/敏感文件修改/证据不完整）
- `REQUIRE_REVIEW`: 非关键问题（网络超限/产物哈希缺失）

**警告**：高syscall计数(>1000)、大量文件变更(>50)

## 五、端到端流程示例

```
1. 用户提交目标: "分析数据并生成报告"
   ↓
2. Control Plane:
   - TaskCompiler.compile() → TaskSpec
   - RuntimeSelector.select() → MicroVM (中可信度+需要Linux工具)
   ↓
3. Execution Plane:
   - RuntimeFactory.create(MICROVM) → MicroVMRuntime
   - runtime.create(spec) → 创建Firecracker VM
   - runtime.exec() → 执行代码
   ↓
4. Policy + Identity (执行中逐次校验):
   - 网络请求 → NetworkPolicy → 白名单允许/拒绝
   - 工具调用 → ToolPolicy → 允许/拒绝/审批
   - 凭证请求 → CredentialVault → 代理中转/空白通行证
   ↓
5. Evidence + Release:
   - EvidenceCollector 收集 diff/测试/轨迹/产物哈希
   - ReleaseGate.verify() → 5项检查 → RELEASE/REJECT/REVIEW
   ↓
6. 结果返回用户 (带证据包和发布决策)
```

## 六、测试覆盖

四层架构共 23 个单元测试：

- RuntimeSelector: 5（画像存在/低可信选MicroVM/高并发选Wasm/高可信选Container/对比表）
- TaskSpec: 4（编译生成/低可信断网/代码执行短TTL/验证拒绝空ID）
- RuntimeInterface: 4（Container创建执行销毁/Python执行/工厂按负载创建/MicroVM可用性检测）
- PolicyEngine: 6（网络默认拒绝/本地允许/未注册工具拒绝/凭证存储获取/空白通行证/审批流程）
- EvidenceRelease: 4（证据收集/失败测试拒绝/干净证据发布/敏感文件拒绝）

全量测试：142 通过 + 2 跳过（CRIU）
