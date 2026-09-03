# 架构借鉴落地报告（灵衢UnifiedBus / openFuyao扶摇 / JiuwenSwarm蜂群）

**日期**: 2026-09-03
**版本**: v1.0
**许可证**: Apache-2.0（与三个上游项目一致）

---

## 概述

本报告记录 PhotonBox 从三个开源项目借鉴架构思想并落地实现的过程：

| 上游项目 | 协议 | 借鉴方向 | 落地模块 |
|---------|------|---------|---------|
| 灵衢 UnifiedBus (openEuler) | Apache-2.0 | UBVA内存模型、设备管理框架、控制面高可用 | 沙盒间安全内存共享（设计阶段） |
| openFuyao 扶摇 | Apache-2.0 | Gang调度、拓扑感知调度、DRA设备插件、在离线混部 | `evolution/gang_scheduler.py`、`evolution/sandbox_resource_plugin.py` |
| JiuwenSwarm 蜂群 | Apache-2.0 | Leader-Teammate团队模型、Inner/Outer Loop、共享工作空间、权限模型 | `evolution/leader_teammate.py` |

**重要原则**：只抄架构思路、数据结构、业务逻辑，不抄底层驱动代码（如灵衢的 ubus.ko 内核驱动，强硬件绑定）。

---

## 一、openFuyao 扶摇借鉴落地

### 1.1 Gang-Scheduling 原子调度

**借鉴点**：必须全部资源就绪，才一次性启动一批 Pod；适配遗传算法批量评测。

**落地实现**：`evolution/gang_scheduler.py` - `GangScheduler` 类

核心能力：
- **原子启动**：`start_gang()` 确保所有实例同时进入 running 状态
- **全有或全无**：`all_or_nothing=True` 时，资源不足不部分启动，避免死锁
- **超时控制**：`timeout_seconds` 防止无限等待资源
- **Gang 状态机**：PENDING → RESOURCES_READY → RUNNING → COMPLETED/FAILED/TIMEOUT

**适用场景**：
- 遗传算法批量评测：一批沙盒实例全部就位再开始压力测试
- 多Agent协同任务：Leader + 多个 Teammate 必须同时启动
- 压力测试：批量启动沙盒实例做并发测试

### 1.2 细粒度拓扑感知调度

**借鉴点**：K8s 原生资源是扁平，扶摇增加 NUMA、PCIe、硬件拓扑。

**落地实现**：`evolution/gang_scheduler.py` - `TopologyAwareScheduler` 类

核心能力：
- **NUMA 拓扑感知**：`find_best_numa_placement()` 尽量把同 Gang 的实例放在同一 NUMA 节点
- **跨 NUMA 延迟感知**：如果必须跨节点，选择延迟最低的组合
- **资源碎片整理**：优先填满已有节点，减少碎片
- **偏好节点支持**：`preferred_numa_node` 允许任务指定偏好节点

### 1.3 在离线混部调度

**借鉴点**：GA压力测试（低优先级离线任务）和正常业务沙盒（高优先级在线任务）混跑，做限流、驱逐保护业务负载。

**落地实现**：`evolution/gang_scheduler.py` - `evict_low_priority_gangs()` 方法

核心能力：
- **三级 QoS**：GUARANTEED（高优先级，不被驱逐）、BURSTABLE（中优先级，可限流）、BEST_EFFORT（低优先级，可被驱逐）
- **低优先级驱逐**：高优先级任务需要资源时，驱逐 BEST_EFFORT 级别的 Gang
- **驱逐保护**：GUARANTEED 级别的 Gang 不会被驱逐

### 1.4 DRA 设备插件模型

**借鉴点**：异构硬件资源上报、配额、硬切分。

**落地实现**：`evolution/sandbox_resource_plugin.py` - `SandboxResourcePlugin` 类

核心能力：
- **资源上报**：上报 LightPool/StrongPool/eBPF/CRIU 等资源容量
- **配额管理**：独立配额管理，硬切分，防止资源抢占
- **健康检查**：定期检查资源健康状态（HEALTHY/DEGRADED/UNAVAILABLE）
- **能力探测**：`CapabilityDetector` 自动探测 KVM/CAP_BPF/CRIU/cgroup v2/Landlock/Namespace
- **自动注册**：`auto_register_resources()` 基于能力探测自动注册可用资源
- **插件化**：资源插件热插拔，不修改主调度器
- **回调机制**：`register_callback()` 支持资源变更事件通知

**资源类型**：
| 资源类型 | 依赖条件 | 单位 |
|---------|---------|------|
| LIGHT_POOL | 无（进程沙盒） | instances |
| STRONG_POOL | KVM 硬件虚拟化 | vm_instances |
| EBPF | CAP_BPF | hooks |
| CRIU | criu 二进制 | snapshots |
| GRPC | libgrpc++-dev | connections |
| K8S_OPERATOR | K8s 集群 | crd_instances |

---

## 二、JiuwenSwarm 蜂群借鉴落地

### 2.1 Leader-Teammate 团队模型

**借鉴点**：Leader 负责任务拆解、动态生成子 Agent；Teammate 执行子任务。

**落地实现**：`evolution/leader_teammate.py` - `LeaderAgent` + `TeammateAgent` 类

核心能力：
- **任务拆解**：`decompose_task()` 支持 GA 评测（按 batch_size 拆分）、代码审计（拆成 SAST/渗透/漏洞评估）
- **动态分配**：`assign_task()` 根据 Teammate 能力（权限+技能匹配）和成功率分配
- **结果汇总**：`execute_outer_loop()` 收集所有 Teammate 结果，计算成功率
- **质量控制**：成功率 < 80% 时触发进化反馈
- **动态注册中心**：`register_teammate()` / `unregister_teammate()` 支持 Agent 动态加入/离开

### 2.2 Inner/Outer Loop 双层反馈

**借鉴点**：Inner-Loop（单 Agent 观察-推理-行动-验证）+ Outer-Loop（目标-计划-评估-更新）。

**落地实现**：`evolution/leader_teammate.py` - `LoopPhase` 枚举 + 执行方法

**Inner Loop**（单 Agent 执行循环）：
1. OBSERVE：观察环境，收集任务信息
2. REASON：推理决策，分析任务需求
3. ACT：执行行动，调用沙盒执行
4. VERIFY：验证结果，检查输出质量

**Outer Loop**（团队进化循环）：
1. GOAL：定义任务目标
2. PLAN：任务拆解、分配资源
3. EXECUTE：团队协作执行
4. EVALUATE：结果评估、反馈
5. UPDATE：技能库、策略更新（成功率 < 80% 触发进化）

### 2.3 Agent 权限模型

**借鉴点**：细粒度工具/沙盒权限隔离，不同 Teammate 分配不同沙盒后端权限。

**落地实现**：`evolution/leader_teammate.py` - `AgentPermission` 类

权限维度：
- `can_access_light_pool`：可访问 LightPool（进程沙盒）
- `can_access_strong_pool`：可访问 StrongPool（KVM MicroVM）
- `can_access_network`：可访问网络
- `can_access_filesystem`：可访问文件系统
- `can_execute_arbitrary_code`：可执行任意代码
- `max_execution_timeout_s`：最大执行超时
- `max_memory_mb`：最大内存
- `allowed_tools`：允许使用的工具列表

**权限校验**：`TeammateAgent.can_handle_task()` 基于权限和技能检查是否能处理任务。

### 2.4 共享工作空间

**借鉴点**：多 Agent 之间文件产物、日志、中间结果共享。

**落地实现**：`evolution/leader_teammate.py` - `SharedWorkspace` 类

核心能力：
- **产物共享**：`add_artifact()` / `get_all_artifacts()` 管理 Agent 产物
- **日志共享**：`add_log()` 记录带时间戳的日志
- **数据共享**：`set_shared_data()` / `get_shared_data()` 共享键值数据
- **线程安全**：所有操作加锁，支持多 Agent 并发访问

---

## 三、灵衢 UnifiedBus 借鉴（设计阶段）

### 3.1 UBVA 统一虚拟地址模型

**借鉴点**：跨节点共享内存描述结构体 segment、EID 节点标识、远程内存导出/导入。

**落地计划**：沙盒之间安全共享内存，带所有权转移、缓存刷回、访问权限控制。

**当前状态**：设计阶段，待 StrongPool 验证完成后实现。

### 3.2 设备管理框架

**借鉴点**：总线设备枚举、热插拔、错误上报、故障隔离。

**落地计划**：将 MicroVM/沙盒实例作为"虚拟总线设备"管理，做沙盒故障隔离。

**当前状态**：设计阶段，`SandboxResourcePlugin` 已实现资源管理框架，可扩展为设备管理框架。

### 3.3 UBS-Engine 控制面

**借鉴点**：分布式自选主、N-1 节点失效高可用逻辑。

**落地计划**：沙盒集群控制面，解决管控节点单点故障。

**当前状态**：设计阶段，待 K8s Operator 验证完成后实现。

---

## 四、不抄的部分（明确边界）

| 项目 | 不抄的部分 | 原因 |
|------|-----------|------|
| 灵衢 UnifiedBus | `ubus.ko`、`ubfi.ko` 内核驱动 | 强绑定灵衢硬件，没有 UnifiedBus 硬件跑不起来 |
| openFuyao | 完整 K8s Operator 整套 | 体量巨大，只抄调度插件的算法与数据结构 |
| JiuwenSwarm | 整套 openJiuwen 推理、LLM 交互代码 | 只抄多 Agent 调度、协同、反馈闭环的架构 |

---

## 五、测试验证

### 5.1 单元测试

新增测试文件：`evolution/tests/test_architecture_adaptation.py`

| 测试类 | 测试数 | 覆盖模块 |
|--------|--------|---------|
| TestGangScheduler | 8 | Gang 调度器 |
| TestTopologyAwareScheduler | 4 | 拓扑感知调度器 |
| TestLeaderTeammate | 12 | Leader-Teammate 团队模型 |
| TestSandboxResourcePlugin | 11 | 沙盒资源上报插件 |
| **合计** | **35** | |

### 5.2 全量回归

- Python 测试：248 通过（原 213 + 新增 35）
- C++ 测试：180 通过（未受影响）

### 5.3 安全验证

| 验证类型 | 结果 |
|---------|------|
| SAST（新模块） | 0 HIGH, 1 MEDIUM, 6 LOW |
| 渗透测试（内部 POC） | 14 通过, 0 失败, 0 逃逸 |
| 漏洞评估 | 2 HIGH CVE（OpenSSL/gRPC，有 fallback） |

### 5.4 Bug 修复

开发过程中发现并修复：
- **死锁 Bug**：`LeaderAgent.get_stats()` 中调用 `get_idle_teammates()` 导致嵌套锁死锁（`threading.Lock` 不可重入）。修复为直接计算空闲/忙碌数量，不调用带锁方法。

---

## 六、代码统计

| 模块 | 文件 | 行数 | 类数 |
|------|------|------|------|
| Gang 调度器 | `evolution/gang_scheduler.py` | 401 | 6 |
| Leader-Teammate | `evolution/leader_teammate.py` | 428 | 9 |
| 资源插件 | `evolution/sandbox_resource_plugin.py` | 447 | 6 |
| 测试 | `evolution/tests/test_architecture_adaptation.py` | ~500 | 4 |
| **合计** | | **~1776** | **25** |

---

## 七、后续计划

### P0（高优先级）
1. 灵衢 UBVA 内存模型落地：实现沙盒间安全共享内存
2. Gang 调度器与 RuntimeSelector 集成：C++ 层调用 Python 调度器
3. 资源插件与 K8s device plugin 集成：上报 K8s 节点资源

### P1（中优先级）
1. 分布式控制面：实现 UBS-Engine 风格的自选主、高可用
2. 设备管理框架：将沙盒实例作为虚拟设备管理
3. 拓扑感知调度增强：支持 PCIe 设备拓扑、NUMA 距离矩阵

### P2（低优先级）
1. 在离线混部增强：实现完整的 QoS 调度策略
2. 多集群调度：支持跨集群 Gang 调度
3. 性能优化：调度器性能压测

---

## 八、许可证合规

所有借鉴的上游项目均为 Apache-2.0 协议，PhotonBox 也已采用 Apache-2.0 协议，许可证兼容。

- 灵衢 UnifiedBus：Apache-2.0
- openFuyao 扶摇：Apache-2.0
- JiuwenSwarm 蜂群：Apache-2.0
- PhotonBox：Apache-2.0

**注意**：如果直接复制 Apache-2.0 源码片段，该部分文件需保留原始版权声明。本项目只借鉴架构思路，未直接复制源码。
