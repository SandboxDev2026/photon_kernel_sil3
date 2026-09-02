# MicroVM 高级特性（借鉴 AgentENV / Kimi K3）

## 背景

AgentENV 是 Kimi K3 开源的基于 Firecracker microVM 的分布式 Agent 训练沙盒系统。其核心洞察：

> Agent 沙箱生命周期中 **98% 时间在等模型推理结果**，这段时间沙箱可以暂停，几乎不占内存和 CPU。需要评分判断时，可以从已有沙箱的精确状态分叉出一个新的，原来那个继续跑。

photon_kernel_sil3 StrongPool 借鉴 AgentENV 四大核心技术，实现 MicroVM 高密度超配和高效状态管理。

## 四大核心特性

### 1. Memory Ballooning（内存气球）

**问题**：每个 MicroVM 分配固定内存，闲置时内存浪费，单机并发密度低。

**方案**：通过 virtio-balloon 设备，VM 闲置时回收内存给宿主机，活动时再充气。

```
VM 活动态:  [========== 1024MB ==========]  ← 完整内存
VM 闲置态:  [==== 128MB ====]               ← 放气，回收 896MB
            回收的内存可分配给其他 VM
```

**配置**：
- `base_memory_mb`：基础内存（运行时最小，默认128MB）
- `max_memory_mb`：最大内存（充气上限，默认1024MB）
- `idle_threshold_sec`：闲置超时（默认30秒）
- `deflate_step_mb` / `inflate_step_mb`：放气/充气步长

**API**：
```cpp
MemoryBalloon balloon(config);
balloon.register_vm("vm-1", 1024);
size_t reclaimed = balloon.deflate("vm-1", 128);  // 闲置放气
size_t restored = balloon.inflate("vm-1", 1024);    // 活动充气
```

**高密度效果**：假设100个VM，每个1024MB，闲置率80%：
- 无气球：100 × 1024MB = 100GB
- 有气球：20 × 1024MB + 80 × 128MB = 30GB（节省70%）

### 2. 沙箱暂停/恢复

**问题**：Agent 等模型推理结果时，VM 仍占 CPU 和内存。

**方案**：通过 cgroup freezer 暂停 VM（释放 CPU），可选压缩内存（zram/swap）。需要时快速恢复。

```
时间线:
[执行代码] → [等推理结果 30s] → [继续执行]
   CPU 100%     CPU 0% (暂停)      CPU 100%
   内存 100%     内存 20% (压缩)    内存 100%
```

**配置**：
- `idle_timeout`：闲置超时自动暂停（默认30秒）
- `compress_memory_on_pause`：暂停时压缩内存
- `resume_timeout`：恢复超时（默认5秒）
- `preserve_network_state`：暂停时保留网络状态

**API**：
```cpp
VmPauser pauser(config);
pauser.register_vm("vm-1");
pauser.pause("vm-1");    // 等推理结果时暂停
// ... 推理结果到达 ...
pauser.resume("vm-1");   // 快速恢复
```

**与 Memory Ballooning 协同**：
1. 闲置30秒 → 先放气（回收内存）
2. 闲置60秒 → 再暂停（释放CPU + 压缩内存）
3. 活动通知 → 先恢复 → 再充气

### 3. 状态分叉（State Fork）

**问题**：评分判断场景需要从同一状态跑多个分支，每个分支从头启动浪费时间。

**方案**：从已有沙箱的精确状态分叉出新沙箱，写时复制（CoW）共享内存页。

```
源 VM 状态: [代码已执行到第N行，变量x=42]
                │
                ├─→ 分叉1: 跑评分A (共享内存页，修改时才复制)
                ├─→ 分叉2: 跑评分B
                └─→ 源VM: 继续执行
```

**配置**：
- `copy_on_write`：写时复制（默认开启）
- `share_readonly_layers`：共享只读层（rootfs基础层）
- `max_forks_per_vm`：每个VM最大分叉数（默认16）
- `fork_ttl`：分叉VM的TTL（默认300秒）

**API**：
```cpp
VmForker forker(config);
auto result = forker.fork("source-vm", "fork-1");
// result.shared_memory_mb: 共享内存量
// result.fork_time: 分叉耗时
```

**实现方式**：
1. Pause 源 VM
2. Create snapshot（内存 + 状态）
3. Restore snapshot 到新 VM
4. Resume 源 VM
5. 新 VM 使用写时复制共享内存页

### 4. 分层镜像共享（Layered Image）

**问题**：每个 VM 独立 rootfs，存储占用大，启动慢。

**方案**：overlaybd 风格分层 rootfs，基础层共享，任务层增量。

```
镜像结构:
[任务层 delta-2]  ← 可写，任务特有文件
[任务层 delta-1]  ← 可写，依赖库
[基础层 base]     ← 只读，所有VM共享（内核+rootfs）
```

**配置**：
- `storage_dir`：层存储目录
- `max_layers`：最大层数（默认128）
- `enable_deduplication`：去重（相同内容只存一份）
- `enable_p2p`：P2P镜像分发（集群环境）

**API**：
```cpp
LayeredImageManager manager(config);
std::string base = manager.create_base_layer("ubuntu-22.04", "/path/to/base");
std::string delta = manager.create_delta_layer(base, "python-deps");
std::string mount = manager.mount_layers(base, {delta}, "/mnt/vm-rootfs");
```

**存储节省**：100个VM，每个rootfs 500MB：
- 无分层：100 × 500MB = 50GB
- 有分层：1 × 500MB（基础层共享）+ 100 × 10MB（增量层）= 1.5GB（节省97%）

## 统一管理器

`MicroVmAdvancedFeatures` 统一管理四大特性，提供自动 tick 机制：

```cpp
MicroVmAdvancedFeatures::Config config;
// 配置各子系统...
MicroVmAdvancedFeatures features(config);

features.register_vm("vm-1", 1024);

// 定期调用（如每秒）：
features.tick("vm-1", last_activity_time);
// 闲置 → 自动放气 + 暂停

// VM 活动时调用：
features.notify_activity("vm-1");
// 自动充气 + 恢复
```

## 能力矩阵

| 特性 | 依赖 | 无环境时行为 |
|------|------|-------------|
| Memory Ballooning | virtio-balloon 设备 | 禁用，VM 使用固定内存 |
| Pause/Resume | cgroup freezer | 禁用，VM 持续运行 |
| State Fork | CRIU 或 Firecracker snapshot | 禁用，需从头启动 |
| Layered Image | overlayfs / ublk+overlaybd | 禁用，使用独立 rootfs |

所有特性均支持优雅降级，无环境时不崩溃。

## 与 StrongPool 集成

StrongPool 调度器在创建 VM 时自动注册到高级特性管理器：

```cpp
// VM 创建时
advanced_features_.register_vm(vm_id, config.memory_mb);

// 调度循环中
advanced_features_.tick(vm_id, vm.last_activity);

// 任务执行时
advanced_features_.notify_activity(vm_id);

// VM 销毁时
advanced_features_.unregister_vm(vm_id);
```

## 测试覆盖

`tests/test_microvm_advanced.cpp` 18个测试：

| 测试套件 | 测试数 | 覆盖 |
|---------|--------|------|
| MemoryBalloonTest | 4 | 注册/放气/充气/闲置判断/注销归还 |
| VmPauserTest | 3 | 暂停/恢复/闲置判断/幂等暂停 |
| VmForkerTest | 4 | 分叉/自动ID/最大分叉数/注销 |
| LayeredImageManagerTest | 5 | 基础层/增量层/去重/引用计数删除/挂载 |
| MicroVmAdvancedFeaturesTest | 2 | 能力矩阵/注册+tick+活动通知 |

## 参考

- AgentENV (kvcache-ai): Firecracker microVM 分布式 Agent 沙盒
- Firecracker (AWS): 极简 MicroVM VMM
- overlaybd: 分层镜像格式
- virtio-balloon: 内存气球设备规范
