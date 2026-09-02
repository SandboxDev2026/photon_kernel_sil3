#ifndef PHOTON_KERNEL_SANDBOX_RUNTIME_SELECTOR_HPP
#define PHOTON_KERNEL_SANDBOX_RUNTIME_SELECTOR_HPP
// 运行时选型器
//
// 四种 Agent Sandbox 运行时没有绝对优劣，选型需要同时考虑：
//   - 代码与租户可信度
//   - Linux 工具兼容性
//   - 冷启动延迟
//   - 并发密度
//   - 状态恢复
//   - 基础设施成本
//
// 运行时对比：
// | 维度       | Container | gVisor      | MicroVM    | Wasm       |
// |------------|-----------|-------------|------------|------------|
// | 隔离强度   | 弱(共享内核)| 中(用户态内核)| 强(独立内核)| 极强(沙箱)|
// | 冷启动     | ~100ms    | ~200ms      | ~125ms     | <1ms       |
// | 并发密度   | 高        | 中          | 低(内存大) | 极高       |
// | Linux兼容  | 完全      | 大部分      | 完全       | 有限(需WASI)|
// | 状态恢复   | CRIU      | CRIU        | 快照       | 原生(小)   |
// | 成本       | 低        | 中          | 高(KVM)    | 极低       |
// | 适用场景   | 可信内部  | 半可信多租户| 公网不可信 | 无状态函数 |
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
namespace photon_kernel {
namespace sandbox {
// 运行时类型
enum class RuntimeType {
    CONTAINER,   // 容器（共享内核，namespace+cgroup）
    GVISOR,      // gVisor（用户态内核，系统调用拦截）
    MICROVM,     // MicroVM（独立内核，KVM 硬件虚拟化）
    WASM,        // Wasm（WebAssembly 沙箱，WASI）
};
std::string runtime_type_name(RuntimeType type);
// 运行时特性画像
struct RuntimeProfile {
    RuntimeType type;
    std::string name;
    // 各项评分 0-100（越高越好）
    int isolation_strength = 0;    // 隔离强度
    int cold_start_speed = 0;      // 冷启动速度
    int concurrency_density = 0;   // 并发密度
    int linux_compatibility = 0;   // Linux 工具兼容性
    int state_recovery = 0;        // 状态恢复能力
    int cost_efficiency = 0;       // 成本效率
    // 典型冷启动延迟（ms）
    int typical_cold_start_ms = 0;
    // 典型单实例内存开销（MB）
    int typical_memory_mb = 0;
    // 是否需要特殊硬件/权限
    bool requires_kvm = false;
    bool requires_root = false;
    bool requires_userns = false;
    // 描述
    std::string description;
};
// 工作负载画像（用于选型决策）
struct WorkloadProfile {
    // 代码可信度（0-100，越高越可信）
    int code_trust_level = 50;
    // 租户可信度（0-100）
    int tenant_trust_level = 50;
    // 是否需要完整 Linux 工具链（bash/python/gcc 等）
    bool needs_full_linux_tools = true;
    // 冷启动敏感度（0-100，越高越敏感）
    int cold_start_sensitivity = 50;
    // 并发密度要求（0-100，越高越需要高密度）
    int concurrency_requirement = 50;
    // 是否需要状态恢复/快照
    bool needs_state_recovery = false;
    // 基础设施成本敏感度（0-100，越高越敏感）
    int cost_sensitivity = 50;
    // 是否需要网络访问
    bool needs_network = false;
    // 任务类型
    std::string task_type = "general";  // general/code_exec/agent/function
};
// 选型结果
struct RuntimeSelection {
    RuntimeType selected;
    std::string reason;
    // 各运行时的综合评分
    std::unordered_map<RuntimeType, int> scores;
    // 推荐的备选运行时
    RuntimeType fallback;
    // 风险提示
    std::vector<std::string> warnings;
};
class RuntimeSelector {
public:
    static RuntimeSelector& instance();
    // 获取所有运行时画像
    std::vector<RuntimeProfile> all_profiles() const;
    // 获取指定运行时画像
    RuntimeProfile profile(RuntimeType type) const;
    // 根据工作负载自动选择运行时
    RuntimeSelection select(const WorkloadProfile& workload) const;
    // 检测当前环境支持哪些运行时
    std::vector<RuntimeType> available_runtimes() const;
    // 检查指定运行时是否可用
    bool is_available(RuntimeType type) const;
    // 获取运行时对比表（Markdown 格式）
    std::string comparison_table() const;
private:
    RuntimeSelector();
    RuntimeSelector(const RuntimeSelector&) = delete;
    RuntimeSelector& operator=(const RuntimeSelector&) = delete;
    std::unordered_map<RuntimeType, RuntimeProfile> profiles_;
    // 加权评分
    int score_runtime(const RuntimeProfile& profile,
                      const WorkloadProfile& workload) const;
};
} // namespace sandbox
} // namespace photon_kernel
#endif
