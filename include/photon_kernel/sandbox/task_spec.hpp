#ifndef PHOTON_KERNEL_SANDBOX_TASK_SPEC_HPP
#define PHOTON_KERNEL_SANDBOX_TASK_SPEC_HPP
// TaskSpec —— 控制平面核心：把用户目标编译成任务规范
//
// Control Plane 职责：
//   1. 接收用户目标（自然语言/代码/API调用）
//   2. 编译成 TaskSpec：定义资源、网络、身份、工具、预算、TTL
//   3. 选择运行时（Container/gVisor/MicroVM/Wasm）
//   4. 下发到 Execution Plane 执行
//   5. 监控执行状态，处理超时/失败/重试
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <memory>
#include "runtime_selector.hpp"
namespace photon_kernel {
namespace sandbox {
// 资源规格
struct ResourceSpec {
    double cpu_cores = 1.0;           // CPU 核数
    size_t memory_mb = 256;            // 内存（MB）
    size_t disk_mb = 1024;             // 磁盘（MB）
    int max_processes = 64;             // 最大进程数
    int max_open_files = 64;            // 最大打开文件数
    size_t max_core_size = 0;           // core 文件大小（0=禁止）
    bool enable_gpu = false;            // 是否启用 GPU
    int gpu_count = 0;                  // GPU 数量
    size_t gpu_memory_mb = 0;           // GPU 显存（MB）
};
// 网络策略
struct NetworkSpec {
    bool enabled = false;                // 是否启用网络
    bool allow_dns = true;               // 是否允许 DNS
    std::vector<std::string> allow_cidrs; // 允许的出口 CIDR 白名单
    std::vector<std::string> deny_cidrs;  // 禁止的出口 CIDR 黑名单
    std::vector<uint16_t> allow_ports;    // 允许的端口
    bool require_proxy = false;          // 是否强制走代理
    std::string proxy_url;               // 代理地址
    int max_connections = 16;            // 最大并发连接数
    int bandwidth_mbps = 0;              // 带宽限制（0=不限制）
};
// 身份与凭证
struct IdentitySpec {
    std::string principal;               // 主体（用户/服务/Agent ID）
    std::string tenant_id;               // 租户 ID
    std::string role;                    // 角色
    std::vector<std::string> capabilities; // 能力列表
    bool inject_credentials = false;     // 是否注入凭证
    std::vector<std::string> credential_ids; // 允许使用的凭证 ID
    std::string capability_token_id;     // CapabilityToken ID
};
// 工具权限
struct ToolSpec {
    std::string name;                    // 工具名
    bool enabled = true;                 // 是否启用
    std::vector<std::string> allowed_args; // 允许的参数模式
    int max_calls = 100;                 // 最大调用次数
    int rate_limit_per_min = 0;          // 每分钟调用限制（0=不限制）
    bool require_approval = false;       // 是否需要审批
};
// 预算与 TTL
struct BudgetSpec {
    std::chrono::seconds ttl{300};       // 任务最大存活时间
    std::chrono::milliseconds execution_timeout{60000}; // 单次执行超时
    int max_retries = 3;                 // 最大重试次数
    double max_cpu_time_seconds = 60;    // 最大 CPU 时间
    size_t max_network_bytes = 0;        // 最大网络流量（0=不限制）
    double cost_budget = 0;              // 成本预算（0=不限制）
};
// 任务规范（Control Plane 编译产物）
struct TaskSpec {
    std::string task_id;                 // 任务 ID
    std::string goal;                    // 用户目标
    std::string description;             // 任务描述
    // 运行时选择
    RuntimeType runtime = RuntimeType::CONTAINER;
    RuntimeSelection runtime_selection;
    // 各维度规格
    ResourceSpec resources;
    NetworkSpec network;
    IdentitySpec identity;
    std::vector<ToolSpec> tools;
    BudgetSpec budget;
    // 工作区
    std::string workspace_path;          // 私有工作区路径
    bool persistent_workspace = false;   // 是否持久化工作区
    // 输入输出
    std::vector<std::string> input_files;
    std::vector<std::string> output_patterns;
    // 元数据
    std::unordered_map<std::string, std::string> labels;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;
    // 优先级
    int priority = 0;                    // 优先级（越高越优先）
    // 序列化
    std::string to_json() const;
    static TaskSpec from_json(const std::string& json);
};
// 任务编译器：把用户目标编译成 TaskSpec
class TaskCompiler {
public:
    static TaskCompiler& instance();
    // 编译用户目标为 TaskSpec
    TaskSpec compile(const std::string& goal,
                     const WorkloadProfile& workload,
                     const std::string& tenant_id = "default");
    // 编译代码执行任务
    TaskSpec compile_code_execution(const std::string& code,
                                     const std::string& language,
                                     const WorkloadProfile& workload);
    // 编译 Agent 任务
    TaskSpec compile_agent_task(const std::string& goal,
                                 const std::vector<std::string>& allowed_tools,
                                 const WorkloadProfile& workload);
    // 验证 TaskSpec 完整性
    bool validate(const TaskSpec& spec, std::string& error) const;
    // 应用默认值
    void apply_defaults(TaskSpec& spec) const;
private:
    TaskCompiler() = default;
    TaskCompiler(const TaskCompiler&) = delete;
    TaskCompiler& operator=(const TaskCompiler&) = delete;
    std::string generate_task_id() const;
};
} // namespace sandbox
} // namespace photon_kernel
#endif
