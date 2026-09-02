// TaskSpec 控制平面实现
#include "photon_kernel/sandbox/task_spec.hpp"
#include <random>
#include <sstream>
#include <iomanip>
namespace photon_kernel {
namespace sandbox {
std::string TaskSpec::to_json() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"task_id\":\"" << task_id << "\",";
    oss << "\"goal\":\"" << goal << "\",";
    oss << "\"runtime\":\"" << runtime_type_name(runtime) << "\",";
    oss << "\"resources\":{\"cpu\":" << resources.cpu_cores
        << ",\"memory_mb\":" << resources.memory_mb << "},";
    oss << "\"network\":{\"enabled\":" << (network.enabled ? "true" : "false") << "},";
    oss << "\"ttl_seconds\":" << budget.ttl.count();
    oss << "}";
    return oss.str();
}
TaskSpec TaskSpec::from_json(const std::string& json) {
    TaskSpec spec;
    // 简化解析（生产环境应用完整 JSON 库）
    auto extract = [&](const std::string& key) -> std::string {
        std::string search = "\"" + key + "\":\"";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return "";
        pos += search.length();
        size_t end = json.find("\"", pos);
        return end == std::string::npos ? "" : json.substr(pos, end - pos);
    };
    spec.task_id = extract("task_id");
    spec.goal = extract("goal");
    return spec;
}
TaskCompiler& TaskCompiler::instance() {
    static TaskCompiler compiler;
    return compiler;
}
std::string TaskCompiler::generate_task_id() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
    std::ostringstream oss;
    oss << "task-" << std::hex << std::setfill('0')
        << std::setw(8) << dis(gen) << std::setw(8) << dis(gen);
    return oss.str();
}
void TaskCompiler::apply_defaults(TaskSpec& spec) const {
    if (spec.task_id.empty()) spec.task_id = generate_task_id();
    if (spec.resources.cpu_cores <= 0) spec.resources.cpu_cores = 1.0;
    if (spec.resources.memory_mb == 0) spec.resources.memory_mb = 256;
    if (spec.budget.ttl.count() == 0) spec.budget.ttl = std::chrono::seconds(300);
    if (spec.budget.execution_timeout.count() == 0) {
        spec.budget.execution_timeout = std::chrono::milliseconds(60000);
    }
    spec.created_at = std::chrono::system_clock::now();
    spec.expires_at = spec.created_at + spec.budget.ttl;
    if (spec.workspace_path.empty()) {
        spec.workspace_path = "/tmp/photon-workspace-" + spec.task_id;
    }
}
bool TaskCompiler::validate(const TaskSpec& spec, std::string& error) const {
    if (spec.task_id.empty()) {
        error = "task_id is empty";
        return false;
    }
    if (spec.goal.empty()) {
        error = "goal is empty";
        return false;
    }
    if (spec.resources.cpu_cores <= 0) {
        error = "cpu_cores must be > 0";
        return false;
    }
    if (spec.resources.memory_mb == 0) {
        error = "memory_mb must be > 0";
        return false;
    }
    if (spec.budget.ttl.count() <= 0) {
        error = "ttl must be > 0";
        return false;
    }
    // 检查运行时是否可用
    if (!RuntimeSelector::instance().is_available(spec.runtime)) {
        error = "runtime " + runtime_type_name(spec.runtime) + " not available in current environment";
        return false;
    }
    return true;
}
TaskSpec TaskCompiler::compile(const std::string& goal,
                                const WorkloadProfile& workload,
                                const std::string& tenant_id) {
    TaskSpec spec;
    spec.goal = goal;
    spec.description = goal;
    spec.identity.tenant_id = tenant_id;
    // 选择运行时
    spec.runtime_selection = RuntimeSelector::instance().select(workload);
    spec.runtime = spec.runtime_selection.selected;
    // 根据运行时设置资源默认值
    switch (spec.runtime) {
        case RuntimeType::CONTAINER:
            spec.resources.memory_mb = 256;
            spec.resources.cpu_cores = 1.0;
            break;
        case RuntimeType::GVISOR:
            spec.resources.memory_mb = 512;
            spec.resources.cpu_cores = 1.0;
            break;
        case RuntimeType::MICROVM:
            spec.resources.memory_mb = 1024;
            spec.resources.cpu_cores = 2.0;
            break;
        case RuntimeType::WASM:
            spec.resources.memory_mb = 64;
            spec.resources.cpu_cores = 0.5;
            break;
    }
    // 根据可信度设置网络策略
    int trust_avg = (workload.code_trust_level + workload.tenant_trust_level) / 2;
    if (trust_avg < 30) {
        // 低可信度：默认断网
        spec.network.enabled = false;
    } else if (trust_avg < 70) {
        // 中可信度：白名单网络
        spec.network.enabled = workload.needs_network;
        spec.network.require_proxy = true;
    } else {
        // 高可信度：允许网络
        spec.network.enabled = workload.needs_network;
    }
    // 根据工作负载设置预算
    spec.budget.ttl = std::chrono::seconds(300);
    spec.budget.execution_timeout = std::chrono::milliseconds(60000);
    spec.budget.max_retries = 3;
    // 工具权限
    ToolSpec code_tool;
    code_tool.name = "code_execution";
    code_tool.enabled = true;
    code_tool.max_calls = 100;
    spec.tools.push_back(code_tool);
    ToolSpec shell_tool;
    shell_tool.name = "shell";
    shell_tool.enabled = trust_avg >= 50;  // 低可信度禁用 shell
    shell_tool.require_approval = trust_avg < 70;
    spec.tools.push_back(shell_tool);
    apply_defaults(spec);
    return spec;
}
TaskSpec TaskCompiler::compile_code_execution(const std::string& code,
                                                const std::string& language,
                                                const WorkloadProfile& workload) {
    TaskSpec spec = compile("Execute " + language + " code", workload);
    spec.description = "Execute code: " + code.substr(0, 100);
    spec.labels["language"] = language;
    spec.labels["code_length"] = std::to_string(code.size());
    // 代码执行任务缩短 TTL
    spec.budget.ttl = std::chrono::seconds(60);
    spec.budget.execution_timeout = std::chrono::milliseconds(30000);
    return spec;
}
TaskSpec TaskCompiler::compile_agent_task(const std::string& goal,
                                            const std::vector<std::string>& allowed_tools,
                                            const WorkloadProfile& workload) {
    TaskSpec spec = compile(goal, workload);
    spec.labels["task_type"] = "agent";
    // Agent 任务延长 TTL
    spec.budget.ttl = std::chrono::seconds(600);
    spec.budget.execution_timeout = std::chrono::milliseconds(120000);
    // 设置允许的工具
    spec.tools.clear();
    for (const auto& tool_name : allowed_tools) {
        ToolSpec tool;
        tool.name = tool_name;
        tool.enabled = true;
        tool.max_calls = 500;
        spec.tools.push_back(tool);
    }
    return spec;
}
} // namespace sandbox
} // namespace photon_kernel
