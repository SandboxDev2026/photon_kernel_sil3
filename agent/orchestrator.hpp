#ifndef PHOTON_KERNEL_AGENT_ORCHESTRATOR_HPP
#define PHOTON_KERNEL_AGENT_ORCHESTRATOR_HPP
// AgentOrchestrator —— 多智能体编排器（借鉴 LangGraph Supervisor + CrewAI Task DAG）
//
// 核心架构：
//   - Supervisor 总控 Agent：任务拆解、分配、汇总、判断是否完成
//   - TaskDAG 任务依赖图：任务之间的依赖关系，按拓扑序调度
//   - WorkerAgent 工作 Agent：按角色执行具体任务
//   - MessageBus 消息总线：Agent 间通信，全部审计
//   - Environment 环境代理：工具调用，CapabilityToken 校验
//
// 使用示例（代码审查多 Agent 团队）：
//   AgentOrchestrator orchestrator;
//   orchestrator.add_agent("architect", AgentRole::ARCHITECT, token);
//   orchestrator.add_agent("developer", AgentRole::DEVELOPER, token);
//   orchestrator.add_agent("tester", AgentRole::TESTER, token);
//   orchestrator.add_task("design", "设计系统架构", AgentRole::ARCHITECT);
//   orchestrator.add_task("implement", "实现代码", AgentRole::DEVELOPER, {"design"});
//   orchestrator.add_task("test", "编写测试", AgentRole::TESTER, {"implement"});
//   auto result = orchestrator.run();
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <queue>
#include <functional>
#include <mutex>
#include <chrono>
#include "agent_base.hpp"
#include "message_bus.hpp"
#include "environment.hpp"
namespace photon_kernel {
namespace agent {
// TaskDAG：任务依赖图（借鉴 CrewAI Task DAG）
class TaskDAG {
public:
    // 添加任务
    void add_task(const Task& task);
    // 获取可执行的任务（依赖已完成的）
    std::vector<Task> get_ready_tasks() const;
    // 标记任务完成
    void complete_task(const std::string& task_id, const std::string& result);
    // 标记任务失败
    void fail_task(const std::string& task_id, const std::string& error);
    // 检查是否全部完成
    bool all_completed() const;
    // 检查是否有失败
    bool has_failure() const;
    // 获取任务
    const Task* get_task(const std::string& task_id) const;
    // 获取所有任务
    const std::unordered_map<std::string, Task>& tasks() const { return tasks_; }
    // 拓扑排序（验证无环）
    bool topological_sort(std::vector<std::string>& order) const;
private:
    mutable std::mutex mtx_;
    std::unordered_map<std::string, Task> tasks_;
};
// Supervisor：总控 Agent（借鉴 LangGraph Supervisor 模式）
class Supervisor : public AgentBase {
public:
    Supervisor(sandbox::CapabilityToken token, TaskDAG& dag);
    void handle_message(const Message& msg) override;
    Task execute_task(const Task& task) override;
    // 任务拆解：把大任务拆成子任务（可自定义拆解策略）
    std::vector<Task> decompose_task(const std::string& goal);
    // 分配任务给合适的 Agent
    bool assign_task(const Task& task, const std::string& agent_id);
    // 收集结果，判断是否完成
    bool collect_and_judge();
    // 设置任务拆解策略
    void set_decompose_strategy(std::function<std::vector<Task>(const std::string&)> strategy);
private:
    TaskDAG& dag_;
    std::unordered_map<std::string, std::string> task_results_;
    std::function<std::vector<Task>(const std::string&)> decompose_strategy_;
};
// AgentOrchestrator：编排器入口
class AgentOrchestrator {
public:
    AgentOrchestrator();
    ~AgentOrchestrator();
    // 添加 Agent
    std::string add_agent(const std::string& name, AgentRole role,
                           sandbox::CapabilityToken token);
    // 添加任务
    void add_task(const std::string& id, const std::string& title,
                  const std::string& description, AgentRole role,
                  const std::vector<std::string>& dependencies = {});
    // 设置目标（Supervisor 自动拆解任务）
    void set_goal(const std::string& goal);
    // 运行编排（阻塞直到完成）
    struct OrchestrationResult {
        bool success = false;
        std::string summary;
        std::unordered_map<std::string, std::string> task_results;
        size_t completed = 0;
        size_t failed = 0;
        std::chrono::milliseconds duration{0};
    };
    OrchestrationResult run(std::chrono::milliseconds timeout = std::chrono::minutes(5));
    // 停止
    void stop();
    // 获取 TaskDAG
    TaskDAG& dag() { return dag_; }
    // 获取 Agent 列表
    std::vector<std::string> agent_ids() const;
private:
    TaskDAG dag_;
    std::unique_ptr<Supervisor> supervisor_;
    std::vector<std::unique_ptr<WorkerAgent>> workers_;
    std::unordered_map<std::string, AgentRole> agent_roles_;
    bool running_ = false;
    std::string goal_;
};
} // namespace agent
} // namespace photon_kernel
#endif
