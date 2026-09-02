// AgentOrchestrator 实现：TaskDAG + Supervisor + 编排器
#include "orchestrator.hpp"
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <thread>
namespace photon_kernel {
namespace agent {
// ==================== TaskDAG ====================
void TaskDAG::add_task(const Task& task) {
    std::lock_guard<std::mutex> lock(mtx_);
    tasks_[task.id] = task;
}
std::vector<Task> TaskDAG::get_ready_tasks() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<Task> ready;
    for (const auto& [id, task] : tasks_) {
        if (task.status != TaskStatus::PENDING) continue;
        // 检查所有依赖是否完成
        bool deps_done = true;
        for (const auto& dep : task.dependencies) {
            auto it = tasks_.find(dep);
            if (it == tasks_.end() || it->second.status != TaskStatus::COMPLETED) {
                deps_done = false;
                break;
            }
        }
        if (deps_done) ready.push_back(task);
    }
    return ready;
}
void TaskDAG::complete_task(const std::string& task_id, const std::string& result) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = tasks_.find(task_id);
    if (it == tasks_.end()) return;
    it->second.status = TaskStatus::COMPLETED;
    it->second.result = result;
    it->second.completed_at = std::chrono::system_clock::now();
}
void TaskDAG::fail_task(const std::string& task_id, const std::string& error) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = tasks_.find(task_id);
    if (it == tasks_.end()) return;
    it->second.status = TaskStatus::FAILED;
    it->second.error = error;
    it->second.completed_at = std::chrono::system_clock::now();
}
bool TaskDAG::all_completed() const {
    std::lock_guard<std::mutex> lock(mtx_);
    for (const auto& [id, task] : tasks_) {
        if (task.status != TaskStatus::COMPLETED) return false;
    }
    return !tasks_.empty();
}
bool TaskDAG::has_failure() const {
    std::lock_guard<std::mutex> lock(mtx_);
    for (const auto& [id, task] : tasks_) {
        if (task.status == TaskStatus::FAILED) return true;
    }
    return false;
}
const Task* TaskDAG::get_task(const std::string& task_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = tasks_.find(task_id);
    return it == tasks_.end() ? nullptr : &it->second;
}
bool TaskDAG::topological_sort(std::vector<std::string>& order) const {
    std::lock_guard<std::mutex> lock(mtx_);
    order.clear();
    std::unordered_map<std::string, int> in_degree;
    std::unordered_map<std::string, std::vector<std::string>> adj;
    for (const auto& [id, task] : tasks_) {
        in_degree[id] = task.dependencies.size();
        for (const auto& dep : task.dependencies) {
            adj[dep].push_back(id);
        }
    }
    std::queue<std::string> q;
    for (const auto& [id, deg] : in_degree) {
        if (deg == 0) q.push(id);
    }
    while (!q.empty()) {
        std::string u = q.front(); q.pop();
        order.push_back(u);
        for (const auto& v : adj[u]) {
            if (--in_degree[v] == 0) q.push(v);
        }
    }
    return order.size() == tasks_.size();  // false = 有环
}
// ==================== Supervisor ====================
Supervisor::Supervisor(sandbox::CapabilityToken token, TaskDAG& dag)
    : AgentBase("supervisor", AgentRole::SUPERVISOR, std::move(token)), dag_(dag) {}
void Supervisor::handle_message(const Message& msg) {
    if (msg.type == MessageType::TASK_RESULT) {
        task_results_[msg.task_id] = msg.content;
        dag_.complete_task(msg.task_id, msg.content);
    }
}
Task Supervisor::execute_task(const Task& task) {
    Task result = task;
    result.status = TaskStatus::COMPLETED;
    result.result = "supervisor: " + task.title;
    return result;
}
std::vector<Task> Supervisor::decompose_task(const std::string& goal) {
    if (decompose_strategy_) {
        return decompose_strategy_(goal);
    }
    // 默认拆解策略：架构师→开发者→测试
    std::vector<Task> tasks;
    static int counter = 0;
    Task t1;
    t1.id = "task-design-" + std::to_string(++counter);
    t1.title = "设计方案";
    t1.description = "为目标设计技术方案: " + goal;
    t1.assigned_role = AgentRole::ARCHITECT;
    t1.status = TaskStatus::PENDING;
    t1.created_at = std::chrono::system_clock::now();
    tasks.push_back(t1);
    Task t2;
    t2.id = "task-impl-" + std::to_string(counter);
    t2.title = "实现代码";
    t2.description = "根据设计方案实现代码";
    t2.assigned_role = AgentRole::DEVELOPER;
    t2.dependencies = {t1.id};
    t2.status = TaskStatus::PENDING;
    t2.created_at = std::chrono::system_clock::now();
    tasks.push_back(t2);
    Task t3;
    t3.id = "task-test-" + std::to_string(counter);
    t3.title = "测试验证";
    t3.description = "编写测试并验证代码正确性";
    t3.assigned_role = AgentRole::TESTER;
    t3.dependencies = {t2.id};
    t3.status = TaskStatus::PENDING;
    t3.created_at = std::chrono::system_clock::now();
    tasks.push_back(t3);
    return tasks;
}
bool Supervisor::assign_task(const Task& task, const std::string& agent_id) {
    Message msg;
    msg.from = agent_id_;
    msg.to = agent_id;
    msg.type = MessageType::TASK_ASSIGN;
    msg.task_id = task.id;
    msg.content = task.description;
    return MessageBus::instance().send(msg);
}
bool Supervisor::collect_and_judge() {
    return dag_.all_completed();
}
void Supervisor::set_decompose_strategy(std::function<std::vector<Task>(const std::string&)> strategy) {
    decompose_strategy_ = std::move(strategy);
}
// ==================== AgentOrchestrator ====================
AgentOrchestrator::AgentOrchestrator() {
    MessageBus::instance().reset();
    Environment::instance().reset();
}
AgentOrchestrator::~AgentOrchestrator() {
    stop();
}
std::string AgentOrchestrator::add_agent(const std::string& name, AgentRole role,
                                           sandbox::CapabilityToken token) {
    auto worker = std::make_unique<WorkerAgent>(name, role, std::move(token));
    worker->start();
    std::string id = worker->id();
    agent_roles_[id] = role;
    workers_.push_back(std::move(worker));
    return id;
}
void AgentOrchestrator::add_task(const std::string& id, const std::string& title,
                                  const std::string& description, AgentRole role,
                                  const std::vector<std::string>& dependencies) {
    Task task;
    task.id = id;
    task.title = title;
    task.description = description;
    task.assigned_role = role;
    task.dependencies = dependencies;
    task.status = TaskStatus::PENDING;
    task.created_at = std::chrono::system_clock::now();
    dag_.add_task(task);
}
void AgentOrchestrator::set_goal(const std::string& goal) {
    goal_ = goal;
}
AgentOrchestrator::OrchestrationResult AgentOrchestrator::run(
    std::chrono::milliseconds timeout) {
    OrchestrationResult result;
    auto start = std::chrono::steady_clock::now();
    running_ = true;
    // 创建 Supervisor
    sandbox::CapabilityTokenManager mgr("orchestrator-key");
    auto sup_token = mgr.issue("supervisor",
        sandbox::Capability::EXEC | sandbox::Capability::FILE_READ);
    supervisor_ = std::make_unique<Supervisor>(std::move(sup_token), dag_);
    supervisor_->start();
    // 如果设置了 goal，Supervisor 自动拆解任务
    if (!goal_.empty()) {
        auto tasks = supervisor_->decompose_task(goal_);
        for (const auto& t : tasks) dag_.add_task(t);
    }
    // 主循环：调度就绪任务
    size_t max_iterations = 1000;
    for (size_t iter = 0; iter < max_iterations && running_; ++iter) {
        // 检查超时
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        if (elapsed > timeout) break;
        // 获取就绪任务
        auto ready = dag_.get_ready_tasks();
        if (ready.empty()) {
            if (dag_.all_completed() || dag_.has_failure()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        // 分配任务给对应角色的 Agent
        for (const auto& task : ready) {
            // 找到匹配角色的 Agent
            std::string target_agent;
            for (const auto& [id, role] : agent_roles_) {
                if (role == task.assigned_role) {
                    target_agent = id;
                    break;
                }
            }
            if (target_agent.empty()) {
                // 没有匹配角色，用任意 Agent
                if (!agent_roles_.empty()) {
                    target_agent = agent_roles_.begin()->first;
                }
            }
            if (!target_agent.empty()) {
                // 标记任务为运行中
                const_cast<Task*>(dag_.get_task(task.id))->status = TaskStatus::RUNNING;
                // 分配任务
                supervisor_->assign_task(task, target_agent);
                // 等待结果（简化：轮询）
                for (int w = 0; w < 100; ++w) {
                    auto msgs = MessageBus::instance().poll(supervisor_->id(), 10);
                    for (const auto& msg : msgs) {
                        supervisor_->handle_message(msg);
                    }
                    const Task* t = dag_.get_task(task.id);
                    if (t && (t->status == TaskStatus::COMPLETED || t->status == TaskStatus::FAILED)) {
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
            }
        }
    }
    // 收集结果
    for (const auto& [id, task] : dag_.tasks()) {
        if (task.status == TaskStatus::COMPLETED) {
            result.completed++;
            result.task_results[id] = task.result;
        } else if (task.status == TaskStatus::FAILED) {
            result.failed++;
        }
    }
    result.success = dag_.all_completed() && !dag_.has_failure();
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    // 生成摘要
    std::ostringstream oss;
    oss << "Orchestration " << (result.success ? "completed" : "failed")
        << ": " << result.completed << " completed, " << result.failed << " failed"
        << " in " << result.duration.count() << "ms";
    result.summary = oss.str();
    running_ = false;
    return result;
}
void AgentOrchestrator::stop() {
    running_ = false;
    if (supervisor_) supervisor_->stop();
    for (auto& w : workers_) w->stop();
}
std::vector<std::string> AgentOrchestrator::agent_ids() const {
    std::vector<std::string> ids;
    for (const auto& [id, _] : agent_roles_) ids.push_back(id);
    return ids;
}
} // namespace agent
} // namespace photon_kernel
