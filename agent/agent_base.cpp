// AgentBase + WorkerAgent 实现
#include "agent_base.hpp"
#include <random>
#include <sstream>
#include <iomanip>
namespace photon_kernel {
namespace agent {
std::string role_name(AgentRole role) {
    switch (role) {
        case AgentRole::SUPERVISOR: return "supervisor";
        case AgentRole::ARCHITECT: return "architect";
        case AgentRole::DEVELOPER: return "developer";
        case AgentRole::TESTER: return "tester";
        case AgentRole::REVIEWER: return "reviewer";
        case AgentRole::RESEARCHER: return "researcher";
        case AgentRole::WORKER: return "worker";
    }
    return "unknown";
}
// ==================== AgentBase ====================
AgentBase::AgentBase(const std::string& name, AgentRole role,
                     sandbox::CapabilityToken token)
    : name_(name), role_(role), token_(std::move(token)) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
    std::ostringstream oss;
    oss << name << "-" << std::hex << std::setfill('0') << std::setw(8) << dis(gen);
    agent_id_ = oss.str();
}
AgentBase::~AgentBase() {
    stop();
}
void AgentBase::start() {
    if (running_) return;
    running_ = true;
    // 使用 register_agent 返回的 ID（MessageBus 内部生成），保持一致
    agent_id_ = MessageBus::instance().register_agent(name_,
        [this](const Message& msg) { this->handle_message(msg); });
}
void AgentBase::stop() {
    if (!running_) return;
    running_ = false;
    MessageBus::instance().unregister_agent(agent_id_);
}
bool AgentBase::send_message(const std::string& to, const std::string& content,
                               MessageType type) {
    Message msg;
    msg.from = agent_id_;
    msg.to = to;
    msg.type = type;
    msg.content = content;
    return MessageBus::instance().send(msg);
}
bool AgentBase::broadcast(const std::string& content) {
    Message msg;
    msg.from = agent_id_;
    msg.type = MessageType::BROADCAST;
    msg.content = content;
    return MessageBus::instance().broadcast(msg);
}
ToolCallResult AgentBase::call_tool(const std::string& tool_name,
                                      const std::string& args_json) {
    ToolCallRequest req;
    req.agent_id = agent_id_;
    req.tool_name = tool_name;
    req.args_json = args_json;
    return Environment::instance().call_tool(req, token_);
}
std::vector<Message> AgentBase::poll_messages(size_t max) {
    return MessageBus::instance().poll(agent_id_, max);
}
// ==================== WorkerAgent ====================
WorkerAgent::WorkerAgent(const std::string& name, AgentRole role,
                         sandbox::CapabilityToken token)
    : AgentBase(name, role, std::move(token)) {}
void WorkerAgent::handle_message(const Message& msg) {
    // WorkerAgent 收到任务分配消息时执行任务
    if (msg.type == MessageType::TASK_ASSIGN) {
        Task task;
        task.id = msg.task_id;
        task.description = msg.content;
        task.assigned_agent = agent_id_;
        task.status = TaskStatus::RUNNING;
        Task result = execute_task(task);
        // 发送结果回 Supervisor
        Message result_msg;
        result_msg.from = agent_id_;
        result_msg.to = msg.from;
        result_msg.type = MessageType::TASK_RESULT;
        result_msg.task_id = task.id;
        result_msg.content = result.result;
        MessageBus::instance().send(result_msg);
    }
}
Task WorkerAgent::execute_task(const Task& task) {
    Task result = task;
    result.status = TaskStatus::RUNNING;
    if (task_handler_) {
        result = task_handler_(task);
    } else {
        // 默认处理：返回任务描述
        result.result = "[" + role_name(role_) + "] completed: " + task.title;
        result.status = TaskStatus::COMPLETED;
    }
    result.completed_at = std::chrono::system_clock::now();
    return result;
}
void WorkerAgent::set_task_handler(std::function<Task(const Task&)> handler) {
    task_handler_ = std::move(handler);
}
} // namespace agent
} // namespace photon_kernel
