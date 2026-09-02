#ifndef PHOTON_KERNEL_AGENT_AGENT_BASE_HPP
#define PHOTON_KERNEL_AGENT_AGENT_BASE_HPP
// AgentBase —— Agent 基类（Actor 模型）
//
// 每个 Agent 是独立的 Actor，通过 MessageBus 通信，不能直接共享变量。
// Agent 可以：
//   - 接收消息（handle_message）
//   - 发送消息（send_message / broadcast）
//   - 调用工具（call_tool，经过 Environment 权限校验）
//   - 执行任务（execute_task）
//
// WorkerAgent：工作 Agent，负责执行具体任务（代码审查、编写代码、测试等）
#include <string>
#include <functional>
#include <memory>
#include <chrono>
#include "message_bus.hpp"
#include "environment.hpp"
#include "photon_kernel/sandbox/capability_token.hpp"
namespace photon_kernel {
namespace agent {
// Agent 角色
enum class AgentRole {
    SUPERVISOR,   // 总控调度
    ARCHITECT,    // 架构师
    DEVELOPER,    // 开发者
    TESTER,       // 测试工程师
    REVIEWER,     // 代码审查员
    RESEARCHER,   // 研究员
    WORKER,       // 通用工作者
};
std::string role_name(AgentRole role);
// 任务状态
enum class TaskStatus {
    PENDING,
    RUNNING,
    COMPLETED,
    FAILED,
    CANCELLED,
};
// 任务定义
struct Task {
    std::string id;
    std::string title;
    std::string description;
    AgentRole assigned_role;
    std::string assigned_agent;
    TaskStatus status = TaskStatus::PENDING;
    std::string result;
    std::string error;
    std::vector<std::string> dependencies;  // 依赖的任务 ID
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point completed_at;
};
// Agent 基类
class AgentBase {
public:
    AgentBase(const std::string& name, AgentRole role,
              sandbox::CapabilityToken token);
    virtual ~AgentBase();
    // 启动 Agent（注册到 MessageBus）
    virtual void start();
    // 停止 Agent
    virtual void stop();
    // 消息处理（子类重写）
    virtual void handle_message(const Message& msg) = 0;
    // 执行任务（子类重写）
    virtual Task execute_task(const Task& task) = 0;
    // 发送消息
    bool send_message(const std::string& to, const std::string& content,
                       MessageType type = MessageType::DIRECT);
    // 广播消息
    bool broadcast(const std::string& content);
    // 调用工具（经过 Environment 权限校验）
    ToolCallResult call_tool(const std::string& tool_name,
                              const std::string& args_json);
    // 轮询收件箱
    std::vector<Message> poll_messages(size_t max = 10);
    // Getters
    std::string id() const { return agent_id_; }
    std::string name() const { return name_; }
    AgentRole role() const { return role_; }
    bool running() const { return running_; }
protected:
    std::string name_;
    AgentRole role_;
    std::string agent_id_;
    sandbox::CapabilityToken token_;
    bool running_ = false;
};
// WorkerAgent：通用工作 Agent
class WorkerAgent : public AgentBase {
public:
    WorkerAgent(const std::string& name, AgentRole role,
                sandbox::CapabilityToken token);
    void handle_message(const Message& msg) override;
    Task execute_task(const Task& task) override;
    // 设置任务处理函数
    void set_task_handler(std::function<Task(const Task&)> handler);
private:
    std::function<Task(const Task&)> task_handler_;
};
} // namespace agent
} // namespace photon_kernel
#endif
