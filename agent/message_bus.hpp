#ifndef PHOTON_KERNEL_AGENT_MESSAGE_BUS_HPP
#define PHOTON_KERNEL_AGENT_MESSAGE_BUS_HPP
// MessageBus —— Actor 消息总线（借鉴 AgentScope Actor 模型）
//
// 核心原则：Agent 之间不能直接共享变量，只能通过消息总线通信。
// 所有消息经过总线，总线做：
//   1. 权限校验（发送方是否有权向接收方发消息）
//   2. 审计记录（所有消息接入 HMAC 哈希链）
//   3. 路由分发（点对点 / 广播 / 订阅）
//   4. 流量控制（防止消息风暴）
//
// 消息类型：
//   - DIRECT: 点对点消息
//   - BROADCAST: 广播消息
//   - TASK_ASSIGN: Supervisor 分配任务
//   - TASK_RESULT: Worker 返回结果
//   - TOOL_CALL: Agent 请求调用工具（经过 Environment）
//   - TOOL_RESULT: Environment 返回工具结果
#include <string>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <chrono>
#include <vector>
namespace photon_kernel {
namespace agent {
enum class MessageType {
    DIRECT,        // 点对点
    BROADCAST,     // 广播
    TASK_ASSIGN,   // 任务分配
    TASK_RESULT,   // 任务结果
    TOOL_CALL,     // 工具调用请求
    TOOL_RESULT,   // 工具调用结果
    SUPERVISOR_CMD, // Supervisor 命令
    HEARTBEAT,     // 心跳
};
struct Message {
    std::string id;           // 消息唯一 ID
    std::string from;         // 发送方 Agent ID
    std::string to;           // 接收方 Agent ID（广播时为空）
    MessageType type;
    std::string content;      // 消息内容（JSON 或文本）
    std::string task_id;      // 关联任务 ID（可选）
    std::string tool_name;    // 工具名（TOOL_CALL 时）
    std::string tool_args;    // 工具参数 JSON（TOOL_CALL 时）
    std::chrono::system_clock::time_point timestamp;
    uint64_t seq = 0;         // 全局序列号
    // 审计相关
    std::string audit_hash;   // 前一条消息的哈希（哈希链）
    std::string hmac;         // 本条消息的 HMAC 签名
};
// 消息处理回调
using MessageHandler = std::function<void(const Message&)>;
class MessageBus {
public:
    static MessageBus& instance();
    // 注册 Agent（返回 Agent ID）
    std::string register_agent(const std::string& name, MessageHandler handler);
    // 注销 Agent
    void unregister_agent(const std::string& agent_id);
    // 发送消息
    bool send(const Message& msg);
    // 广播消息
    bool broadcast(const Message& msg);
    // 订阅特定类型消息
    void subscribe(const std::string& agent_id, MessageType type, MessageHandler handler);
    // 获取 Agent 收件箱中的消息（轮询模式）
    std::vector<Message> poll(const std::string& agent_id, size_t max = 10);
    // 获取统计
    size_t total_messages() const;
    size_t active_agents() const;
    // 清空（测试用）
    void reset();
private:
    MessageBus() = default;
    MessageBus(const MessageBus&) = delete;
    MessageBus& operator=(const MessageBus&) = delete;
    mutable std::mutex mtx_;
    std::unordered_map<std::string, MessageHandler> agents_;           // agent_id -> handler
    std::unordered_map<std::string, std::string> agent_names_;          // agent_id -> name
    std::unordered_map<std::string, std::queue<Message>> inboxes_;      // agent_id -> 收件箱
    std::unordered_map<std::string, std::unordered_map<MessageType, MessageHandler>> subscriptions_;
    uint64_t global_seq_ = 0;
    std::string last_audit_hash_;
    size_t total_messages_ = 0;
    // 审计：计算消息 HMAC（接入沙盒的审计哈希链）
    std::string compute_audit_hash(const Message& msg);
    // 生成消息 ID
    std::string generate_id();
};
} // namespace agent
} // namespace photon_kernel
#endif
