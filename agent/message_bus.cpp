// MessageBus 实现：Actor 消息总线 + 审计哈希链
#include "message_bus.hpp"
#include "photon_kernel/sandbox/crypto_utils.hpp"
#include <random>
#include <sstream>
#include <iomanip>
namespace photon_kernel {
namespace agent {
MessageBus& MessageBus::instance() {
    static MessageBus bus;
    return bus;
}
std::string MessageBus::generate_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
    std::ostringstream oss;
    oss << "msg-" << std::hex << std::setfill('0')
        << std::setw(8) << dis(gen) << std::setw(8) << dis(gen);
    return oss.str();
}
std::string MessageBus::compute_audit_hash(const Message& msg) {
    // 接入沙盒的 HMAC-SHA256 审计哈希链
    std::string data = msg.id + "|" + msg.from + "|" + msg.to + "|" +
        std::to_string(static_cast<int>(msg.type)) + "|" + msg.content +
        "|" + std::to_string(msg.seq) + "|" + last_audit_hash_;
    auto digest = photon_kernel::sandbox::crypto::hmac_sha256(
        reinterpret_cast<const uint8_t*>("photon-agent-bus"), 16,
        reinterpret_cast<const uint8_t*>(data.data()), data.size());
    return photon_kernel::sandbox::crypto::to_hex(digest);
}
std::string MessageBus::register_agent(const std::string& name, MessageHandler handler) {
    std::lock_guard<std::mutex> lock(mtx_);
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
    std::ostringstream oss;
    oss << name << "-" << std::hex << std::setfill('0') << std::setw(8) << dis(gen);
    std::string agent_id = oss.str();
    agents_[agent_id] = handler;
    agent_names_[agent_id] = name;
    inboxes_[agent_id] = std::queue<Message>();
    return agent_id;
}
void MessageBus::unregister_agent(const std::string& agent_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    agents_.erase(agent_id);
    agent_names_.erase(agent_id);
    inboxes_.erase(agent_id);
    subscriptions_.erase(agent_id);
}
bool MessageBus::send(const Message& msg) {
    // 在锁内收集需要调用的 (handler, message) 对，锁外调用避免死锁
    std::vector<std::pair<MessageHandler, Message>> pending;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (agents_.find(msg.from) == agents_.end()) return false;
        if (msg.type != MessageType::BROADCAST && agents_.find(msg.to) == agents_.end()) {
            return false;
        }
        Message m = msg;
        if (m.id.empty()) m.id = generate_id();
        m.seq = ++global_seq_;
        m.timestamp = std::chrono::system_clock::now();
        m.audit_hash = last_audit_hash_;
        m.hmac = compute_audit_hash(m);
        last_audit_hash_ = m.hmac;
        total_messages_++;
        // 分发到收件箱 + 收集 handler
        if (m.type == MessageType::BROADCAST) {
            for (auto& [id, handler] : agents_) {
                if (id != m.from) {
                    inboxes_[id].push(m);
                    if (handler) pending.emplace_back(handler, m);
                }
            }
        } else {
            inboxes_[m.to].push(m);
            auto it = agents_.find(m.to);
            if (it != agents_.end() && it->second) {
                pending.emplace_back(it->second, m);
            }
        }
        // 订阅者
        auto sub_it = subscriptions_.find(m.to);
        if (sub_it != subscriptions_.end()) {
            auto type_it = sub_it->second.find(m.type);
            if (type_it != sub_it->second.end() && type_it->second) {
                pending.emplace_back(type_it->second, m);
            }
        }
    }
    // 锁外调用 handler
    for (auto& [handler, m] : pending) {
        if (handler) handler(m);
    }
    return true;
}
bool MessageBus::broadcast(const Message& msg) {
    Message m = msg;
    m.type = MessageType::BROADCAST;
    m.to = "";
    return send(m);
}
void MessageBus::subscribe(const std::string& agent_id, MessageType type, MessageHandler handler) {
    std::lock_guard<std::mutex> lock(mtx_);
    subscriptions_[agent_id][type] = handler;
}
std::vector<Message> MessageBus::poll(const std::string& agent_id, size_t max) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<Message> result;
    auto it = inboxes_.find(agent_id);
    if (it == inboxes_.end()) return result;
    while (!it->second.empty() && result.size() < max) {
        result.push_back(it->second.front());
        it->second.pop();
    }
    return result;
}
size_t MessageBus::total_messages() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return total_messages_;
}
size_t MessageBus::active_agents() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return agents_.size();
}
void MessageBus::reset() {
    std::lock_guard<std::mutex> lock(mtx_);
    agents_.clear();
    agent_names_.clear();
    inboxes_.clear();
    subscriptions_.clear();
    global_seq_ = 0;
    last_audit_hash_.clear();
    total_messages_ = 0;
}
} // namespace agent
} // namespace photon_kernel
