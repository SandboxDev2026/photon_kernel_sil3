#ifndef PHOTON_KERNEL_AGENT_ENVIRONMENT_HPP
#define PHOTON_KERNEL_AGENT_ENVIRONMENT_HPP
// Environment —— 环境代理层（借鉴 AgentVerse Environment 抽象）
//
// 核心原则：Agent 不能直接调用工具/沙盒/外部资源，全部请求发送给 Environment。
// Environment 做：
//   1. CapabilityToken 票据校验（Agent 是否有权调用该工具）
//   2. 工具调用路由（代码执行 → photon E2B 网关，文件 → ResourceProxy，网络 → 代理）
//   3. 审计记录（所有工具调用接入 HMAC 哈希链）
//   4. 资源限制（超时、重试、限流）
//
// 与 photon 沙盒对接：
//   - 代码执行工具：通过 E2B 兼容 HTTP 网关调用 photon 沙盒
//     POST /v1/sandboxes          创建沙盒
//     POST /v1/sandboxes/{id}/run  执行代码
//     DELETE /v1/sandboxes/{id}    销毁沙盒
#include <string>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <chrono>
#include "photon_kernel/sandbox/capability_token.hpp"
namespace photon_kernel {
namespace agent {
struct ToolCallRequest {
    std::string agent_id;       // 调用方 Agent ID
    std::string tool_name;      // 工具名
    std::string args_json;      // 参数 JSON
    std::string task_id;        // 关联任务 ID
    std::chrono::milliseconds timeout{5000};
};
struct ToolCallResult {
    bool success = false;
    std::string output;         // 工具输出
    std::string error;          // 错误信息
    int exit_code = 0;
    std::chrono::milliseconds duration{0};
    std::string audit_hash;     // 审计哈希
};
// 工具接口
class Tool {
public:
    virtual ~Tool() = default;
    virtual std::string name() const = 0;
    virtual std::string description() const = 0;
    virtual ToolCallResult execute(const ToolCallRequest& req) = 0;
    // 需要的 Capability
    virtual sandbox::Capability required_capability() const = 0;
};
// 代码执行工具：通过 E2B 网关调用 photon 沙盒
class CodeExecutionTool : public Tool {
public:
    explicit CodeExecutionTool(std::string e2b_endpoint = "http://127.0.0.1:3000");
    std::string name() const override { return "code_execution"; }
    std::string description() const override { return "在 photon 沙盒中执行代码（Python/Shell）"; }
    ToolCallResult execute(const ToolCallRequest& req) override;
    sandbox::Capability required_capability() const override {
        return sandbox::Capability::EXEC;
    }
private:
    std::string e2b_endpoint_;
    // HTTP POST（简化实现，生产环境应用 libcurl）
    std::string http_post(const std::string& url, const std::string& body);
    std::string http_delete(const std::string& url);
};
// Shell 命令工具
class ShellTool : public Tool {
public:
    std::string name() const override { return "shell"; }
    std::string description() const override { return "在沙盒中执行 shell 命令"; }
    ToolCallResult execute(const ToolCallRequest& req) override;
    sandbox::Capability required_capability() const override {
        return sandbox::Capability::EXEC | sandbox::Capability::FILE_READ;
    }
};
// 文件读取工具（经过 ResourceProxy）
class FileReadTool : public Tool {
public:
    std::string name() const override { return "file_read"; }
    std::string description() const override { return "读取文件（经过 ResourceProxy 权限校验）"; }
    ToolCallResult execute(const ToolCallRequest& req) override;
    sandbox::Capability required_capability() const override {
        return sandbox::Capability::FILE_READ;
    }
};
// Environment 环境代理层
class Environment {
public:
    static Environment& instance();
    // 注册工具
    void register_tool(std::unique_ptr<Tool> tool);
    // Agent 调用工具（经过 CapabilityToken 校验）
    ToolCallResult call_tool(const ToolCallRequest& req,
                              const sandbox::CapabilityToken& token);
    // 获取可用工具列表
    std::vector<std::string> available_tools() const;
    // 获取工具描述
    std::string tool_description(const std::string& name) const;
    // 统计
    size_t total_tool_calls() const;
    size_t denied_calls() const;
    // 重置（测试用）
    void reset();
private:
    Environment();
    Environment(const Environment&) = delete;
    Environment& operator=(const Environment&) = delete;
    mutable std::mutex mtx_;
    std::unordered_map<std::string, std::unique_ptr<Tool>> tools_;
    size_t total_calls_ = 0;
    size_t denied_calls_ = 0;
    std::string last_audit_hash_;
};
} // namespace agent
} // namespace photon_kernel
#endif
