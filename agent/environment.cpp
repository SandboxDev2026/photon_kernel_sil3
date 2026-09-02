// Environment 实现：环境代理层 + CapabilityToken 校验 + E2B 网关调用
#include "environment.hpp"
#include "photon_kernel/sandbox/crypto_utils.hpp"
#include <sstream>
#include <cstdlib>
#include <fstream>
#include <iostream>
namespace photon_kernel {
namespace agent {
// 简单 JSON 字段提取（避免外部依赖）
static std::string json_get_string(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) {
        search = "\"" + key + "\": \"";
        pos = json.find(search);
    }
    if (pos == std::string::npos) return "";
    pos += search.length();
    size_t end = json.find("\"", pos);
    if (end == std::string::npos) return "";
    return json.substr(pos, end - pos);
}
static int json_get_int(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return 0;
    pos += search.length();
    while (pos < json.size() && json[pos] == ' ') pos++;
    int val = 0;
    bool neg = false;
    if (pos < json.size() && json[pos] == '-') { neg = true; pos++; }
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
        val = val * 10 + (json[pos] - '0');
        pos++;
    }
    return neg ? -val : val;
}
static bool json_get_bool(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":true";
    if (json.find(search) != std::string::npos) return true;
    search = "\"" + key + "\": true";
    return json.find(search) != std::string::npos;
}
static std::string escape_json_string(const std::string& s) {
    std::string result;
    for (char c : s) {
        if (c == '"') result += "\\\"";
        else if (c == '\\') result += "\\\\";
        else if (c == '\n') result += "\\n";
        else if (c == '\r') result += "\\r";
        else if (c == '\t') result += "\\t";
        else result += c;
    }
    return result;
}
// ==================== CodeExecutionTool ====================
CodeExecutionTool::CodeExecutionTool(std::string e2b_endpoint)
    : e2b_endpoint_(std::move(e2b_endpoint)) {}
std::string CodeExecutionTool::http_post(const std::string& url, const std::string& body) {
    std::string cmd = "curl -s -X POST '" + url + "' "
        "-H 'Content-Type: application/json' "
        "-d '" + body + "' 2>/dev/null";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    std::string result;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) result += buffer;
    pclose(pipe);
    return result;
}
std::string CodeExecutionTool::http_delete(const std::string& url) {
    std::string cmd = "curl -s -X DELETE '" + url + "' 2>/dev/null";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    std::string result;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) result += buffer;
    pclose(pipe);
    return result;
}
ToolCallResult CodeExecutionTool::execute(const ToolCallRequest& req) {
    ToolCallResult result;
    auto start = std::chrono::steady_clock::now();
    try {
        std::string code = json_get_string(req.args_json, "code");
        std::string language = json_get_string(req.args_json, "language");
        if (language.empty()) language = "python";
        if (code.empty()) {
            result.success = false;
            result.error = "code is empty";
            return result;
        }
        // 1. 创建沙盒
        std::string create_body = "{\"template\":\"default\"}";
        std::string create_resp = http_post(e2b_endpoint_ + "/v1/sandboxes", create_body);
        std::string sandbox_id = json_get_string(create_resp, "sandbox_id");
        if (sandbox_id.empty()) {
            result.success = false;
            result.error = "failed to create sandbox: " + create_resp;
            return result;
        }
        // 2. 执行代码
        std::string escaped_code = escape_json_string(code);
        std::string run_body = "{\"code\":\"" + escaped_code + "\",\"language\":\"" + language + "\"}";
        std::string run_resp = http_post(
            e2b_endpoint_ + "/v1/sandboxes/" + sandbox_id + "/run",
            run_body);
        result.output = json_get_string(run_resp, "output");
        result.error = json_get_string(run_resp, "error");
        result.exit_code = json_get_int(run_resp, "exit_code");
        result.success = json_get_bool(run_resp, "success");
        // 3. 销毁沙盒
        http_delete(e2b_endpoint_ + "/v1/sandboxes/" + sandbox_id);
    } catch (const std::exception& e) {
        result.success = false;
        result.error = e.what();
    }
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    return result;
}
// ==================== ShellTool ====================
ToolCallResult ShellTool::execute(const ToolCallRequest& req) {
    ToolCallResult result;
    auto start = std::chrono::steady_clock::now();
    try {
        std::string cmd = json_get_string(req.args_json, "command");
        if (cmd.empty()) {
            result.success = false;
            result.error = "command is empty";
            return result;
        }
        CodeExecutionTool code_tool;
        ToolCallRequest code_req = req;
        code_req.tool_name = "code_execution";
        std::string escaped_cmd = escape_json_string(cmd);
        code_req.args_json = "{\"code\":\"" + escaped_cmd + "\",\"language\":\"shell\"}";
        result = code_tool.execute(code_req);
    } catch (const std::exception& e) {
        result.success = false;
        result.error = e.what();
    }
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    return result;
}
// ==================== FileReadTool ====================
ToolCallResult FileReadTool::execute(const ToolCallRequest& req) {
    ToolCallResult result;
    auto start = std::chrono::steady_clock::now();
    try {
        std::string path = json_get_string(req.args_json, "path");
        if (path.empty()) {
            result.success = false;
            result.error = "path is empty";
            return result;
        }
        std::ifstream f(path);
        if (!f.is_open()) {
            result.success = false;
            result.error = "cannot open file: " + path;
            return result;
        }
        std::ostringstream ss;
        ss << f.rdbuf();
        result.output = ss.str();
        result.success = true;
    } catch (const std::exception& e) {
        result.success = false;
        result.error = e.what();
    }
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    return result;
}
// ==================== Environment ====================
Environment::Environment() {
    register_tool(std::make_unique<CodeExecutionTool>());
    register_tool(std::make_unique<ShellTool>());
    register_tool(std::make_unique<FileReadTool>());
}
Environment& Environment::instance() {
    static Environment env;
    return env;
}
void Environment::register_tool(std::unique_ptr<Tool> tool) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::string name = tool->name();
    tools_[name] = std::move(tool);
}
ToolCallResult Environment::call_tool(const ToolCallRequest& req,
                                        const sandbox::CapabilityToken& token) {
    std::lock_guard<std::mutex> lock(mtx_);
    total_calls_++;
    ToolCallResult result;
    auto it = tools_.find(req.tool_name);
    if (it == tools_.end()) {
        result.success = false;
        result.error = "tool not found: " + req.tool_name;
        denied_calls_++;
        return result;
    }
    sandbox::Capability required = it->second->required_capability();
    if (!token.has(required)) {
        result.success = false;
        result.error = "permission denied: tool '" + req.tool_name +
            "' requires capability " + std::to_string(static_cast<uint32_t>(required));
        denied_calls_++;
        return result;
    }
    if (token.is_expired()) {
        result.success = false;
        result.error = "capability token expired";
        denied_calls_++;
        return result;
    }
    result = it->second->execute(req);
    std::string audit_data = req.agent_id + "|" + req.tool_name + "|" +
        req.args_json + "|" + (result.success ? "ok" : "fail") + "|" + last_audit_hash_;
    auto digest = sandbox::crypto::hmac_sha256(
        reinterpret_cast<const uint8_t*>("photon-env-audit"), 18,
        reinterpret_cast<const uint8_t*>(audit_data.data()), audit_data.size());
    result.audit_hash = sandbox::crypto::to_hex(digest);
    last_audit_hash_ = result.audit_hash;
    return result;
}
std::vector<std::string> Environment::available_tools() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<std::string> names;
    for (const auto& [name, _] : tools_) names.push_back(name);
    return names;
}
std::string Environment::tool_description(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = tools_.find(name);
    if (it == tools_.end()) return "";
    return it->second->description();
}
size_t Environment::total_tool_calls() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return total_calls_;
}
size_t Environment::denied_calls() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return denied_calls_;
}
void Environment::reset() {
    std::lock_guard<std::mutex> lock(mtx_);
    tools_.clear();
    total_calls_ = 0;
    denied_calls_ = 0;
    last_audit_hash_.clear();
    // 重新注册默认工具
    tools_["code_execution"] = std::make_unique<CodeExecutionTool>();
    tools_["shell"] = std::make_unique<ShellTool>();
    tools_["file_read"] = std::make_unique<FileReadTool>();
}
} // namespace agent
} // namespace photon_kernel
