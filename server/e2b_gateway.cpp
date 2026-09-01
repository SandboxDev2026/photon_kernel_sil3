// E2B SDK 兼容 HTTP 网关（核弹级优化四）。
// 把内部沙盒 API 映射成 E2B REST API，使所有 E2B 生态工具可直接对接。
// 不依赖 gRPC，直接调用 PrewarmedWorker（真预 fork 预热池），可独立编译运行。
//
// E2B 兼容 API：
//   POST   /v1/sandboxes              创建沙盒
//   POST   /v1/sandboxes/{id}/run     执行代码
//   GET    /v1/sandboxes/{id}/logs    获取日志
//   DELETE /v1/sandboxes/{id}         删除沙盒
//   GET    /v1/sandboxes               列出沙盒
#include <iostream>
#include <csignal>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <map>
#include <string>
#include <sstream>
#include <atomic>
#include "photon_kernel/sandbox/http_server.hpp"
#include "photon_kernel/sandbox/prewarmed_worker.hpp"
#include "photon_kernel/sandbox/code_runner.hpp"
#include "photon_kernel/sandbox/sandbox_config.hpp"
using namespace photon_kernel::sandbox;
// ---- 有状态沙盒实例管理器 ----
class E2BSandboxManager {
public:
    static E2BSandboxManager& instance() {
        static E2BSandboxManager mgr;
        return mgr;
    }
    // 创建沙盒：分配一个预 fork worker（已装好 seccomp）
    std::string create(const std::string& language = "python3") {
        std::lock_guard<std::mutex> lock(mtx_);
        std::string id = "sb-" + std::to_string(++counter_);
        SandboxConfig cfg = SandboxConfig::for_code_runner();
        try {
            auto worker = std::make_unique<PrewarmedWorker>(cfg);
            workers_[id] = std::move(worker);
            languages_[id] = language;
            return id;
        } catch (const std::exception& e) {
            std::cerr << "[E2B] create sandbox failed: " << e.what() << "\n";
            return "";
        }
    }
    // 执行代码
    struct RunResult {
        bool success = false;
        std::string stdout;
        std::string stderr;
        int exit_code = -1;
    };
    RunResult run(const std::string& id, const std::string& code, const std::string& language = "") {
        std::lock_guard<std::mutex> lock(mtx_);
        RunResult result;
        auto it = workers_.find(id);
        if (it == workers_.end()) {
            result.stderr = "sandbox not found: " + id;
            return result;
        }
        CodeRunRequest req;
        req.code = code;
        req.timeout = std::chrono::milliseconds(5000);
        // 语言映射
        std::string lang = language.empty() ? languages_[id] : language;
        if (lang == "node" || lang == "javascript" || lang == "js") {
            req.runner = CodeRunner::NODE;
        } else if (lang == "shell" || lang == "bash" || lang == "sh") {
            req.runner = CodeRunner::SHELL;
        } else {
            req.runner = CodeRunner::PYTHON3;
        }
        try {
            CodeRunResult r = it->second->run(req);
            result.success = r.success;
            result.stdout = r.output;
            result.stderr = r.error;
            result.exit_code = r.exit_code;
            // 缓存最近一次日志
            logs_[id] = r.output + (r.error.empty() ? "" : "\n" + r.error);
        } catch (const std::exception& e) {
            result.stderr = e.what();
        }
        return result;
    }
    std::string logs(const std::string& id) {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = logs_.find(id);
        return it == logs_.end() ? "" : it->second;
    }
    bool destroy(const std::string& id) {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = workers_.find(id);
        if (it == workers_.end()) return false;
        it->second->shutdown();
        workers_.erase(it);
        logs_.erase(id);
        languages_.erase(id);
        return true;
    }
    std::vector<std::string> list() {
        std::lock_guard<std::mutex> lock(mtx_);
        std::vector<std::string> ids;
        for (const auto& [id, _] : workers_) ids.push_back(id);
        return ids;
    }
    size_t count() {
        std::lock_guard<std::mutex> lock(mtx_);
        return workers_.size();
    }
private:
    E2BSandboxManager() = default;
    std::mutex mtx_;
    std::atomic<uint64_t> counter_{0};
    std::map<std::string, std::unique_ptr<PrewarmedWorker>> workers_;
    std::map<std::string, std::string> logs_;
    std::map<std::string, std::string> languages_;
};
// ---- JSON 辅助 ----
static std::string json_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c;
        }
    }
    return out;
}
static std::string extract_json_field(const std::string& body, const std::string& key) {
    std::string pattern = "\"" + key + "\"";
    auto pos = body.find(pattern);
    if (pos == std::string::npos) return "";
    pos = body.find(':', pos);
    if (pos == std::string::npos) return "";
    pos++;
    while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) pos++;
    if (pos >= body.size()) return "";
    if (body[pos] == '"') {
        pos++;
        std::string val;
        while (pos < body.size() && body[pos] != '"') {
            if (body[pos] == '\\' && pos + 1 < body.size()) {
                char next = body[pos + 1];
                if (next == 'n') val += '\n';
                else if (next == 't') val += '\t';
                else if (next == 'r') val += '\r';
                else val += next;
                pos += 2;
            } else {
                val += body[pos++];
            }
        }
        return val;
    }
    // 数字/布尔：取到逗号或 }
    size_t end = body.find_first_of(",}", pos);
    if (end == std::string::npos) end = body.size();
    return body.substr(pos, end - pos);
}
static std::unique_ptr<HttpServer> g_server;
static void signal_handler(int sig) {
    std::cout << "\n[E2BGateway] Shutting down (signal " << sig << ")...\n";
    if (g_server) g_server->stop();
    exit(0);
}
int main(int argc, char** argv) {
    int port = 3000;  // E2B 默认端口
    if (argc > 1) port = std::atoi(argv[1]);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    auto& mgr = E2BSandboxManager::instance();
    g_server = std::make_unique<HttpServer>();
    // POST /v1/sandboxes — 创建沙盒
    g_server->route("POST", "/v1/sandboxes", [&](const HttpRequest& req) -> HttpResponse {
        std::string language = extract_json_field(req.body, "language");
        if (language.empty()) language = extract_json_field(req.body, "template");
        std::string id = mgr.create(language);
        HttpResponse resp;
        if (id.empty()) {
            resp.status_code = 500;
            resp.status_text = "Internal Server Error";
            resp.headers["Content-Type"] = "application/json";
            resp.body = "{\"error\":\"failed to create sandbox\"}";
            return resp;
        }
        resp.status_code = 201;
        resp.status_text = "Created";
        resp.headers["Content-Type"] = "application/json";
        resp.body = "{\"sandbox_id\":\"" + id + "\",\"status\":\"running\"}";
        return resp;
    });
    // POST /v1/sandboxes/{id}/run — 执行代码
    g_server->route("POST", "/v1/sandboxes/{id}/run", [&](const HttpRequest& req) -> HttpResponse {
        std::string id = req.path_params.count("id") ? req.path_params.at("id") : "";
        std::string code = extract_json_field(req.body, "code");
        std::string language = extract_json_field(req.body, "language");
        auto result = mgr.run(id, code, language);
        HttpResponse resp;
        resp.status_code = 200;
        resp.headers["Content-Type"] = "application/json";
        std::ostringstream body;
        body << "{\"success\":" << (result.success ? "true" : "false")
             << ",\"stdout\":\"" << json_escape(result.stdout) << "\""
             << ",\"stderr\":\"" << json_escape(result.stderr) << "\""
             << ",\"exit_code\":" << result.exit_code << "}";
        resp.body = body.str();
        return resp;
    });
    // GET /v1/sandboxes/{id}/logs — 获取日志
    g_server->route("GET", "/v1/sandboxes/{id}/logs", [&](const HttpRequest& req) -> HttpResponse {
        std::string id = req.path_params.count("id") ? req.path_params.at("id") : "";
        std::string logs = mgr.logs(id);
        HttpResponse resp;
        resp.status_code = 200;
        resp.headers["Content-Type"] = "application/json";
        resp.body = "{\"sandbox_id\":\"" + id + "\",\"logs\":\"" + json_escape(logs) + "\"}";
        return resp;
    });
    // DELETE /v1/sandboxes/{id} — 删除沙盒
    g_server->route("DELETE", "/v1/sandboxes/{id}", [&](const HttpRequest& req) -> HttpResponse {
        std::string id = req.path_params.count("id") ? req.path_params.at("id") : "";
        bool ok = mgr.destroy(id);
        HttpResponse resp;
        resp.status_code = ok ? 200 : 404;
        resp.headers["Content-Type"] = "application/json";
        resp.body = ok ? "{\"sandbox_id\":\"" + id + "\",\"status\":\"deleted\"}"
                       : "{\"error\":\"sandbox not found\"}";
        return resp;
    });
    // GET /v1/sandboxes — 列出沙盒
    g_server->route("GET", "/v1/sandboxes", [&](const HttpRequest&) -> HttpResponse {
        auto ids = mgr.list();
        HttpResponse resp;
        resp.status_code = 200;
        resp.headers["Content-Type"] = "application/json";
        std::ostringstream body;
        body << "{\"count\":" << ids.size() << ",\"sandboxes\":[";
        for (size_t i = 0; i < ids.size(); ++i) {
            if (i > 0) body << ",";
            body << "\"" << ids[i] << "\"";
        }
        body << "]}";
        resp.body = body.str();
        return resp;
    });
    // GET /health — 健康检查
    g_server->route("GET", "/health", [](const HttpRequest&) -> HttpResponse {
        HttpResponse resp;
        resp.status_code = 200;
        resp.headers["Content-Type"] = "application/json";
        resp.body = "{\"status\":\"ok\",\"service\":\"e2b-compat-gateway\"}";
        return resp;
    });
    std::cout << "[E2BGateway] E2B-compatible REST API: http://0.0.0.0:" << port << "/v1/sandboxes\n";
    std::cout << "[E2BGateway] Health check:            http://0.0.0.0:" << port << "/health\n";
    if (!g_server->start(port)) {
        std::cerr << "[E2BGateway] Failed to start on port " << port << "\n";
        return 1;
    }
    return 0;
}
