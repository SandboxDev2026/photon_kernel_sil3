#ifndef PHOTON_KERNEL_SANDBOX_HTTP_SERVER_HPP
#define PHOTON_KERNEL_SANDBOX_HTTP_SERVER_HPP
// 轻量 HTTP/1.1 服务器（无外部依赖）。
// 用于 Prometheus /metrics 端点和 E2B 兼容 REST API 网关。
// 设计：单线程 accept 循环，每个请求同步处理（metrics 端点和沙盒控制面 QPS 低，足够）。
#include <string>
#include <functional>
#include <map>
#include <vector>
#include <atomic>
namespace photon_kernel {
namespace sandbox {
struct HttpRequest {
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::string body;
    // 路径参数（如 /v1/sandboxes/{id} 中的 id）
    std::map<std::string, std::string> path_params;
};
struct HttpResponse {
    int status_code = 200;
    std::string status_text = "OK";
    std::map<std::string, std::string> headers;
    std::string body;
};
using HttpHandler = std::function<HttpResponse(const HttpRequest&)>;
class HttpServer {
public:
    HttpServer() = default;
    ~HttpServer();
    // 注册路由（支持 {param} 路径参数，如 "/v1/sandboxes/{id}"）
    void route(const std::string& method, const std::string& path_pattern, HttpHandler handler);
    // 启动服务器（阻塞，直到 stop() 被调用或出错）
    // 返回 false 表示启动失败（端口被占用等）
    bool start(int port);
    // 停止服务器
    void stop();
    [[nodiscard]] bool running() const { return running_.load(); }
private:
    struct Route {
        std::string method;
        std::string pattern;
        std::vector<std::string> param_names;
        HttpHandler handler;
    };
    void handle_client(int client_fd);
    bool match_route(const std::string& method, const std::string& path,
                     const Route& route, std::map<std::string, std::string>& params) const;
    std::vector<Route> routes_;
    int listen_fd_ = -1;
    std::atomic<bool> running_{false};
};
} // namespace sandbox
} // namespace photon_kernel
#endif
