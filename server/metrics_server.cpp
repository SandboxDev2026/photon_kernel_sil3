// Prometheus /metrics HTTP 端点（生产级优化三）。
// 独立轻量 HTTP 服务器，监听 9090 端口，GET /metrics 返回标准 Prometheus 文本格式。
// 不依赖 gRPC，可独立编译运行。
#include <iostream>
#include <memory>
#include <csignal>
#include <cstdlib>
#include "photon_kernel/sandbox/http_server.hpp"
#include "photon_kernel/sandbox/metrics.hpp"
using namespace photon_kernel::sandbox;
static std::unique_ptr<HttpServer> g_server;
static void signal_handler(int sig) {
    std::cout << "\n[MetricsServer] Shutting down (signal " << sig << ")...\n";
    if (g_server) g_server->stop();
    exit(0);
}
int main(int argc, char** argv) {
    int port = 9090;
    if (argc > 1) port = std::atoi(argv[1]);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    g_server = std::make_unique<HttpServer>();
    // GET /metrics → Prometheus 文本格式
    g_server->route("GET", "/metrics", [](const HttpRequest&) -> HttpResponse {
        HttpResponse resp;
        resp.status_code = 200;
        resp.status_text = "OK";
        resp.headers["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8";
        resp.body = Metrics::instance().export_prometheus();
        return resp;
    });
    // GET /health → 健康检查
    g_server->route("GET", "/health", [](const HttpRequest&) -> HttpResponse {
        HttpResponse resp;
        resp.status_code = 200;
        resp.headers["Content-Type"] = "application/json";
        resp.body = "{\"status\":\"ok\"}";
        return resp;
    });
    std::cout << "[MetricsServer] Prometheus endpoint: http://0.0.0.0:" << port << "/metrics\n";
    std::cout << "[MetricsServer] Health check:     http://0.0.0.0:" << port << "/health\n";
    if (!g_server->start(port)) {
        std::cerr << "[MetricsServer] Failed to start on port " << port << "\n";
        return 1;
    }
    return 0;
}
