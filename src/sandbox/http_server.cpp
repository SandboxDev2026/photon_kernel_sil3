#include "photon_kernel/sandbox/http_server.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <iostream>
#include <atomic>
namespace photon_kernel {
namespace sandbox {
HttpServer::~HttpServer() {
    stop();
}
void HttpServer::route(const std::string& method, const std::string& path_pattern, HttpHandler handler) {
    Route r;
    r.method = method;
    r.pattern = path_pattern;
    r.handler = std::move(handler);
    // 解析路径参数：{param}
    std::string segment;
    std::istringstream iss(path_pattern);
    while (std::getline(iss, segment, '/')) {
        if (segment.size() > 2 && segment.front() == '{' && segment.back() == '}') {
            r.param_names.push_back(segment.substr(1, segment.size() - 2));
        }
    }
    routes_.push_back(std::move(r));
}
bool HttpServer::match_route(const std::string& method, const std::string& path,
                              const Route& route, std::map<std::string, std::string>& params) const {
    if (route.method != method) return false;
    std::istringstream pattern_ss(route.pattern);
    std::istringstream path_ss(path);
    std::string p_seg, path_seg;
    size_t param_idx = 0;
    while (std::getline(pattern_ss, p_seg, '/')) {
        if (!std::getline(path_ss, path_seg, '/')) return false;
        if (p_seg.size() > 2 && p_seg.front() == '{' && p_seg.back() == '}') {
            if (param_idx < route.param_names.size()) {
                params[route.param_names[param_idx]] = path_seg;
            }
            param_idx++;
        } else if (p_seg != path_seg) {
            return false;
        }
    }
    // path 还有剩余段则不匹配
    if (std::getline(path_ss, path_seg, '/') && !path_seg.empty()) return false;
    return true;
}
void HttpServer::handle_client(int client_fd) {
    char buf[8192];
    std::string request_data;
    // 读取请求（简单实现：一次 read，足够 metrics 和小 body）
    ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
    if (n <= 0) { close(client_fd); return; }
    buf[n] = '\0';
    request_data = buf;
    // 解析请求行
    HttpRequest req;
    std::istringstream iss(request_data);
    std::string request_line;
    std::getline(iss, request_line);
    {
        std::istringstream rl(request_line);
        rl >> req.method >> req.path;
    }
    // 解析 headers
    std::string header_line;
    size_t content_length = 0;
    while (std::getline(iss, header_line) && header_line != "\r" && !header_line.empty()) {
        auto colon = header_line.find(':');
        if (colon != std::string::npos) {
            std::string key = header_line.substr(0, colon);
            std::string val = header_line.substr(colon + 1);
            // 去除首尾空格和 \r
            while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) val.erase(0, 1);
            while (!val.empty() && (val.back() == ' ' || val.back() == '\r' || val.back() == '\n')) val.pop_back();
            req.headers[key] = val;
            if (key == "Content-Length") content_length = std::stoul(val);
        }
    }
    // 读取 body
    if (content_length > 0) {
        // body 可能已在 buf 中，或需要继续读
        size_t header_end = request_data.find("\r\n\r\n");
        if (header_end != std::string::npos) {
            req.body = request_data.substr(header_end + 4);
        }
        while (req.body.size() < content_length) {
            n = read(client_fd, buf, sizeof(buf) - 1);
            if (n <= 0) break;
            buf[n] = '\0';
            req.body += buf;
        }
        if (req.body.size() > content_length) req.body.resize(content_length);
    }
    // 匹配路由
    HttpResponse resp;
    bool matched = false;
    for (const auto& route : routes_) {
        std::map<std::string, std::string> params;
        if (match_route(req.method, req.path, route, params)) {
            req.path_params = params;
            resp = route.handler(req);
            matched = true;
            break;
        }
    }
    if (!matched) {
        resp.status_code = 404;
        resp.status_text = "Not Found";
        resp.body = "{\"error\":\"not found\",\"path\":\"" + req.path + "\"}";
        resp.headers["Content-Type"] = "application/json";
    }
    // 构建响应
    if (resp.headers.find("Content-Type") == resp.headers.end()) {
        resp.headers["Content-Type"] = "text/plain";
    }
    resp.headers["Content-Length"] = std::to_string(resp.body.size());
    resp.headers["Connection"] = "close";
    std::ostringstream out;
    out << "HTTP/1.1 " << resp.status_code << " " << resp.status_text << "\r\n";
    for (const auto& [k, v] : resp.headers) {
        out << k << ": " << v << "\r\n";
    }
    out << "\r\n" << resp.body;
    std::string response_str = out.str();
    write(client_fd, response_str.data(), response_str.size());
    close(client_fd);
}
bool HttpServer::start(int port) {
    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        std::cerr << "[HttpServer] socket() failed\n";
        return false;
    }
    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "[HttpServer] bind(" << port << ") failed: " << std::strerror(errno) << "\n";
        close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    if (listen(listen_fd_, 16) < 0) {
        std::cerr << "[HttpServer] listen() failed\n";
        close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    running_ = true;
    std::cout << "[HttpServer] Listening on 0.0.0.0:" << port << "\n";
    while (running_) {
        int client_fd = accept(listen_fd_, nullptr, nullptr);
        if (client_fd < 0) {
            if (running_) std::cerr << "[HttpServer] accept() failed\n";
            break;
        }
        handle_client(client_fd);
    }
    return true;
}
void HttpServer::stop() {
    running_ = false;
    if (listen_fd_ >= 0) {
        close(listen_fd_);
        listen_fd_ = -1;
    }
}
} // namespace sandbox
} // namespace photon_kernel
