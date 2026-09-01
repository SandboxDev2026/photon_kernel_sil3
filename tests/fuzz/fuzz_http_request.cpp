// Fuzz target: HTTP 请求解析
#include <cstdint>
#include <cstddef>
#include <string>
#include <map>
struct FuzzHttpRequest {
    std::string method;
    std::string path;
    std::string body;
    std::map<std::string, std::string> headers;
};
static bool parse_http_request(const std::string& raw, FuzzHttpRequest& req) {
    size_t pos = 0;
    size_t line_end = raw.find("\r\n", pos);
    if (line_end == std::string::npos) line_end = raw.find('\n', pos);
    if (line_end == std::string::npos) return false;
    std::string request_line = raw.substr(pos, line_end - pos);
    size_t sp1 = request_line.find(' ');
    if (sp1 == std::string::npos) return false;
    req.method = request_line.substr(0, sp1);
    size_t sp2 = request_line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) req.path = request_line.substr(sp1 + 1);
    else req.path = request_line.substr(sp1 + 1, sp2 - sp1 - 1);
    pos = line_end + 2;
    while (pos < raw.size()) {
        size_t header_end = raw.find("\r\n", pos);
        if (header_end == std::string::npos) header_end = raw.find('\n', pos);
        if (header_end == std::string::npos) break;
        std::string header = raw.substr(pos, header_end - pos);
        if (header.empty()) { pos = header_end + 2; break; }
        size_t colon = header.find(':');
        if (colon != std::string::npos) {
            std::string key = header.substr(0, colon);
            std::string val = header.substr(colon + 1);
            while (!val.empty() && (val[0] == ' ' || val[0] == '\t')) val.erase(0, 1);
            req.headers[key] = val;
        }
        pos = header_end + 2;
    }
    if (pos < raw.size()) req.body = raw.substr(pos);
    return true;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    std::string raw(reinterpret_cast<const char*>(data), size);
    FuzzHttpRequest req;
    if (parse_http_request(raw, req)) {
        (void)req.method; (void)req.path; (void)req.body; (void)req.headers.size();
    }
    return 0;
}
