// Fuzz target: JSON 解析（e2b_gateway extract_json_field 逻辑）
#include <cstdint>
#include <cstddef>
#include <string>
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
                else val += next;
                pos += 2;
            } else {
                val += body[pos++];
            }
        }
        return val;
    }
    size_t end = body.find_first_of(",}", pos);
    if (end == std::string::npos) end = body.size();
    return body.substr(pos, end - pos);
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    std::string body(reinterpret_cast<const char*>(data), size);
    const char* keys[] = {"code", "language", "task_id", "a", "json", "name", "value", ""};
    for (const char* key : keys) {
        (void)extract_json_field(body, key);
    }
    return 0;
}
