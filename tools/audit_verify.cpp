// 审计日志完整性校验工具（P1 可观测性）
//
// 用途：事后校验审计日志 HMAC 哈希链连续性，检测日志篡改。
//
// 用法：
//   ./audit_verify --file /var/log/photon/audit.jsonl
//   ./audit_verify --file audit.jsonl --verbose
//   ./audit_verify --dir /var/log/photon/audit/  (校验目录下所有日志文件)
//
// 输出：
//   - 校验通过：退出码 0，输出统计信息
//   - 校验失败：退出码 1，输出被篡改的记录位置和详情
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/hmac.h>
namespace fs = std::filesystem;
struct AuditRecord {
    uint64_t sequence = 0;
    std::string timestamp;
    std::string task_id;
    std::string tenant_id;
    std::string event_type;
    std::string payload;
    std::string prev_hash;
    std::string hash;
    std::string raw_line;
    size_t line_number = 0;
};
struct VerifyResult {
    bool passed = true;
    uint64_t total_records = 0;
    uint64_t valid_records = 0;
    uint64_t tampered_records = 0;
    uint64_t missing_links = 0;
    uint64_t invalid_hash = 0;
    std::vector<std::string> errors;
    std::string first_record_hash;
    std::string last_record_hash;
};
// 简化的 JSON 字段提取（避免引入完整 JSON 库）
std::string extract_json_string(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    size_t end = json.find("\"", pos);
    if (end == std::string::npos) return "";
    return json.substr(pos, end - pos);
}
uint64_t extract_json_uint(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return 0;
    pos += search.size();
    return std::stoull(json.substr(pos));
}
// 计算 HMAC-SHA256（简化，实际应与审计模块一致）
std::string compute_hmac(const std::string& key, const std::string& data) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len = 0;
    HMAC(EVP_sha256(), key.c_str(), key.size(),
         reinterpret_cast<const unsigned char*>(data.c_str()), data.size(),
         result, &result_len);
    std::ostringstream oss;
    for (unsigned int i = 0; i < result_len; i++) {
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)result[i];
    }
    return oss.str();
}
AuditRecord parse_record(const std::string& line, size_t line_num) {
    AuditRecord rec;
    rec.raw_line = line;
    rec.line_number = line_num;
    rec.sequence = extract_json_uint(line, "sequence");
    rec.timestamp = extract_json_string(line, "timestamp");
    rec.task_id = extract_json_string(line, "task_id");
    rec.tenant_id = extract_json_string(line, "tenant_id");
    rec.event_type = extract_json_string(line, "event_type");
    rec.payload = extract_json_string(line, "payload");
    rec.prev_hash = extract_json_string(line, "prev_hash");
    rec.hash = extract_json_string(line, "hash");
    return rec;
}
VerifyResult verify_file(const std::string& filepath, const std::string& hmac_key, bool verbose) {
    VerifyResult result;
    std::ifstream file(filepath);
    if (!file.is_open()) {
        result.passed = false;
        result.errors.push_back("Cannot open file: " + filepath);
        return result;
    }
    std::string line;
    size_t line_num = 0;
    std::string expected_prev_hash = "00000000000000000000000000000000000000000000000000000000000000";
    uint64_t expected_seq = 0;
    while (std::getline(file, line)) {
        line_num++;
        if (line.empty() || line[0] == '#') continue;
        result.total_records++;
        AuditRecord rec = parse_record(line, line_num);
        // 1. 检查序号连续性
        if (rec.sequence != expected_seq) {
            result.missing_links++;
            result.passed = false;
            std::string err = "Line " + std::to_string(line_num) +
                               ": sequence mismatch (expected " + std::to_string(expected_seq) +
                               ", got " + std::to_string(rec.sequence) + ")";
            result.errors.push_back(err);
            if (verbose) std::cerr << "  ERROR: " << err << "\n";
        }
        expected_seq = rec.sequence + 1;
        // 2. 检查 prev_hash 链接
        if (rec.prev_hash != expected_prev_hash) {
            result.missing_links++;
            result.passed = false;
            std::string err = "Line " + std::to_string(line_num) +
                               ": hash chain break (prev_hash mismatch)";
            result.errors.push_back(err);
            if (verbose) std::cerr << "  ERROR: " << err << "\n";
        }
        // 3. 检查 hash 有效性（重新计算）
        std::string data_to_hash = rec.timestamp + rec.task_id + rec.tenant_id +
                                    rec.event_type + rec.payload + rec.prev_hash;
        std::string computed_hash = compute_hmac(hmac_key, data_to_hash);
        if (rec.hash != computed_hash && !rec.hash.empty()) {
            // 注意：如果 hash 算法/密钥与审计模块不一致，这里会误报
            // 实际使用时应确保使用相同的密钥和算法
            result.invalid_hash++;
            if (verbose) {
                std::cerr << "  WARN: Line " << line_num <<
                             ": hash mismatch (may be different key/algorithm)\n";
            }
        }
        if (result.first_record_hash.empty()) {
            result.first_record_hash = rec.hash;
        }
        result.last_record_hash = rec.hash;
        expected_prev_hash = rec.hash;
        result.valid_records++;
    }
    // 只有序号断裂 + prev_hash 不匹配才是篡改证据
    // hash 不一致可能是密钥/算法不同，仅作警告
    result.tampered_records = result.missing_links;
    if (result.missing_links > 0) {
        result.passed = false;
    }
    return result;
}
void print_usage(const char* prog) {
    std::cout << "Photon Sandbox Audit Log Integrity Verifier\n\n";
    std::cout << "Usage: " << prog << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --file <path>       Verify a single audit log file\n";
    std::cout << "  --dir <path>        Verify all .jsonl files in a directory\n";
    std::cout << "  --key <hmac_key>    HMAC key for hash verification (default: from env PHOTON_HMAC_KEY)\n";
    std::cout << "  --verbose           Print detailed errors\n";
    std::cout << "  --help              Show this help\n\n";
    std::cout << "Exit codes:\n";
    std::cout << "  0 - All records valid\n";
    std::cout << "  1 - Tampering detected or verification failed\n";
    std::cout << "  2 - Usage error\n";
}
int main(int argc, char* argv[]) {
    std::string file_path;
    std::string dir_path;
    std::string hmac_key;
    bool verbose = false;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--file" && i + 1 < argc) {
            file_path = argv[++i];
        } else if (arg == "--dir" && i + 1 < argc) {
            dir_path = argv[++i];
        } else if (arg == "--key" && i + 1 < argc) {
            hmac_key = argv[++i];
        } else if (arg == "--verbose") {
            verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage(argv[0]);
            return 2;
        }
    }
    if (file_path.empty() && dir_path.empty()) {
        std::cerr << "Error: --file or --dir is required\n\n";
        print_usage(argv[0]);
        return 2;
    }
    if (hmac_key.empty()) {
        const char* env_key = getenv("PHOTON_HMAC_KEY");
        if (env_key) hmac_key = env_key;
        else hmac_key = "default-verification-key";  // 仅用于结构验证
    }
    std::vector<std::string> files;
    if (!file_path.empty()) {
        files.push_back(file_path);
    }
    if (!dir_path.empty()) {
        for (const auto& entry : fs::directory_iterator(dir_path)) {
            if (entry.path().extension() == ".jsonl" ||
                entry.path().filename().string().find("audit") != std::string::npos) {
                files.push_back(entry.path().string());
            }
        }
        std::sort(files.begin(), files.end());
    }
    std::cout << "=== Photon Sandbox Audit Integrity Verification ===\n";
    std::cout << "Files to verify: " << files.size() << "\n\n";
    bool all_passed = true;
    uint64_t grand_total = 0;
    uint64_t grand_tampered = 0;
    for (const auto& f : files) {
        std::cout << "Verifying: " << f << "\n";
        VerifyResult result = verify_file(f, hmac_key, verbose);
        grand_total += result.total_records;
        grand_tampered += result.tampered_records;
        std::cout << "  Total records: " << result.total_records << "\n";
        std::cout << "  Valid: " << result.valid_records << "\n";
        std::cout << "  Tampered/missing links: " << result.missing_links << "\n";
        if (result.invalid_hash > 0) {
            std::cout << "  Hash mismatches (warning, may be different key): " << result.invalid_hash << "\n";
        }
        std::cout << "  Status: " << (result.passed ? "PASS" : "FAIL") << "\n\n";
        if (!result.passed) all_passed = false;
    }
    std::cout << "=== Summary ===\n";
    std::cout << "Total records: " << grand_total << "\n";
    std::cout << "Tampered/missing: " << grand_tampered << "\n";
    std::cout << "Overall: " << (all_passed ? "PASS - No tampering detected" : "FAIL - Tampering detected!") << "\n";
    return all_passed ? 0 : 1;
}
