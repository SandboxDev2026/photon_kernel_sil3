#include "photon_kernel/sandbox/sandbox_snapshot.hpp"
#include "photon_kernel/sandbox/sandbox_policy.hpp"

#include <sys/types.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <ctime>

namespace photon_kernel {
namespace sandbox {

namespace {

std::string join(const std::vector<int>& v, char sep) {
    std::ostringstream oss;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) oss << sep;
        oss << v[i];
    }
    return oss.str();
}

std::vector<int> split_ints(const std::string& s, char sep) {
    std::vector<int> out;
    std::string cur;
    std::istringstream iss(s);
    while (std::getline(iss, cur, sep)) {
        if (cur.empty()) continue;
        out.push_back(std::atoi(cur.c_str()));
    }
    return out;
}

std::string join_str(const std::vector<std::string>& v, char sep) {
    std::ostringstream oss;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) oss << sep;
        oss << v[i];
    }
    return oss.str();
}

std::vector<std::string> split_strs(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string cur;
    std::istringstream iss(s);
    while (std::getline(iss, cur, sep)) {
        out.push_back(cur);
    }
    return out;
}

} // namespace

bool SandboxSnapshot::save(const std::string& path) const {
    std::ofstream f(path, std::ios::trunc);
    if (!f.is_open()) return false;

    f << "format_version=" << format_version << "\n";
    f << "created_at=" << created_at << "\n";
    f << "label=" << label << "\n";
    f << "risk_level=" << risk_level_to_string(config.risk_level) << "\n";
    f << "memory_limit_bytes=" << config.memory_limit_bytes << "\n";
    f << "cpu_time_limit_sec=" << config.cpu_time_limit.count() << "\n";
    f << "process_limit=" << config.process_limit << "\n";
    f << "file_size_limit=" << config.file_size_limit << "\n";
    f << "allow_network=" << (config.allow_network ? 1 : 0) << "\n";
    f << "allow_filesystem_read=" << (config.allow_filesystem_read ? 1 : 0) << "\n";
    f << "allow_filesystem_write=" << (config.allow_filesystem_write ? 1 : 0) << "\n";
    f << "audit_prefix=" << config.audit_prefix << "\n";
    f << "read_whitelist=" << join_str(config.read_whitelist, ';') << "\n";
    f << "extra_syscalls=" << join(config.extra_allowed_syscalls, ',') << "\n";
    f << "whitelist_syscalls=" << join(whitelist, ',') << "\n";
    return f.good();
}

bool SandboxSnapshot::load(const std::string& path, SandboxSnapshot& out) {
    std::ifstream f(path);
    if (!f.is_open()) return false;

    SandboxSnapshot snap;
    std::string line;
    while (std::getline(f, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);

        if (key == "format_version") snap.format_version = val;
        else if (key == "created_at") snap.created_at = val;
        else if (key == "label") snap.label = val;
        else if (key == "risk_level") {
            if (val == "LOW") snap.config.risk_level = RiskLevel::LOW;
            else if (val == "MEDIUM") snap.config.risk_level = RiskLevel::MEDIUM;
            else if (val == "HIGH") snap.config.risk_level = RiskLevel::HIGH;
        }
        else if (key == "memory_limit_bytes") snap.config.memory_limit_bytes = std::stoull(val);
        else if (key == "cpu_time_limit_sec") snap.config.cpu_time_limit = std::chrono::seconds(std::stoll(val));
        else if (key == "process_limit") snap.config.process_limit = std::stoull(val);
        else if (key == "file_size_limit") snap.config.file_size_limit = std::stoull(val);
        else if (key == "allow_network") snap.config.allow_network = (val == "1");
        else if (key == "allow_filesystem_read") snap.config.allow_filesystem_read = (val == "1");
        else if (key == "allow_filesystem_write") snap.config.allow_filesystem_write = (val == "1");
        else if (key == "audit_prefix") snap.config.audit_prefix = val;
        else if (key == "read_whitelist") snap.config.read_whitelist = split_strs(val, ';');
        else if (key == "extra_syscalls") snap.config.extra_allowed_syscalls = split_ints(val, ',');
        else if (key == "whitelist_syscalls") snap.whitelist = split_ints(val, ',');
    }

    if (snap.format_version != FORMAT_VERSION) return false;
    out = std::move(snap);
    return true;
}

// ======================= CRIU 集成（进程级快照，AgentENV 级别） =======================
// 运行时检测 criu 可用性；无 criu 时自动降级，不影响核心功能。
// 需要 root 权限 + 内核 CONFIG_CHECKPOINT_RESTORE。

#include <unistd.h>
#include <fstream>

bool criu_available() {
    // 高效检测：依次检查常见路径，不启动 shell
    static const char* paths[] = {"/usr/bin/criu", "/usr/sbin/criu", "/usr/local/bin/criu", nullptr};
    for (int i = 0; paths[i]; ++i) {
        if (::access(paths[i], X_OK) == 0) return true;
    }
    return ::system("command -v criu >/dev/null 2>&1") == 0;
}

bool criu_dump_process(pid_t pid, const std::string& image_dir, std::string& err) {
    if (!criu_available()) {
        err = "criu not installed (needs root + kernel CONFIG_CHECKPOINT_RESTORE)";
        return false;
    }
    // 创建快照目录
    std::string mkdir_cmd = "mkdir -p " + image_dir;
    ::system(mkdir_cmd.c_str());
    // --shell-job：允许控制终端相关进程；--leave-running：dump 后原进程继续运行
    std::string cmd = "criu dump -t " + std::to_string(static_cast<long>(pid)) +
                      " -D " + image_dir + " --shell-job --leave-running 2>&1";
    int rc = ::system(cmd.c_str());
    if (rc != 0) {
        err = "criu dump failed, rc=" + std::to_string(rc);
        return false;
    }
    return true;
}

bool criu_restore_process(const std::string& image_dir, pid_t& out_pid, std::string& err) {
    if (!criu_available()) {
        err = "criu not installed (needs root + kernel CONFIG_CHECKPOINT_RESTORE)";
        return false;
    }
    // --pidfile：恢复后将 PID 写入文件，便于调用方获取
    std::string pidfile = image_dir + "/restored.pid";
    std::string cmd = "criu restore -d -D " + image_dir +
                      " --shell-job --pidfile " + pidfile + " 2>&1";
    int rc = ::system(cmd.c_str());
    if (rc != 0) {
        err = "criu restore failed, rc=" + std::to_string(rc);
        return false;
    }
    // 读取恢复后的 PID
    std::ifstream pf(pidfile);
    if (pf.good()) {
        pf >> out_pid;
    } else {
        out_pid = -1;  // 恢复成功但无法读取 PID（由调用方从进程树发现）
    }
    return true;
}

} // namespace sandbox
} // namespace photon_kernel
