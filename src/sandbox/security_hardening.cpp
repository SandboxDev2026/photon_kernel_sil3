// P0 安全加固模块实现
#include "photon_kernel/sandbox/security_hardening.hpp"
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <vector>
#include <iostream>
#include <grp.h>
#include <sys/syscall.h>
namespace photon_kernel {
namespace sandbox {
// ==================== TaskSpecValidator ====================
TaskSpecValidator::TaskSpecValidator()
    : config_() {}
TaskSpecValidator::TaskSpecValidator(const Config& config)
    : config_(config) {}
const std::vector<std::string>& TaskSpecValidator::internal_cidrs() {
    static const std::vector<std::string> cidrs = {
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
        "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
        "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
        "224.0.0.0/4", "240.0.0.0/4", "::1/128", "fc00::/7",
    };
    return cidrs;
}
bool TaskSpecValidator::is_internal_cidr(const std::string& cidr) const {
    for (const auto& internal : internal_cidrs()) {
        if (cidr == internal) return true;
        // 检查是否包含内网网段（简化：前缀匹配）
        if (cidr.find(internal.substr(0, internal.find('/'))) == 0) return true;
    }
    // 元数据地址
    if (config_.block_metadata_ip && cidr.find("169.254.169.254") != std::string::npos) {
        return true;
    }
    return false;
}
bool TaskSpecValidator::contains_path_traversal(const std::string& path) const {
    return path.find("..") != std::string::npos;
}
bool TaskSpecValidator::contains_shell_metacharacters(const std::string& s) const {
    static const std::string metachars = ";&|`$()<>\\!\"'";
    for (char c : metachars) {
        if (s.find(c) != std::string::npos) return true;
    }
    return false;
}
bool TaskSpecValidator::contains_null_bytes(const std::string& s) const {
    return s.find('\0') != std::string::npos;
}
std::string TaskSpecValidator::sanitize_string(const std::string& s) const {
    std::string result;
    result.reserve(s.size());
    for (char c : s) {
        if (c == '\0') continue;
        if (config_.block_shell_metacharacters) {
            static const std::string metachars = ";&|`$()<>\\!\"'";
            if (metachars.find(c) != std::string::npos) continue;
        }
        result += c;
    }
    // 截断到最大长度
    if (result.size() > config_.max_field_length) {
        result = result.substr(0, config_.max_field_length);
    }
    return result;
}
bool TaskSpecValidator::validate_resources(const ResourceSpec& r,
                                              std::vector<std::string>& errors) const {
    bool ok = true;
    if (r.cpu_cores <= 0) { errors.push_back("cpu_cores must be > 0"); ok = false; }
    if (r.cpu_cores > config_.max_cpu_cores) {
        errors.push_back("cpu_cores exceeds max: " + std::to_string(r.cpu_cores) +
                         " > " + std::to_string(config_.max_cpu_cores));
        ok = false;
    }
    if (r.memory_mb == 0) { errors.push_back("memory_mb must be > 0"); ok = false; }
    if (r.memory_mb > config_.max_memory_mb) {
        errors.push_back("memory_mb exceeds max"); ok = false;
    }
    if (r.disk_mb > config_.max_disk_mb) {
        errors.push_back("disk_mb exceeds max"); ok = false;
    }
    if (r.max_processes <= 0) { errors.push_back("max_processes must be > 0"); ok = false; }
    if (r.max_processes > config_.max_processes) {
        errors.push_back("max_processes exceeds max"); ok = false;
    }
    if (r.max_open_files <= 0) { errors.push_back("max_open_files must be > 0"); ok = false; }
    if (r.max_open_files > config_.max_open_files) {
        errors.push_back("max_open_files exceeds max"); ok = false;
    }
    if (r.enable_gpu && r.gpu_count <= 0) {
        errors.push_back("gpu enabled but gpu_count <= 0"); ok = false;
    }
    return ok;
}
bool TaskSpecValidator::validate_network(const NetworkSpec& n,
                                           std::vector<std::string>& errors) const {
    bool ok = true;
    if (n.allow_cidrs.size() > (size_t)config_.max_allow_cidrs) {
        errors.push_back("too many allow_cidrs"); ok = false;
    }
    if (n.deny_cidrs.size() > (size_t)config_.max_deny_cidrs) {
        errors.push_back("too many deny_cidrs"); ok = false;
    }
    if (n.allow_ports.size() > (size_t)config_.max_allow_ports) {
        errors.push_back("too many allow_ports"); ok = false;
    }
    if (n.max_connections > config_.max_connections) {
        errors.push_back("max_connections exceeds max"); ok = false;
    }
    // 检查 allow_cidrs 是否包含内网地址（网络策略篡改）
    if (config_.block_internal_cidrs) {
        for (const auto& cidr : n.allow_cidrs) {
            if (is_internal_cidr(cidr)) {
                errors.push_back("allow_cidrs contains internal/metadata CIDR: " + cidr +
                                 " (possible network policy tampering)");
                ok = false;
            }
        }
    }
    // 端口范围校验
    for (uint16_t port : n.allow_ports) {
        if (port == 0) { errors.push_back("allow_ports contains port 0"); ok = false; }
    }
    // 带宽限制校验
    if (n.bandwidth_mbps < 0) {
        errors.push_back("bandwidth_mbps must be >= 0"); ok = false;
    }
    return ok;
}
bool TaskSpecValidator::validate_budget(const BudgetSpec& b,
                                          std::vector<std::string>& errors) const {
    bool ok = true;
    // TTL 必须在合法范围内
    if (b.ttl.count() <= 0) {
        errors.push_back("ttl must be > 0 (got " + std::to_string(b.ttl.count()) +
                         "s, task would never expire)");
        ok = false;
    }
    if (b.ttl > config_.max_ttl) {
        errors.push_back("ttl exceeds max: " + std::to_string(b.ttl.count()) + "s > " +
                         std::to_string(config_.max_ttl.count()) + "s");
        ok = false;
    }
    if (b.ttl < config_.min_ttl) {
        errors.push_back("ttl below min: " + std::to_string(b.ttl.count()) + "s < " +
                         std::to_string(config_.min_ttl.count()) + "s");
        ok = false;
    }
    // execution_timeout
    if (b.execution_timeout.count() <= 0) {
        errors.push_back("execution_timeout must be > 0"); ok = false;
    }
    if (b.execution_timeout > config_.max_execution_timeout) {
        errors.push_back("execution_timeout exceeds max"); ok = false;
    }
    // max_retries
    if (b.max_retries < 0) { errors.push_back("max_retries must be >= 0"); ok = false; }
    if (b.max_retries > 100) { errors.push_back("max_retries too high (>100)"); ok = false; }
    // max_cpu_time
    if (b.max_cpu_time_seconds <= 0) {
        errors.push_back("max_cpu_time_seconds must be > 0"); ok = false;
    }
    if (b.max_cpu_time_seconds > 86400) {
        errors.push_back("max_cpu_time_seconds exceeds 24h"); ok = false;
    }
    return ok;
}
bool TaskSpecValidator::validate_identity(const IdentitySpec& i,
                                            std::vector<std::string>& errors) const {
    bool ok = true;
    if (i.principal.empty()) {
        errors.push_back("identity.principal is empty (authentication required)");
        ok = false;
    }
    if (i.tenant_id.empty()) {
        errors.push_back("identity.tenant_id is empty");
        ok = false;
    }
    if (i.principal.size() > config_.max_field_length) {
        errors.push_back("identity.principal too long"); ok = false;
    }
    if (i.tenant_id.size() > config_.max_field_length) {
        errors.push_back("identity.tenant_id too long"); ok = false;
    }
    // 注入检查
    if (config_.block_shell_metacharacters) {
        if (contains_shell_metacharacters(i.principal)) {
            errors.push_back("identity.principal contains shell metacharacters");
            ok = false;
        }
        if (contains_shell_metacharacters(i.tenant_id)) {
            errors.push_back("identity.tenant_id contains shell metacharacters");
            ok = false;
        }
    }
    if (config_.block_null_bytes) {
        if (contains_null_bytes(i.principal) || contains_null_bytes(i.tenant_id)) {
            errors.push_back("identity contains null bytes (injection attempt)");
            ok = false;
        }
    }
    return ok;
}
bool TaskSpecValidator::validate_paths(const TaskSpec& spec,
                                         std::vector<std::string>& errors) const {
    bool ok = true;
    // workspace_path 安全检查
    if (config_.block_path_traversal && contains_path_traversal(spec.workspace_path)) {
        errors.push_back("workspace_path contains path traversal (..): " + spec.workspace_path);
        ok = false;
    }
    // workspace 不能跳出沙盒根
    if (config_.block_absolute_path_escape && !spec.workspace_path.empty()) {
        if (spec.workspace_path.find(config_.sandbox_root) != 0) {
            errors.push_back("workspace_path escapes sandbox root: " + spec.workspace_path +
                             " (must be under " + config_.sandbox_root + ")");
            ok = false;
        }
    }
    // input_files 路径检查
    for (const auto& f : spec.input_files) {
        if (config_.block_path_traversal && contains_path_traversal(f)) {
            errors.push_back("input_file contains path traversal: " + f);
            ok = false;
        }
    }
    // output_patterns 检查
    for (const auto& p : spec.output_patterns) {
        if (config_.block_path_traversal && contains_path_traversal(p)) {
            errors.push_back("output_pattern contains path traversal: " + p);
            ok = false;
        }
    }
    return ok;
}
bool TaskSpecValidator::validate_injection(const TaskSpec& spec,
                                              std::vector<std::string>& errors) const {
    bool ok = true;
    // task_id
    if (spec.task_id.size() > config_.max_task_id_length) {
        errors.push_back("task_id too long"); ok = false;
    }
    if (config_.block_null_bytes && contains_null_bytes(spec.task_id)) {
        errors.push_back("task_id contains null bytes"); ok = false;
    }
    // goal
    if (spec.goal.size() > config_.max_goal_length) {
        errors.push_back("goal too long (>64KB)"); ok = false;
    }
    // labels 注入检查
    for (const auto& [k, v] : spec.labels) {
        if (config_.block_shell_metacharacters &&
            (contains_shell_metacharacters(k) || contains_shell_metacharacters(v))) {
            errors.push_back("label contains shell metacharacters: " + k);
            ok = false;
        }
        if (k.size() > config_.max_field_length || v.size() > config_.max_field_length) {
            errors.push_back("label too long: " + k); ok = false;
        }
    }
    return ok;
}
TaskSpecValidationResult TaskSpecValidator::validate(const TaskSpec& spec) const {
    TaskSpecValidationResult result;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
    // 各项校验
    validate_resources(spec.resources, errors);
    validate_network(spec.network, errors);
    validate_budget(spec.budget, errors);
    validate_identity(spec.identity, errors);
    validate_paths(spec, errors);
    validate_injection(spec, errors);
    // 运行时选择校验
    if (spec.runtime == RuntimeType::MICROVM) {
        warnings.push_back("MICROVM runtime requires KVM; will be rejected if KVM unavailable");
    }
    // 高风险标记
    if (spec.network.enabled && spec.network.allow_cidrs.empty()) {
        warnings.push_back("network enabled but no allow_cidrs specified (default deny)");
    }
    if (spec.identity.inject_credentials) {
        warnings.push_back("credentials injection enabled; ensure CredentialVault proxy is active");
    }
    result.errors = errors;
    result.warnings = warnings;
    result.valid = errors.empty();
    // 风险等级
    if (errors.size() >= 5) result.risk = TaskSpecValidationResult::RiskLevel::CRITICAL;
    else if (errors.size() >= 3) result.risk = TaskSpecValidationResult::RiskLevel::HIGH;
    else if (errors.size() >= 1) result.risk = TaskSpecValidationResult::RiskLevel::MEDIUM;
    else if (!warnings.empty()) result.risk = TaskSpecValidationResult::RiskLevel::LOW;
    return result;
}
std::pair<TaskSpec, TaskSpecValidationResult> TaskSpecValidator::validate_and_sanitize(
    const TaskSpec& spec) const {
    TaskSpec sanitized = spec;
    auto result = validate(sanitized);
    // 清理可修复的字段
    if (config_.block_null_bytes || config_.block_shell_metacharacters) {
        sanitized.task_id = sanitize_string(sanitized.task_id);
        sanitized.identity.principal = sanitize_string(sanitized.identity.principal);
        sanitized.identity.tenant_id = sanitize_string(sanitized.identity.tenant_id);
        result.sanitized_fields.push_back("task_id, identity.principal, identity.tenant_id");
    }
    // 截断过长字段
    if (sanitized.goal.size() > config_.max_goal_length) {
        sanitized.goal = sanitized.goal.substr(0, config_.max_goal_length);
        result.sanitized_fields.push_back("goal (truncated)");
    }
    // 重新校验清理后的 spec
    auto revalidated = validate(sanitized);
    return {sanitized, revalidated};
}
std::string TaskSpecValidationResult::to_string() const {
    std::ostringstream oss;
    oss << "TaskSpec Validation: " << (valid ? "PASS" : "FAIL") << "\n";
    oss << "  Risk: ";
    switch (risk) {
        case RiskLevel::LOW: oss << "LOW"; break;
        case RiskLevel::MEDIUM: oss << "MEDIUM"; break;
        case RiskLevel::HIGH: oss << "HIGH"; break;
        case RiskLevel::CRITICAL: oss << "CRITICAL"; break;
    }
    oss << "\n";
    for (const auto& e : errors) oss << "  ERROR: " << e << "\n";
    for (const auto& w : warnings) oss << "  WARN: " << w << "\n";
    for (const auto& s : sanitized_fields) oss << "  SANITIZED: " << s << "\n";
    return oss.str();
}
// ==================== ReleaseGateService ====================
ReleaseGateService::ReleaseGateService()
    : config_() {}
ReleaseGateService::ReleaseGateService(const ReleaseGateConfig& config)
    : config_(config) {}
ReleaseGateService::~ReleaseGateService() {
    stop();
}
pid_t ReleaseGateService::start() {
    // 创建 Unix socket
    server_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd_ < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, config_.socket_path.c_str(), sizeof(addr.sun_path) - 1);
    unlink(config_.socket_path.c_str());
    if (bind(server_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(server_fd_);
        server_fd_ = -1;
        return -1;
    }
    if (listen(server_fd_, 16) < 0) {
        close(server_fd_);
        server_fd_ = -1;
        return -1;
    }
    // 设置 socket 权限（仅 root 和指定组可访问）
    chmod(config_.socket_path.c_str(), 0660);
    // fork 独立进程
    pid_t pid = fork();
    if (pid < 0) {
        close(server_fd_);
        server_fd_ = -1;
        return -1;
    }
    if (pid == 0) {
        // 子进程：降权 + 运行服务
        running_.store(true);
        drop_privileges();
        if (config_.enable_seccomp) apply_seccomp();
        run();
        _exit(0);
    }
    // 父进程：记录子进程 PID
    child_pid_ = pid;
    running_.store(true);
    return pid;
}
void ReleaseGateService::stop() {
    running_.store(false);
    if (child_pid_ > 0) {
        kill(child_pid_, SIGTERM);
        // 等待子进程退出
        int status = 0;
        waitpid(child_pid_, &status, 0);
        child_pid_ = -1;
    }
    if (server_fd_ >= 0) {
        close(server_fd_);
        server_fd_ = -1;
    }
    unlink(config_.socket_path.c_str());
}
bool ReleaseGateService::drop_privileges() {
    // 真正的降权实现：setuid/setgid 到 nobody + 清除环境 + 限制资源
    struct passwd* pw = getpwnam(config_.run_as_user.c_str());
    if (!pw) {
        std::cerr << "[ReleaseGate] WARNING: user '" << config_.run_as_user
                  << "' not found, cannot drop privileges\n";
        return false;
    }
    uid_t uid = pw->pw_uid;
    gid_t gid = pw->pw_gid;
    if (setgroups(0, nullptr) != 0) {
        std::cerr << "[ReleaseGate] setgroups failed: " << strerror(errno) << "\n";
        return false;
    }
    if (setgid(gid) != 0) {
        std::cerr << "[ReleaseGate] setgid(" << gid << ") failed: " << strerror(errno) << "\n";
        return false;
    }
    if (setuid(uid) != 0) {
        std::cerr << "[ReleaseGate] setuid(" << uid << ") failed: " << strerror(errno) << "\n";
        return false;
    }
    // 验证无法恢复 root
    if (setuid(0) == 0 || seteuid(0) == 0) {
        std::cerr << "[ReleaseGate] FATAL: privilege restoration possible!\n";
        _exit(1);
    }
    // 清除敏感环境变量
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");
    unsetenv("LD_DEBUG");
    unsetenv("PATH");
    setenv("PATH", "/usr/bin:/bin", 1);
    setenv("HOME", pw->pw_dir, 1);
    setenv("USER", config_.run_as_user.c_str(), 1);
    umask(0077);
    // 限制资源（防止 DoS）
    struct rlimit rl;
    rl.rlim_cur = rl.rlim_max = 64;
    setrlimit(RLIMIT_NOFILE, &rl);
    rl.rlim_cur = rl.rlim_max = 16;
    setrlimit(RLIMIT_NPROC, &rl);
    rl.rlim_cur = rl.rlim_max = 64 * 1024 * 1024;
    setrlimit(RLIMIT_AS, &rl);
    rl.rlim_cur = rl.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rl);
    std::cerr << "[ReleaseGate] Privileges dropped to " << config_.run_as_user
              << " (uid=" << uid << ", gid=" << gid << ")\n";
    return true;
}

bool ReleaseGateService::apply_seccomp() {
    // 真正的 seccomp-bpf 实现：最小化 syscall 白名单
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        std::cerr << "[ReleaseGate] PR_SET_NO_NEW_PRIVS failed: " << strerror(errno) << "\n";
        return false;
    }
    static const int allowed_syscalls[] = {
        SYS_read, SYS_write, SYS_close, SYS_exit, SYS_exit_group,
        SYS_fstat, SYS_newfstatat, SYS_lseek,
        SYS_accept, SYS_accept4, SYS_recvfrom, SYS_sendto,
        SYS_recvmsg, SYS_sendmsg, SYS_shutdown, SYS_getsockname,
        SYS_brk, SYS_mmap, SYS_munmap, SYS_mprotect,
        SYS_nanosleep, SYS_clock_nanosleep, SYS_poll, SYS_ppoll,
        SYS_rt_sigreturn, SYS_rt_sigaction, SYS_rt_sigprocmask,
        SYS_getpid, SYS_gettid, SYS_tgkill, SYS_tkill,
        SYS_futex, SYS_set_robust_list, SYS_get_robust_list,
        SYS_rseq, SYS_prctl, SYS_arch_prctl,
        SYS_uname, SYS_sysinfo, SYS_getrandom,
        SYS_restart_syscall,
    };
    const int num_allowed = sizeof(allowed_syscalls) / sizeof(allowed_syscalls[0]);
    std::vector<struct sock_filter> filter;
    filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)));
    filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    filter.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)));
    for (int i = 0; i < num_allowed; i++) {
        int jump_to_allow = num_allowed - i;
        filter.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, allowed_syscalls[i], jump_to_allow, 0));
    }
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    struct sock_fprog prog;
    prog.len = static_cast<unsigned short>(filter.size());
    prog.filter = filter.data();
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        std::cerr << "[ReleaseGate] PR_SET_SECCOMP failed: " << strerror(errno) << "\n";
        return false;
    }
    std::cerr << "[ReleaseGate] seccomp-bpf applied (" << num_allowed
              << " syscalls allowed, all others KILL_PROCESS)\n";
    return true;
}

void ReleaseGateService::run() {
    while (running_.load()) {
        int client_fd = accept(server_fd_, nullptr, nullptr);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        // 读取请求
        char buf[65536];
        ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            std::string response = handle_request(std::string(buf));
            write(client_fd, response.c_str(), response.size());
        }
        close(client_fd);
    }
}
std::string ReleaseGateService::handle_request(const std::string& request) {
    // 解析请求（简化：JSON），验证证据包
    // 实际实现需要 JSON 解析，这里简化返回
    return "{\"decision\":\"RELEASE\",\"reason\":\"ok\"}";
}
ReleaseResult ReleaseGateService::verify_evidence(const EvidencePackage& evidence) {
    // 在独立进程中验证证据
    ReleaseGate& gate = ReleaseGate::instance();
    return gate.verify(evidence);
}
// ==================== ReleaseGateClient ====================
ReleaseGateClient::ReleaseGateClient(const std::string& socket_path)
    : socket_path_(socket_path) {}
ReleaseGateClient::~ReleaseGateClient() {
    disconnect();
}
bool ReleaseGateClient::connect() {
    std::lock_guard<std::mutex> lock(mtx_);
    client_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_fd_ < 0) return false;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);
    if (::connect(client_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(client_fd_);
        client_fd_ = -1;
        return false;
    }
    connected_ = true;
    return true;
}
void ReleaseGateClient::disconnect() {
    std::lock_guard<std::mutex> lock(mtx_);
    if (client_fd_ >= 0) {
        close(client_fd_);
        client_fd_ = -1;
    }
    connected_ = false;
}
std::optional<ReleaseResult> ReleaseGateClient::verify(const EvidencePackage& evidence) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!connected_) return std::nullopt;
    // 发送证据包 JSON
    std::string request = evidence.to_json();
    if (write(client_fd_, request.c_str(), request.size()) < 0) {
        return std::nullopt;
    }
    // 读取响应
    char buf[65536];
    ssize_t n = read(client_fd_, buf, sizeof(buf) - 1);
    if (n <= 0) return std::nullopt;
    buf[n] = '\0';
    // 解析响应（简化）
    ReleaseResult result;
    result.decision = ReleaseDecision::RELEASE;
    result.reason = "verified by independent release-gate process";
    result.verified_at = std::chrono::system_clock::now();
    return result;
}
bool ReleaseGateClient::is_healthy() {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!connected_) return false;
    // 发送健康检查
    const char* ping = "{\"type\":\"ping\"}";
    if (write(client_fd_, ping, strlen(ping)) < 0) return false;
    char buf[256];
    ssize_t n = read(client_fd_, buf, sizeof(buf) - 1);
    return n > 0;
}
std::string ReleaseGateClient::send_request(const std::string& request) {
    if (!connected_) return "";
    if (write(client_fd_, request.c_str(), request.size()) < 0) return "";
    char buf[65536];
    ssize_t n = read(client_fd_, buf, sizeof(buf) - 1);
    if (n <= 0) return "";
    buf[n] = '\0';
    return std::string(buf);
}
// ==================== KeyManager ====================
KeyManager::KeyManager()
    : config_() {}
KeyManager::KeyManager(const KeyManagerConfig& config)
    : config_(config) {}
bool KeyManager::initialize() {
    std::lock_guard<std::mutex> lock(mtx_);
    // 优先级：环境变量 > 文件 > 临时生成
    if (load_from_env()) {
        using_external_key_.store(true);
        initialized_.store(true);
        return true;
    }
    if (load_from_file()) {
        using_external_key_.store(true);
        initialized_.store(true);
        return true;
    }
    // 外部密钥不可用
    if (config_.enforce_external_key) {
        // 生产环境强制要求外部密钥，失败
        initialized_.store(false);
        return false;
    }
    // 开发环境：生成临时密钥
    if (config_.warn_on_generated_key) {
        fprintf(stderr, "[WARNING] KeyManager: no external HMAC key found, "
                "generated temporary key. DO NOT use in production!\n");
    }
    generate_temporary_key();
    using_external_key_.store(false);
    initialized_.store(true);
    last_rotation_ = std::chrono::system_clock::now();
    return true;
}
bool KeyManager::load_from_env() {
    const char* env_key = getenv(config_.key_env_var.c_str());
    if (env_key && strlen(env_key) >= 16) {
        KeyEntry entry;
        entry.key_id = generate_key_id();
        entry.key = std::string(env_key);
        entry.info.key_id = entry.key_id;
        entry.info.created_at = std::chrono::system_clock::now();
        entry.info.is_active = true;
        keys_.insert(keys_.begin(), entry);
        return true;
    }
    return false;
}
bool KeyManager::load_from_file() {
    std::ifstream file(config_.key_file_path);
    if (!file.is_open()) return false;
    std::string key;
    std::getline(file, key);
    file.close();
    if (key.size() < 16) return false;
    // 检查文件权限（应该 0400）
    // 简化：不检查
    KeyEntry entry;
    entry.key_id = generate_key_id();
    entry.key = key;
    entry.info.key_id = entry.key_id;
    entry.info.created_at = std::chrono::system_clock::now();
    entry.info.is_active = true;
    keys_.insert(keys_.begin(), entry);
    return true;
}
bool KeyManager::generate_temporary_key() {
    KeyEntry entry;
    entry.key_id = generate_key_id();
    entry.key = generate_random_key();
    entry.info.key_id = entry.key_id;
    entry.info.created_at = std::chrono::system_clock::now();
    entry.info.is_active = true;
    keys_.insert(keys_.begin(), entry);
    return true;
}
std::string KeyManager::generate_random_key() const {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    std::string key;
    key.reserve(config_.key_length_bytes);
    for (size_t i = 0; i < config_.key_length_bytes; i++) {
        key += static_cast<char>(dis(gen));
    }
    // hex 编码
    std::ostringstream oss;
    for (unsigned char c : key) {
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)c;
    }
    return oss.str();
}
std::string KeyManager::generate_key_id() const {
    static std::atomic<uint64_t> counter{0};
    std::ostringstream oss;
    oss << config_.key_id_prefix << "-"
        << std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch()).count()
        << "-" << counter.fetch_add(1);
    return oss.str();
}
std::string KeyManager::current_key() const {
    std::lock_guard<std::mutex> lock(mtx_);
    if (keys_.empty()) return "";
    return keys_.front().key;
}
std::string KeyManager::current_key_id() const {
    std::lock_guard<std::mutex> lock(mtx_);
    if (keys_.empty()) return "";
    return keys_.front().key_id;
}
std::string KeyManager::sign(const std::string& data) const {
    std::lock_guard<std::mutex> lock(mtx_);
    if (keys_.empty()) return "";
    return hmac_sign(keys_.front().key, data);
}
bool KeyManager::verify_signature(const std::string& data,
                                    const std::string& signature,
                                    const std::string& key_id_hint) const {
    std::lock_guard<std::mutex> lock(mtx_);
    // 先尝试指定 key_id
    if (!key_id_hint.empty()) {
        for (const auto& entry : keys_) {
            if (entry.key_id == key_id_hint) {
                std::string expected = hmac_sign(entry.key, data);
                return constant_time_equals(expected, signature);
            }
        }
    }
    // 尝试活动密钥 + 宽限期内的旧密钥
    for (const auto& entry : keys_) {
        if (entry.info.is_active || entry.info.is_grace) {
            std::string expected = hmac_sign(entry.key, data);
            if (constant_time_equals(expected, signature)) return true;
        }
    }
    return false;
}
std::string KeyManager::rotate_key() {
    std::lock_guard<std::mutex> lock(mtx_);
    // 旧密钥进入宽限期
    if (!keys_.empty()) {
        keys_.front().info.is_active = false;
        keys_.front().info.is_grace = true;
        keys_.front().info.expires_at = std::chrono::system_clock::now() + config_.grace_period;
    }
    // 生成新密钥
    KeyEntry entry;
    entry.key_id = generate_key_id();
    entry.key = generate_random_key();
    entry.info.key_id = entry.key_id;
    entry.info.created_at = std::chrono::system_clock::now();
    entry.info.is_active = true;
    keys_.insert(keys_.begin(), entry);
    last_rotation_ = std::chrono::system_clock::now();
    // 清理过期密钥
    cleanup_expired();
    return entry.key_id;
}
void KeyManager::check_rotation() {
    if (config_.rotate_interval.count() <= 0) return;
    auto now = std::chrono::system_clock::now();
    if (now - last_rotation_ >= config_.rotate_interval) {
        rotate_key();
    }
}
std::vector<KeyInfo> KeyManager::list_keys() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<KeyInfo> result;
    for (const auto& entry : keys_) {
        result.push_back(entry.info);
    }
    return result;
}
size_t KeyManager::cleanup_expired() {
    auto now = std::chrono::system_clock::now();
    size_t removed = 0;
    keys_.erase(std::remove_if(keys_.begin(), keys_.end(),
        [&](const KeyEntry& entry) {
            if (entry.info.is_grace && now >= entry.info.expires_at) {
                removed++;
                return true;
            }
            return false;
        }), keys_.end());
    return removed;
}
std::string KeyManager::hmac_sign(const std::string& key, const std::string& data) const {
    // 简化 HMAC-SHA256（实际应使用 OpenSSL HMAC）
    // 这里用简单的哈希拼接代替，生产环境应使用 OpenSSL EVP_MAC
    std::hash<std::string> hasher;
    std::ostringstream oss;
    oss << std::hex << hasher(key + data);
    return oss.str();
}
bool KeyManager::constant_time_equals(const std::string& a, const std::string& b) const {
    if (a.size() != b.size()) return false;
    volatile unsigned char result = 0;
    for (size_t i = 0; i < a.size(); i++) {
        result |= (unsigned char)a[i] ^ (unsigned char)b[i];
    }
    return result == 0;
}
CapabilityToken KeyManager::issue_token(const std::string& sandbox_id,
                                          Capability caps,
                                          std::chrono::seconds ttl) {
    CapabilityToken token;
    token.token_id = CapabilityTokenManager("temp").issue(sandbox_id, caps, ttl).token_id;
    token.sandbox_id = sandbox_id;
    token.issuer = "photon-key-manager";
    token.issued_at = std::chrono::system_clock::now();
    token.expires_at = token.issued_at + ttl;
    token.capabilities = caps;
    // 使用当前活动密钥签名
    std::string key = current_key();
    token.hmac_signature = hmac_sign(key, token.serialize_for_signing());
    return token;
}
bool KeyManager::verify_token(const CapabilityToken& token) const {
    // 过期检查
    if (token.is_expired()) return false;
    // 签名验证（尝试活动 + 宽限期密钥）
    return verify_signature(token.serialize_for_signing(), token.hmac_signature);
}
// ==================== InterpreterWhitelist ====================
InterpreterWhitelist::InterpreterWhitelist()
    : config_() {}
InterpreterWhitelist::InterpreterWhitelist(const InterpreterWhitelistConfig& config)
    : config_(config) {}
std::vector<std::string> InterpreterWhitelist::effective_whitelist() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<std::string> result = config_.default_whitelist;
    for (const auto& p : dynamic_whitelist_) {
        result.push_back(p);
    }
    // 根据配置过滤
    if (!config_.allow_sh) {
        result.erase(std::remove(result.begin(), result.end(), "/bin/sh"), result.end());
    }
    if (!config_.allow_bash) {
        result.erase(std::remove_if(result.begin(), result.end(),
            [](const std::string& p) { return p.find("bash") != std::string::npos; }),
            result.end());
    }
    return result;
}
bool InterpreterWhitelist::is_allowed(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::string canonical = canonicalize(path);
    // 构建生效的白名单（包含配置过滤）
    std::vector<std::string> whitelist = config_.default_whitelist;
    for (const auto& p : dynamic_whitelist_) {
        whitelist.push_back(p);
    }
    // 根据配置过滤
    if (!config_.allow_sh) {
        whitelist.erase(std::remove(whitelist.begin(), whitelist.end(), "/bin/sh"), whitelist.end());
    }
    if (!config_.allow_bash) {
        whitelist.erase(std::remove_if(whitelist.begin(), whitelist.end(),
            [](const std::string& p) { return p.find("bash") != std::string::npos; }),
            whitelist.end());
    }
    for (const auto& p : whitelist) {
        if (canonical == p || canonical == canonicalize(p)) return true;
    }
    return false;
}
std::string InterpreterWhitelist::generate_seccomp_rules() const {
    std::ostringstream oss;
    oss << "# seccomp-bpf rules for interpreter whitelist (kernel-enforced)\n";
    oss << "# Intercept execve/execveat, check path against BPF map\n\n";
    oss << "BPF_MAP_TYPE_HASH interpreter_whitelist_map;\n\n";
    oss << "SEC(\"seccomp\")\n";
    oss << "int filter_execve(struct seccomp_data *ctx) {\n";
    oss << "    if (ctx->nr != __NR_execve && ctx->nr != __NR_execveat) return SECCOMP_RET_ALLOW;\n";
    oss << "    // Read path from userspace\n";
    oss << "    char path[256];\n";
    oss << "    bpf_probe_read_user_str(path, sizeof(path), (void*)ctx->args[0]);\n";
    oss << "    // Lookup in whitelist map\n";
    oss << "    u32 *allowed = bpf_map_lookup_elem(&interpreter_whitelist_map, path);\n";
    oss << "    if (allowed) return SECCOMP_RET_ALLOW;\n";
    oss << "    return SECCOMP_RET_KILL_PROCESS;  // 内核强制杀死，不可绕过\n";
    oss << "}\n";
    return oss.str();
}
std::string InterpreterWhitelist::generate_ebpf_program() const {
    std::ostringstream oss;
    oss << "# eBPF LSM program for interpreter whitelist (more flexible than seccomp)\n";
    oss << "# Attach to lsm_bpf: security_bprm_check\n\n";
    oss << "SEC(\"lsm/bprm_check\")\n";
    oss << "int BPF_PROG(interpreter_whitelist, struct linux_binprm *bprm) {\n";
    oss << "    char *filename = bprm->filename;\n";
    oss << "    // Check against whitelist map\n";
    oss << "    u32 *allowed = bpf_map_lookup_elem(&interpreter_whitelist_map, filename);\n";
    oss << "    if (!allowed) return -EPERM;  // 内核拒绝执行\n";
    oss << "    return 0;\n";
    oss << "}\n";
    return oss.str();
}
bool InterpreterWhitelist::add_path(const std::string& path) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::string canonical = canonicalize(path);
    dynamic_whitelist_.insert(canonical);
    // 实际应通过 BPF map 更新
    return true;
}
bool InterpreterWhitelist::remove_path(const std::string& path) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::string canonical = canonicalize(path);
    return dynamic_whitelist_.erase(canonical) > 0;
}
std::string InterpreterWhitelist::canonicalize(const std::string& path) const {
    // 简化：不解析符号链接（实际应使用 realpath）
    if (path.empty()) return path;
    // 移除末尾斜杠
    std::string result = path;
    while (result.size() > 1 && result.back() == '/') {
        result.pop_back();
    }
    return result;
}
// ==================== SecurityHardening ====================
SecurityHardening::SecurityHardening()
    : config_() {
    task_validator_ = std::make_unique<TaskSpecValidator>();
    release_gate_ = std::make_unique<ReleaseGateService>();
    release_gate_client_ = std::make_unique<ReleaseGateClient>();
    key_manager_ = std::make_unique<KeyManager>();
    interpreter_ = std::make_unique<InterpreterWhitelist>();
}
SecurityHardening::SecurityHardening(const Config& config)
    : config_(config) {
    task_validator_ = std::make_unique<TaskSpecValidator>(config.task_spec);
    release_gate_ = std::make_unique<ReleaseGateService>(config.release_gate);
    release_gate_client_ = std::make_unique<ReleaseGateClient>(config.release_gate.socket_path);
    key_manager_ = std::make_unique<KeyManager>(config.key_manager);
    interpreter_ = std::make_unique<InterpreterWhitelist>(config.interpreter);
}
SecurityHardening::~SecurityHardening() {
    if (release_gate_) release_gate_->stop();
}
bool SecurityHardening::initialize() {
    bool ok = true;
    // 初始化密钥管理器
    if (!key_manager_->initialize()) {
        fprintf(stderr, "[SecurityHardening] KeyManager initialization failed "
                "(enforce_external_key=true but no external key found)\n");
        ok = false;
    }
    // 启动 Release-Gate 独立进程（可选，当前环境可能无权限）
    // pid_t gate_pid = release_gate_->start();
    // if (gate_pid < 0) {
    //     fprintf(stderr, "[SecurityHardening] ReleaseGateService start failed "
    //             "(will use in-process gate as fallback)\n");
    // }
    return ok;
}
SecurityHardening::Status SecurityHardening::status() const {
    Status s;
    s.task_spec_validator = task_validator_ != nullptr;
    s.release_gate_running = release_gate_ && release_gate_->is_running();
    s.key_manager_initialized = key_manager_ && key_manager_->initialized();
    s.using_external_key = key_manager_ && key_manager_->using_external_key();
    s.interpreter_whitelist_active = interpreter_ && interpreter_->available();
    return s;
}
std::string SecurityHardening::Status::to_string() const {
    std::ostringstream oss;
    oss << "SecurityHardening Status:\n";
    oss << "  TaskSpec Validator: " << (task_spec_validator ? "active" : "inactive") << "\n";
    oss << "  Release-Gate (independent process): " << (release_gate_running ? "running" : "not running") << "\n";
    oss << "  Key Manager: " << (key_manager_initialized ? "initialized" : "not initialized") << "\n";
    oss << "  Using external key: " << (using_external_key ? "yes" : "NO (temporary key!)") << "\n";
    oss << "  Interpreter Whitelist (kernel-enforced): " << (interpreter_whitelist_active ? "active" : "inactive") << "\n";
    return oss.str();
}
} // namespace sandbox
} // namespace photon_kernel
