#ifndef PHOTON_KERNEL_SANDBOX_SECURITY_HARDENING_HPP
#define PHOTON_KERNEL_SANDBOX_SECURITY_HARDENING_HPP
// P0 安全加固模块
//
// 1. TaskSpec 严格校验器：防止恶意 spec 绕过限制（资源溢出/TTL为0/网络策略篡改）
// 2. Release-Gate 独立进程服务：产物释放闸门独立进程，不与沙盒执行进程同权限
// 3. 密钥管理器：HMAC 密钥外部注入 + 轮换，移除硬编码
// 4. 解释器白名单 seccomp 内核强制：从应用层判断改为内核 execve 拦截
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <optional>
#include <functional>
#include "task_spec.hpp"
#include "capability_token.hpp"
#include "evidence_release.hpp"
namespace photon_kernel {
namespace sandbox {
// ==================== TaskSpec 严格校验器 ====================
//
// 防止恶意 TaskSpec 绕过限制：
// - 资源溢出：CPU/内存/磁盘超过系统硬上限
// - TTL 为0或负数：任务永不过期
// - 网络策略篡改：allow_cidrs 包含内网地址/元数据地址
// - 路径遍历：workspace_path 包含 ../
// - 注入攻击：字段包含 shell 元字符
struct TaskSpecValidationResult {
    bool valid = false;
    std::vector<std::string> errors;      // 致命错误（必须拒绝）
    std::vector<std::string> warnings;    // 警告（可接受但需记录）
    std::vector<std::string> sanitized_fields;  // 被清理的字段
    // 风险等级
    enum class RiskLevel { LOW, MEDIUM, HIGH, CRITICAL } risk = RiskLevel::LOW;
    std::string to_string() const;
};
class TaskSpecValidator {
public:
    struct Config {
        // 系统硬上限
        double max_cpu_cores = 64.0;
        size_t max_memory_mb = 65536;       // 64GB
        size_t max_disk_mb = 1048576;        // 1TB
        int max_processes = 4096;
        int max_open_files = 65536;
        // TTL 限制
        std::chrono::seconds min_ttl{1};
        std::chrono::seconds max_ttl{86400};  // 24小时
        std::chrono::milliseconds max_execution_timeout{3600000};  // 1小时
        // 网络限制
        bool block_internal_cidrs = true;     // 禁止 allow_cidrs 包含内网地址
        bool block_metadata_ip = true;         // 禁止 169.254.169.254
        int max_allow_cidrs = 64;
        int max_deny_cidrs = 64;
        int max_allow_ports = 128;
        int max_connections = 1024;
        // 路径安全
        bool block_path_traversal = true;
        bool block_absolute_path_escape = true;  // 禁止 workspace 跳出沙盒根
        std::string sandbox_root = "/var/lib/photon/sandboxes";
        // 字段长度限制
        size_t max_field_length = 4096;
        size_t max_task_id_length = 128;
        size_t max_goal_length = 65536;
        // 注入防护
        bool block_shell_metacharacters = true;
        bool block_null_bytes = true;
    };
    TaskSpecValidator();
    explicit TaskSpecValidator(const Config& config);
    ~TaskSpecValidator() = default;
    // 严格校验 TaskSpec
    TaskSpecValidationResult validate(const TaskSpec& spec) const;
    // 校验并自动清理（返回清理后的 spec）
    std::pair<TaskSpec, TaskSpecValidationResult> validate_and_sanitize(
        const TaskSpec& spec) const;
    // 单项校验
    bool validate_resources(const ResourceSpec& r, std::vector<std::string>& errors) const;
    bool validate_network(const NetworkSpec& n, std::vector<std::string>& errors) const;
    bool validate_budget(const BudgetSpec& b, std::vector<std::string>& errors) const;
    bool validate_identity(const IdentitySpec& i, std::vector<std::string>& errors) const;
    bool validate_paths(const TaskSpec& spec, std::vector<std::string>& errors) const;
    bool validate_injection(const TaskSpec& spec, std::vector<std::string>& errors) const;
    // 配置
    const Config& config() const { return config_; }
private:
    Config config_;
    // 内网 CIDR 列表（用于检测网络策略篡改）
    static const std::vector<std::string>& internal_cidrs();
    bool is_internal_cidr(const std::string& cidr) const;
    bool contains_path_traversal(const std::string& path) const;
    bool contains_shell_metacharacters(const std::string& s) const;
    bool contains_null_bytes(const std::string& s) const;
    std::string sanitize_string(const std::string& s) const;
};
// ==================== Release-Gate 独立进程服务 ====================
//
// P0 安全要求：Release-Gate 必须独立进程运行，不与沙盒执行进程同权限。
// 如果沙盒逃逸，闸门不能被篡改，审计证据、输出产物不能被伪造。
//
// 架构：
//   [沙盒执行进程] --Unix socket--> [Release-Gate 独立进程]
//         |                                    |
//    低权限( nobody )                     降权运行
//                                          - 独立 UID
//                                          - 独立 cgroup
//                                          - seccomp 限制
//                                          - 只读根文件系统
struct ReleaseGateConfig {
    std::string socket_path = "/run/photon/release-gate.sock";
    std::string run_as_user = "nobody";     // 降权运行用户
    std::string run_as_group = "nogroup";
    bool enable_seccomp = true;              // 闸门进程也启用 seccomp
    bool read_only_rootfs = true;            // 只读根文件系统
    std::string evidence_dir = "/var/lib/photon/evidence";  // 证据存储（独立目录）
    std::chrono::milliseconds request_timeout{5000};
    size_t max_evidence_size_mb = 100;       // 单次证据包大小上限
    bool require_hmac_chain = true;           // 必须验证 HMAC 哈希链
    bool require_artifact_hash = true;         // 必须验证产物哈希
};
// Release-Gate 服务端（独立进程运行）
class ReleaseGateService {
public:
    ReleaseGateService();
    explicit ReleaseGateService(const ReleaseGateConfig& config);
    ~ReleaseGateService();
    // 启动独立进程（fork + 降权 + seccomp）
    // 返回子进程 PID，父进程通过 socket 通信
    pid_t start();
    // 停止服务
    void stop();
    // 服务端主循环（在子进程中运行）
    void run();
    // 状态
    bool is_running() const { return running_.load(); }
    pid_t pid() const { return child_pid_; }
    const ReleaseGateConfig& config() const { return config_; }
private:
    ReleaseGateConfig config_;
    std::atomic<bool> running_{false};
    pid_t child_pid_ = -1;
    int server_fd_ = -1;
    // 降权
    bool drop_privileges();
    // 启用 seccomp（闸门进程最小化 syscall）
    bool apply_seccomp();
    // 处理客户端请求
    std::string handle_request(const std::string& request);
    // 验证证据包（在独立进程中）
    ReleaseResult verify_evidence(const EvidencePackage& evidence);
};
// Release-Gate 客户端（沙盒执行进程中使用，通过 socket 连接独立进程）
class ReleaseGateClient {
public:
    explicit ReleaseGateClient(const std::string& socket_path = "/run/photon/release-gate.sock");
    ~ReleaseGateClient();
    // 连接到独立 Release-Gate 进程
    bool connect();
    // 断开
    void disconnect();
    // 提交证据包验证（通过 socket 发送到独立进程）
    std::optional<ReleaseResult> verify(const EvidencePackage& evidence);
    // 健康检查
    bool is_healthy();
    bool connected() const { return connected_; }
private:
    std::string socket_path_;
    int client_fd_ = -1;
    bool connected_ = false;
    std::mutex mtx_;
    std::string send_request(const std::string& request);
};
// ==================== 密钥管理器 ====================
//
// P0 安全要求：HMAC 密钥不能硬编码进二进制，必须外部注入 + 支持轮换。
//
// 密钥来源优先级：
// 1. 环境变量 PHOTON_HMAC_KEY
// 2. 密钥文件 /etc/photon/hmac.key（权限 0400）
// 3. KMS / Vault（通过插件接口）
// 4. 启动时生成临时密钥（仅用于开发，生产环境警告）
//
// 密钥轮换：
// - 主动轮换：rotate_key() 生成新密钥，旧密钥进入宽限期
// - 定时轮换：配置 rotate_interval，自动轮换
// - 宽限期：grace_period 内旧密钥仍可验证（用于滚动更新）
struct KeyManagerConfig {
    std::string key_env_var = "PHOTON_HMAC_KEY";
    std::string key_file_path = "/etc/photon/hmac.key";
    std::string key_id_prefix = "photon-key";
    size_t key_length_bytes = 32;           // SHA256-HMAC 密钥长度
    std::chrono::seconds rotate_interval{0};  // 0=不自动轮换
    std::chrono::seconds grace_period{300};    // 旧密钥宽限期（5分钟）
    bool warn_on_generated_key = true;         // 生成临时密钥时警告
    bool enforce_external_key = false;         // 强制要求外部密钥（生产环境）
};
struct KeyInfo {
    std::string key_id;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;  // 宽限期结束时间
    bool is_active = false;
    bool is_grace = false;  // 宽限期内（可验证但不可签名）
};
class KeyManager {
public:
    KeyManager();
    explicit KeyManager(const KeyManagerConfig& config);
    ~KeyManager() = default;
    // 初始化：从环境变量/文件加载密钥
    // 返回是否成功（enforce_external_key=true 时失败返回 false）
    bool initialize();
    // 获取当前活动密钥（用于签名）
    std::string current_key() const;
    std::string current_key_id() const;
    // 使用当前活动密钥签名
    std::string sign(const std::string& data) const;
    // 验证签名（尝试活动密钥 + 宽限期内的旧密钥）
    bool verify_signature(const std::string& data, const std::string& signature,
                          const std::string& key_id_hint = "") const;
    // 主动轮换密钥
    // 返回新密钥 ID
    std::string rotate_key();
    // 定时轮换检查（应定期调用）
    void check_rotation();
    // 列出所有密钥（活动 + 宽限期）
    std::vector<KeyInfo> list_keys() const;
    // 清理过期密钥（超过宽限期）
    size_t cleanup_expired();
    // 状态
    bool initialized() const { return initialized_.load(); }
    bool using_external_key() const { return using_external_key_.load(); }
    const KeyManagerConfig& config() const { return config_; }
    // 签发 CapabilityToken（使用当前活动密钥签名）
    CapabilityToken issue_token(const std::string& sandbox_id,
                                 Capability caps,
                                 std::chrono::seconds ttl = std::chrono::hours(1));
    // 验证 CapabilityToken（尝试活动 + 宽限期密钥）
    bool verify_token(const CapabilityToken& token) const;
private:
    KeyManagerConfig config_;
    mutable std::mutex mtx_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> using_external_key_{false};
    struct KeyEntry {
        std::string key_id;
        std::string key;
        KeyInfo info;
    };
    std::vector<KeyEntry> keys_;  // 按创建时间排序，最新的在前面
    std::chrono::system_clock::time_point last_rotation_;
    // 从环境变量加载
    bool load_from_env();
    // 从文件加载
    bool load_from_file();
    // 生成临时密钥
    bool generate_temporary_key();
    // 生成随机密钥
    std::string generate_random_key() const;
    // 生成密钥 ID
    std::string generate_key_id() const;
    // HMAC 签名
    std::string hmac_sign(const std::string& key, const std::string& data) const;
    // 常量时间比较
    bool constant_time_equals(const std::string& a, const std::string& b) const;
};
// ==================== 解释器白名单 seccomp 内核强制 ====================
//
// P0 安全要求：解释器路径白名单不能只靠应用层判断，必须内核强制。
// 沙盒内如果逃逸应用层逻辑，可以绕过解释器限制。
//
// 方案：seccomp-bpf 拦截 execve/execveat，在 BPF 程序中检查路径是否在白名单。
// 白名单路径通过 seccomp BPF map 配置，内核态匹配，不可绕过。
struct InterpreterWhitelistConfig {
    bool enabled = true;
    // 白名单解释器路径（默认仅允许安全解释器）
    std::vector<std::string> default_whitelist = {
        "/usr/bin/python3",
        "/usr/bin/python3.11",
        "/usr/bin/node",
        "/usr/bin/nodejs",
        "/usr/local/bin/python3",
        "/usr/local/bin/node",
        "/bin/sh",
        "/bin/bash",
        "/usr/bin/bash",
    };
    bool allow_sh = true;       // 是否允许 /bin/sh
    bool allow_bash = true;      // 是否允许 /bin/bash
    bool block_other_exec = true; // 阻止白名单外的所有 execve
    // seccomp BPF map 路径（用于动态更新白名单）
    std::string bpf_map_path = "/sys/fs/bpf/photon_interpreter_whitelist";
};
class InterpreterWhitelist {
public:
    InterpreterWhitelist();
    explicit InterpreterWhitelist(const InterpreterWhitelistConfig& config);
    ~InterpreterWhitelist() = default;
    // 获取生效的白名单（合并默认 + 配置）
    std::vector<std::string> effective_whitelist() const;
    // 检查路径是否在白名单（应用层快速检查，内核层有 seccomp 强制）
    bool is_allowed(const std::string& path) const;
    // 生成 seccomp BPF 规则（拦截 execve，内核态匹配白名单）
    // 返回 BPF 指令的文本描述（实际编译需要 libbpf）
    std::string generate_seccomp_rules() const;
    // 生成 eBPF 程序（lsm_bpf 或 seccomp 过滤器，更灵活）
    std::string generate_ebpf_program() const;
    // 添加路径到白名单（运行时动态添加，通过 BPF map）
    bool add_path(const std::string& path);
    // 移除路径
    bool remove_path(const std::string& path);
    // 配置
    const InterpreterWhitelistConfig& config() const { return config_; }
    // 白名单是否可用（需要内核 seccomp 支持）
    bool available() const { return available_; }
private:
    InterpreterWhitelistConfig config_;
    mutable std::mutex mtx_;
    std::unordered_set<std::string> dynamic_whitelist_;  // 运行时添加的路径
    bool available_ = true;
    // 规范化路径（解析符号链接、相对路径）
    std::string canonicalize(const std::string& path) const;
};
// ==================== P0 安全加固统一入口 ====================
class SecurityHardening {
public:
    struct Config {
        TaskSpecValidator::Config task_spec;
        ReleaseGateConfig release_gate;
        KeyManagerConfig key_manager;
        InterpreterWhitelistConfig interpreter;
    };
    SecurityHardening();
    explicit SecurityHardening(const Config& config);
    ~SecurityHardening();
    // 初始化所有子系统
    bool initialize();
    // 子系统访问
    TaskSpecValidator& task_spec_validator() { return *task_validator_; }
    ReleaseGateService& release_gate_service() { return *release_gate_; }
    ReleaseGateClient& release_gate_client() { return *release_gate_client_; }
    KeyManager& key_manager() { return *key_manager_; }
    InterpreterWhitelist& interpreter_whitelist() { return *interpreter_; }
    // 状态报告
    struct Status {
        bool task_spec_validator = false;
        bool release_gate_running = false;
        bool key_manager_initialized = false;
        bool using_external_key = false;
        bool interpreter_whitelist_active = false;
        std::string to_string() const;
    };
    Status status() const;
private:
    Config config_;
    std::unique_ptr<TaskSpecValidator> task_validator_;
    std::unique_ptr<ReleaseGateService> release_gate_;
    std::unique_ptr<ReleaseGateClient> release_gate_client_;
    std::unique_ptr<KeyManager> key_manager_;
    std::unique_ptr<InterpreterWhitelist> interpreter_;
};
} // namespace sandbox
} // namespace photon_kernel
#endif
