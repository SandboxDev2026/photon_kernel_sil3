#pragma once
// LightPool seccomp-BPF 双模式策略
//
// 两种运行模式：
//   default_mode:        常规业务进程，宽松基础白名单
//   untrusted_code_mode: 执行不可信用户代码，严格最小权限
//
// 核心安全原则：
//   1. 白名单之外全部 SECCOMP_RET_KILL_PROCESS（不使用 TRAP，避免信号绕过）
//   2. 高危 syscall 不仅拦截调用号，还校验参数 flag（BPF 参数过滤）
//   3. 被拒绝的 syscall 完整上报审计模块（pid、syscall号、参数摘要、时间戳）
//   4. 不可信代码模式额外禁用 ptrace/mount/clone(namespace)/init_module 等

#include <string>
#include <vector>
#include <set>
#include <map>
#include <cstdint>
#include <linux/seccomp.h>

namespace photon_kernel {
namespace sandbox {

// seccomp 运行模式
enum class SeccompMode {
    DEFAULT = 0,          // 常规业务，宽松白名单
    UNTRUSTED_CODE = 1,   // 不可信用户代码，严格最小权限
};

// 高危系统调用定义（不可信代码模式必须禁用）
struct DangerousSyscall {
    int nr;               // syscall 号
    std::string name;     // 名称
    std::string reason;   // 禁用原因
    bool param_filter;    // 是否需要参数过滤
};

// seccomp 拦截审计事件
struct SeccompViolationEvent {
    uint64_t timestamp_ns;   // 纳秒时间戳
    pid_t pid;               // 进程 PID
    int syscall_nr;          // 系统调用号
    std::string syscall_name; // 系统调用名称
    uint64_t args[6];        // 参数摘要（前6个参数）
    std::string mode;         // 触发时的 seccomp 模式
    bool killed;              // 是否被 KILL_PROCESS
};

// syscall 参数过滤规则
struct ParamFilterRule {
    int syscall_nr;
    int arg_index;        // 参数索引 (0-5)
    uint64_t mask;        // 位掩码
    uint64_t value;       // 匹配值（mask & arg == value 时拦截）
    std::string description;
};

// seccomp 策略配置
class SeccompPolicy {
public:
    explicit SeccompPolicy(SeccompMode mode = SeccompMode::DEFAULT);

    // 获取当前模式
    SeccompMode mode() const { return mode_; }
    std::string mode_name() const;

    // 获取允许的 syscall 列表（白名单）
    const std::set<int>& allowed_syscalls() const { return allowed_; }

    // 获取禁用的高危 syscall 列表
    const std::vector<DangerousSyscall>& dangerous_syscalls() const { return dangerous_; }

    // 获取参数过滤规则
    const std::vector<ParamFilterRule>& param_filters() const { return param_filters_; }

    // 检查某个 syscall 是否被允许
    bool is_allowed(int syscall_nr) const;

    // 检查某个 syscall 是否需要参数过滤
    bool has_param_filter(int syscall_nr) const;

    // 生成 BPF 程序文本（用于调试和审计快照）
    std::string generate_bpf_program() const;

    // 生成规则快照 JSON（用于合规证据收集）
    std::string generate_snapshot_json() const;

    // 计算规则集 SHA256 哈希（用于配置完整性校验）
    std::string compute_hash() const;

    // 记录 seccomp 违规事件（审计上报）
    static void log_violation(const SeccompViolationEvent& event);

    // 获取违规事件计数（用于 metrics）
    static uint64_t violation_count();

    // strace 采集辅助：从 strace 输出解析实际使用的 syscall，用于裁剪白名单
    static std::set<int> parse_strace_syscalls(const std::string& strace_output);

private:
    SeccompMode mode_;
    std::set<int> allowed_;
    std::vector<DangerousSyscall> dangerous_;
    std::vector<ParamFilterRule> param_filters_;

    void init_default_mode();
    void init_untrusted_mode();
    void add_common_allowed();
    void add_dangerous_syscalls();
    void add_param_filters();

    static uint64_t violation_count_;
};

} // namespace sandbox
} // namespace photon_kernel
