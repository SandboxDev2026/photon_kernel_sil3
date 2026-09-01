#ifndef PHOTON_KERNEL_SANDBOX_POLICY_HPP
#define PHOTON_KERNEL_SANDBOX_POLICY_HPP

#include <vector>
#include <cstdint>

#include "sandbox_config.hpp"

namespace photon_kernel {
namespace sandbox {

class SandboxPolicy {
public:
    // ---- 获取系统调用白名单（参考 NsJail seccomp_policy.cpp） ----
    static std::vector<int> get_whitelist_for_risk(RiskLevel level);

    // ---- 代码执行白名单：LOW 基础上允许 execve/进程管理/临时文件 ----
    // 用于预 fork worker 中通过 stdin 执行用户代码（解释器路径由调用方硬编码限制）
    static std::vector<int> get_whitelist_for_code_runner();

    // ---- 合并额外 syscall（参考 libseccomp 示例） ----
    static std::vector<int> merge_with_extra(
        const std::vector<int>& base,
        const std::vector<int>& extra);

    // ---- 安装 seccomp 过滤器（参考 libseccomp 官方示例 + NsJail） ----
    static void install_seccomp_filter(const std::vector<int>& allowed_syscalls);

    // ---- 应用 rlimit（参考 NsJail + JudgeServer） ----
    // apply_nproc=false 时跳过 RLIMIT_NPROC：供“预 fork worker”使用，
    // worker 需要持续 fork 任务进程，NPROC 收紧应在任务进程内部单独设置（防 fork 炸弹）。
    static void apply_rlimits(const SandboxConfig& config, bool apply_nproc = true);

private:
    SandboxPolicy() = delete;
};

} // namespace sandbox
} // namespace photon_kernel

#endif
