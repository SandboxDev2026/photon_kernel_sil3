#ifndef PHOTON_KERNEL_SANDBOX_EXCEPTION_HPP
#define PHOTON_KERNEL_SANDBOX_EXCEPTION_HPP

#include <stdexcept>
#include <string>

namespace photon_kernel {
namespace sandbox {

// 参考：Z-Jail 错误码设计（Division-36/Z-Jail）
enum class SandboxErrorCode {
    OK = 0,
    FORK_FAILED,                // fork 失败
    SECCOMP_INSTALL_FAILED,     // seccomp 安装失败
    RESOURCE_LIMIT_EXCEEDED,    // rlimit 超限
    TIMEOUT_EXPIRED,            // 看门狗超时
    ILLEGAL_SYSCALL,            // seccomp 拦截非法调用
    INTERNAL_PIPE_ERROR,        // 管道通信失败
    TASK_CRASHED,               // 子进程崩溃
    CONFIG_INVALID,             // 配置无效
    PATH_NOT_WHITELISTED,       // 路径不在白名单
};

class SandboxException : public std::runtime_error {
public:
    SandboxException(SandboxErrorCode code, const std::string& msg)
        : std::runtime_error(msg), code_(code) {}

    SandboxErrorCode code() const noexcept { return code_; }

private:
    SandboxErrorCode code_;
};

} // namespace sandbox
} // namespace photon_kernel

#endif
