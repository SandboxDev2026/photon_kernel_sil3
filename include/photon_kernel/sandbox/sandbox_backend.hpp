#ifndef PHOTON_KERNEL_SANDBOX_SANDBOX_BACKEND_HPP
#define PHOTON_KERNEL_SANDBOX_SANDBOX_BACKEND_HPP
// 沙盒后端抽象层：支持 Process（fork+seccomp）和 MicroVM（Firecracker）两种后端。
// 根据风险等级和部署环境选择合适的隔离强度。
//
// 隔离等级对比：
//   PROCESS: 启动 <2ms, 共享内核, 适合可信/半可信代码
//   MICROVM: 启动 <125ms, 独立内核, 适合公网不可信代码（需要 Firecracker）
#include <memory>
#include <string>
#include <chrono>
#include "code_runner.hpp"
#include "sandbox_config.hpp"
namespace photon_kernel {
namespace sandbox {
enum class SandboxBackend {
    PROCESS,   // fork+seccomp（当前默认，轻量快速）
    MICROVM,   // Firecracker（强隔离，需要 firecracker 二进制）
};
struct BackendStatus {
    SandboxBackend type;
    bool available = false;
    size_t active_instances = 0;
    std::string message;
};
// 沙盒后端统一接口
class ISandboxBackend {
public:
    virtual ~ISandboxBackend() = default;
    // 同步执行代码（无状态，每次新建沙盒）
    virtual CodeRunResult execute(const CodeRunRequest& req) = 0;
    // 创建有状态沙盒实例（返回 handle，可多次执行）
    virtual std::string create(const SandboxConfig& cfg) = 0;
    // 在有状态沙盒中执行代码
    virtual CodeRunResult run(const std::string& handle, const CodeRunRequest& req) = 0;
    // 销毁沙盒实例
    virtual void destroy(const std::string& handle) = 0;
    // 后端状态
    virtual BackendStatus status() const = 0;
    // 后端类型
    virtual SandboxBackend type() const = 0;
};
// 后端工厂：根据类型创建后端实例
class SandboxBackendFactory {
public:
    static std::unique_ptr<ISandboxBackend> create(SandboxBackend type);
    // 根据风险等级自动选择：LOW/MEDIUM→Process, HIGH→MicroVM（如果可用）
    static SandboxBackend choose_by_risk(RiskLevel level);
    // 检测 MicroVM 后端是否可用（firecracker 二进制存在 + /dev/kvm 可访问）
    static bool microvm_available();
};
} // namespace sandbox
} // namespace photon_kernel
#endif
