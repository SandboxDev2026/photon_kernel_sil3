#ifndef PHOTON_KERNEL_SANDBOX_RUNTIME_INTERFACE_HPP
#define PHOTON_KERNEL_SANDBOX_RUNTIME_INTERFACE_HPP
// 统一运行时接口 —— Execution Plane 核心
//
// 四种运行时实现同一接口，上层业务不感知底层差异：
//   - ContainerRuntime: namespace+cgroup 进程沙盒
//   - GVisorRuntime: runsc 用户态内核
//   - MicroVMRuntime: Firecracker 独立内核
//   - WasmRuntime: wasmtime/wasmer WASI 沙箱
//
// 所有运行时支持：
//   - create/destroy 生命周期
//   - exec 执行代码/命令
//   - snapshot/restore 状态恢复
//   - status 状态查询
//   - 私有工作区管理
#include <string>
#include <memory>
#include <chrono>
#include <mutex>
#include <unordered_map>
#include "task_spec.hpp"
namespace photon_kernel {
namespace sandbox {
// 执行结果
struct RuntimeExecResult {
    bool success = false;
    std::string output;
    std::string error;
    int exit_code = -1;
    std::chrono::milliseconds duration{0};
    size_t memory_used_mb = 0;
    double cpu_used_seconds = 0;
};
// 运行时状态
struct RuntimeStatus {
    RuntimeType type;
    bool available = false;
    bool running = false;
    size_t active_instances = 0;
    size_t total_instances = 0;
    size_t failed_instances = 0;
    std::string message;
};
// 统一运行时接口
class IRuntime {
public:
    virtual ~IRuntime() = default;
    // 创建运行时实例
    virtual std::string create(const TaskSpec& spec) = 0;
    // 销毁运行时实例
    virtual void destroy(const std::string& instance_id) = 0;
    // 执行代码/命令
    virtual RuntimeExecResult exec(const std::string& instance_id,
                                     const std::string& code,
                                     const std::string& language = "shell") = 0;
    // 快照
    virtual bool snapshot(const std::string& instance_id,
                          const std::string& snapshot_path) = 0;
    // 恢复
    virtual std::string restore(const std::string& snapshot_path) = 0;
    // 状态查询
    virtual RuntimeStatus status() const = 0;
    // 运行时类型
    virtual RuntimeType type() const = 0;
    // 是否可用
    virtual bool available() const = 0;
    // 私有工作区路径
    virtual std::string workspace_path(const std::string& instance_id) const = 0;
};
// Container 运行时（进程沙盒）
class ContainerRuntime : public IRuntime {
public:
    ContainerRuntime();
    std::string create(const TaskSpec& spec) override;
    void destroy(const std::string& instance_id) override;
    RuntimeExecResult exec(const std::string& instance_id,
                            const std::string& code,
                            const std::string& language) override;
    bool snapshot(const std::string& instance_id,
                  const std::string& snapshot_path) override;
    std::string restore(const std::string& snapshot_path) override;
    RuntimeStatus status() const override;
    RuntimeType type() const override { return RuntimeType::CONTAINER; }
    bool available() const override { return true; }
    std::string workspace_path(const std::string& instance_id) const override;
private:
    struct Instance {
        std::string id;
        std::string workspace;
        pid_t pid = -1;
        bool running = false;
        TaskSpec spec;
    };
    mutable std::mutex mtx_;
    std::unordered_map<std::string, Instance> instances_;
    size_t total_created_ = 0;
};
// gVisor 运行时
class GVisorRuntime : public IRuntime {
public:
    GVisorRuntime();
    std::string create(const TaskSpec& spec) override;
    void destroy(const std::string& instance_id) override;
    RuntimeExecResult exec(const std::string& instance_id,
                            const std::string& code,
                            const std::string& language) override;
    bool snapshot(const std::string& instance_id,
                  const std::string& snapshot_path) override;
    std::string restore(const std::string& snapshot_path) override;
    RuntimeStatus status() const override;
    RuntimeType type() const override { return RuntimeType::GVISOR; }
    bool available() const override;
    std::string workspace_path(const std::string& instance_id) const override;
private:
    struct Instance {
        std::string id;
        std::string sandbox_id;
        std::string workspace;
        bool running = false;
    };
    mutable std::mutex mtx_;
    std::unordered_map<std::string, Instance> instances_;
};
// MicroVM 运行时
class MicroVMRuntime : public IRuntime {
public:
    MicroVMRuntime();
    std::string create(const TaskSpec& spec) override;
    void destroy(const std::string& instance_id) override;
    RuntimeExecResult exec(const std::string& instance_id,
                            const std::string& code,
                            const std::string& language) override;
    bool snapshot(const std::string& instance_id,
                  const std::string& snapshot_path) override;
    std::string restore(const std::string& snapshot_path) override;
    RuntimeStatus status() const override;
    RuntimeType type() const override { return RuntimeType::MICROVM; }
    bool available() const override;
    std::string workspace_path(const std::string& instance_id) const override;
private:
    struct Instance {
        std::string id;
        std::string sock_path;
        std::string workspace;
        bool running = false;
    };
    mutable std::mutex mtx_;
    std::unordered_map<std::string, Instance> instances_;
};
// Wasm 运行时
class WasmRuntime : public IRuntime {
public:
    WasmRuntime();
    std::string create(const TaskSpec& spec) override;
    void destroy(const std::string& instance_id) override;
    RuntimeExecResult exec(const std::string& instance_id,
                            const std::string& code,
                            const std::string& language) override;
    bool snapshot(const std::string& instance_id,
                  const std::string& snapshot_path) override;
    std::string restore(const std::string& snapshot_path) override;
    RuntimeStatus status() const override;
    RuntimeType type() const override { return RuntimeType::WASM; }
    bool available() const override;
    std::string workspace_path(const std::string& instance_id) const override;
private:
    struct Instance {
        std::string id;
        std::string workspace;
        bool running = false;
    };
    mutable std::mutex mtx_;
    std::unordered_map<std::string, Instance> instances_;
    std::string wasm_runtime_;  // wasmtime / wasmer
};
// 运行时工厂
class RuntimeFactory {
public:
    static std::unique_ptr<IRuntime> create(RuntimeType type);
    static std::unique_ptr<IRuntime> create_by_workload(const WorkloadProfile& workload);
};
} // namespace sandbox
} // namespace photon_kernel
#endif
