// 沙盒后端实现：Process（fork+seccomp）和 MicroVM（Firecracker）。
#include "photon_kernel/sandbox/sandbox_backend.hpp"
#include "photon_kernel/sandbox/sandboxed_executor.hpp"
#include "photon_kernel/sandbox/prewarmed_worker.hpp"
#include "photon_kernel/sandbox/sandbox_pool_v2.hpp"
#include <sys/stat.h>
#include <unistd.h>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <mutex>
#include <map>
namespace photon_kernel {
namespace sandbox {
// ==================== Process 后端 ====================
class ProcessBackend : public ISandboxBackend {
public:
    ProcessBackend() {
        PoolV2Config pcfg;
        pcfg.min_size = 8;
        pcfg.risk_level = RiskLevel::MEDIUM;
        pool_ = std::make_shared<SandboxPoolV2>(pcfg);
        pool_->initialize();
    }
    CodeRunResult execute(const CodeRunRequest& req) override {
        return pool_->execute(req);
    }
    std::string create(const SandboxConfig& cfg) override {
        std::lock_guard<std::mutex> lock(mtx_);
        static uint64_t counter = 0;
        std::string handle = "proc-" + std::to_string(++counter);
        auto worker = std::make_unique<PrewarmedWorker>(cfg);
        workers_[handle] = std::move(worker);
        return handle;
    }
    CodeRunResult run(const std::string& handle, const CodeRunRequest& req) override {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = workers_.find(handle);
        if (it == workers_.end()) {
            CodeRunResult r;
            r.success = false;
            r.error = "sandbox not found: " + handle;
            return r;
        }
        return it->second->run(req);
    }
    void destroy(const std::string& handle) override {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = workers_.find(handle);
        if (it != workers_.end()) {
            it->second->shutdown();
            workers_.erase(it);
        }
    }
    BackendStatus status() const override {
        BackendStatus s;
        s.type = SandboxBackend::PROCESS;
        s.available = true;
        s.active_instances = workers_.size();
        s.message = "process backend (fork+seccomp, shared kernel)";
        return s;
    }
    SandboxBackend type() const override { return SandboxBackend::PROCESS; }
private:
    std::shared_ptr<SandboxPoolV2> pool_;
    std::mutex mtx_;
    std::map<std::string, std::unique_ptr<PrewarmedWorker>> workers_;
};
// ==================== MicroVM 后端（Firecracker）====================
class MicroVMBackend : public ISandboxBackend {
public:
    MicroVMBackend() : available_(false) {
        available_ = check_available();
    }
    CodeRunResult execute(const CodeRunRequest& req) override {
        CodeRunResult result;
        if (!available_) {
            result.success = false;
            result.error = "MicroVM backend not available";
            return result;
        }
        std::string handle = create(SandboxConfig::for_code_runner());
        if (handle.empty()) {
            result.success = false;
            result.error = "failed to create MicroVM";
            return result;
        }
        result = run(handle, req);
        destroy(handle);
        return result;
    }
    std::string create(const SandboxConfig& cfg) override {
        if (!available_) return "";
        std::lock_guard<std::mutex> lock(mtx_);
        static uint64_t counter = 0;
        std::string handle = "microvm-" + std::to_string(++counter);
        std::string sock_path = "/tmp/fc-" + handle + ".sock";
        // 启动 firecracker（生产环境应 fork+exec，不用 system）
        std::string cmd = "firecracker --api-sock " + sock_path + " >/dev/null 2>&1 &";
        (void)system(cmd.c_str());
        // 等待 socket 就绪
        for (int i = 0; i < 50; ++i) {
            struct stat st;
            if (stat(sock_path.c_str(), &st) == 0) break;
            usleep(10000);
        }
        VmInstance vm;
        vm.sock_path = sock_path;
        vm.memory_mb = cfg.memory_limit_bytes / (1024*1024);
        vms_[handle] = vm;
        return handle;
    }
    CodeRunResult run(const std::string& handle, const CodeRunRequest& req) override {
        CodeRunResult result;
        if (!available_) {
            result.success = false;
            result.error = "MicroVM backend not available";
            return result;
        }
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = vms_.find(handle);
        if (it == vms_.end()) {
            result.success = false;
            result.error = "MicroVM not found";
            return result;
        }
        // 启动 VM（如果未启动）
        if (!it->second.started) {
            std::string start_cmd =
                "curl -s --unix-socket " + it->second.sock_path +
                " -X PUT http://localhost/actions "
                "-H 'Content-Type: application/json' "
                "-d '{\"action_type\":\"InstanceStart\"}' >/dev/null 2>&1";
            (void)system(start_cmd.c_str());
            it->second.started = true;
            usleep(100000);
        }
        // 通过 vsock/serial 执行代码（需要 VM 内 agent，此处为占位）
        result.success = true;
        result.output = "[MicroVM] executed (requires vsock agent for real output)";
        result.exit_code = 0;
        return result;
    }
    void destroy(const std::string& handle) override {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = vms_.find(handle);
        if (it != vms_.end()) {
            std::string kill_cmd = "pkill -f 'firecracker.*" + it->second.sock_path + "' 2>/dev/null";
            (void)system(kill_cmd.c_str());
            unlink(it->second.sock_path.c_str());
            vms_.erase(it);
        }
    }
    BackendStatus status() const override {
        BackendStatus s;
        s.type = SandboxBackend::MICROVM;
        s.available = available_;
        s.active_instances = vms_.size();
        s.message = available_ ? "microvm backend (Firecracker, isolated kernel)"
                                : "microvm backend not available (need firecracker+/dev/kvm+root)";
        return s;
    }
    SandboxBackend type() const override { return SandboxBackend::MICROVM; }
private:
    struct VmInstance {
        std::string sock_path;
        size_t memory_mb = 128;
        bool started = false;
    };
    bool available_;
    std::mutex mtx_;
    std::map<std::string, VmInstance> vms_;
    static bool check_available() {
        if (system("command -v firecracker >/dev/null 2>&1") != 0) return false;
        struct stat st;
        if (stat("/dev/kvm", &st) != 0) return false;
        if (geteuid() != 0) return false;
        return true;
    }
};
// ==================== 工厂 ====================
std::unique_ptr<ISandboxBackend> SandboxBackendFactory::create(SandboxBackend type) {
    switch (type) {
        case SandboxBackend::PROCESS: return std::make_unique<ProcessBackend>();
        case SandboxBackend::MICROVM: return std::make_unique<MicroVMBackend>();
    }
    return std::make_unique<ProcessBackend>();
}
SandboxBackend SandboxBackendFactory::choose_by_risk(RiskLevel level) {
    if (level == RiskLevel::HIGH && microvm_available()) {
        return SandboxBackend::MICROVM;
    }
    return SandboxBackend::PROCESS;
}
bool SandboxBackendFactory::microvm_available() {
    if (system("command -v firecracker >/dev/null 2>&1") != 0) return false;
    struct stat st;
    if (stat("/dev/kvm", &st) != 0) return false;
    return true;
}
} // namespace sandbox
} // namespace photon_kernel
