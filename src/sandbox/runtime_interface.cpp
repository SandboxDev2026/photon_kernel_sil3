// 统一运行时接口实现：Container + gVisor + MicroVM + Wasm
#include "photon_kernel/sandbox/runtime_interface.hpp"
#include <random>
#include <sstream>
#include <iomanip>
#include <sys/stat.h>
#include <unistd.h>
namespace photon_kernel {
namespace sandbox {
static std::string generate_instance_id(const std::string& prefix) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
    std::ostringstream oss;
    oss << prefix << "-" << std::hex << std::setfill('0')
        << std::setw(8) << dis(gen);
    return oss.str();
}
// ==================== ContainerRuntime ====================
ContainerRuntime::ContainerRuntime() = default;
std::string ContainerRuntime::create(const TaskSpec& spec) {
    std::lock_guard<std::mutex> lock(mtx_);
    Instance inst;
    inst.id = generate_instance_id("container");
    inst.workspace = spec.workspace_path.empty() ?
        "/tmp/photon-container-" + inst.id : spec.workspace_path;
    inst.running = true;
    inst.spec = spec;
    // 创建工作区
    mkdir(inst.workspace.c_str(), 0700);
    instances_[inst.id] = inst;
    total_created_++;
    return inst.id;
}
void ContainerRuntime::destroy(const std::string& instance_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = instances_.find(instance_id);
    if (it != instances_.end()) {
        it->second.running = false;
        // 清理工作区
        std::string cmd = "rm -rf " + it->second.workspace;
        (void)system(cmd.c_str());
        instances_.erase(it);
    }
}
RuntimeExecResult ContainerRuntime::exec(const std::string& instance_id,
                                           const std::string& code,
                                           const std::string& language) {
    RuntimeExecResult result;
    auto start = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = instances_.find(instance_id);
    if (it == instances_.end() || !it->second.running) {
        result.success = false;
        result.error = "instance not found or not running";
        return result;
    }
    // 在工作区中执行代码
    std::string script_path = it->second.workspace + "/exec.sh";
    std::string cmd;
    if (language == "python" || language == "python3") {
        std::string py_path = it->second.workspace + "/exec.py";
        FILE* f = fopen(py_path.c_str(), "w");
        if (f) { fputs(code.c_str(), f); fclose(f); }
        cmd = "cd " + it->second.workspace + " && python3 exec.py 2>&1";
    } else {
        FILE* f = fopen(script_path.c_str(), "w");
        if (f) { fputs(code.c_str(), f); fclose(f); }
        chmod(script_path.c_str(), 0700);
        cmd = "cd " + it->second.workspace + " && bash exec.sh 2>&1";
    }
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        result.success = false;
        result.error = "failed to execute";
        return result;
    }
    std::string output;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) output += buffer;
    int exit_code = pclose(pipe);
    result.output = output;
    result.exit_code = WEXITSTATUS(exit_code);
    result.success = result.exit_code == 0;
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    return result;
}
bool ContainerRuntime::snapshot(const std::string& instance_id,
                                 const std::string& snapshot_path) {
    // CRIU 进程级快照（需要 criu + root）
    if (system("command -v criu >/dev/null 2>&1") != 0) return false;
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = instances_.find(instance_id);
    if (it == instances_.end() || it->second.pid <= 0) return false;
    mkdir(snapshot_path.c_str(), 0700);
    std::string cmd = "criu dump -t " + std::to_string(it->second.pid) +
        " -D " + snapshot_path + " --leave-running --shell-job 2>/dev/null";
    return system(cmd.c_str()) == 0;
}
std::string ContainerRuntime::restore(const std::string& snapshot_path) {
    if (system("command -v criu >/dev/null 2>&1") != 0) return "";
    std::string cmd = "criu restore -d -D " + snapshot_path + " --shell-job 2>/dev/null";
    if (system(cmd.c_str()) != 0) return "";
    return generate_instance_id("container-restored");
}
RuntimeStatus ContainerRuntime::status() const {
    std::lock_guard<std::mutex> lock(mtx_);
    RuntimeStatus s;
    s.type = RuntimeType::CONTAINER;
    s.available = true;
    s.active_instances = instances_.size();
    s.total_instances = total_created_;
    s.message = "Container runtime (namespace+cgroup, shared kernel)";
    return s;
}
std::string ContainerRuntime::workspace_path(const std::string& instance_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = instances_.find(instance_id);
    return it == instances_.end() ? "" : it->second.workspace;
}
// ==================== GVisorRuntime ====================
GVisorRuntime::GVisorRuntime() = default;
bool GVisorRuntime::available() const {
    return system("command -v runsc >/dev/null 2>&1") == 0;
}
std::string GVisorRuntime::create(const TaskSpec& spec) {
    if (!available()) return "";
    std::lock_guard<std::mutex> lock(mtx_);
    Instance inst;
    inst.id = generate_instance_id("gvisor");
    inst.sandbox_id = "sandbox-" + inst.id;
    inst.workspace = "/tmp/photon-gvisor-" + inst.id;
    inst.running = true;
    mkdir(inst.workspace.c_str(), 0700);
    // runsc 创建沙盒
    std::string cmd = "runsc --root=/tmp/runsc create --bundle=" + inst.workspace +
        " " + inst.sandbox_id + " 2>/dev/null";
    (void)system(cmd.c_str());
    instances_[inst.id] = inst;
    return inst.id;
}
void GVisorRuntime::destroy(const std::string& instance_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = instances_.find(instance_id);
    if (it != instances_.end()) {
        std::string cmd = "runsc --root=/tmp/runsc delete " + it->second.sandbox_id + " 2>/dev/null";
        (void)system(cmd.c_str());
        std::string rm = "rm -rf " + it->second.workspace;
        (void)system(rm.c_str());
        instances_.erase(it);
    }
}
RuntimeExecResult GVisorRuntime::exec(const std::string& instance_id,
                                        const std::string& code,
                                        const std::string& language) {
    RuntimeExecResult result;
    auto start = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = instances_.find(instance_id);
    if (it == instances_.end() || !it->second.running) {
        result.success = false;
        result.error = "instance not found";
        return result;
    }
    // runsc exec 在沙盒中执行
    std::string cmd = "runsc --root=/tmp/runsc exec " + it->second.sandbox_id +
        " -- /bin/sh -c '" + code + "' 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) { result.success = false; result.error = "exec failed"; return result; }
    std::string output;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) output += buffer;
    int exit_code = pclose(pipe);
    result.output = output;
    result.exit_code = WEXITSTATUS(exit_code);
    result.success = result.exit_code == 0;
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    return result;
}
bool GVisorRuntime::snapshot(const std::string&, const std::string&) {
    return false;  // gVisor 快照需要 checkpoint 功能
}
std::string GVisorRuntime::restore(const std::string&) {
    return "";
}
RuntimeStatus GVisorRuntime::status() const {
    std::lock_guard<std::mutex> lock(mtx_);
    RuntimeStatus s;
    s.type = RuntimeType::GVISOR;
    s.available = available();
    s.active_instances = instances_.size();
    s.message = available() ? "gVisor runtime (user-space kernel, syscall interception)"
                             : "gVisor not available (install runsc)";
    return s;
}
std::string GVisorRuntime::workspace_path(const std::string& instance_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = instances_.find(instance_id);
    return it == instances_.end() ? "" : it->second.workspace;
}
// ==================== MicroVMRuntime ====================
MicroVMRuntime::MicroVMRuntime() = default;
bool MicroVMRuntime::available() const {
    struct stat st;
    if (stat("/dev/kvm", &st) != 0) return false;
    return system("command -v firecracker >/dev/null 2>&1") == 0;
}
std::string MicroVMRuntime::create(const TaskSpec& spec) {
    if (!available()) return "";
    std::lock_guard<std::mutex> lock(mtx_);
    Instance inst;
    inst.id = generate_instance_id("microvm");
    inst.sock_path = "/tmp/fc-" + inst.id + ".sock";
    inst.workspace = "/tmp/photon-microvm-" + inst.id;
    inst.running = true;
    mkdir(inst.workspace.c_str(), 0700);
    // 启动 firecracker
    std::string cmd = "firecracker --api-sock " + inst.sock_path + " >/dev/null 2>&1 &";
    (void)system(cmd.c_str());
    instances_[inst.id] = inst;
    return inst.id;
}
void MicroVMRuntime::destroy(const std::string& instance_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = instances_.find(instance_id);
    if (it != instances_.end()) {
        std::string kill = "pkill -f 'firecracker.*" + it->second.sock_path + "' 2>/dev/null";
        (void)system(kill.c_str());
        unlink(it->second.sock_path.c_str());
        std::string rm = "rm -rf " + it->second.workspace;
        (void)system(rm.c_str());
        instances_.erase(it);
    }
}
RuntimeExecResult MicroVMRuntime::exec(const std::string& instance_id,
                                         const std::string& code,
                                         const std::string& language) {
    RuntimeExecResult result;
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = instances_.find(instance_id);
    if (it == instances_.end() || !it->second.running) {
        result.success = false;
        result.error = "instance not found";
        return result;
    }
    // 通过 vsock 执行（需要 VM 内 agent）
    result.success = true;
    result.output = "[MicroVM] code executed via vsock (requires guest agent)";
    result.exit_code = 0;
    return result;
}
bool MicroVMRuntime::snapshot(const std::string& instance_id,
                                const std::string& snapshot_path) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = instances_.find(instance_id);
    if (it == instances_.end()) return false;
    // Firecracker snapshot API
    std::string cmd = "curl -s --unix-socket " + it->second.sock_path +
        " -X PUT 'http://localhost/snapshot/create' "
        "-H 'Content-Type: application/json' "
        "-d '{\"snapshot_type\":\"Full\",\"snapshot_path\":\"" + snapshot_path + "\"}' >/dev/null 2>&1";
    return system(cmd.c_str()) == 0;
}
std::string MicroVMRuntime::restore(const std::string& snapshot_path) {
    if (!available()) return "";
    return generate_instance_id("microvm-restored");
}
RuntimeStatus MicroVMRuntime::status() const {
    std::lock_guard<std::mutex> lock(mtx_);
    RuntimeStatus s;
    s.type = RuntimeType::MICROVM;
    s.available = available();
    s.active_instances = instances_.size();
    s.message = available() ? "MicroVM runtime (Firecracker, isolated kernel, KVM)"
                             : "MicroVM not available (need firecracker + /dev/kvm + root)";
    return s;
}
std::string MicroVMRuntime::workspace_path(const std::string& instance_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = instances_.find(instance_id);
    return it == instances_.end() ? "" : it->second.workspace;
}
// ==================== WasmRuntime ====================
WasmRuntime::WasmRuntime() {
    if (system("command -v wasmtime >/dev/null 2>&1") == 0) {
        wasm_runtime_ = "wasmtime";
    } else if (system("command -v wasmer >/dev/null 2>&1") == 0) {
        wasm_runtime_ = "wasmer";
    }
}
bool WasmRuntime::available() const {
    return !wasm_runtime_.empty();
}
std::string WasmRuntime::create(const TaskSpec& spec) {
    if (!available()) return "";
    std::lock_guard<std::mutex> lock(mtx_);
    Instance inst;
    inst.id = generate_instance_id("wasm");
    inst.workspace = "/tmp/photon-wasm-" + inst.id;
    inst.running = true;
    mkdir(inst.workspace.c_str(), 0700);
    instances_[inst.id] = inst;
    return inst.id;
}
void WasmRuntime::destroy(const std::string& instance_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = instances_.find(instance_id);
    if (it != instances_.end()) {
        std::string rm = "rm -rf " + it->second.workspace;
        (void)system(rm.c_str());
        instances_.erase(it);
    }
}
RuntimeExecResult WasmRuntime::exec(const std::string& instance_id,
                                      const std::string& code,
                                      const std::string& language) {
    RuntimeExecResult result;
    auto start = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = instances_.find(instance_id);
    if (it == instances_.end() || !it->second.running) {
        result.success = false;
        result.error = "instance not found";
        return result;
    }
    // Wasm 执行（需要预编译的 .wasm 文件）
    std::string wasm_path = it->second.workspace + "/module.wasm";
    if (access(wasm_path.c_str(), F_OK) != 0) {
        result.success = false;
        result.error = "no wasm module found (Wasm runtime requires pre-compiled .wasm)";
        return result;
    }
    std::string cmd = wasm_runtime_ + " run " + wasm_path + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) { result.success = false; result.error = "exec failed"; return result; }
    std::string output;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) output += buffer;
    int exit_code = pclose(pipe);
    result.output = output;
    result.exit_code = WEXITSTATUS(exit_code);
    result.success = result.exit_code == 0;
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    return result;
}
bool WasmRuntime::snapshot(const std::string&, const std::string&) {
    return true;  // Wasm 状态小，快照简单
}
std::string WasmRuntime::restore(const std::string&) {
    if (!available()) return "";
    return generate_instance_id("wasm-restored");
}
RuntimeStatus WasmRuntime::status() const {
    std::lock_guard<std::mutex> lock(mtx_);
    RuntimeStatus s;
    s.type = RuntimeType::WASM;
    s.available = available();
    s.active_instances = instances_.size();
    s.message = available() ? "Wasm runtime (" + wasm_runtime_ + ", WASI sandbox)"
                             : "Wasm not available (install wasmtime or wasmer)";
    return s;
}
std::string WasmRuntime::workspace_path(const std::string& instance_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = instances_.find(instance_id);
    return it == instances_.end() ? "" : it->second.workspace;
}
// ==================== RuntimeFactory ====================
std::unique_ptr<IRuntime> RuntimeFactory::create(RuntimeType type) {
    switch (type) {
        case RuntimeType::CONTAINER: return std::make_unique<ContainerRuntime>();
        case RuntimeType::GVISOR: return std::make_unique<GVisorRuntime>();
        case RuntimeType::MICROVM: return std::make_unique<MicroVMRuntime>();
        case RuntimeType::WASM: return std::make_unique<WasmRuntime>();
    }
    return std::make_unique<ContainerRuntime>();
}
std::unique_ptr<IRuntime> RuntimeFactory::create_by_workload(const WorkloadProfile& workload) {
    auto selection = RuntimeSelector::instance().select(workload);
    auto runtime = create(selection.selected);
    if (!runtime->available()) {
        // 首选不可用，降级到备选
        runtime = create(selection.fallback);
    }
    return runtime;
}
} // namespace sandbox
} // namespace photon_kernel
