// GPU/CUDA 隔离实现
#include "photon_kernel/sandbox/gpu_isolation.hpp"
#include <sstream>
#include <cstdlib>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
namespace photon_kernel {
namespace sandbox {
GpuIsolationManager& GpuIsolationManager::instance() {
    static GpuIsolationManager mgr;
    return mgr;
}
std::string GpuIsolationManager::run_nvidia_smi(const std::string& args) const {
    std::string cmd = "nvidia-smi " + args + " 2>/dev/null";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    std::string result;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) result += buffer;
    pclose(pipe);
    return result;
}
bool GpuIsolationManager::detect_gpus() {
    std::lock_guard<std::mutex> lock(mtx_);
    gpus_.clear();
    detected_ = true;
    // 检查 nvidia-smi 是否可用
    if (system("command -v nvidia-smi >/dev/null 2>&1") != 0) {
        return false;
    }
    // 检查 /dev/nvidia0 是否存在
    struct stat st;
    if (stat("/dev/nvidia0", &st) != 0) {
        return false;
    }
    // 通过 nvidia-smi 查询 GPU 列表
    std::string output = run_nvidia_smi("--query-gpu=index,uuid,name,memory.total --format=csv,noheader,nounits");
    if (output.empty()) return false;
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty()) continue;
        GpuDevice dev;
        // 解析 CSV: index, uuid, name, memory.total
        std::istringstream ls(line);
        std::string field;
        int field_idx = 0;
        while (std::getline(ls, field, ',')) {
            // 去除首尾空格
            size_t start = field.find_first_not_of(" \t");
            size_t end = field.find_last_not_of(" \t");
            if (start != std::string::npos) field = field.substr(start, end - start + 1);
            switch (field_idx) {
                case 0: dev.index = std::stoi(field); break;
                case 1: dev.uuid = field; break;
                case 2: dev.name = field; break;
                case 3: dev.total_memory_mb = std::stoul(field); break;
            }
            field_idx++;
        }
        dev.available = true;
        gpus_.push_back(dev);
    }
    return !gpus_.empty();
}
std::vector<GpuDevice> GpuIsolationManager::available_gpus() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<GpuDevice> result;
    for (const auto& gpu : gpus_) {
        if (gpu.available) result.push_back(gpu);
    }
    return result;
}
std::vector<int> GpuIsolationManager::allocate_gpus(
    const std::string& sandbox_id, const GpuIsolationConfig& config) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<int> allocated;
    // 如果没有指定允许的 GPU，不分配
    if (config.allowed_gpu_indices.empty()) {
        sandbox_gpus_[sandbox_id] = {};
        sandbox_configs_[sandbox_id] = config;
        return {};
    }
    // 分配指定的 GPU
    for (int idx : config.allowed_gpu_indices) {
        bool found = false;
        for (auto& gpu : gpus_) {
            if (gpu.index == idx && gpu.available) {
                gpu.available = false;
                allocated.push_back(idx);
                found = true;
                break;
            }
        }
        if (!found) {
            // GPU 不可用，记录但不中断
        }
    }
    sandbox_gpus_[sandbox_id] = allocated;
    sandbox_configs_[sandbox_id] = config;
    return allocated;
}
void GpuIsolationManager::release_gpus(const std::string& sandbox_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = sandbox_gpus_.find(sandbox_id);
    if (it != sandbox_gpus_.end()) {
        for (int idx : it->second) {
            for (auto& gpu : gpus_) {
                if (gpu.index == idx) {
                    gpu.available = true;
                    break;
                }
            }
        }
        sandbox_gpus_.erase(it);
    }
    sandbox_configs_.erase(sandbox_id);
}
std::unordered_map<std::string, std::string> GpuIsolationManager::sandbox_env(
    const std::string& sandbox_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::unordered_map<std::string, std::string> env;
    auto it = sandbox_gpus_.find(sandbox_id);
    if (it == sandbox_gpus_.end() || it->second.empty()) {
        // 没有分配 GPU，设置 CUDA_VISIBLE_DEVICES 为空（禁止 GPU 访问）
        env["CUDA_VISIBLE_DEVICES"] = "";
        env["NVIDIA_VISIBLE_DEVICES"] = "";
        return env;
    }
    // 生成 CUDA_VISIBLE_DEVICES
    std::string cuda_devices;
    for (size_t i = 0; i < it->second.size(); ++i) {
        if (i > 0) cuda_devices += ",";
        cuda_devices += std::to_string(it->second[i]);
    }
    auto cfg_it = sandbox_configs_.find(sandbox_id);
    if (cfg_it != sandbox_configs_.end() && cfg_it->second.use_cuda_visible_devices) {
        env["CUDA_VISIBLE_DEVICES"] = cuda_devices;
        env["NVIDIA_VISIBLE_DEVICES"] = cuda_devices;
    }
    // MPS 相关环境变量
    if (cfg_it != sandbox_configs_.end() && cfg_it->second.enable_mps) {
        env["CUDA_MPS_PIPE_DIRECTORY"] = cfg_it->second.mps_pipe_dir + "/" + sandbox_id;
        env["CUDA_MPS_LOG_DIRECTORY"] = "/tmp/nvidia-mps-log/" + sandbox_id;
    }
    return env;
}
std::vector<std::string> GpuIsolationManager::cgroup_device_rules(
    const std::string& sandbox_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<std::string> rules;
    auto it = sandbox_gpus_.find(sandbox_id);
    if (it == sandbox_gpus_.end() || it->second.empty()) {
        // 禁止所有 NVIDIA 设备
        rules.push_back("c 195:* rwm");  // /dev/nvidia*
        rules.push_back("c 509:* rwm");  // /dev/nvidiactl 等
        rules.push_back("c 510:* rwm");  // /dev/nvidia-uvm
        return rules;
    }
    // 允许分配的 GPU 设备
    for (int idx : it->second) {
        rules.push_back("c 195:" + std::to_string(idx) + " rwm");  // /dev/nvidiaN
    }
    // 始终允许 nvidiactl 和 nvidia-uvm
    rules.push_back("c 195:255 rwm");  // /dev/nvidiactl
    rules.push_back("c 510:* rwm");     // /dev/nvidia-uvm
    return rules;
}
bool GpuIsolationManager::gpu_available() const {
    if (system("command -v nvidia-smi >/dev/null 2>&1") != 0) return false;
    struct stat st;
    return stat("/dev/nvidia0", &st) == 0;
}
size_t GpuIsolationManager::total_gpus() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return gpus_.size();
}
size_t GpuIsolationManager::allocated_gpus() const {
    std::lock_guard<std::mutex> lock(mtx_);
    size_t count = 0;
    for (const auto& [id, gpus] : sandbox_gpus_) {
        count += gpus.size();
    }
    return count;
}
void GpuIsolationManager::reset() {
    std::lock_guard<std::mutex> lock(mtx_);
    gpus_.clear();
    sandbox_gpus_.clear();
    sandbox_configs_.clear();
    detected_ = false;
}
} // namespace sandbox
} // namespace photon_kernel
