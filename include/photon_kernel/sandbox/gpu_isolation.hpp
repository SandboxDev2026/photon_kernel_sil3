#ifndef PHOTON_KERNEL_SANDBOX_GPU_ISOLATION_HPP
#define PHOTON_KERNEL_SANDBOX_GPU_ISOLATION_HPP
// GPU/CUDA 隔离模块
//
// 目标：限制沙盒内进程对 GPU 的访问，防止：
//   1. GPU 显存耗尽（DoS）
//   2. 未授权访问 GPU 设备
//   3. GPU 之间的信息泄露
//
// 实现方式：
//   1. CUDA_VISIBLE_DEVICES 环境变量隔离（指定沙盒可见的 GPU）
//   2. GPU 设备 cgroup 隔离（限制 /dev/nvidia* 访问）
//   3. 显存限制（通过 nvidia-cgroup 或 MPS）
//   4. GPU 利用率监控
//
// 注意：完整的 GPU 硬隔离需要 NVIDIA MPS（Multi-Process Service）或
// MIG（Multi-Instance GPU），本模块提供框架和基础隔离。
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <memory>
namespace photon_kernel {
namespace sandbox {
struct GpuDevice {
    int index = 0;
    std::string uuid;
    std::string name;
    size_t total_memory_mb = 0;
    size_t used_memory_mb = 0;
    int utilization_percent = 0;
    bool available = true;
};
struct GpuIsolationConfig {
    // 允许沙盒使用的 GPU 索引列表（空=不允许使用 GPU）
    std::vector<int> allowed_gpu_indices;
    // 每个沙盒最大显存（MB，0=不限制）
    size_t max_memory_mb = 0;
    // 最大 GPU 利用率（%，0=不限制）
    int max_utilization_percent = 0;
    // 是否启用 MPS（Multi-Process Service）
    bool enable_mps = false;
    // MPS 管道目录
    std::string mps_pipe_dir = "/tmp/nvidia-mps";
    // 是否使用 CUDA_VISIBLE_DEVICES 隔离
    bool use_cuda_visible_devices = true;
};
class GpuIsolationManager {
public:
    static GpuIsolationManager& instance();
    // 检测系统 GPU（通过 nvidia-smi）
    bool detect_gpus();
    // 获取可用 GPU 列表
    std::vector<GpuDevice> available_gpus() const;
    // 为沙盒分配 GPU（返回分配的 GPU 索引）
    std::vector<int> allocate_gpus(const std::string& sandbox_id,
                                     const GpuIsolationConfig& config);
    // 释放沙盒的 GPU
    void release_gpus(const std::string& sandbox_id);
    // 生成沙盒的环境变量（CUDA_VISIBLE_DEVICES 等）
    std::unordered_map<std::string, std::string> sandbox_env(
        const std::string& sandbox_id) const;
    // 生成 cgroup 设备限制规则（/dev/nvidia*）
    std::vector<std::string> cgroup_device_rules(
        const std::string& sandbox_id) const;
    // 检查 GPU 是否可用（nvidia-smi + /dev/nvidia*）
    bool gpu_available() const;
    // 获取统计
    size_t total_gpus() const;
    size_t allocated_gpus() const;
    // 重置（测试用）
    void reset();
private:
    GpuIsolationManager() = default;
    GpuIsolationManager(const GpuIsolationManager&) = delete;
    GpuIsolationManager& operator=(const GpuIsolationManager&) = delete;
    mutable std::mutex mtx_;
    std::vector<GpuDevice> gpus_;
    std::unordered_map<std::string, std::vector<int>> sandbox_gpus_;  // sandbox_id -> gpu indices
    std::unordered_map<std::string, GpuIsolationConfig> sandbox_configs_;
    bool detected_ = false;
    // 执行 nvidia-smi 并解析输出
    std::string run_nvidia_smi(const std::string& args) const;
};
} // namespace sandbox
} // namespace photon_kernel
#endif
