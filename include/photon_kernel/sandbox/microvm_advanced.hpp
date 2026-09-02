#ifndef PHOTON_KERNEL_SANDBOX_MICROVM_ADVANCED_HPP
#define PHOTON_KERNEL_SANDBOX_MICROVM_ADVANCED_HPP
// MicroVM 高级特性（借鉴 AgentENV / Kimi K3 开源沙盒）
//
// 1. Memory Ballooning（内存气球）：VM 闲置时回收内存，高密度超配
// 2. 沙箱暂停/恢复：等模型推理结果时暂停 VM，几乎不占 CPU/内存
// 3. 状态分叉：从已有沙箱精确状态分叉出新沙箱，写时复制
// 4. 分层镜像共享：overlaybd 风格分层 rootfs，基础层共享+任务层增量
//
// AgentENV 核心洞察：Agent 沙箱生命周期中 98% 时间在等模型推理结果，
// 这段时间沙箱可以暂停，几乎不占内存和 CPU。需要评分判断时，
// 可以从已有沙箱的精确状态分叉出一个新的，原来那个继续跑。
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <functional>
namespace photon_kernel {
namespace sandbox {
// 前向声明
struct VmInstance;
// ==================== Memory Ballooning（内存气球） ====================
// 借鉴 AgentENV：VM 闲置时通过 virtio-balloon 回收内存给宿主机，
// 需要时再充气。实现高密度超配，单机可跑更多 VM 实例。
struct BalloonConfig {
    bool enabled = true;
    size_t base_memory_mb = 128;        // 基础内存（运行时最小）
    size_t max_memory_mb = 1024;        // 最大内存（充气上限）
    size_t idle_threshold_sec = 30;      // 闲置超过此时间开始放气
    size_t deflate_step_mb = 32;         // 每次放气步长
    size_t inflate_step_mb = 64;         // 每次充气步长
    bool auto_deflate_on_idle = true;     // 闲置自动放气
    bool auto_inflate_on_activity = true;  // 活动自动充气
};
enum class BalloonState {
    INFLATED,      // 已充气（VM 有完整内存）
    DEFLATED,      // 已放气（VM 内存被回收）
    DEFLATING,     // 放气中
    INFLATING,     // 充气中
    DISABLED,      // 气球不可用
};
class MemoryBalloon {
public:
    explicit MemoryBalloon(const BalloonConfig& config = {});
    ~MemoryBalloon();
    // 放气：回收 VM 内存给宿主机（VM 闲置时调用）
    // 返回实际回收的内存量（MB）
    size_t deflate(const std::string& vm_id, size_t target_memory_mb = 0);
    // 充气：恢复 VM 内存（VM 活动时调用）
    // 返回实际恢复的内存量（MB）
    size_t inflate(const std::string& vm_id, size_t target_memory_mb = 0);
    // 检查 VM 是否应该放气（闲置超时）
    bool should_deflate(const std::string& vm_id,
                         std::chrono::system_clock::time_point last_activity);
    // 获取 VM 当前气球状态
    BalloonState state(const std::string& vm_id) const;
    // 获取 VM 当前内存（MB）
    size_t current_memory_mb(const std::string& vm_id) const;
    // 获取总回收内存（MB）
    size_t total_reclaimed_mb() const { return total_reclaimed_.load(); }
    // 注册 VM
    void register_vm(const std::string& vm_id, size_t initial_memory_mb);
    // 注销 VM
    void unregister_vm(const std::string& vm_id);
    // 气球是否可用（需要 virtio-balloon 支持）
    bool available() const { return available_; }
    // 配置
    const BalloonConfig& config() const { return config_; }
private:
    BalloonConfig config_;
    bool available_ = false;
    mutable std::mutex mtx_;
    struct VmBalloonInfo {
        BalloonState state = BalloonState::INFLATED;
        size_t current_memory_mb = 128;
        size_t original_memory_mb = 128;
    };
    std::unordered_map<std::string, VmBalloonInfo> vms_;
    std::atomic<size_t> total_reclaimed_{0};
    // 实际通过 Firecracker API 调整 balloon（需要 virtio-balloon 设备）
    bool adjust_balloon_device(const std::string& vm_id, size_t target_mb);
};
// ==================== 沙箱暂停/恢复 ====================
// 借鉴 AgentENV：等模型推理结果时暂停 VM（cgroup freezer + 内存压缩），
// 几乎不占 CPU 和内存。需要时快速恢复。
struct PauseConfig {
    bool enabled = true;
    bool compress_memory_on_pause = true;   // 暂停时压缩内存（zram/swap）
    std::chrono::seconds idle_timeout{30};  // 闲置超时自动暂停
    std::chrono::milliseconds resume_timeout{5000};  // 恢复超时
    bool preserve_network_state = true;      // 暂停时保留网络状态
};
enum class VmPauseState {
    RUNNING,       // 运行中
    PAUSING,       // 暂停中
    PAUSED,        // 已暂停
    RESUMING,      // 恢复中
    FAILED,        // 暂停/恢复失败
};
class VmPauser {
public:
    explicit VmPauser(const PauseConfig& config = {});
    ~VmPauser();
    // 暂停 VM（释放 CPU，可选压缩内存）
    // 返回是否成功
    bool pause(const std::string& vm_id);
    // 恢复 VM
    bool resume(const std::string& vm_id);
    // 检查 VM 是否应该暂停（闲置超时）
    bool should_pause(const std::string& vm_id,
                       std::chrono::system_clock::time_point last_activity) const;
    // 获取暂停状态
    VmPauseState state(const std::string& vm_id) const;
    // 获取暂停持续时间
    std::chrono::seconds pause_duration(const std::string& vm_id) const;
    // 注册/注销 VM
    void register_vm(const std::string& vm_id);
    void unregister_vm(const std::string& vm_id);
    // 统计
    size_t total_paused() const;
    size_t total_resumed() const;
    std::chrono::seconds total_pause_time() const { return total_pause_time_; }
    // 是否可用
    bool available() const { return available_; }
    const PauseConfig& config() const { return config_; }
private:
    PauseConfig config_;
    bool available_ = false;
    mutable std::mutex mtx_;
    struct VmPauseInfo {
        VmPauseState state = VmPauseState::RUNNING;
        std::chrono::system_clock::time_point paused_at;
        std::chrono::system_clock::time_point resumed_at;
    };
    std::unordered_map<std::string, VmPauseInfo> vms_;
    std::atomic<size_t> total_paused_{0};
    std::atomic<size_t> total_resumed_{0};
    std::chrono::seconds total_pause_time_{0};
    // 通过 cgroup freezer 暂停/恢复（实际实现）
    bool freeze_vm(const std::string& vm_id);
    bool unfreeze_vm(const std::string& vm_id);
};
// ==================== 状态分叉（VmFork） ====================
// 借鉴 AgentENV：从已有沙箱的精确状态分叉出新沙箱，写时复制。
// 用于评分判断场景：从已有沙箱分叉一个新的来跑评分，原来的继续跑。
struct ForkConfig {
    bool enabled = true;
    bool copy_on_write = true;         // 写时复制（共享内存页，修改时才复制）
    bool share_readonly_layers = true;  // 共享只读层（rootfs 基础层）
    size_t max_forks_per_vm = 16;      // 每个 VM 最大分叉数
    std::chrono::seconds fork_ttl{300};  // 分叉 VM 的 TTL
};
struct ForkResult {
    bool success = false;
    std::string error;
    std::string forked_vm_id;          // 分叉出的新 VM ID
    size_t shared_memory_mb = 0;        // 共享内存量（MB）
    size_t copied_memory_mb = 0;         // 复制内存量（MB）
    std::chrono::milliseconds fork_time{0};  // 分叉耗时
};
class VmForker {
public:
    explicit VmForker(const ForkConfig& config = {});
    ~VmForker();
    // 从源 VM 分叉出新 VM
    ForkResult fork(const std::string& source_vm_id,
                     const std::string& new_vm_id = "");
    // 获取源 VM 的分叉列表
    std::vector<std::string> forks_of(const std::string& source_vm_id) const;
    // 获取分叉的源 VM
    std::string source_of(const std::string& forked_vm_id) const;
    // 检查 VM 是否是分叉出来的
    bool is_fork(const std::string& vm_id) const;
    // 注销分叉 VM
    void unregister_fork(const std::string& forked_vm_id);
    // 统计
    size_t total_forks() const { return total_forks_.load(); }
    size_t active_forks() const;
    // 是否可用（需要 CRIU 或 Firecracker snapshot 支持）
    bool available() const { return available_; }
    const ForkConfig& config() const { return config_; }
private:
    ForkConfig config_;
    bool available_ = false;
    mutable std::mutex mtx_;
    struct ForkInfo {
        std::string source_vm_id;
        std::string forked_vm_id;
        std::chrono::system_clock::time_point forked_at;
        size_t shared_memory_mb = 0;
    };
    std::unordered_map<std::string, ForkInfo> forks_;  // forked_vm_id -> info
    std::unordered_map<std::string, std::vector<std::string>> source_to_forks_;
    std::atomic<size_t> total_forks_{0};
    // 实际通过 Firecracker snapshot/restore 或 CRIU 实现分叉
    bool do_fork(const std::string& source_vm_id, const std::string& new_vm_id,
                 size_t& shared_memory_mb);
};
// ==================== 分层镜像共享（LayeredImage） ====================
// 借鉴 AgentENV / overlaybd：分层 rootfs，基础层共享，任务层增量。
// 减少存储占用和启动时间，基础层只存一份，所有 VM 共享。
struct LayerInfo {
    std::string layer_id;
    std::string path;           // 层文件路径
    size_t size_mb = 0;         // 层大小
    bool read_only = true;       // 是否只读
    std::string parent_layer;    // 父层（空=基础层）
    std::string digest;          // 内容哈希
    int ref_count = 0;           // 引用计数
};
struct LayeredImageConfig {
    bool enabled = true;
    std::string storage_dir = "/var/lib/photon/layered-images";
    size_t max_layers = 128;     // 最大层数
    bool enable_deduplication = true;  // 去重（相同内容只存一份）
    bool enable_p2p = false;     // P2P 镜像分发（集群环境）
};
class LayeredImageManager {
public:
    explicit LayeredImageManager(const LayeredImageConfig& config = {});
    ~LayeredImageManager();
    // 创建基础层（只读，所有 VM 共享）
    std::string create_base_layer(const std::string& name,
                                    const std::string& source_path);
    // 创建增量层（基于父层，可写）
    std::string create_delta_layer(const std::string& parent_layer_id,
                                     const std::string& name);
    // 组装分层镜像（基础层 + 增量层），返回挂载点
    std::string mount_layers(const std::string& base_layer_id,
                              const std::vector<std::string>& delta_layers,
                              const std::string& mount_point);
    // 卸载分层镜像
    bool unmount_layers(const std::string& mount_point);
    // 获取层信息
    std::shared_ptr<LayerInfo> get_layer(const std::string& layer_id) const;
    // 列出所有层
    std::vector<std::shared_ptr<LayerInfo>> list_layers() const;
    // 删除层（引用计数减1，为0时实际删除）
    bool remove_layer(const std::string& layer_id);
    // 计算总存储节省（共享层节省的空间）
    size_t total_storage_saved_mb() const;
    // 统计
    size_t total_layers() const;
    size_t total_shared_layers() const;
    // 是否可用
    bool available() const { return available_; }
    const LayeredImageConfig& config() const { return config_; }
private:
    LayeredImageConfig config_;
    bool available_ = false;
    mutable std::mutex mtx_;
    std::unordered_map<std::string, std::shared_ptr<LayerInfo>> layers_;
    std::unordered_map<std::string, std::string> digest_to_layer_;  // 去重用
    // 计算层内容哈希（用于去重）
    std::string compute_digest(const std::string& path) const;
    // 实际通过 overlayfs 或 ublk+overlaybd 挂载
    bool do_mount(const std::vector<std::string>& layers,
                   const std::string& mount_point);
};
// ==================== MicroVM 高级特性统一管理器 ====================
class MicroVmAdvancedFeatures {
public:
    struct Config {
        BalloonConfig balloon;
        PauseConfig pause;
        ForkConfig fork;
        LayeredImageConfig layered_image;
    };
    explicit MicroVmAdvancedFeatures(const Config& config = {});
    ~MicroVmAdvancedFeatures();
    // 注册 VM 到所有子系统
    void register_vm(const std::string& vm_id, size_t memory_mb);
    // 注销 VM
    void unregister_vm(const std::string& vm_id);
    // VM 活动通知（重置闲置计时器）
    void notify_activity(const std::string& vm_id);
    // 自动管理（定期调用：闲置放气/暂停，活动充气/恢复）
    void tick(const std::string& vm_id,
              std::chrono::system_clock::time_point last_activity);
    // 子系统访问
    MemoryBalloon& balloon() { return *balloon_; }
    VmPauser& pauser() { return *pauser_; }
    VmForker& forker() { return *forker_; }
    LayeredImageManager& image_manager() { return *image_manager_; }
    // 能力矩阵
    struct CapabilityMatrix {
        bool balloon = false;
        bool pause = false;
        bool fork = false;
        bool layered_image = false;
        std::string to_string() const;
    };
    CapabilityMatrix capabilities() const;
private:
    Config config_;
    std::unique_ptr<MemoryBalloon> balloon_;
    std::unique_ptr<VmPauser> pauser_;
    std::unique_ptr<VmForker> forker_;
    std::unique_ptr<LayeredImageManager> image_manager_;
};
} // namespace sandbox
} // namespace photon_kernel
#endif
