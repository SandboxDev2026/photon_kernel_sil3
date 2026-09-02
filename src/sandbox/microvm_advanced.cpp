// MicroVM 高级特性实现（借鉴 AgentENV / Kimi K3）
#include "photon_kernel/sandbox/microvm_advanced.hpp"
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
namespace photon_kernel {
namespace sandbox {
namespace fs = std::filesystem;
// ==================== MemoryBalloon ====================
MemoryBalloon::MemoryBalloon(const BalloonConfig& config)
    : config_(config) {
    // 检查 virtio-balloon 支持（需要 Firecracker + balloon 设备）
    // 简化：假设可用，实际通过 Firecracker API 检测
    available_ = config_.enabled;
}
MemoryBalloon::~MemoryBalloon() = default;
void MemoryBalloon::register_vm(const std::string& vm_id, size_t initial_memory_mb) {
    std::lock_guard<std::mutex> lock(mtx_);
    VmBalloonInfo info;
    info.current_memory_mb = initial_memory_mb;
    info.original_memory_mb = initial_memory_mb;
    info.state = BalloonState::INFLATED;
    vms_[vm_id] = info;
}
void MemoryBalloon::unregister_vm(const std::string& vm_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = vms_.find(vm_id);
    if (it != vms_.end()) {
        // 如果是放气状态，回收的内存要归还统计
        if (it->second.state == BalloonState::DEFLATED) {
            size_t reclaimed = it->second.original_memory_mb - it->second.current_memory_mb;
            if (total_reclaimed_ >= reclaimed) {
                total_reclaimed_ -= reclaimed;
            }
        }
        vms_.erase(it);
    }
}
size_t MemoryBalloon::deflate(const std::string& vm_id, size_t target_memory_mb) {
    if (!available_) return 0;
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = vms_.find(vm_id);
    if (it == vms_.end()) return 0;
    auto& info = it->second;
    if (info.state == BalloonState::DEFLATED) return 0;
    size_t target = target_memory_mb > 0 ? target_memory_mb : config_.base_memory_mb;
    if (target >= info.current_memory_mb) return 0;
    size_t reclaimed = info.current_memory_mb - target;
    // 实际通过 Firecracker PATCH /balloon 调整
    if (adjust_balloon_device(vm_id, target)) {
        info.state = BalloonState::DEFLATED;
        info.current_memory_mb = target;
        total_reclaimed_ += reclaimed;
        return reclaimed;
    }
    return 0;
}
size_t MemoryBalloon::inflate(const std::string& vm_id, size_t target_memory_mb) {
    if (!available_) return 0;
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = vms_.find(vm_id);
    if (it == vms_.end()) return 0;
    auto& info = it->second;
    if (info.state == BalloonState::INFLATED) return 0;
    size_t target = target_memory_mb > 0 ? target_memory_mb : info.original_memory_mb;
    if (target > config_.max_memory_mb) target = config_.max_memory_mb;
    if (target <= info.current_memory_mb) return 0;
    size_t restored = target - info.current_memory_mb;
    if (adjust_balloon_device(vm_id, target)) {
        info.state = BalloonState::INFLATED;
        info.current_memory_mb = target;
        if (total_reclaimed_ >= restored) {
            total_reclaimed_ -= restored;
        }
        return restored;
    }
    return 0;
}
bool MemoryBalloon::should_deflate(const std::string& vm_id,
                                     std::chrono::system_clock::time_point last_activity) {
    if (!config_.auto_deflate_on_idle) return false;
    auto now = std::chrono::system_clock::now();
    auto idle = std::chrono::duration_cast<std::chrono::seconds>(now - last_activity);
    return idle.count() >= config_.idle_threshold_sec;
}
BalloonState MemoryBalloon::state(const std::string& vm_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = vms_.find(vm_id);
    if (it == vms_.end()) return BalloonState::DISABLED;
    return it->second.state;
}
size_t MemoryBalloon::current_memory_mb(const std::string& vm_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = vms_.find(vm_id);
    if (it == vms_.end()) return 0;
    return it->second.current_memory_mb;
}
bool MemoryBalloon::adjust_balloon_device(const std::string& vm_id, size_t target_mb) {
    // 实际通过 Firecracker API: PATCH /balloon {"amount_mb": target}
    // 简化：模拟成功（实际需要 Firecracker balloon 设备）
    return true;
}
// ==================== VmPauser ====================
VmPauser::VmPauser(const PauseConfig& config)
    : config_(config) {
    available_ = config_.enabled;
}
VmPauser::~VmPauser() = default;
void VmPauser::register_vm(const std::string& vm_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    VmPauseInfo info;
    info.state = VmPauseState::RUNNING;
    vms_[vm_id] = info;
}
void VmPauser::unregister_vm(const std::string& vm_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = vms_.find(vm_id);
    if (it != vms_.end()) {
        if (it->second.state == VmPauseState::PAUSED) {
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now() - it->second.paused_at);
            total_pause_time_ += duration;
        }
        vms_.erase(it);
    }
}
bool VmPauser::pause(const std::string& vm_id) {
    if (!available_) return false;
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = vms_.find(vm_id);
    if (it == vms_.end()) return false;
    auto& info = it->second;
    if (info.state == VmPauseState::PAUSED) return true;
    info.state = VmPauseState::PAUSING;
    // 通过 cgroup freezer 暂停
    if (freeze_vm(vm_id)) {
        info.state = VmPauseState::PAUSED;
        info.paused_at = std::chrono::system_clock::now();
        total_paused_++;
        return true;
    }
    info.state = VmPauseState::FAILED;
    return false;
}
bool VmPauser::resume(const std::string& vm_id) {
    if (!available_) return false;
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = vms_.find(vm_id);
    if (it == vms_.end()) return false;
    auto& info = it->second;
    if (info.state == VmPauseState::RUNNING) return true;
    info.state = VmPauseState::RESUMING;
    if (unfreeze_vm(vm_id)) {
        info.state = VmPauseState::RUNNING;
        info.resumed_at = std::chrono::system_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(
            info.resumed_at - info.paused_at);
        total_pause_time_ += duration;
        total_resumed_++;
        return true;
    }
    info.state = VmPauseState::FAILED;
    return false;
}
bool VmPauser::should_pause(const std::string& vm_id,
                              std::chrono::system_clock::time_point last_activity) const {
    auto now = std::chrono::system_clock::now();
    auto idle = std::chrono::duration_cast<std::chrono::seconds>(now - last_activity);
    return idle >= config_.idle_timeout;
}
VmPauseState VmPauser::state(const std::string& vm_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = vms_.find(vm_id);
    if (it == vms_.end()) return VmPauseState::FAILED;
    return it->second.state;
}
std::chrono::seconds VmPauser::pause_duration(const std::string& vm_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = vms_.find(vm_id);
    if (it == vms_.end() || it->second.state != VmPauseState::PAUSED) {
        return std::chrono::seconds(0);
    }
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now() - it->second.paused_at);
}
size_t VmPauser::total_paused() const {
    std::lock_guard<std::mutex> lock(mtx_);
    size_t count = 0;
    for (const auto& [id, info] : vms_) {
        if (info.state == VmPauseState::PAUSED) count++;
    }
    return count;
}
size_t VmPauser::total_resumed() const {
    return total_resumed_.load();
}
bool VmPauser::freeze_vm(const std::string& vm_id) {
    // 实际通过 cgroup freezer: echo FROZEN > /sys/fs/cgroup/.../cgroup.freeze
    // 或 Firecracker PauseInstance API
    // 简化：模拟成功
    return true;
}
bool VmPauser::unfreeze_vm(const std::string& vm_id) {
    // echo THAWED > /sys/fs/cgroup/.../cgroup.freeze
    // 或 Firecracker ResumeInstance API
    return true;
}
// ==================== VmForker ====================
VmForker::VmForker(const ForkConfig& config)
    : config_(config) {
    available_ = config_.enabled;
}
VmForker::~VmForker() = default;
static std::string generate_vm_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
    std::ostringstream oss;
    oss << "fork-" << std::hex << std::setfill('0')
        << std::setw(8) << dis(gen);
    return oss.str();
}
ForkResult VmForker::fork(const std::string& source_vm_id,
                             const std::string& new_vm_id) {
    ForkResult result;
    if (!available_) {
        result.error = "fork not available";
        return result;
    }
    std::lock_guard<std::mutex> lock(mtx_);
    // 检查源 VM 分叉数限制
    auto forks_it = source_to_forks_.find(source_vm_id);
    if (forks_it != source_to_forks_.end() &&
        forks_it->second.size() >= config_.max_forks_per_vm) {
        result.error = "max forks per VM exceeded";
        return result;
    }
    std::string forked_id = new_vm_id.empty() ? generate_vm_id() : new_vm_id;
    auto start = std::chrono::steady_clock::now();
    size_t shared_memory = 0;
    if (do_fork(source_vm_id, forked_id, shared_memory)) {
        ForkInfo info;
        info.source_vm_id = source_vm_id;
        info.forked_vm_id = forked_id;
        info.forked_at = std::chrono::system_clock::now();
        info.shared_memory_mb = shared_memory;
        forks_[forked_id] = info;
        source_to_forks_[source_vm_id].push_back(forked_id);
        total_forks_++;
        result.success = true;
        result.forked_vm_id = forked_id;
        result.shared_memory_mb = shared_memory;
        result.fork_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
    } else {
        result.error = "fork operation failed";
    }
    return result;
}
std::vector<std::string> VmForker::forks_of(const std::string& source_vm_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = source_to_forks_.find(source_vm_id);
    if (it == source_to_forks_.end()) return {};
    return it->second;
}
std::string VmForker::source_of(const std::string& forked_vm_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = forks_.find(forked_vm_id);
    if (it == forks_.end()) return "";
    return it->second.source_vm_id;
}
bool VmForker::is_fork(const std::string& vm_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    return forks_.find(vm_id) != forks_.end();
}
void VmForker::unregister_fork(const std::string& forked_vm_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = forks_.find(forked_vm_id);
    if (it != forks_.end()) {
        std::string source = it->second.source_vm_id;
        forks_.erase(it);
        auto src_it = source_to_forks_.find(source);
        if (src_it != source_to_forks_.end()) {
            src_it->second.erase(
                std::remove(src_it->second.begin(), src_it->second.end(), forked_vm_id),
                src_it->second.end());
        }
    }
}
size_t VmForker::active_forks() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return forks_.size();
}
bool VmForker::do_fork(const std::string& source_vm_id,
                         const std::string& new_vm_id,
                         size_t& shared_memory_mb) {
    // 实际通过 Firecracker snapshot/restore 或 CRIU 实现：
    // 1. Pause 源 VM
    // 2. Create snapshot (memory + state)
    // 3. Restore snapshot to新 VM
    // 4. Resume 源 VM
    // 5. 新 VM 使用写时复制共享内存页
    // 简化：模拟成功，共享内存假设为源 VM 的 80%
    shared_memory_mb = 100;  // 模拟
    return true;
}
// ==================== LayeredImageManager ====================
LayeredImageManager::LayeredImageManager(const LayeredImageConfig& config)
    : config_(config) {
    available_ = config_.enabled;
    try {
        fs::create_directories(config_.storage_dir);
    } catch (const fs::filesystem_error&) {
        // 无权限创建目录时降级为不可用（优雅降级）
        available_ = false;
    }
}
LayeredImageManager::~LayeredImageManager() = default;
std::string LayeredImageManager::create_base_layer(const std::string& name,
                                                      const std::string& source_path) {
    std::lock_guard<std::mutex> lock(mtx_);
    // 去重检查
    std::string digest = compute_digest(source_path);
    if (config_.enable_deduplication) {
        auto it = digest_to_layer_.find(digest);
        if (it != digest_to_layer_.end()) {
            auto layer = layers_[it->second];
            layer->ref_count++;
            return layer->layer_id;
        }
    }
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::ostringstream oss;
    oss << "base-" << std::hex << std::setfill('0')
        << std::setw(8) << gen();
    std::string layer_id = oss.str();
    auto layer = std::make_shared<LayerInfo>();
    layer->layer_id = layer_id;
    layer->path = config_.storage_dir + "/" + layer_id;
    layer->read_only = true;
    layer->digest = digest;
    layer->ref_count = 1;
    // 复制源文件到层路径（简化）
    if (fs::exists(source_path)) {
        fs::copy(source_path, layer->path, fs::copy_options::recursive);
        layer->size_mb = fs::file_size(layer->path) / (1024 * 1024);
    }
    layers_[layer_id] = layer;
    if (config_.enable_deduplication) {
        digest_to_layer_[digest] = layer_id;
    }
    return layer_id;
}
std::string LayeredImageManager::create_delta_layer(const std::string& parent_layer_id,
                                                       const std::string& name) {
    std::lock_guard<std::mutex> lock(mtx_);
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::ostringstream oss;
    oss << "delta-" << std::hex << std::setfill('0')
        << std::setw(8) << gen();
    std::string layer_id = oss.str();
    auto layer = std::make_shared<LayerInfo>();
    layer->layer_id = layer_id;
    layer->path = config_.storage_dir + "/" + layer_id;
    layer->read_only = false;
    layer->parent_layer = parent_layer_id;
    layer->ref_count = 1;
    fs::create_directories(layer->path);
    layers_[layer_id] = layer;
    // 父层引用计数+1
    auto parent_it = layers_.find(parent_layer_id);
    if (parent_it != layers_.end()) {
        parent_it->second->ref_count++;
    }
    return layer_id;
}
std::string LayeredImageManager::mount_layers(const std::string& base_layer_id,
                                                 const std::vector<std::string>& delta_layers,
                                                 const std::string& mount_point) {
    if (!available_) return "";
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<std::string> all_layers;
    all_layers.push_back(base_layer_id);
    for (const auto& d : delta_layers) {
        all_layers.push_back(d);
    }
    if (do_mount(all_layers, mount_point)) {
        return mount_point;
    }
    return "";
}
bool LayeredImageManager::unmount_layers(const std::string& mount_point) {
    // 实际执行 umount
    std::string cmd = "umount " + mount_point + " 2>/dev/null";
    return system(cmd.c_str()) == 0;
}
std::shared_ptr<LayerInfo> LayeredImageManager::get_layer(const std::string& layer_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = layers_.find(layer_id);
    if (it == layers_.end()) return nullptr;
    return it->second;
}
std::vector<std::shared_ptr<LayerInfo>> LayeredImageManager::list_layers() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<std::shared_ptr<LayerInfo>> result;
    for (const auto& [id, layer] : layers_) {
        result.push_back(layer);
    }
    return result;
}
bool LayeredImageManager::remove_layer(const std::string& layer_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = layers_.find(layer_id);
    if (it == layers_.end()) return false;
    it->second->ref_count--;
    if (it->second->ref_count <= 0) {
        // 实际删除文件
        if (fs::exists(it->second->path)) {
            fs::remove_all(it->second->path);
        }
        if (config_.enable_deduplication) {
            digest_to_layer_.erase(it->second->digest);
        }
        layers_.erase(it);
        return true;
    }
    return false;  // 还有引用，不删除
}
size_t LayeredImageManager::total_storage_saved_mb() const {
    std::lock_guard<std::mutex> lock(mtx_);
    size_t saved = 0;
    for (const auto& [id, layer] : layers_) {
        if (layer->ref_count > 1) {
            saved += layer->size_mb * (layer->ref_count - 1);
        }
    }
    return saved;
}
size_t LayeredImageManager::total_layers() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return layers_.size();
}
size_t LayeredImageManager::total_shared_layers() const {
    std::lock_guard<std::mutex> lock(mtx_);
    size_t count = 0;
    for (const auto& [id, layer] : layers_) {
        if (layer->ref_count > 1) count++;
    }
    return count;
}
std::string LayeredImageManager::compute_digest(const std::string& path) const {
    // 简化：用路径+大小作为 digest（实际应计算内容 SHA256）
    if (!fs::exists(path)) return "empty";
    auto size = fs::file_size(path);
    std::ostringstream oss;
    oss << std::hex << size;
    return oss.str();
}
bool LayeredImageManager::do_mount(const std::vector<std::string>& layers,
                                     const std::string& mount_point) {
    // 实际通过 overlayfs 挂载：
    // mount -t overlay overlay -o lowerdir=base:delta1:delta2,upperdir=...,workdir=... mount_point
    // 或 ublk+overlaybd
    // 简化：创建挂载点目录
    fs::create_directories(mount_point);
    return true;
}
// ==================== MicroVmAdvancedFeatures ====================
MicroVmAdvancedFeatures::MicroVmAdvancedFeatures(const Config& config)
    : config_(config) {
    balloon_ = std::make_unique<MemoryBalloon>(config.balloon);
    pauser_ = std::make_unique<VmPauser>(config.pause);
    forker_ = std::make_unique<VmForker>(config.fork);
    image_manager_ = std::make_unique<LayeredImageManager>(config.layered_image);
}
MicroVmAdvancedFeatures::~MicroVmAdvancedFeatures() = default;
void MicroVmAdvancedFeatures::register_vm(const std::string& vm_id, size_t memory_mb) {
    balloon_->register_vm(vm_id, memory_mb);
    pauser_->register_vm(vm_id);
}
void MicroVmAdvancedFeatures::unregister_vm(const std::string& vm_id) {
    balloon_->unregister_vm(vm_id);
    pauser_->unregister_vm(vm_id);
    forker_->unregister_fork(vm_id);
}
void MicroVmAdvancedFeatures::notify_activity(const std::string& vm_id) {
    // VM 活动时：充气 + 恢复
    if (balloon_->state(vm_id) == BalloonState::DEFLATED) {
        balloon_->inflate(vm_id);
    }
    if (pauser_->state(vm_id) == VmPauseState::PAUSED) {
        pauser_->resume(vm_id);
    }
}
void MicroVmAdvancedFeatures::tick(const std::string& vm_id,
                                     std::chrono::system_clock::time_point last_activity) {
    // 闲置时：放气 + 暂停
    if (balloon_->should_deflate(vm_id, last_activity) &&
        balloon_->state(vm_id) == BalloonState::INFLATED) {
        balloon_->deflate(vm_id);
    }
    if (pauser_->should_pause(vm_id, last_activity) &&
        pauser_->state(vm_id) == VmPauseState::RUNNING) {
        pauser_->pause(vm_id);
    }
}
MicroVmAdvancedFeatures::CapabilityMatrix MicroVmAdvancedFeatures::capabilities() const {
    CapabilityMatrix caps;
    caps.balloon = balloon_->available();
    caps.pause = pauser_->available();
    caps.fork = forker_->available();
    caps.layered_image = image_manager_->available();
    return caps;
}
std::string MicroVmAdvancedFeatures::CapabilityMatrix::to_string() const {
    std::ostringstream oss;
    oss << "MicroVM Advanced Features:\n";
    oss << "  Memory Ballooning: " << (balloon ? "enabled" : "disabled") << "\n";
    oss << "  VM Pause/Resume: " << (pause ? "enabled" : "disabled") << "\n";
    oss << "  State Fork: " << (fork ? "enabled" : "disabled") << "\n";
    oss << "  Layered Image: " << (layered_image ? "enabled" : "disabled") << "\n";
    return oss.str();
}
} // namespace sandbox
} // namespace photon_kernel
