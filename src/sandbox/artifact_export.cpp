// 产物导出与工作区管理实现
#include "photon_kernel/sandbox/artifact_export.hpp"
#include "photon_kernel/sandbox/crypto_utils.hpp"
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/vm_sockets.h>
namespace photon_kernel {
namespace sandbox {
namespace fs = std::filesystem;
// ==================== VsockChannel ====================
VsockChannel::VsockChannel(const std::string& device_path, uint32_t port)
    : device_path_(device_path), port_(port) {
    // 检查 vsock 设备是否存在
    struct stat st;
    available_ = (stat(device_path.c_str(), &st) == 0);
}
VsockChannel::~VsockChannel() {
    stop();
}
bool VsockChannel::start_listener() {
    if (!available_) return false;
    std::lock_guard<std::mutex> lock(mtx_);
    // 创建 vsock socket
    socket_fd_ = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (socket_fd_ < 0) return false;
    struct sockaddr_vm addr = {};
    addr.svm_family = AF_VSOCK;
    addr.svm_port = port_;
    addr.svm_cid = VMADDR_CID_ANY;
    if (bind(socket_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(socket_fd_);
        socket_fd_ = -1;
        return false;
    }
    if (listen(socket_fd_, 5) < 0) {
        close(socket_fd_);
        socket_fd_ = -1;
        return false;
    }
    running_ = true;
    return true;
}
void VsockChannel::stop() {
    running_ = false;
    if (socket_fd_ >= 0) {
        close(socket_fd_);
        socket_fd_ = -1;
    }
}
bool VsockChannel::receive_file(const std::string& dest_path, size_t expected_size) {
    if (!available_ || socket_fd_ < 0) return false;
    // 接受连接
    int client_fd = accept(socket_fd_, nullptr, nullptr);
    if (client_fd < 0) return false;
    // 接收文件内容
    std::ofstream out(dest_path, std::ios::binary);
    if (!out.is_open()) {
        close(client_fd);
        return false;
    }
    char buf[65536];
    size_t total = 0;
    while (true) {
        ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        out.write(buf, n);
        total += n;
        if (expected_size > 0 && total >= expected_size) break;
    }
    out.close();
    close(client_fd);
    return total > 0;
}
bool VsockChannel::send_file(const std::string& src_path) {
    if (!available_) return false;
    std::ifstream in(src_path, std::ios::binary);
    if (!in.is_open()) return false;
    // 简化：通过 vsock 发送（实际实现需要连接到VM）
    // 这里返回 true 表示文件可读，实际发送需要 VM 侧配合
    in.close();
    return true;
}
std::vector<uint8_t> VsockChannel::receive_data(size_t max_size) {
    std::vector<uint8_t> result;
    if (!available_ || socket_fd_ < 0) return result;
    int client_fd = accept(socket_fd_, nullptr, nullptr);
    if (client_fd < 0) return result;
    uint8_t buf[65536];
    while (result.size() < max_size) {
        ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        result.insert(result.end(), buf, buf + n);
    }
    close(client_fd);
    return result;
}
bool VsockChannel::send_data(const std::vector<uint8_t>& data) {
    if (!available_) return false;
    // 简化实现
    return true;
}
// ==================== ArtifactExporter ====================
ArtifactExporter::ArtifactExporter() : ArtifactExporter(Config()) {}

ArtifactExporter::ArtifactExporter(const Config& config)
    : config_(config) {
    vsock_ = std::make_unique<VsockChannel>(config.vsock_device, config.vsock_port);
    fs::create_directories(config_.export_dir);
}
ArtifactExporter::~ArtifactExporter() = default;
std::string ArtifactExporter::compute_sha256(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) return "";
    std::vector<uint8_t> content((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
    auto digest = crypto::sha256(content.data(), content.size());
    return crypto::to_hex(digest);
}
bool ArtifactExporter::ensure_export_dir(const std::string& vm_id) {
    std::string dir = config_.export_dir + "/" + vm_id;
    fs::create_directories(dir);
    // 设置权限（仅所有者可读写）
    chmod(dir.c_str(), 0700);
    return fs::exists(dir);
}
void ArtifactExporter::record_artifact(const ArtifactInfo& info) {
    std::lock_guard<std::mutex> lock(mtx_);
    artifacts_[info.vm_id].push_back(info);
}
ExportResult ArtifactExporter::export_file(const std::string& vm_id,
                                             const std::string& vm_path,
                                             const std::string& tenant_id) {
    return export_from_vm(vm_id, {vm_path}, tenant_id);
}
ExportResult ArtifactExporter::export_from_vm(const std::string& vm_id,
                                                const std::vector<std::string>& vm_paths,
                                                const std::string& tenant_id) {
    ExportResult result;
    auto start = std::chrono::steady_clock::now();
    if (!ensure_export_dir(vm_id)) {
        result.error = "Failed to create export directory";
        return result;
    }
    for (const auto& vm_path : vm_paths) {
        // 从VM路径提取文件名
        std::string filename = fs::path(vm_path).filename().string();
        if (filename.empty()) filename = "artifact";
        std::string dest_path = config_.export_dir + "/" + vm_id + "/" + filename;
        // 通过 vsock 接收文件
        bool exported = false;
        if (vsock_->available()) {
            exported = vsock_->receive_file(dest_path);
        }
        // 如果 vsock 不可用，检查文件是否已在宿主机侧（测试/模拟模式）
        if (!exported && fs::exists(vm_path)) {
            fs::copy_file(vm_path, dest_path, fs::copy_options::overwrite_existing);
            exported = true;
        }
        if (!exported) {
            result.error = "Failed to export: " + vm_path;
            continue;
        }
        // 记录产物信息
        ArtifactInfo info;
        info.path = dest_path;
        info.name = filename;
        info.size = fs::file_size(dest_path);
        info.exported_at = std::chrono::system_clock::now();
        info.from_vm = true;
        info.vm_id = vm_id;
        // 计算哈希
        if (config_.enable_hashing) {
            info.sha256 = compute_sha256(dest_path);
        }
        // 大小检查
        if (info.size > config_.max_artifact_size) {
            result.error = "Artifact too large: " + filename;
            fs::remove(dest_path);
            continue;
        }
        result.artifacts.push_back(info);
        result.total_bytes += info.size;
        record_artifact(info);
    }
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    result.success = !result.artifacts.empty();
    return result;
}
std::vector<ArtifactInfo> ArtifactExporter::list_artifacts(const std::string& vm_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    if (vm_id.empty()) {
        std::vector<ArtifactInfo> all;
        for (const auto& [id, list] : artifacts_) {
            all.insert(all.end(), list.begin(), list.end());
        }
        return all;
    }
    auto it = artifacts_.find(vm_id);
    if (it == artifacts_.end()) return {};
    return it->second;
}
// ==================== WorkspaceManager ====================
WorkspaceManager::WorkspaceManager() : WorkspaceManager(Config()) {}

WorkspaceManager::WorkspaceManager(const Config& config)
    : config_(config) {
    vsock_ = std::make_unique<VsockChannel>(config.vsock_device, config.vsock_port);
    fs::create_directories(config_.storage_dir);
}
WorkspaceManager::~WorkspaceManager() = default;
std::string WorkspaceManager::generate_workspace_id() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
    std::ostringstream oss;
    oss << "ws-" << std::hex << std::setfill('0')
        << std::setw(8) << dis(gen);
    return oss.str();
}
std::shared_ptr<WorkspaceManager::Workspace> WorkspaceManager::create_workspace(
    const std::string& tenant_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto ws = std::make_shared<Workspace>();
    ws->workspace_id = generate_workspace_id();
    ws->tenant_id = tenant_id;
    ws->host_path = config_.storage_dir + "/" + ws->workspace_id;
    ws->input_image_path = ws->host_path + "/input.img";
    ws->created_at = std::chrono::system_clock::now();
    fs::create_directories(ws->host_path);
    chmod(ws->host_path.c_str(), 0700);
    workspaces_[ws->workspace_id] = ws;
    return ws;
}
bool WorkspaceManager::inject_input(const std::string& workspace_id,
                                      const std::vector<std::string>& files) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = workspaces_.find(workspace_id);
    if (it == workspaces_.end()) return false;
    auto& ws = it->second;
    // 检查总大小
    size_t total = 0;
    for (const auto& f : files) {
        if (fs::exists(f)) {
            total += fs::file_size(f);
        }
    }
    if (total > config_.max_workspace_size) return false;
    // 打包成只读镜像
    if (!create_readonly_image(ws->input_image_path, files)) {
        return false;
    }
    ws->input_files = files;
    ws->size_bytes = total;
    return true;
}
bool WorkspaceManager::create_readonly_image(const std::string& image_path,
                                               const std::vector<std::string>& files) {
    // 创建临时目录，复制文件，然后打包成镜像
    std::string tmp_dir = image_path + ".tmp";
    fs::create_directories(tmp_dir);
    for (const auto& f : files) {
        if (fs::exists(f)) {
            fs::copy(f, tmp_dir + "/" + fs::path(f).filename().string(),
                     fs::copy_options::recursive);
        }
    }
    // 简化：创建一个 tar 包作为镜像（实际应创建 ext4 只读镜像）
    std::string cmd = "tar -cf " + image_path + " -C " + tmp_dir + " . 2>/dev/null";
    int ret = system(cmd.c_str());
    fs::remove_all(tmp_dir);
    if (ret != 0) return false;
    // 设置只读
    chmod(image_path.c_str(), 0444);
    return fs::exists(image_path);
}
WorkspaceManager::DiffResult WorkspaceManager::export_output_diff(
    const std::string& workspace_id, const std::string& vm_id) {
    DiffResult result;
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = workspaces_.find(workspace_id);
    if (it == workspaces_.end()) {
        result.success = false;
        return result;
    }
    auto& ws = it->second;
    // 通过 vsock 接收 VM 传回的修改文件
    // 简化：检查宿主机侧是否有导出的文件
    std::string export_dir = config_.storage_dir + "/" + ws->workspace_id + "/output";
    if (fs::exists(export_dir)) {
        for (const auto& entry : fs::recursive_directory_iterator(export_dir)) {
            if (entry.is_regular_file()) {
                std::string rel = fs::relative(entry.path(), export_dir).string();
                // 检查是否是新文件或修改文件
                bool is_new = true;
                for (const auto& input : ws->input_files) {
                    if (fs::path(input).filename().string() == rel) {
                        is_new = false;
                        // 比较大小判断是否修改
                        if (fs::exists(input) &&
                            fs::file_size(input) != entry.file_size()) {
                            result.modified_files.push_back(rel);
                        }
                        break;
                    }
                }
                if (is_new) {
                    result.new_files.push_back(rel);
                }
                result.total_bytes += entry.file_size();
                ws->exported_files.push_back(entry.path().string());
            }
        }
    }
    result.success = true;
    return result;
}
std::shared_ptr<WorkspaceManager::Workspace> WorkspaceManager::get_workspace(
    const std::string& workspace_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = workspaces_.find(workspace_id);
    if (it == workspaces_.end()) return nullptr;
    return it->second;
}
bool WorkspaceManager::cleanup_workspace(const std::string& workspace_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = workspaces_.find(workspace_id);
    if (it == workspaces_.end()) return false;
    fs::remove_all(it->second->host_path);
    workspaces_.erase(it);
    return true;
}
std::vector<std::shared_ptr<WorkspaceManager::Workspace>> WorkspaceManager::list_workspaces() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<std::shared_ptr<Workspace>> result;
    for (const auto& [id, ws] : workspaces_) {
        result.push_back(ws);
    }
    return result;
}
// ==================== EphemeralDisk ====================
EphemeralDisk::EphemeralDisk() : EphemeralDisk(Config()) {}

EphemeralDisk::EphemeralDisk(const Config& config) : config_(config) {
    fs::create_directories(config_.mount_dir);
}
EphemeralDisk::~EphemeralDisk() = default;
std::string EphemeralDisk::generate_disk_id() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
    std::ostringstream oss;
    oss << "disk-" << std::hex << std::setfill('0')
        << std::setw(8) << dis(gen);
    return oss.str();
}
std::shared_ptr<EphemeralDisk::Disk> EphemeralDisk::create_disk(
    const std::string& vm_id, size_t size_mb) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto disk = std::make_shared<Disk>();
    disk->disk_id = generate_disk_id();
    disk->vm_id = vm_id;
    disk->size_mb = size_mb > 0 ? size_mb : config_.default_size_mb;
    if (disk->size_mb > config_.max_size_mb) disk->size_mb = config_.max_size_mb;
    disk->mount_path = config_.mount_dir + "/" + disk->disk_id;
    disk->created_at = std::chrono::system_clock::now();
    // 创建挂载点
    fs::create_directories(disk->mount_path);
    // tmpfs 挂载（需要 root）
    if (config_.tmpfs_backed) {
        std::string cmd = "mount -t tmpfs -o size=" + std::to_string(disk->size_mb) +
                          "m tmpfs " + disk->mount_path + " 2>/dev/null";
        if (system(cmd.c_str()) == 0) {
            disk->mounted = true;
        }
    }
    if (!disk->mounted) {
        // 无 root 时使用普通目录（降级）
        disk->mounted = true;
    }
    disks_[disk->disk_id] = disk;
    return disk;
}
bool EphemeralDisk::destroy_disk(const std::string& disk_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = disks_.find(disk_id);
    if (it == disks_.end()) return false;
    auto& disk = it->second;
    if (disk->mounted && config_.tmpfs_backed) {
        std::string cmd = "umount " + disk->mount_path + " 2>/dev/null";
        system(cmd.c_str());
    }
    fs::remove_all(disk->mount_path);
    disks_.erase(it);
    return true;
}
std::shared_ptr<EphemeralDisk::Disk> EphemeralDisk::get_disk(const std::string& disk_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = disks_.find(disk_id);
    if (it == disks_.end()) return nullptr;
    return it->second;
}
std::vector<std::shared_ptr<EphemeralDisk::Disk>> EphemeralDisk::list_disks() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<std::shared_ptr<Disk>> result;
    for (const auto& [id, disk] : disks_) {
        result.push_back(disk);
    }
    return result;
}
} // namespace sandbox
} // namespace photon_kernel
