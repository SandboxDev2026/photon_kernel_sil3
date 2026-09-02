#ifndef PHOTON_KERNEL_SANDBOX_ARTIFACT_EXPORT_HPP
#define PHOTON_KERNEL_SANDBOX_ARTIFACT_EXPORT_HPP
// 产物导出与工作区管理（限制3：只读rootfs，VM销毁数据丢失）
//
// 解决方案：
//   1. 任务结束产物导出：VM内写临时盘 → vsock通道拷贝出VM → 宿主机落盘 → 哈希入证据链
//   2. 只读rootfs + 独立临时可写磁盘：每个VM独立tmpfs-backed块设备
//   3. 外部工作区存储：输入注入(只读镜像) + 输出diff导出，VM本身无状态
//   4. 快照恢复：有限制，用于任务状态恢复
//
// 安全关键点：
//   - 禁止宿主机目录RW直通VM内部（virtio-fs读写直通增大逃逸攻击面）
//   - 所有数据进出VM受控，纳入审计证据链
//   - 输入注入为只读镜像，VM只能读不能写
//   - 输出导出通过vsock通道，宿主机计算diff
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <chrono>
#include <unordered_map>
namespace photon_kernel {
namespace sandbox {
// ==================== 产物信息 ====================
struct ArtifactInfo {
    std::string path;           // 宿主机侧路径
    std::string name;           // 文件名
    size_t size = 0;            // 文件大小
    std::string sha256;         // 文件哈希
    std::chrono::system_clock::time_point exported_at;
    bool from_vm = false;       // 是否从VM导出
    std::string vm_id;          // 来源VM
};
// 导出结果
struct ExportResult {
    bool success = false;
    std::string error;
    std::vector<ArtifactInfo> artifacts;
    size_t total_bytes = 0;
    std::chrono::milliseconds duration{0};
};
// ==================== vsock 通道 ====================
// virtio-vsock 用于 VM 与宿主机之间的通信
// VM 内通过 vsock 发送文件，宿主机接收并落盘
class VsockChannel {
public:
    explicit VsockChannel(const std::string& device_path = "/dev/vhost-vsock",
                          uint32_t port = 1234);
    ~VsockChannel();
    // 启动监听（宿主机侧）
    bool start_listener();
    // 停止监听
    void stop();
    // 接收文件（从VM拷贝到宿主机）
    bool receive_file(const std::string& dest_path, size_t expected_size = 0);
    // 发送文件（从宿主机注入VM，用于输入注入）
    bool send_file(const std::string& src_path);
    // 接收数据（原始字节）
    std::vector<uint8_t> receive_data(size_t max_size = 10 * 1024 * 1024);
    // 发送数据
    bool send_data(const std::vector<uint8_t>& data);
    // 通道是否可用
    bool available() const { return available_; }
private:
    std::string device_path_;
    uint32_t port_;
    int socket_fd_ = -1;
    bool available_ = false;
    bool running_ = false;
    std::mutex mtx_;
};
// ==================== 产物导出器 ====================
class ArtifactExporter {
public:
    struct Config {
        std::string export_dir = "/var/lib/photon/artifacts";
        std::string vsock_device = "/dev/vhost-vsock";
        uint32_t vsock_port = 1234;
        bool enable_hashing = true;       // 计算文件哈希
        bool enable_evidence_chain = true; // 纳入证据链
        size_t max_artifact_size = 100 * 1024 * 1024;  // 单文件最大100MB
        size_t max_total_size = 1024 * 1024 * 1024;     // 总大小1GB
    };
    ArtifactExporter();
    explicit ArtifactExporter(const Config& config);
    ~ArtifactExporter();
    // 从VM导出产物（任务结束前调用）
    // 流程：VM内文件 → vsock通道 → 宿主机落盘 → 计算哈希 → 入证据链
    ExportResult export_from_vm(const std::string& vm_id,
                                  const std::vector<std::string>& vm_paths,
                                  const std::string& tenant_id = "");
    // 导出单个文件
    ExportResult export_file(const std::string& vm_id,
                              const std::string& vm_path,
                              const std::string& tenant_id = "");
    // 计算文件 SHA256
    static std::string compute_sha256(const std::string& file_path);
    // 获取导出的产物列表
    std::vector<ArtifactInfo> list_artifacts(const std::string& vm_id = "") const;
    // 获取导出目录
    const std::string& export_dir() const { return config_.export_dir; }
    // vsock 通道
    VsockChannel& vsock() { return *vsock_; }
private:
    Config config_;
    std::unique_ptr<VsockChannel> vsock_;
    mutable std::mutex mtx_;
    std::unordered_map<std::string, std::vector<ArtifactInfo>> artifacts_;  // vm_id -> artifacts
    // 确保导出目录存在
    bool ensure_export_dir(const std::string& vm_id);
    // 记录产物
    void record_artifact(const ArtifactInfo& info);
};
// ==================== 工作区管理器 ====================
// 外部工作区存储：输入注入 + 输出导出，VM本身无状态
//
// 安全实现：
//   1. 启动前：宿主机把需要的文件打包成临时只读镜像，作为virtio-block设备挂载进VM
//   2. 执行结束：VM把修改过的文件通过vsock通道传回宿主机，宿主机计算diff
//   3. 禁止：直接RW挂载宿主机目录到VM内
class WorkspaceManager {
public:
    struct Config {
        std::string storage_dir = "/var/lib/photon/workspaces";
        std::string vsock_device = "/dev/vhost-vsock";
        uint32_t vsock_port = 1235;
        size_t max_workspace_size = 512 * 1024 * 1024;  // 工作区最大512MB
        bool enable_diff_export = true;    // 启用diff导出
        bool read_only_input = true;        // 输入镜像只读（安全强制）
    };
    struct Workspace {
        std::string workspace_id;
        std::string tenant_id;
        std::string host_path;           // 宿主机侧路径
        std::string input_image_path;    // 输入只读镜像路径
        std::vector<std::string> input_files;  // 注入的文件列表
        std::vector<std::string> exported_files; // 导出的文件列表
        std::chrono::system_clock::time_point created_at;
        size_t size_bytes = 0;
    };
    WorkspaceManager();
    explicit WorkspaceManager(const Config& config);
    ~WorkspaceManager();
    // 创建工作区
    std::shared_ptr<Workspace> create_workspace(const std::string& tenant_id);
    // 注入输入文件（打包成只读镜像）
    // 安全：输入镜像为只读，VM只能读不能写
    bool inject_input(const std::string& workspace_id,
                       const std::vector<std::string>& files);
    // 导出输出diff（VM通过vsock传回修改的文件）
    struct DiffResult {
        bool success = false;
        std::vector<std::string> modified_files;
        std::vector<std::string> new_files;
        std::vector<std::string> deleted_files;
        size_t total_bytes = 0;
    };
    DiffResult export_output_diff(const std::string& workspace_id,
                                    const std::string& vm_id);
    // 获取工作区
    std::shared_ptr<Workspace> get_workspace(const std::string& workspace_id) const;
    // 清理工作区
    bool cleanup_workspace(const std::string& workspace_id);
    // 列出工作区
    std::vector<std::shared_ptr<Workspace>> list_workspaces() const;
private:
    Config config_;
    std::unique_ptr<VsockChannel> vsock_;
    mutable std::mutex mtx_;
    std::unordered_map<std::string, std::shared_ptr<Workspace>> workspaces_;
    // 生成工作区ID
    std::string generate_workspace_id() const;
    // 打包输入文件为只读镜像
    bool create_readonly_image(const std::string& image_path,
                                 const std::vector<std::string>& files);
};
// ==================== 临时可写磁盘 ====================
// 每个VM独立的tmpfs-backed块设备，用于任务运行期中间数据
// 生命周期和VM绑定，VM销毁设备释放
class EphemeralDisk {
public:
    struct Config {
        std::string mount_dir = "/var/lib/photon/ephemeral";
        size_t default_size_mb = 64;     // 默认64MB
        size_t max_size_mb = 512;         // 最大512MB
        bool tmpfs_backed = true;         // 使用tmpfs（内存盘）
    };
    struct Disk {
        std::string disk_id;
        std::string vm_id;
        std::string mount_path;     // 宿主机侧挂载点
        std::string device_path;    // 块设备路径（用于virtio-block挂载进VM）
        size_t size_mb = 64;
        bool mounted = false;
        std::chrono::system_clock::time_point created_at;
    };
    EphemeralDisk();
    explicit EphemeralDisk(const Config& config);
    ~EphemeralDisk();
    // 创建临时磁盘（VM启动前）
    std::shared_ptr<Disk> create_disk(const std::string& vm_id, size_t size_mb = 0);
    // 销毁临时磁盘（VM销毁后）
    bool destroy_disk(const std::string& disk_id);
    // 获取磁盘
    std::shared_ptr<Disk> get_disk(const std::string& disk_id) const;
    // 列出所有磁盘
    std::vector<std::shared_ptr<Disk>> list_disks() const;
private:
    Config config_;
    mutable std::mutex mtx_;
    std::unordered_map<std::string, std::shared_ptr<Disk>> disks_;
    std::string generate_disk_id() const;
};
} // namespace sandbox
} // namespace photon_kernel
#endif
