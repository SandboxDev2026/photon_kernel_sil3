#ifndef PHOTON_KERNEL_SANDBOX_STRONG_POOL_HPP
#define PHOTON_KERNEL_SANDBOX_STRONG_POOL_HPP
// StrongPool (MicroVM) 工程落地：解决三大限制
//
// 限制1：无KVM → 运行时探测 + 高风险任务拒绝(不静默降级) + 低风险自动降级LightPool
// 限制2：高并发内存开销 → 风险分级调度 + 并发上限 + TTL + 短生命周期 + 快照池
// 限制3：只读rootfs数据丢失 → 产物导出(vsock) + 工作区注入导出 + 临时可写磁盘
//
// 安全关键点：
//   - 禁止高风险任务静默降级到进程沙盒（会造成安全降级漏洞）
//   - 禁止宿主机目录RW直通VM内部（增大逃逸攻击面）
//   - 所有数据进出VM受控，纳入审计证据链
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <queue>
#include <unordered_map>
#include <functional>
namespace photon_kernel {
namespace sandbox {
// 前向声明
enum class RiskLevel;
struct CodeRunRequest;
struct CodeRunResult;
// ==================== StrongPool 配置 ====================
struct StrongPoolConfig {
    // 并发控制（限制2：内存开销）
    size_t max_concurrent_vms = 100;        // 单机最大并发VM数（一般控制在几百以内）
    size_t max_queue_size = 1000;            // 排队任务上限
    std::chrono::seconds max_ttl{300};       // 任务最大执行时间（防僵死VM泄漏内存）
    std::chrono::seconds queue_timeout{60};   // 排队超时
    // 内存控制
    size_t default_vm_memory_mb = 128;       // 默认VM内存
    size_t max_vm_memory_mb = 1024;          // 单VM最大内存
    size_t total_memory_limit_mb = 16384;     // 池总内存上限
    // 快照池（限制2：降低启动开销+内存）
    bool enable_snapshot_pool = true;
    size_t snapshot_pool_size = 10;           // 预创建快照数量
    std::string snapshot_dir = "/var/lib/photon/snapshots";
    // 产物导出（限制3：数据持久化）
    bool enable_artifact_export = true;
    std::string artifact_export_dir = "/var/lib/photon/artifacts";
    std::string vsock_device = "/dev/vhost-vsock";
    uint32_t vsock_port = 1234;
    // 工作区（限制3：输入注入输出导出）
    bool enable_workspace_injection = true;
    std::string workspace_storage_dir = "/var/lib/photon/workspaces";
    // KVM 探测（限制1）
    std::string kvm_device = "/dev/kvm";
    std::string firecracker_binary = "firecracker";
    // 降级策略（限制1：关键安全点）
    bool allow_low_risk_fallback = true;      // 低风险任务允许降级到LightPool
    bool allow_medium_risk_fallback = false;  // 中风险默认不允许降级
    // 高风险任务：KVM缺失时直接拒绝，绝不降级
    bool reject_high_risk_without_kvm = true;
};
// ==================== KVM 能力探测 ====================
struct KvmCapabilities {
    bool kvm_available = false;           // /dev/kvm 存在且可打开
    bool firecracker_available = false;   // firecracker 二进制存在
    bool cpu_virtualization = false;       // CPU支持VM-X/RV
    // 嵌套虚拟化检测（仅限调试，禁止生产安全验收）
    bool is_nested_vm = false;             // 是否运行在嵌套虚拟化环境中
    bool hypervisor_bit_detected = false;  // CPUID hypervisor 位（运行在虚拟机中）
    bool production_acceptance_valid = true; // 是否可用于生产验收（嵌套环境为false）
    std::string nested_warning;            // 嵌套环境警告信息
    std::string kvm_path;
    std::string firecracker_path;
    std::string message;
    // 能力矩阵输出
    std::string to_string() const;
};
class KvmDetector {
public:
    // 探测 KVM 能力（运行时调用）
    static KvmCapabilities detect();
    static KvmCapabilities detect(const StrongPoolConfig& config);
    // 快速检查（仅 /dev/kvm）
    static bool kvm_available(const std::string& path = "/dev/kvm");
    // 检查 CPU 虚拟化支持
    static bool cpu_supports_virtualization();
    // 检查 firecracker 二进制
    static bool firecracker_available(const std::string& binary = "firecracker");
    // 嵌套虚拟化检测（CPUID hypervisor 位 + KVM 嵌套参数）
    // 嵌套环境仅限开发调试，禁止生产安全验收
    static bool detect_nested_vm();
    // 检测 CPUID hypervisor 位（是否运行在虚拟机中）
    static bool detect_hypervisor_bit();
};
// ==================== VM 实例状态 ====================
enum class VmInstanceState {
    PENDING,       // 排队中
    STARTING,      // 启动中
    RUNNING,       // 运行中
    EXPORTING,     // 导出产物中
    TERMINATING,   // 终止中
    TERMINATED,    // 已终止
    FAILED,        // 失败
};
struct VmInstance {
    std::string vm_id;
    std::string task_id;
    std::string tenant_id;
    RiskLevel risk_level;
    VmInstanceState state = VmInstanceState::PENDING;
    size_t memory_mb = 128;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point started_at;
    std::chrono::system_clock::time_point expires_at;  // TTL 到期时间
    std::string socket_path;       // Firecracker API socket
    std::string vsock_path;        // vsock 设备路径
    std::string workspace_dir;     // 工作区目录（宿主机侧）
    std::string artifact_dir;      // 产物目录（宿主机侧）
    std::string rootfs_path;       // rootfs 路径
    std::string ephemeral_disk;    // 临时可写磁盘
    bool from_snapshot = false;     // 是否从快照恢复
    size_t pid = 0;                 // Firecracker 进程 PID
};
// ==================== 调度决策 ====================
enum class SchedulingDecision {
    RUN_MICROVM,          // 运行 MicroVM
    FALLBACK_PROCESS,     // 降级到进程沙盒（低风险）
    REJECT_NO_KVM,        // 拒绝（高风险无KVM）
    REJECT_QUEUE_FULL,    // 拒绝（队列满）
    QUEUED,               // 排队
    REJECT_TTL_EXPIRED,   // 拒绝（TTL过期）
};
struct SchedulingResult {
    SchedulingDecision decision;
    std::string reason;
    std::string vm_id;           // 如果立即运行，返回 vm_id
    std::chrono::milliseconds queue_position{0};  // 排队位置
};
// ==================== StrongPool 调度器 ====================
class StrongPoolScheduler {
public:
    StrongPoolScheduler();
    explicit StrongPoolScheduler(const StrongPoolConfig& config);
    ~StrongPoolScheduler();
    // 调度一个任务（核心入口）
    // 根据风险等级、KVM可用性、并发上限决定：
    //   - 高风险 + 无KVM → 拒绝（绝不降级）
    //   - 低风险 + 无KVM → 降级到LightPool（如果允许）
    //   - 并发满 → 排队或拒绝
    SchedulingResult schedule(const std::string& task_id, const std::string& tenant_id,
                               RiskLevel risk_level, size_t memory_mb = 0);
    // 任务完成，释放VM资源
    void complete(const std::string& vm_id);
    // 任务失败
    void fail(const std::string& vm_id, const std::string& reason);
    // 检查并终止超时VM（TTL）
    size_t enforce_ttl();
    // 获取池状态
    struct PoolStatus {
        size_t active_vms = 0;
        size_t queued_tasks = 0;
        size_t total_memory_mb = 0;
        size_t completed_tasks = 0;
        size_t failed_tasks = 0;
        size_t rejected_tasks = 0;
        size_t fallback_tasks = 0;
        bool kvm_available = false;
        std::string message;
    };
    PoolStatus status() const;
    // KVM 能力（启动时探测）
    const KvmCapabilities& capabilities() const { return capabilities_; }
    // 配置
    const StrongPoolConfig& config() const { return config_; }
    // 获取VM实例
    std::shared_ptr<VmInstance> get_vm(const std::string& vm_id) const;
    // 列出所有活跃VM
    std::vector<std::shared_ptr<VmInstance>> active_vms() const;
    // 回调：当需要创建VM时（由外部实现实际Firecracker启动）
    using VmCreator = std::function<bool(std::shared_ptr<VmInstance>)>;
    void set_vm_creator(VmCreator creator) { vm_creator_ = creator; }
    // 回调：当需要销毁VM时
    using VmDestroyer = std::function<void(std::shared_ptr<VmInstance>)>;
    void set_vm_destroyer(VmDestroyer destroyer) { vm_destroyer_ = destroyer; }
private:
    StrongPoolConfig config_;
    KvmCapabilities capabilities_;
    mutable std::mutex mtx_;
    std::unordered_map<std::string, std::shared_ptr<VmInstance>> vms_;
    std::queue<std::shared_ptr<VmInstance>> pending_queue_;
    std::atomic<size_t> completed_{0};
    std::atomic<size_t> failed_{0};
    std::atomic<size_t> rejected_{0};
    std::atomic<size_t> fallback_{0};
    VmCreator vm_creator_;
    VmDestroyer vm_destroyer_;
    // 生成VM ID
    std::string generate_vm_id() const;
    // 检查内存是否足够
    bool has_memory_for(size_t memory_mb) const;
    // 当前总内存
    size_t current_memory_mb() const;
    // 尝试从队列启动下一个任务
    void try_process_queue();
};
} // namespace sandbox
} // namespace photon_kernel
#endif
