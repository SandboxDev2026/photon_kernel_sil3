#ifndef PHOTON_KERNEL_SANDBOX_METRICS_HPP
#define PHOTON_KERNEL_SANDBOX_METRICS_HPP
// 生产级 Metrics（P1 可观测性）：Prometheus 指标导出。
//
// 指标分类：
//   1. 任务指标：创建/成功/失败/执行时长（按池维度）
//   2. 降级事件：KVM降级、eBPF降级、CRIU降级、namespace降级
//   3. 安全拦截：eBPF内网拦截、seccomp拦截、DNS劫持拦截、元数据拦截
//   4. 池状态：各池活跃实例数、等待队列长度、预热池命中
//   5. 审计：spool大小、堆积告警、哈希链验证
//   6. TaskSpec维度：风险分数分布、使用后端、执行时长直方图
#include <atomic>
#include <cstdint>
#include <string>
namespace photon_kernel {
namespace sandbox {
enum class PoolType { LIGHT, STRONG, ONCE };
inline const char* pool_type_name(PoolType t) {
    switch (t) { case PoolType::LIGHT: return "light"; case PoolType::STRONG: return "strong"; case PoolType::ONCE: return "once"; } return "unknown";
}
enum class DegradationType {
    KVM_UNAVAILABLE, EBPF_NO_CAP, CRIU_UNAVAILABLE,
    NAMESPACE_NO_PERM, LANDLOCK_UNSUPPORTED, GRPC_CPP_MISSING,
};
inline const char* degradation_type_name(DegradationType t) {
    switch (t) {
        case DegradationType::KVM_UNAVAILABLE: return "kvm_unavailable";
        case DegradationType::EBPF_NO_CAP: return "ebpf_no_cap";
        case DegradationType::CRIU_UNAVAILABLE: return "criu_unavailable";
        case DegradationType::NAMESPACE_NO_PERM: return "namespace_no_perm";
        case DegradationType::LANDLOCK_UNSUPPORTED: return "landlock_unsupported";
        case DegradationType::GRPC_CPP_MISSING: return "grpc_cpp_missing";
    } return "unknown";
}
enum class SecurityBlockType {
    EBPF_INTERNAL_IP, EBPF_METADATA_IP, EBPF_LOOPBACK, EBPF_DNS_HIJACK,
    SECCOMP_SYSCALL, SECCOMP_EXEC_WHITELIST, LANDLOCK_PATH,
    GATEWAY_DOMAIN, GATEWAY_CONNECTION_LIMIT,
};
inline const char* security_block_type_name(SecurityBlockType t) {
    switch (t) {
        case SecurityBlockType::EBPF_INTERNAL_IP: return "ebpf_internal_ip";
        case SecurityBlockType::EBPF_METADATA_IP: return "ebpf_metadata_ip";
        case SecurityBlockType::EBPF_LOOPBACK: return "ebpf_loopback";
        case SecurityBlockType::EBPF_DNS_HIJACK: return "ebpf_dns_hijack";
        case SecurityBlockType::SECCOMP_SYSCALL: return "seccomp_syscall";
        case SecurityBlockType::SECCOMP_EXEC_WHITELIST: return "seccomp_exec_whitelist";
        case SecurityBlockType::LANDLOCK_PATH: return "landlock_path";
        case SecurityBlockType::GATEWAY_DOMAIN: return "gateway_domain";
        case SecurityBlockType::GATEWAY_CONNECTION_LIMIT: return "gateway_connection_limit";
    } return "unknown";
}
enum class RiskLevel { LOW, MEDIUM, HIGH, CRITICAL };
inline const char* risk_level_name(RiskLevel r) {
    switch (r) { case RiskLevel::LOW: return "low"; case RiskLevel::MEDIUM: return "medium"; case RiskLevel::HIGH: return "high"; case RiskLevel::CRITICAL: return "critical"; } return "unknown";
}
class Metrics {
public:
    static Metrics& instance();
    // 1. 任务指标
    void record_task(PoolType pool, bool success, uint64_t execution_time_us);
    void record_task_rejected(PoolType pool, const std::string& reason = "");
    void increment_concurrent(PoolType pool);
    void decrement_concurrent(PoolType pool);
    // 2. 降级事件
    void record_degradation(DegradationType type, const std::string& detail = "");
    uint64_t degradation_count(DegradationType type) const;
    bool is_degraded(DegradationType type) const;
    // 3. 安全拦截
    void record_security_block(SecurityBlockType type, const std::string& detail = "");
    uint64_t security_block_count(SecurityBlockType type) const;
    uint64_t total_security_blocks() const;
    // 4. 池状态
    void set_pool_active(PoolType pool, uint64_t count);
    void set_pool_queue_length(PoolType pool, uint64_t length);
    void record_pool_hit(PoolType pool);
    void record_pool_miss(PoolType pool);
    void record_snapshot_fork();
    // 5. 审计
    void set_audit_spool_size(uint64_t size);
    void set_audit_spool_pending(uint64_t count);
    void record_audit_hash_verification(bool passed);
    // 6. TaskSpec 维度
    void record_task_risk(RiskLevel level);
    void record_task_backend(PoolType pool);
    void record_execution_duration(PoolType pool, uint64_t us);
    // 7. 僵尸实例/资源泄漏
    void set_zombie_count(uint64_t count);
    void record_fd_count(uint64_t count);
    void record_memory_usage_mb(uint64_t mb);
    // 导出
    [[nodiscard]] std::string export_prometheus() const;
    void reset();
    [[nodiscard]] uint64_t tasks_total() const { return tasks_total_.load(); }
    [[nodiscard]] uint64_t tasks_failed() const { return tasks_failed_.load(); }
    [[nodiscard]] uint64_t peak_concurrent() const { return peak_concurrent_.load(); }
    // 兼容旧 API
    void record_task(bool success, uint64_t execution_time_us) { record_task(PoolType::LIGHT, success, execution_time_us); }
    void increment_concurrent() { increment_concurrent(PoolType::LIGHT); }
    void decrement_concurrent() { decrement_concurrent(PoolType::LIGHT); }
    void record_pool_hit() { record_pool_hit(PoolType::LIGHT); }
    [[nodiscard]] uint64_t execution_time_us_total() const { return execution_time_us_total_.load(); }
    [[nodiscard]] uint64_t snapshot_fork_total() const { return snapshot_fork_total_.load(); }
    [[nodiscard]] uint64_t pool_hit_total() const { return light_pool_hits_.load(); }
    [[nodiscard]] uint64_t audit_spool_size() const { return audit_spool_size_.load(); }
private:
    Metrics() = default;
    ~Metrics() = default;
    Metrics(const Metrics&) = delete;
    Metrics& operator=(const Metrics&) = delete;
    std::atomic<uint64_t> tasks_total_{0}, tasks_failed_{0}, tasks_rejected_{0};
    std::atomic<uint64_t> execution_time_us_total_{0};
    std::atomic<uint64_t> current_concurrent_{0}, peak_concurrent_{0};
    std::atomic<uint64_t> light_tasks_total_{0}, light_tasks_failed_{0};
    std::atomic<uint64_t> strong_tasks_total_{0}, strong_tasks_failed_{0};
    std::atomic<uint64_t> once_tasks_total_{0}, once_tasks_failed_{0};
    std::atomic<uint64_t> kvm_unavailable_{0}, ebpf_no_cap_{0}, criu_unavailable_{0};
    std::atomic<uint64_t> namespace_no_perm_{0}, landlock_unsupported_{0}, grpc_cpp_missing_{0};
    std::atomic<uint64_t> ebpf_internal_ip_blocks_{0}, ebpf_metadata_ip_blocks_{0};
    std::atomic<uint64_t> ebpf_loopback_blocks_{0}, ebpf_dns_hijack_blocks_{0};
    std::atomic<uint64_t> seccomp_syscall_blocks_{0}, seccomp_exec_whitelist_blocks_{0};
    std::atomic<uint64_t> landlock_path_blocks_{0}, gateway_domain_blocks_{0}, gateway_connection_limit_blocks_{0};
    std::atomic<uint64_t> light_active_{0}, strong_active_{0}, once_active_{0};
    std::atomic<uint64_t> light_queue_{0}, strong_queue_{0};
    std::atomic<uint64_t> light_pool_hits_{0}, light_pool_misses_{0}, strong_pool_hits_{0};
    std::atomic<uint64_t> snapshot_fork_total_{0};
    std::atomic<uint64_t> audit_spool_size_{0}, audit_spool_pending_{0};
    std::atomic<uint64_t> audit_hash_verified_{0}, audit_hash_failed_{0};
    std::atomic<uint64_t> risk_low_{0}, risk_medium_{0}, risk_high_{0}, risk_critical_{0};
    std::atomic<uint64_t> dur_lt_1ms_{0}, dur_lt_10ms_{0}, dur_lt_100ms_{0};
    std::atomic<uint64_t> dur_lt_1s_{0}, dur_lt_10s_{0}, dur_gt_10s_{0};
    std::atomic<uint64_t> zombie_count_{0}, fd_count_{0}, memory_usage_mb_{0};
    void record_duration_bucket(uint64_t us);
};
} // namespace sandbox
} // namespace photon_kernel
#endif
