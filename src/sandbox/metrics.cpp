#include "photon_kernel/sandbox/metrics.hpp"
#include <sstream>
namespace photon_kernel {
namespace sandbox {
Metrics& Metrics::instance() {
    static Metrics m;
    return m;
}
void Metrics::record_task(PoolType pool, bool success, uint64_t execution_time_us) {
    tasks_total_.fetch_add(1, std::memory_order_relaxed);
    if (!success) tasks_failed_.fetch_add(1, std::memory_order_relaxed);
    execution_time_us_total_.fetch_add(execution_time_us, std::memory_order_relaxed);
    switch (pool) {
        case PoolType::LIGHT:
            light_tasks_total_.fetch_add(1, std::memory_order_relaxed);
            if (!success) light_tasks_failed_.fetch_add(1, std::memory_order_relaxed);
            break;
        case PoolType::STRONG:
            strong_tasks_total_.fetch_add(1, std::memory_order_relaxed);
            if (!success) strong_tasks_failed_.fetch_add(1, std::memory_order_relaxed);
            break;
        case PoolType::ONCE:
            once_tasks_total_.fetch_add(1, std::memory_order_relaxed);
            if (!success) once_tasks_failed_.fetch_add(1, std::memory_order_relaxed);
            break;
    }
    record_duration_bucket(execution_time_us);
}
void Metrics::record_task_rejected(PoolType pool, const std::string&) {
    tasks_rejected_.fetch_add(1, std::memory_order_relaxed);
}
void Metrics::increment_concurrent(PoolType) {
    uint64_t cur = current_concurrent_.fetch_add(1, std::memory_order_relaxed) + 1;
    uint64_t peak = peak_concurrent_.load(std::memory_order_relaxed);
    while (cur > peak && !peak_concurrent_.compare_exchange_weak(peak, cur, std::memory_order_relaxed)) {}
}
void Metrics::decrement_concurrent(PoolType) {
    current_concurrent_.fetch_sub(1, std::memory_order_relaxed);
}
void Metrics::record_degradation(DegradationType type, const std::string&) {
    switch (type) {
        case DegradationType::KVM_UNAVAILABLE: kvm_unavailable_.fetch_add(1); break;
        case DegradationType::EBPF_NO_CAP: ebpf_no_cap_.fetch_add(1); break;
        case DegradationType::CRIU_UNAVAILABLE: criu_unavailable_.fetch_add(1); break;
        case DegradationType::NAMESPACE_NO_PERM: namespace_no_perm_.fetch_add(1); break;
        case DegradationType::LANDLOCK_UNSUPPORTED: landlock_unsupported_.fetch_add(1); break;
        case DegradationType::GRPC_CPP_MISSING: grpc_cpp_missing_.fetch_add(1); break;
    }
}
uint64_t Metrics::degradation_count(DegradationType type) const {
    switch (type) {
        case DegradationType::KVM_UNAVAILABLE: return kvm_unavailable_.load();
        case DegradationType::EBPF_NO_CAP: return ebpf_no_cap_.load();
        case DegradationType::CRIU_UNAVAILABLE: return criu_unavailable_.load();
        case DegradationType::NAMESPACE_NO_PERM: return namespace_no_perm_.load();
        case DegradationType::LANDLOCK_UNSUPPORTED: return landlock_unsupported_.load();
        case DegradationType::GRPC_CPP_MISSING: return grpc_cpp_missing_.load();
    }
    return 0;
}
bool Metrics::is_degraded(DegradationType type) const {
    return degradation_count(type) > 0;
}
void Metrics::record_security_block(SecurityBlockType type, const std::string&) {
    switch (type) {
        case SecurityBlockType::EBPF_INTERNAL_IP: ebpf_internal_ip_blocks_.fetch_add(1); break;
        case SecurityBlockType::EBPF_METADATA_IP: ebpf_metadata_ip_blocks_.fetch_add(1); break;
        case SecurityBlockType::EBPF_LOOPBACK: ebpf_loopback_blocks_.fetch_add(1); break;
        case SecurityBlockType::EBPF_DNS_HIJACK: ebpf_dns_hijack_blocks_.fetch_add(1); break;
        case SecurityBlockType::SECCOMP_SYSCALL: seccomp_syscall_blocks_.fetch_add(1); break;
        case SecurityBlockType::SECCOMP_EXEC_WHITELIST: seccomp_exec_whitelist_blocks_.fetch_add(1); break;
        case SecurityBlockType::LANDLOCK_PATH: landlock_path_blocks_.fetch_add(1); break;
        case SecurityBlockType::GATEWAY_DOMAIN: gateway_domain_blocks_.fetch_add(1); break;
        case SecurityBlockType::GATEWAY_CONNECTION_LIMIT: gateway_connection_limit_blocks_.fetch_add(1); break;
    }
}
uint64_t Metrics::security_block_count(SecurityBlockType type) const {
    switch (type) {
        case SecurityBlockType::EBPF_INTERNAL_IP: return ebpf_internal_ip_blocks_.load();
        case SecurityBlockType::EBPF_METADATA_IP: return ebpf_metadata_ip_blocks_.load();
        case SecurityBlockType::EBPF_LOOPBACK: return ebpf_loopback_blocks_.load();
        case SecurityBlockType::EBPF_DNS_HIJACK: return ebpf_dns_hijack_blocks_.load();
        case SecurityBlockType::SECCOMP_SYSCALL: return seccomp_syscall_blocks_.load();
        case SecurityBlockType::SECCOMP_EXEC_WHITELIST: return seccomp_exec_whitelist_blocks_.load();
        case SecurityBlockType::LANDLOCK_PATH: return landlock_path_blocks_.load();
        case SecurityBlockType::GATEWAY_DOMAIN: return gateway_domain_blocks_.load();
        case SecurityBlockType::GATEWAY_CONNECTION_LIMIT: return gateway_connection_limit_blocks_.load();
    }
    return 0;
}
uint64_t Metrics::total_security_blocks() const {
    return ebpf_internal_ip_blocks_.load() + ebpf_metadata_ip_blocks_.load() +
           ebpf_loopback_blocks_.load() + ebpf_dns_hijack_blocks_.load() +
           seccomp_syscall_blocks_.load() + seccomp_exec_whitelist_blocks_.load() +
           landlock_path_blocks_.load() + gateway_domain_blocks_.load() +
           gateway_connection_limit_blocks_.load();
}
void Metrics::set_pool_active(PoolType pool, uint64_t count) {
    switch (pool) {
        case PoolType::LIGHT: light_active_.store(count); break;
        case PoolType::STRONG: strong_active_.store(count); break;
        case PoolType::ONCE: once_active_.store(count); break;
    }
}
void Metrics::set_pool_queue_length(PoolType pool, uint64_t length) {
    switch (pool) {
        case PoolType::LIGHT: light_queue_.store(length); break;
        case PoolType::STRONG: strong_queue_.store(length); break;
        case PoolType::ONCE: break;
    }
}
void Metrics::record_pool_hit(PoolType pool) {
    switch (pool) {
        case PoolType::LIGHT: light_pool_hits_.fetch_add(1); break;
        case PoolType::STRONG: strong_pool_hits_.fetch_add(1); break;
        case PoolType::ONCE: break;
    }
}
void Metrics::record_pool_miss(PoolType pool) {
    if (pool == PoolType::LIGHT) light_pool_misses_.fetch_add(1);
}
void Metrics::record_snapshot_fork() { snapshot_fork_total_.fetch_add(1); }
void Metrics::set_audit_spool_size(uint64_t size) { audit_spool_size_.store(size); }
void Metrics::set_audit_spool_pending(uint64_t count) { audit_spool_pending_.store(count); }
void Metrics::record_audit_hash_verification(bool passed) {
    if (passed) audit_hash_verified_.fetch_add(1);
    else audit_hash_failed_.fetch_add(1);
}
void Metrics::record_task_risk(RiskLevel level) {
    switch (level) {
        case RiskLevel::LOW: risk_low_.fetch_add(1); break;
        case RiskLevel::MEDIUM: risk_medium_.fetch_add(1); break;
        case RiskLevel::HIGH: risk_high_.fetch_add(1); break;
        case RiskLevel::CRITICAL: risk_critical_.fetch_add(1); break;
    }
}
void Metrics::record_task_backend(PoolType pool) {
    switch (pool) {
        case PoolType::LIGHT: light_tasks_total_.fetch_add(1); break;
        case PoolType::STRONG: strong_tasks_total_.fetch_add(1); break;
        case PoolType::ONCE: once_tasks_total_.fetch_add(1); break;
    }
}
void Metrics::record_execution_duration(PoolType, uint64_t us) {
    record_duration_bucket(us);
}
void Metrics::set_zombie_count(uint64_t count) { zombie_count_.store(count); }
void Metrics::record_fd_count(uint64_t count) { fd_count_.store(count); }
void Metrics::record_memory_usage_mb(uint64_t mb) { memory_usage_mb_.store(mb); }
void Metrics::record_duration_bucket(uint64_t us) {
    if (us < 1000) dur_lt_1ms_.fetch_add(1);
    else if (us < 10000) dur_lt_10ms_.fetch_add(1);
    else if (us < 100000) dur_lt_100ms_.fetch_add(1);
    else if (us < 1000000) dur_lt_1s_.fetch_add(1);
    else if (us < 10000000) dur_lt_10s_.fetch_add(1);
    else dur_gt_10s_.fetch_add(1);
}
void Metrics::reset() {
    tasks_total_.store(0); tasks_failed_.store(0); tasks_rejected_.store(0);
    execution_time_us_total_.store(0); current_concurrent_.store(0); peak_concurrent_.store(0);
    light_tasks_total_.store(0); light_tasks_failed_.store(0);
    strong_tasks_total_.store(0); strong_tasks_failed_.store(0);
    once_tasks_total_.store(0); once_tasks_failed_.store(0);
    kvm_unavailable_.store(0); ebpf_no_cap_.store(0); criu_unavailable_.store(0);
    namespace_no_perm_.store(0); landlock_unsupported_.store(0); grpc_cpp_missing_.store(0);
    ebpf_internal_ip_blocks_.store(0); ebpf_metadata_ip_blocks_.store(0);
    ebpf_loopback_blocks_.store(0); ebpf_dns_hijack_blocks_.store(0);
    seccomp_syscall_blocks_.store(0); seccomp_exec_whitelist_blocks_.store(0);
    landlock_path_blocks_.store(0); gateway_domain_blocks_.store(0); gateway_connection_limit_blocks_.store(0);
    light_active_.store(0); strong_active_.store(0); once_active_.store(0);
    light_queue_.store(0); strong_queue_.store(0);
    light_pool_hits_.store(0); light_pool_misses_.store(0); strong_pool_hits_.store(0);
    snapshot_fork_total_.store(0);
    audit_spool_size_.store(0); audit_spool_pending_.store(0);
    audit_hash_verified_.store(0); audit_hash_failed_.store(0);
    risk_low_.store(0); risk_medium_.store(0); risk_high_.store(0); risk_critical_.store(0);
    dur_lt_1ms_.store(0); dur_lt_10ms_.store(0); dur_lt_100ms_.store(0);
    dur_lt_1s_.store(0); dur_lt_10s_.store(0); dur_gt_10s_.store(0);
    zombie_count_.store(0); fd_count_.store(0); memory_usage_mb_.store(0);
}
std::string Metrics::export_prometheus() const {
    std::ostringstream oss;
    auto emit_counter = [&](const char* name, const char* help, uint64_t val) {
        oss << "# HELP " << name << " " << help << "\n# TYPE " << name << " counter\n"
            << name << " " << val << "\n\n";
    };
    auto emit_gauge = [&](const char* name, const char* help, uint64_t val) {
        oss << "# HELP " << name << " " << help << "\n# TYPE " << name << " gauge\n"
            << name << " " << val << "\n\n";
    };
    // 1. 任务指标
    emit_counter("photon_sandbox_tasks_total", "Total tasks executed", tasks_total_.load());
    emit_counter("photon_sandbox_tasks_failed_total", "Total failed tasks", tasks_failed_.load());
    emit_counter("photon_sandbox_tasks_rejected_total", "Total rejected tasks (e.g. high-risk no KVM)", tasks_rejected_.load());
    emit_counter("photon_sandbox_execution_time_us_total", "Total execution time in microseconds", execution_time_us_total_.load());
    emit_gauge("photon_sandbox_peak_concurrent", "Peak concurrent tasks", peak_concurrent_.load());
    // 按池维度
    emit_counter("photon_sandbox_light_tasks_total", "Light pool tasks", light_tasks_total_.load());
    emit_counter("photon_sandbox_light_tasks_failed_total", "Light pool failed tasks", light_tasks_failed_.load());
    emit_counter("photon_sandbox_strong_tasks_total", "Strong pool tasks", strong_tasks_total_.load());
    emit_counter("photon_sandbox_strong_tasks_failed_total", "Strong pool failed tasks", strong_tasks_failed_.load());
    // 2. 降级事件
    emit_counter("photon_sandbox_degradation_kvm_unavailable_total", "KVM unavailable events", kvm_unavailable_.load());
    emit_counter("photon_sandbox_degradation_ebpf_no_cap_total", "eBPF no CAP_BPF events", ebpf_no_cap_.load());
    emit_counter("photon_sandbox_degradation_criu_unavailable_total", "CRIU unavailable events", criu_unavailable_.load());
    emit_counter("photon_sandbox_degradation_namespace_no_perm_total", "Namespace no permission events", namespace_no_perm_.load());
    // 3. 安全拦截（告警关键指标）
    emit_counter("photon_sandbox_security_block_ebpf_internal_ip_total", "eBPF blocked internal IP access (possible escape attempt)", ebpf_internal_ip_blocks_.load());
    emit_counter("photon_sandbox_security_block_ebpf_metadata_ip_total", "eBPF blocked metadata IP (169.254.169.254)", ebpf_metadata_ip_blocks_.load());
    emit_counter("photon_sandbox_security_block_ebpf_dns_hijack_total", "eBPF blocked DNS hijack attempt", ebpf_dns_hijack_blocks_.load());
    emit_counter("photon_sandbox_security_block_seccomp_syscall_total", "seccomp blocked syscall", seccomp_syscall_blocks_.load());
    emit_counter("photon_sandbox_security_block_seccomp_exec_whitelist_total", "seccomp blocked non-whitelisted interpreter", seccomp_exec_whitelist_blocks_.load());
    emit_counter("photon_sandbox_security_block_landlock_path_total", "Landlock blocked path access", landlock_path_blocks_.load());
    emit_counter("photon_sandbox_security_block_gateway_domain_total", "Gateway blocked domain", gateway_domain_blocks_.load());
    // 4. 池状态
    emit_gauge("photon_sandbox_light_active_instances", "Light pool active instances", light_active_.load());
    emit_gauge("photon_sandbox_strong_active_instances", "Strong pool active VMs", strong_active_.load());
    emit_gauge("photon_sandbox_light_queue_length", "Light pool waiting queue length", light_queue_.load());
    emit_gauge("photon_sandbox_strong_queue_length", "Strong pool waiting queue length", strong_queue_.load());
    emit_counter("photon_sandbox_pool_hit_total", "Pre-warmed pool hits", light_pool_hits_.load());
    emit_counter("photon_sandbox_pool_miss_total", "Pre-warmed pool misses", light_pool_misses_.load());
    emit_counter("photon_sandbox_snapshot_fork_total", "Snapshot fork operations", snapshot_fork_total_.load());
    // 5. 审计
    emit_gauge("photon_sandbox_audit_spool_size", "Audit spool current size (records)", audit_spool_size_.load());
    emit_gauge("photon_sandbox_audit_spool_pending", "Audit records pending send", audit_spool_pending_.load());
    emit_counter("photon_sandbox_audit_hash_verified_total", "Audit hash chain verification passed", audit_hash_verified_.load());
    emit_counter("photon_sandbox_audit_hash_failed_total", "Audit hash chain verification FAILED (possible tampering)", audit_hash_failed_.load());
    // 6. TaskSpec 维度
    emit_counter("photon_sandbox_task_risk_low_total", "Low risk tasks", risk_low_.load());
    emit_counter("photon_sandbox_task_risk_medium_total", "Medium risk tasks", risk_medium_.load());
    emit_counter("photon_sandbox_task_risk_high_total", "High risk tasks", risk_high_.load());
    emit_counter("photon_sandbox_task_risk_critical_total", "Critical risk tasks", risk_critical_.load());
    // 执行时长直方图
    emit_counter("photon_sandbox_execution_duration_lt_1ms_total", "Tasks < 1ms", dur_lt_1ms_.load());
    emit_counter("photon_sandbox_execution_duration_lt_10ms_total", "Tasks < 10ms", dur_lt_10ms_.load());
    emit_counter("photon_sandbox_execution_duration_lt_100ms_total", "Tasks < 100ms", dur_lt_100ms_.load());
    emit_counter("photon_sandbox_execution_duration_lt_1s_total", "Tasks < 1s", dur_lt_1s_.load());
    emit_counter("photon_sandbox_execution_duration_lt_10s_total", "Tasks < 10s", dur_lt_10s_.load());
    emit_counter("photon_sandbox_execution_duration_gt_10s_total", "Tasks > 10s", dur_gt_10s_.load());
    // 7. 僵尸实例/资源
    emit_gauge("photon_sandbox_zombie_instances", "Zombie sandbox/VM instances (should be 0)", zombie_count_.load());
    emit_gauge("photon_sandbox_fd_count", "Current file descriptor count", fd_count_.load());
    emit_gauge("photon_sandbox_memory_usage_mb", "Current memory usage in MB", memory_usage_mb_.load());
    return oss.str();
}
} // namespace sandbox
} // namespace photon_kernel
