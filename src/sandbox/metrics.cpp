#include "photon_kernel/sandbox/metrics.hpp"
#include <sstream>
namespace photon_kernel {
namespace sandbox {
Metrics& Metrics::instance() {
    static Metrics m;
    return m;
}
void Metrics::record_task(bool success, uint64_t execution_time_us) {
    tasks_total_.fetch_add(1, std::memory_order_relaxed);
    if (!success) {
        tasks_failed_.fetch_add(1, std::memory_order_relaxed);
    }
    execution_time_us_total_.fetch_add(execution_time_us, std::memory_order_relaxed);
}
void Metrics::increment_concurrent() {
    uint64_t cur = current_concurrent_.fetch_add(1, std::memory_order_relaxed) + 1;
    uint64_t peak = peak_concurrent_.load(std::memory_order_relaxed);
    while (cur > peak && !peak_concurrent_.compare_exchange_weak(peak, cur, std::memory_order_relaxed)) {
    }
}
void Metrics::decrement_concurrent() {
    current_concurrent_.fetch_sub(1, std::memory_order_relaxed);
}
void Metrics::record_snapshot_fork() {
    snapshot_fork_total_.fetch_add(1, std::memory_order_relaxed);
}
void Metrics::record_pool_hit() {
    pool_hit_total_.fetch_add(1, std::memory_order_relaxed);
}
void Metrics::set_audit_spool_size(uint64_t size) {
    audit_spool_size_.store(size, std::memory_order_relaxed);
}
void Metrics::reset() {
    tasks_total_.store(0);
    tasks_failed_.store(0);
    execution_time_us_total_.store(0);
    current_concurrent_.store(0);
    peak_concurrent_.store(0);
    snapshot_fork_total_.store(0);
    pool_hit_total_.store(0);
    audit_spool_size_.store(0);
}
std::string Metrics::export_prometheus() const {
    std::ostringstream oss;
    oss << "# HELP photon_sandbox_tasks_total Total number of sandbox tasks executed\n";
    oss << "# TYPE photon_sandbox_tasks_total counter\n";
    oss << "photon_sandbox_tasks_total " << tasks_total_.load() << "\n\n";
    oss << "# HELP photon_sandbox_tasks_failed_total Total number of failed sandbox tasks\n";
    oss << "# TYPE photon_sandbox_tasks_failed_total counter\n";
    oss << "photon_sandbox_tasks_failed_total " << tasks_failed_.load() << "\n\n";
    oss << "# HELP photon_sandbox_execution_time_us_total Total execution time in microseconds\n";
    oss << "# TYPE photon_sandbox_execution_time_us_total counter\n";
    oss << "photon_sandbox_execution_time_us_total " << execution_time_us_total_.load() << "\n\n";
    oss << "# HELP photon_sandbox_peak_concurrent Peak number of concurrent sandbox tasks\n";
    oss << "# TYPE photon_sandbox_peak_concurrent gauge\n";
    oss << "photon_sandbox_peak_concurrent " << peak_concurrent_.load() << "\n\n";
    oss << "# HELP photon_sandbox_snapshot_fork_total Total number of snapshot fork clones\n";
    oss << "# TYPE photon_sandbox_snapshot_fork_total counter\n";
    oss << "photon_sandbox_snapshot_fork_total " << snapshot_fork_total_.load() << "\n\n";
    oss << "# HELP photon_sandbox_pool_hit_total Total number of pre-warmed pool hits\n";
    oss << "# TYPE photon_sandbox_pool_hit_total counter\n";
    oss << "photon_sandbox_pool_hit_total " << pool_hit_total_.load() << "\n\n";
    oss << "# HELP photon_sandbox_audit_spool_size Current audit spool size in records\n";
    oss << "# TYPE photon_sandbox_audit_spool_size gauge\n";
    oss << "photon_sandbox_audit_spool_size " << audit_spool_size_.load() << "\n";
    return oss.str();
}
} // namespace sandbox
} // namespace photon_kernel
