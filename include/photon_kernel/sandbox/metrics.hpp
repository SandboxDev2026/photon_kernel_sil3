#ifndef PHOTON_KERNEL_SANDBOX_METRICS_HPP
#define PHOTON_KERNEL_SANDBOX_METRICS_HPP
// 实时可观测性（核弹级优化四）：Prometheus 指标导出。
// 全局原子计数器，记录沙盒运行时关键指标，可通过 /metrics 端点曝露。
//
// 指标列表：
//   - photon_sandbox_tasks_total：累计任务数（counter）
//   - photon_sandbox_tasks_failed_total：累计失败任务数（counter）
//   - photon_sandbox_execution_time_us_total：累计执行时间（counter, microseconds）
//   - photon_sandbox_peak_concurrent：峰值并发数（gauge）
//   - photon_sandbox_snapshot_fork_total：快照克隆累计次数（counter）
//   - photon_sandbox_pool_hit_total：预热池命中次数（counter）
//   - photon_sandbox_audit_spool_size：审计 spool 当前大小（gauge）
#include <atomic>
#include <cstdint>
#include <string>
namespace photon_kernel {
namespace sandbox {
class Metrics {
public:
    static Metrics& instance();
    // 任务计数
    void record_task(bool success, uint64_t execution_time_us);
    void increment_concurrent();
    void decrement_concurrent();
    // 快照克隆计数
    void record_snapshot_fork();
    // 预热池命中计数
    void record_pool_hit();
    // 审计 spool 大小
    void set_audit_spool_size(uint64_t size);
    // 导出 Prometheus 文本格式
    [[nodiscard]] std::string export_prometheus() const;
    // 重置所有指标（测试用）
    void reset();
    // 只读访问器
    [[nodiscard]] uint64_t tasks_total() const { return tasks_total_.load(); }
    [[nodiscard]] uint64_t tasks_failed() const { return tasks_failed_.load(); }
    [[nodiscard]] uint64_t execution_time_us_total() const { return execution_time_us_total_.load(); }
    [[nodiscard]] uint64_t peak_concurrent() const { return peak_concurrent_.load(); }
    [[nodiscard]] uint64_t snapshot_fork_total() const { return snapshot_fork_total_.load(); }
    [[nodiscard]] uint64_t pool_hit_total() const { return pool_hit_total_.load(); }
    [[nodiscard]] uint64_t audit_spool_size() const { return audit_spool_size_.load(); }
private:
    Metrics() = default;
    ~Metrics() = default;
    Metrics(const Metrics&) = delete;
    Metrics& operator=(const Metrics&) = delete;
    std::atomic<uint64_t> tasks_total_{0};
    std::atomic<uint64_t> tasks_failed_{0};
    std::atomic<uint64_t> execution_time_us_total_{0};
    std::atomic<uint64_t> current_concurrent_{0};
    std::atomic<uint64_t> peak_concurrent_{0};
    std::atomic<uint64_t> snapshot_fork_total_{0};
    std::atomic<uint64_t> pool_hit_total_{0};
    std::atomic<uint64_t> audit_spool_size_{0};
};
} // namespace sandbox
} // namespace photon_kernel
#endif
