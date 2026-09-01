#ifndef PHOTON_KERNEL_INCREMENTAL_COMPLIANCE_HPP
#define PHOTON_KERNEL_INCREMENTAL_COMPLIANCE_HPP

#include <string>
#include <vector>
#include <chrono>
#include <mutex>

namespace photon_kernel {

// ---- V4.14 增量合规 ----
// 模型权重、训练数据或核心推理逻辑发生变更时，
// 须重新评估跳数和约束强度，变更评估周期不超过30天
struct ChangeRecord {
    std::string change_type;        // "weights", "training_data", "inference_logic"
    std::string description;
    std::chrono::system_clock::time_point change_time;
    bool review_completed;
    std::chrono::system_clock::time_point review_deadline;
};

class IncrementalComplianceTracker {
public:
    IncrementalComplianceTracker();

    void record_change(const std::string& change_type, const std::string& description);
    [[nodiscard]] bool is_compliant() const;
    [[nodiscard]] std::vector<ChangeRecord> get_pending_changes() const;
    void complete_review(const std::string& change_type);

private:
    std::vector<ChangeRecord> changes_;
    mutable std::mutex mtx_;
    bool compliant_;
};

} // namespace photon_kernel

#endif
