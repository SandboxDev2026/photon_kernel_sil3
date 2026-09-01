#include "photon_kernel/incremental_compliance.hpp"

#include <iostream>

namespace photon_kernel {

IncrementalComplianceTracker::IncrementalComplianceTracker()
    : compliant_(true) {}

void IncrementalComplianceTracker::record_change(const std::string& change_type,
                                                 const std::string& description) {
    std::lock_guard<std::mutex> lock(mtx_);

    ChangeRecord record;
    record.change_type = change_type;
    record.description = description;
    record.change_time = std::chrono::system_clock::now();
    record.review_completed = false;
    record.review_deadline = record.change_time + std::chrono::hours(24 * 30); // 30天

    changes_.push_back(record);
    compliant_ = false;

    std::cout << "[IncrementalCompliance] Change recorded: " << change_type
              << " (deadline: 30 days)\n";
}

bool IncrementalComplianceTracker::is_compliant() const {
    std::lock_guard<std::mutex> lock(mtx_);
    // 存在任一未完成审查的变更即不合规（无论是否已到 30 天期限，超期仅影响紧急度）
    for (const auto& c : changes_) {
        if (!c.review_completed) {
            return false;
        }
    }
    return true;
}

std::vector<ChangeRecord> IncrementalComplianceTracker::get_pending_changes() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<ChangeRecord> pending;
    for (const auto& c : changes_) {
        if (!c.review_completed) {
            pending.push_back(c);
        }
    }
    return pending;
}

void IncrementalComplianceTracker::complete_review(const std::string& change_type) {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto& c : changes_) {
        if (c.change_type == change_type && !c.review_completed) {
            c.review_completed = true;
            std::cout << "[IncrementalCompliance] Review completed for: "
                      << change_type << "\n";
        }
    }

    // 检查是否所有变更都已审查
    bool all_complete = true;
    for (const auto& c : changes_) {
        if (!c.review_completed) {
            all_complete = false;
            break;
        }
    }
    if (all_complete) {
        compliant_ = true;
    }
}

} // namespace photon_kernel
