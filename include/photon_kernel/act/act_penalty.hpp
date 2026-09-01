#ifndef PHOTON_KERNEL_ACT_PENALTY_HPP
#define PHOTON_KERNEL_ACT_PENALTY_HPP

// 第十九条 —— 违规认定；第二十条 —— 处罚执行
// 违规行为与处罚映射；处罚决定须载明事实/条款/措施/期限，被处罚方有权申诉。

#include <cstdint>
#include <string>
#include <vector>

namespace photon_kernel {
namespace act {

// 违规行为类型（第十九条表）
enum class Violation {
    RISK_DECLARATION_FALSE,     // 风险等级申报不实
    OUTPUT_LIMITER_MISSING,     // 输出限幅缺失（中风险及以上）
    HARDWARE_SELFDIAG_MISSING,  // 硬件自诊断缺失（高风险）
    LOGIC_BREAKER_MISSING,      // 逻辑熔断缺失（中风险及以上）
    SAFETY_ASSESS_MISSING,      // 安全评估缺失（高风险）
    AUDIT_LOG_FORGED,           // 审计日志造假或缺失
    REFUSE_INSPECTION           // 拒绝配合检查
};

const char* violation_name(Violation v);

// 处罚措施
struct Penalty {
    Violation violation;
    const char* measure;   // 处罚措施描述
    const char* deadline;  // 整改期限
    bool escalate;         // 是否含暂停交付/公开通报等升级措施
};

// 返回第十九条处罚映射
Penalty penalty_for(Violation v);

// 处罚决定（第二十条：须载明事实/条款/措施/期限；被处罚方有权申诉）
struct PenaltyDecision {
    Violation violation;
    std::string facts;       // 违规事实
    int article;             // 适用条款（19/20）
    std::string measure;     // 处罚措施
    std::string deadline;    // 整改期限
    bool appealed = false;   // 是否已申诉
};

class ActPenalty {
public:
    // 对违规行为作出处罚决定（记录审计事件）
    PenaltyDecision issue(Violation v, const std::string& facts);

    // 被处罚方申诉（第二十条）
    void appeal(const std::string& decision_ref);

    [[nodiscard]] std::vector<PenaltyDecision> decisions() const { return decisions_; }

    // 第十九条合规自检：无待整改的严重违规
    [[nodiscard]] bool self_check_pass() const;

private:
    std::vector<PenaltyDecision> decisions_;
};

} // namespace act
} // namespace photon_kernel

#endif
