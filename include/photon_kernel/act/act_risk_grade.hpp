#ifndef PHOTON_KERNEL_ACT_RISK_GRADE_HPP
#define PHOTON_KERNEL_ACT_RISK_GRADE_HPP

// 第七条 —— 风险等级判定；第八条 —— 豁免机制
// 系统按输出对物理世界与人类认知的潜在影响分三级；初始等级开发者自评、
// 安全委员会确认，变更须重新评估并备案。
// 豁免：纯研发实验/内部测试/开源非商业分发/已被等效合规框架覆盖。

#include <cstdint>
#include <string>
#include <vector>

namespace photon_kernel {
namespace act {

// 输出对物理世界与人类认知的潜在影响维度（第七条判定依据）
enum class OutputImpact {
    INFORMATION_ONLY,      // 低风险：仅用于信息呈现，不直接影响物理世界或人类决策
    ASSISTED_DECISION,     // 中风险：经规则校验后辅助决策，或输出涉及专业领域信息
    PHYSICAL_EXECUTOR      // 高风险：直接驱动物理执行器，或涉及人身安全/重大公共利益
};

// 与沙盒工程风险等级映射：LOW=低风险 / MEDIUM=中风险 / HIGH=高风险
enum class ActRiskGrade {
    LOW = 0,
    MEDIUM = 1,
    HIGH = 2
};

const char* risk_grade_name(ActRiskGrade g);

// 第七条：由影响维度判定风险等级
ActRiskGrade grade_by_impact(OutputImpact impact);

// 第八条：豁免情形
enum class ExemptionReason {
    PURE_RESEARCH,        // 纯研发实验，未部署生产
    INTERNAL_TEST,        // 内部测试，不面向公众
    OPEN_SOURCE_NONCOMMERCIAL, // 开源模型非商业分发
    EQUIVALENT_FRAMEWORK  // 已被等效合规框架覆盖
};

const char* exemption_reason_name(ExemptionReason r);

// 风险等级登记（第七条）：自评 + 委员会确认 + 变更备案
class RiskRegister {
public:
    // 初始登记：开发者自评等级 + 影响维度
    void self_assess(OutputImpact impact);
    // 安全委员会确认/调整等级（第五条：委员会审批风险等级判定与调整）
    void committee_confirm(ActRiskGrade grade, const std::string& committee_ref);
    // 等级变更备案（记录审计事件）
    void change_grade(ActRiskGrade new_grade, const std::string& reason);

    [[nodiscard]] ActRiskGrade current_grade() const { return grade_; }
    [[nodiscard]] bool is_confirmed() const { return confirmed_; }
    [[nodiscard]] std::string committee_ref() const { return committee_ref_; }
    [[nodiscard]] uint64_t change_count() const { return changes_; }

    // 第八条：申请豁免
    void apply_exemption(ExemptionReason reason, const std::string& applicant);
    [[nodiscard]] bool is_exempt() const { return exempt_; }
    [[nodiscard]] ExemptionReason exemption_reason() const { return exempt_reason_; }

    // 复评：返回当前判定（供合规自检）
    [[nodiscard]] bool self_check_pass() const;

private:
    ActRiskGrade grade_ = ActRiskGrade::LOW;
    bool confirmed_ = false;
    std::string committee_ref_;
    uint64_t changes_ = 0;
    bool exempt_ = false;
    ExemptionReason exempt_reason_ = ExemptionReason::PURE_RESEARCH;
};

} // namespace act
} // namespace photon_kernel

#endif
