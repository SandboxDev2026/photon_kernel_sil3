#ifndef PHOTON_KERNEL_ACT_COMPLIANCE_HPP
#define PHOTON_KERNEL_ACT_COMPLIANCE_HPP

// 法案合规引擎：将《人工智能工程安全管理法案》22 条逐条落地为可执行的合规自检。
// 运行时对全部条款 self-check，输出每条 PASS / FAIL / N/A 与证据，并生成合规报告。

#include <string>
#include <vector>

#include "photon_kernel/act/act_defs.hpp"
#include "photon_kernel/act/act_risk_grade.hpp"
#include "photon_kernel/act/act_output_limiter.hpp"
#include "photon_kernel/act/act_circuit_breaker.hpp"
#include "photon_kernel/act/act_self_diagnosis.hpp"
#include "photon_kernel/act/act_governance.hpp"
#include "photon_kernel/act/act_lifecycle.hpp"
#include "photon_kernel/act/act_penalty.hpp"
#include "photon_kernel/act/act_evidence.hpp"

namespace photon_kernel {
namespace act {

struct ComplianceItem {
    int article;
    ActChapter chapter;
    std::string title;
    ComplianceStatus status;
    std::string evidence;
};

class ActComplianceEngine {
public:
    ActComplianceEngine();

    // 关联各可执行条款模块
    void attach(RiskRegister* risk, OutputLimiter* limiter, CircuitBreaker* breaker,
                HardwareSelfDiagnosis* selfdiag, ActGovernance* governance,
                ActLifecycleChecklist* lifecycle, ActPenalty* penalty);
    // å³èå¯è¿½æº¯æ§è¯æ®é¾ï¼V4.14 ç¬¬åå­æ¡ï¼
    void attach(EvidenceLogger* evidence);

    // 对单条 self-check
    ComplianceItem check_article(int n);

    // 全量 22 条 self-check
    std::vector<ComplianceItem> self_check();

    // 汇总：是否全部合规（无 FAIL）
    bool all_compliant();

    // 生成 JSON 合规报告
    std::string generate_report();

private:
    RiskRegister* risk_ = nullptr;
    OutputLimiter* limiter_ = nullptr;
    CircuitBreaker* breaker_ = nullptr;
    HardwareSelfDiagnosis* selfdiag_ = nullptr;
    ActGovernance* governance_ = nullptr;
    ActLifecycleChecklist* lifecycle_ = nullptr;
    ActPenalty* penalty_ = nullptr;
    EvidenceLogger* evidence_ = nullptr;
};

} // namespace act
} // namespace photon_kernel

#endif
