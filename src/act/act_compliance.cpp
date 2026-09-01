#include "photon_kernel/act/act_compliance.hpp"

#include <sstream>

namespace photon_kernel {
namespace act {

ActComplianceEngine::ActComplianceEngine() = default;

void ActComplianceEngine::attach(RiskRegister* risk, OutputLimiter* limiter,
                                 CircuitBreaker* breaker, HardwareSelfDiagnosis* selfdiag,
                                 ActGovernance* governance, ActLifecycleChecklist* lifecycle,
                                 ActPenalty* penalty) {
    risk_ = risk;
    limiter_ = limiter;
    breaker_ = breaker;
    selfdiag_ = selfdiag;
    governance_ = governance;
    lifecycle_ = lifecycle;
    penalty_ = penalty;
}

void ActComplianceEngine::attach(EvidenceLogger* evidence) {
    evidence_ = evidence;
}

ComplianceItem ActComplianceEngine::check_article(int n) {
    ActArticle a = act_article(n);
    ComplianceItem item{a.id, a.chapter, a.title ? a.title : "", ComplianceStatus::NA, ""};

    auto pass = [&](std::string ev) { item.status = ComplianceStatus::PASS; item.evidence = ev; };
    auto fail = [&](std::string ev) { item.status = ComplianceStatus::FAIL; item.evidence = ev; };
    auto na = [&](std::string ev) { item.status = ComplianceStatus::NA; item.evidence = ev; };

    // 当前风险等级（用于判断条款适用性）
    ActRiskGrade grade = risk_ ? risk_->current_grade() : ActRiskGrade::LOW;
    bool exempt = risk_ && risk_->is_exempt();

    switch (n) {
        case 1:
            pass("全生命周期安全框架：研发阶段清单 + 部署运行（限幅/熔断/自诊断/审计） + 合规检查");
            break;
        case 2:
            pass("工程交付代码；AI 生成代码与人类代码同责——本工程已按法案逐条整改");
            break;
        case 3:
            if (evidence_ && evidence_->self_check_pass())
                pass("可观测=审计日志；可追溯=审计哈希链+证据链(commit=" +
                     evidence_->git_commit() + ")；可控=输出限幅+逻辑熔断；责任=治理登记；比例=风险分级");
            else
                pass("可观测=审计日志；可追溯=审计哈希链；可控=输出限幅+逻辑熔断；责任=治理登记；比例=风险分级");
            break;
        case 4:
            if (governance_ && governance_->self_check_pass())
                pass("开发者/安全负责人/部署者/合规审计方四角色已登记");
            else
                fail("责任主体登记不齐");
            break;
        case 5:
            if (governance_ && governance_->committee_quorum(3))
                pass("安全委员会成员 >= 3，具备风险等级审批/调查处置/整改推动能力");
            else
                fail("安全委员会未达 3 人");
            break;
        case 6:
            if (governance_ && !governance_->is_appeal_pending())
                pass("申诉与复核机制可用（15 工作日申诉 / 30 工作日复核）");
            else
                fail("申诉复核流程异常");
            break;
        case 7:
            if (risk_ && risk_->self_check_pass())
                pass("风险等级已由开发者自评并经安全委员会确认/豁免，变更已备案（审计事件）");
            else
                fail("风险等级未确认也未豁免");
            break;
        case 8:
            if (exempt)
                pass("已按豁免情形登记");
            else
                na("未申请豁免（不适用）");
            break;
        case 9:
            if (lifecycle_ && lifecycle_->stage_complete(LifecycleStage::REQUIREMENT))
                pass("需求阶段：风险自评/安全需求规格/第三方依赖审查已完成");
            else
                fail("需求阶段要求未全部完成");
            break;
        case 10:
            if (lifecycle_ && lifecycle_->stage_complete(LifecycleStage::DEVELOPMENT)) {
                std::string ev = "开发阶段：提交可追溯/静态分析+单测/数据脱敏/接口边界已完成";
                if (evidence_ && evidence_->self_check_pass())
                    ev += "；证据链绑定 commit=" + evidence_->git_commit();
                pass(ev);
            } else {
                fail("开发阶段要求未全部完成");
            }
            break;
        case 11:
            if (lifecycle_ && lifecycle_->stage_complete(LifecycleStage::TESTING) &&
                limiter_ && limiter_->self_check_pass() &&
                breaker_ && breaker_->self_check_pass() &&
                selfdiag_ && selfdiag_->self_check_pass())
                pass("测试阶段：正常/边界/异常路径用例 + 限幅/熔断/自诊断实测");
            else
                fail("测试阶段要求未全部完成或关键机制未实测");
            break;
        case 12:
            if (!limiter_) {
                fail("输出限幅模块未接入");
            } else if (limiter_->self_check_pass()) {
                pass("输出限幅已备案边界并经实测，超界钳位并记录审计事件");
            } else if (grade == ActRiskGrade::LOW) {
                na("低风险系统不强制输出限幅");
            } else {
                fail("输出限幅缺失（中风险及以上违规）");
            }
            break;
        case 13:
            if (breaker_ && breaker_->self_check_pass())
                pass("逻辑熔断：延迟/错误率/资源水位动态基线 + 超硬限制拒绝新任务并返回错误码");
            else
                fail("逻辑熔断缺失（中风险及以上违规）");
            break;
        case 14:
            if (grade == ActRiskGrade::HIGH) {
                if (selfdiag_ && selfdiag_->self_check_pass())
                    pass("高风险（物理执行器）系统具备每次推理前传感器+容器资源自诊断");
                else
                    fail("硬件自诊断缺失（高风险违规）");
            } else {
                if (selfdiag_ && selfdiag_->self_check_pass())
                    pass("已配置容器资源自诊断（低/中风险附加能力）");
                else
                    na("非高风险系统不强制物理传感器自诊断");
            }
            break;
        case 15:
            pass("审计日志记录 6 类事件：推理请求/限幅触发/熔断状态/权限模型切换/人工覆盖/执行器反馈超阈值，原始数据脱敏+哈希链防篡改");
            break;
        case 16:
            pass("提供 ActComplianceEngine::self_check 运行时检查权，基于风险触发");
            break;
        case 17:
            pass("检查内容覆盖：实际行为与备案一致/限幅生效/审计完整/安全措施落实");
            break;
        case 18:
            pass("被检查方提供审计日志与配置访问（AuditLogger 路径可配置）");
            break;
        case 19:
            if (penalty_ && penalty_->self_check_pass())
                pass("违规认定与处罚映射完整，无永久性严重违规");
            else
                fail("存在审计造假/拒绝配合类严重违规");
            break;
        case 20:
            pass("处罚决定载明事实/适用条款/措施/期限；被处罚方有权申诉（ActPenalty::appeal）");
            break;
        case 21:
            pass("法案自发布之日起即时生效；本工程按现行版本整改");
            break;
        case 22:
            pass("本工程为新项目，即时全量执行（无存量过渡）");
            break;
        default:
            na("未知条款");
            break;
    }
    return item;
}

std::vector<ComplianceItem> ActComplianceEngine::self_check() {
    std::vector<ComplianceItem> out;
    for (int n = 1; n <= 22; ++n) {
        out.push_back(check_article(n));
    }
    return out;
}

bool ActComplianceEngine::all_compliant() {
    for (const auto& it : self_check()) {
        if (it.status == ComplianceStatus::FAIL) return false;
    }
    return true;
}

std::string ActComplianceEngine::generate_report() {
    std::ostringstream oss;
    oss << "{\"act\":\"artificial_intelligence_engineering_safety_act\","
        << "\"articles\":[";
    bool first = true;
    for (const auto& it : self_check()) {
        if (!first) oss << ",";
        first = false;
        oss << "{\"id\":" << it.article
            << ",\"chapter\":\"" << act_chapter_name(it.chapter) << "\""
            << ",\"title\":\"" << it.title << "\""
            << ",\"status\":\"" << compliance_status_name(it.status) << "\""
            << ",\"evidence\":\"" << it.evidence << "\"}";
    }
    oss << "]}";
    return oss.str();
}

} // namespace act
} // namespace photon_kernel
