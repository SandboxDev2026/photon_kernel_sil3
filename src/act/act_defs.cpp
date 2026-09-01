#include "photon_kernel/act/act_defs.hpp"

namespace photon_kernel {
namespace act {

const char* act_chapter_name(ActChapter ch) {
    switch (ch) {
        case ActChapter::GENERAL:          return "第一章 总则";
        case ActChapter::GOVERNANCE:       return "第二章 组织治理";
        case ActChapter::RISK_GRADING:     return "第三章 风险分级";
        case ActChapter::R_D:              return "第四章 研发阶段要求";
        case ActChapter::DEPLOY_RUN:       return "第五章 部署与运行";
        case ActChapter::COMPLIANCE_CHECK: return "第六章 合规检查";
        case ActChapter::VIOLATION:        return "第七章 违规与处罚";
        case ActChapter::TRANSITION:       return "第八章 生效与过渡";
    }
    return "未知章节";
}

const char* compliance_status_name(ComplianceStatus st) {
    switch (st) {
        case ComplianceStatus::PASS: return "PASS";
        case ComplianceStatus::FAIL: return "FAIL";
        case ComplianceStatus::NA:   return "N/A";
    }
    return "?";
}

ActArticle act_article(int n) {
    static const ActArticle kArticles[] = {
        {1,  ActChapter::GENERAL,          "目的",
         "建立AI系统全生命周期安全管理框架，满足可观测、可控、可追溯"},
        {2,  ActChapter::GENERAL,          "适用范围",
         "适用于工程交付/生产就绪的代码、数据、模型及配套文档；AI生成代码与人类代码同责"},
        {3,  ActChapter::GENERAL,          "核心原则",
         "可观测性、可追溯性、可控性、责任明确、比例原则"},
        {4,  ActChapter::GOVERNANCE,       "责任主体",
         "明确开发者/安全负责人/部署者/合规审计方职责"},
        {5,  ActChapter::GOVERNANCE,       "安全委员会",
         "设立安全委员会：审批风险等级、调查处置、推动整改"},
        {6,  ActChapter::GOVERNANCE,       "申诉与复核",
         "被审计方15个工作日内申诉，复核小组30个工作日内复核"},
        {7,  ActChapter::RISK_GRADING,     "风险等级判定",
         "按输出对物理世界与人类认知的影响分低/中/高三等，自评+委员会确认+变更备案"},
        {8,  ActChapter::RISK_GRADING,     "豁免机制",
         "纯研发/内部测试/开源非商业/等效框架覆盖可申请豁免"},
        {9,  ActChapter::R_D,              "需求阶段",
         "风险自评、安全需求规格（数据来源合法性）、第三方依赖合规审查"},
        {10, ActChapter::R_D,              "开发阶段",
         "提交可追溯、静态分析+单元测试、数据脱敏与权限控制、接口边界"},
        {11, ActChapter::R_D,              "测试阶段",
         "正常/边界/异常路径用例、输出限幅实测、高风险红队或沙盒推演"},
        {12, ActChapter::DEPLOY_RUN,       "输出限幅",
         "预设输出安全边界，超界自动钳位到边界值并继续运行，边界值备案"},
        {13, ActChapter::DEPLOY_RUN,       "逻辑熔断",
         "维护关键指标动态基线，超绝对硬限制拒绝新任务并返回明确错误码"},
        {14, ActChapter::DEPLOY_RUN,       "硬件自诊断",
         "物理执行器系统每次推理前检查传感器；云原生检查容器资源节流与内存"},
        {15, ActChapter::DEPLOY_RUN,       "审计日志",
         "记录6类关键事件：推理请求输出/限幅触发/熔断状态/权限模型切换/人工覆盖/执行器反馈超阈值，原始数据脱敏"},
        {16, ActChapter::COMPLIANCE_CHECK, "检查权",
         "安全委员会基于风险触发对已交付系统进行运行时检查"},
        {17, ActChapter::COMPLIANCE_CHECK, "检查内容",
         "实际行为与备案一致、限幅生效、审计完整、安全措施落实"},
        {18, ActChapter::COMPLIANCE_CHECK, "检查配合",
         "被检查方须配合，提供访问权限/日志/配置，拒绝视为违规"},
        {19, ActChapter::VIOLATION,        "违规认定",
         "申报不实/限幅缺失/自诊断缺失/熔断缺失/评估缺失/审计造假/拒绝配合的处罚映射"},
        {20, ActChapter::VIOLATION,        "处罚执行",
         "处罚决定须载明事实/条款/措施/期限，被处罚方有权申诉"},
        {21, ActChapter::TRANSITION,       "生效日期",
         "自发布之日起即时生效"},
        {22, ActChapter::TRANSITION,       "过渡期",
         "新项目即时全量执行；存量低风险3/中9/高15个月"},
    };
    if (n < 1 || n > 22) return ActArticle{0, ActChapter::GENERAL, nullptr, nullptr};
    return kArticles[n - 1];
}

} // namespace act
} // namespace photon_kernel
