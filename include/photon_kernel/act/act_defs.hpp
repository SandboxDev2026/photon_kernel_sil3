#ifndef PHOTON_KERNEL_ACT_DEFS_HPP
#define PHOTON_KERNEL_ACT_DEFS_HPP

// 《人工智能工程安全管理法案》——条款编号与合规状态基础定义
// 该法案 8 章 22 条，约束人工智能系统从概念到工程实体的完整落地。
// 本模块将 22 条逐条结构化，供合规引擎（act_compliance）与各可执行条款模块使用。

#include <cstdint>
#include <string>

namespace photon_kernel {
namespace act {

// ---- 法案章节 ----
enum class ActChapter {
    GENERAL,          // 第一章 总则（1-3）
    GOVERNANCE,       // 第二章 组织治理（4-6）
    RISK_GRADING,     // 第三章 风险分级（7-8）
    R_D,              // 第四章 研发阶段（9-11）
    DEPLOY_RUN,       // 第五章 部署与运行（12-15）
    COMPLIANCE_CHECK, // 第六章 合规检查（16-18）
    VIOLATION,        // 第七章 违规与处罚（19-20）
    TRANSITION        // 第八章 生效与过渡（21-22）
};

// ---- 合规项状态 ----
enum class ComplianceStatus {
    PASS,   // 已满足并留有证据
    FAIL,   // 未满足（违规）
    NA      // 不适用（如豁免/低风险不要求项）
};

const char* act_chapter_name(ActChapter ch);
const char* compliance_status_name(ComplianceStatus st);

// ---- 法案条款常量（article 编号 1..22） ----
struct ActArticle {
    int id;                 // 条款号
    ActChapter chapter;
    const char* title;
    const char* requirement; // 法案要求摘要
};

// 返回第 n 条的元数据（n 越界返回 {0,null,null,null}）
ActArticle act_article(int n);

} // namespace act
} // namespace photon_kernel

#endif
