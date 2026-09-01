#ifndef PHOTON_KERNEL_ACT_GOVERNANCE_HPP
#define PHOTON_KERNEL_ACT_GOVERNANCE_HPP

// 第四条 —— 责任主体；第五条 —— 安全委员会；第六条 —— 申诉与复核
// 开发/部署/运维各环节明确：开发者、安全负责人、部署者、合规审计方；
// 安全委员会负责审批风险等级、调查处置、推动整改；被审计方 15 工作日申诉、
// 复核小组 30 工作日复核（紧急措施除外）。

#include <cstdint>
#include <string>
#include <vector>

namespace photon_kernel {
namespace act {

enum class ResponsibleRole {
    DEVELOPER,            // 开发者：设计/编码/测试
    SAFETY_OFFICER,       // 安全负责人：安全需求评审/风险识别/合规审查/事件响应
    DEPLOYER,             // 部署者：部署/配置管理/运行监控/日志留存
    COMPLIANCE_AUDITOR    // 合规审计方：独立定期/不定期检查
};

const char* responsible_role_name(ResponsibleRole r);

// 第四条：责任主体登记
class ActGovernance {
public:
    // 登记责任主体（name + 角色）
    void assign(ResponsibleRole role, const std::string& name);
    [[nodiscard]] bool has_role(ResponsibleRole role) const;
    [[nodiscard]] std::vector<std::string> role_holders(ResponsibleRole role) const;

    // 第五条：安全委员会（成员与项目无直接利益关联）
    void add_committee_member(const std::string& name, const std::string& domain);
    [[nodiscard]] size_t committee_size() const;
    [[nodiscard]] bool committee_quorum(size_t need = 1) const;

    // 第六条：申诉与复核（15 工作日申诉 / 30 工作日复核）
    // 返回是否受理（申诉在期限内）
    bool submit_appeal(const std::string& from, const std::string& decision_ref);
    [[nodiscard]] bool is_appeal_pending() const;
    // 复核完成（30 工作日内）
    bool conclude_review(const std::string& decision);
    [[nodiscard]] bool review_concluded() const;

    // 合规自检：第四条 责任主体齐备
    [[nodiscard]] bool self_check_pass() const;

private:
    std::vector<std::pair<ResponsibleRole, std::string>> assignees_;
    std::vector<std::pair<std::string, std::string>> committee_;
    std::string appeal_from_;
    std::string appeal_decision_ref_;
    bool appeal_pending_ = false;
    bool review_done_ = false;
};

} // namespace act
} // namespace photon_kernel

#endif
