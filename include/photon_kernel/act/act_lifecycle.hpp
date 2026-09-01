#ifndef PHOTON_KERNEL_ACT_LIFECYCLE_HPP
#define PHOTON_KERNEL_ACT_LIFECYCLE_HPP

// 第九条 —— 需求阶段；第十条 —— 开发阶段；第十一条 —— 测试阶段
// 研发阶段要求清单（每项登记完成状态与证据）。

#include <cstdint>
#include <string>
#include <vector>

namespace photon_kernel {
namespace act {

enum class LifecycleStage {
    REQUIREMENT,  // 第九条 需求阶段
    DEVELOPMENT,  // 第十条 开发阶段
    TESTING       // 第十一条 测试阶段
};

const char* lifecycle_stage_name(LifecycleStage s);

// 研发阶段要求项
struct LifecycleItem {
    LifecycleStage stage;
    const char* title;      // 要求名称
    bool done = false;
    std::string evidence;   // 证据（如报告/提交/测试引用）
};

class ActLifecycleChecklist {
public:
    // 创建标准检查清单（第九~十一条）
    ActLifecycleChecklist();

    // 标记某要求项完成并附证据
    bool complete(LifecycleStage stage, const char* title, const std::string& evidence);

    // 按阶段汇总：是否全部完成
    [[nodiscard]] bool stage_complete(LifecycleStage stage) const;
    [[nodiscard]] bool all_complete() const;

    [[nodiscard]] std::vector<LifecycleItem> items() const;
    [[nodiscard]] std::vector<LifecycleItem> items_of(LifecycleStage stage) const;

    // 合规自检：三阶段要求全部完成
    [[nodiscard]] bool self_check_pass() const;

private:
    std::vector<LifecycleItem> items_;
};

} // namespace act
} // namespace photon_kernel

#endif
