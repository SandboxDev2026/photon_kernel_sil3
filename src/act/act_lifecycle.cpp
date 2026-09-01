#include "photon_kernel/act/act_lifecycle.hpp"

namespace photon_kernel {
namespace act {

const char* lifecycle_stage_name(LifecycleStage s) {
    switch (s) {
        case LifecycleStage::REQUIREMENT: return "requirement";
        case LifecycleStage::DEVELOPMENT: return "development";
        case LifecycleStage::TESTING:     return "testing";
    }
    return "?";
}

ActLifecycleChecklist::ActLifecycleChecklist() {
    // 第九条 需求阶段
    items_.push_back({LifecycleStage::REQUIREMENT, "风险等级自评", false, ""});
    items_.push_back({LifecycleStage::REQUIREMENT,
                      "安全需求规格文档（含数据来源合法性声明）", false, ""});
    items_.push_back({LifecycleStage::REQUIREMENT, "第三方依赖合规审查", false, ""});
    // 第十条 开发阶段
    items_.push_back({LifecycleStage::DEVELOPMENT, "代码提交记录完整可追溯", false, ""});
    items_.push_back({LifecycleStage::DEVELOPMENT, "核心模块静态分析与单元测试", false, ""});
    items_.push_back({LifecycleStage::DEVELOPMENT, "数据脱敏与权限控制", false, ""});
    items_.push_back({LifecycleStage::DEVELOPMENT, "接口输入输出边界与异常处理", false, ""});
    // 第十一条 测试阶段
    items_.push_back({LifecycleStage::TESTING, "正常/边界/异常路径用例", false, ""});
    items_.push_back({LifecycleStage::TESTING, "输出限幅机制实测", false, ""});
    items_.push_back({LifecycleStage::TESTING, "高风险红队测试/沙盒推演", false, ""});
}

bool ActLifecycleChecklist::complete(LifecycleStage stage, const char* title,
                                     const std::string& evidence) {
    for (auto& it : items_) {
        if (it.stage == stage && std::string(it.title) == title) {
            it.done = true;
            it.evidence = evidence;
            return true;
        }
    }
    return false;
}

bool ActLifecycleChecklist::stage_complete(LifecycleStage stage) const {
    for (const auto& it : items_) {
        if (it.stage == stage && !it.done) return false;
    }
    return true;
}

bool ActLifecycleChecklist::all_complete() const {
    return stage_complete(LifecycleStage::REQUIREMENT) &&
           stage_complete(LifecycleStage::DEVELOPMENT) &&
           stage_complete(LifecycleStage::TESTING);
}

std::vector<LifecycleItem> ActLifecycleChecklist::items() const {
    return items_;
}

std::vector<LifecycleItem> ActLifecycleChecklist::items_of(LifecycleStage stage) const {
    std::vector<LifecycleItem> out;
    for (const auto& it : items_) {
        if (it.stage == stage) out.push_back(it);
    }
    return out;
}

bool ActLifecycleChecklist::self_check_pass() const {
    return all_complete();
}

} // namespace act
} // namespace photon_kernel
