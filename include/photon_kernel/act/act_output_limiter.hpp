#ifndef PHOTON_KERNEL_ACT_OUTPUT_LIMITER_HPP
#define PHOTON_KERNEL_ACT_OUTPUT_LIMITER_HPP

// 第十二条 —— 输出限幅
// 系统须预设输出安全边界；输出超出边界时自动钳位在边界值，系统继续运行。
// 边界值须在安全案例中记录并备案。

#include <cstdint>
#include <mutex>
#include <string>

namespace photon_kernel {
namespace act {

struct LimitBounds {
    double min_value;
    double max_value;
};

class OutputLimiter {
public:
    OutputLimiter() = default;
    OutputLimiter(double lo, double hi) { set_bounds(lo, hi); }

    // 设置（备案）输出安全边界
    void set_bounds(double lo, double hi);

    // 对输出值限幅：超出边界钳位到边界值并返回（系统继续运行）
    // triggered 输出参数：是否触发限幅
    double apply(double value, bool* triggered = nullptr);

    // 触发次数与备案信息
    [[nodiscard]] uint64_t trigger_count() const;
    [[nodiscard]] LimitBounds bounds() const;

    // 第十二条合规自检：边界已备案且触发过实测（第十一条测试阶段要求限幅实测）
    [[nodiscard]] bool self_check_pass() const;

    // 标记已实测（第十一条：输出限幅机制须通过实测验证）
    void mark_verified_in_test();

private:
    mutable std::mutex mtx_;
    LimitBounds bounds_{0.0, 0.0};
    bool bounds_set_ = false;
    uint64_t triggers_ = 0;
    bool verified_in_test_ = false;
};

} // namespace act
} // namespace photon_kernel

#endif
