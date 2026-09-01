#include "photon_kernel/act/act_output_limiter.hpp"

#include <mutex>

#include "photon_kernel/act/act_audit_events.hpp"

namespace photon_kernel {
namespace act {

void OutputLimiter::set_bounds(double lo, double hi) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (hi < lo) std::swap(lo, hi);
    bounds_ = {lo, hi};
    bounds_set_ = true;
}

double OutputLimiter::apply(double value, bool* triggered) {
    bool trig = false;
    double out = value;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (bounds_set_) {
            if (value > bounds_.max_value) {
                out = bounds_.max_value;
                trig = true;
            } else if (value < bounds_.min_value) {
                out = bounds_.min_value;
                trig = true;
            }
            if (trig) ++triggers_;
        }
    }
    if (trig) {
        // 第十五条：限幅触发事件审计
        ActAuditRecorder().record(AuditEventType::LIMITER_TRIGGERED,
                                  "output clamped",
                                  "\"raw\":" + std::to_string(value) +
                                  ",\"clamped\":" + std::to_string(out));
    }
    if (triggered) *triggered = trig;
    return out;
}

uint64_t OutputLimiter::trigger_count() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return triggers_;
}

LimitBounds OutputLimiter::bounds() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return bounds_;
}

bool OutputLimiter::self_check_pass() const {
    std::lock_guard<std::mutex> lock(mtx_);
    // 第十二条：边界已备案；第十一条测试：限幅已实测
    return bounds_set_ && verified_in_test_;
}

void OutputLimiter::mark_verified_in_test() {
    std::lock_guard<std::mutex> lock(mtx_);
    verified_in_test_ = true;
}

} // namespace act
} // namespace photon_kernel
