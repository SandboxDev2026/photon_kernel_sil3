#ifndef PHOTON_KERNEL_ACT_CIRCUIT_BREAKER_HPP
#define PHOTON_KERNEL_ACT_CIRCUIT_BREAKER_HPP

// 第十三条 —— 逻辑熔断
// 系统须维护关键运行指标（延迟、错误率、资源水位）的动态基线；当指标超出
// 绝对硬限制时，系统须拒绝新任务提交并返回明确错误码。

#include <cstdint>
#include <mutex>
#include <string>

namespace photon_kernel {
namespace act {

// 明确错误码（拒绝新任务时返回）
enum class BreakerError {
    OK = 0,
    REJECTED_HIGH_LATENCY,      // 延迟超绝对硬限制
    REJECTED_HIGH_ERROR_RATE,   // 错误率超绝对硬限制
    REJECTED_HIGH_RESOURCE,     // 资源水位超绝对硬限制
};

enum class BreakerState {
    CLOSED,   // 正常，接受新任务
    OPEN      // 熔断，拒绝新任务
};

const char* breaker_state_name(BreakerState s);
const char* breaker_error_name(BreakerError e);

struct BreakerLimits {
    double max_latency_ms = 1000.0;     // 绝对硬限制：延迟
    double max_error_rate = 0.50;       // 绝对硬限制：错误率（EWMA，0~1）
    double max_resource_watermark = 0.90; // 绝对硬限制：资源水位（0~1）
};

class CircuitBreaker {
public:
    explicit CircuitBreaker(BreakerLimits limits = {}) : limits_(limits) {
        limits_set_ = true;  // 构造即配置绝对硬限制
    }

    // 配置绝对硬限制
    void set_limits(BreakerLimits l);

    // ---- 记录关键运行指标（用于维护动态基线） ----
    void record_latency(double latency_ms);
    void record_error(bool is_error);
    void record_resource(double watermark);

    // 提交新任务前检查：任一指标超硬限制 -> 拒绝并返回明确错误码
    [[nodiscard]] BreakerError check_accept();

    // 当前状态 / 动态基线
    [[nodiscard]] BreakerState state() const;
    [[nodiscard]] double baseline_latency_ms() const;
    [[nodiscard]] double baseline_error_rate() const;
    [[nodiscard]] double baseline_resource_watermark() const;

    // 第十三条合规自检：限幅/熔断已配置且状态机工作
    [[nodiscard]] bool self_check_pass() const;
    void mark_verified_in_test();

private:
    mutable std::mutex mtx_;
    BreakerLimits limits_;
    BreakerState state_ = BreakerState::CLOSED;

    double ewma_latency_ = 0.0;
    double ewma_error_ = 0.0;
    double ewma_resource_ = 0.0;
    uint64_t samples_ = 0;

    bool limits_set_ = false;
    bool verified_in_test_ = false;
};

} // namespace act
} // namespace photon_kernel

#endif
