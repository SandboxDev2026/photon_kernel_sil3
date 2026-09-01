#include "photon_kernel/act/act_circuit_breaker.hpp"

#include <algorithm>
#include <mutex>

#include "photon_kernel/act/act_audit_events.hpp"

namespace photon_kernel {
namespace act {

namespace {
constexpr double kAlpha = 0.3;  // EWMA 平滑系数（动态基线）
}

const char* breaker_state_name(BreakerState s) {
    switch (s) {
        case BreakerState::CLOSED: return "CLOSED";
        case BreakerState::OPEN:   return "OPEN";
    }
    return "?";
}

const char* breaker_error_name(BreakerError e) {
    switch (e) {
        case BreakerError::OK:                  return "OK";
        case BreakerError::REJECTED_HIGH_LATENCY: return "REJECTED_HIGH_LATENCY";
        case BreakerError::REJECTED_HIGH_ERROR_RATE: return "REJECTED_HIGH_ERROR_RATE";
        case BreakerError::REJECTED_HIGH_RESOURCE: return "REJECTED_HIGH_RESOURCE";
    }
    return "?";
}

void CircuitBreaker::set_limits(BreakerLimits l) {
    std::lock_guard<std::mutex> lock(mtx_);
    limits_ = l;
    limits_set_ = true;
}

void CircuitBreaker::record_latency(double latency_ms) {
    std::lock_guard<std::mutex> lock(mtx_);
    ewma_latency_ = (samples_ == 0) ? latency_ms
                                    : kAlpha * latency_ms + (1 - kAlpha) * ewma_latency_;
    ++samples_;
}

void CircuitBreaker::record_error(bool is_error) {
    std::lock_guard<std::mutex> lock(mtx_);
    double val = is_error ? 1.0 : 0.0;
    ewma_error_ = (samples_ == 0) ? val : kAlpha * val + (1 - kAlpha) * ewma_error_;
    ++samples_;
}

void CircuitBreaker::record_resource(double watermark) {
    std::lock_guard<std::mutex> lock(mtx_);
    watermark = std::clamp(watermark, 0.0, 1.0);
    ewma_resource_ = (samples_ == 0) ? watermark
                                     : kAlpha * watermark + (1 - kAlpha) * ewma_resource_;
    ++samples_;
}

BreakerError CircuitBreaker::check_accept() {
    BreakerError err = BreakerError::OK;
    BreakerState new_state = BreakerState::CLOSED;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (limits_set_) {
            if (ewma_latency_ > limits_.max_latency_ms) {
                err = BreakerError::REJECTED_HIGH_LATENCY;
            } else if (ewma_error_ > limits_.max_error_rate) {
                err = BreakerError::REJECTED_HIGH_ERROR_RATE;
            } else if (ewma_resource_ > limits_.max_resource_watermark) {
                err = BreakerError::REJECTED_HIGH_RESOURCE;
            }
            if (err != BreakerError::OK) new_state = BreakerState::OPEN;
        }
    }
    // 状态变更：审计（第十五条 熔断状态变更）
    if (new_state != state_) {
        ActAuditRecorder().record(AuditEventType::BREAKER_STATE_CHANGE,
                                  "breaker " + std::string(breaker_state_name(state_)) +
                                      " -> " + std::string(breaker_state_name(new_state)),
                                  "\"reason\":\"" + std::string(breaker_error_name(err)) + "\"");
        std::lock_guard<std::mutex> lock(mtx_);
        state_ = new_state;
    }
    return err;
}

BreakerState CircuitBreaker::state() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return state_;
}

double CircuitBreaker::baseline_latency_ms() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return ewma_latency_;
}

double CircuitBreaker::baseline_error_rate() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return ewma_error_;
}

double CircuitBreaker::baseline_resource_watermark() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return ewma_resource_;
}

bool CircuitBreaker::self_check_pass() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return limits_set_ && verified_in_test_;
}

void CircuitBreaker::mark_verified_in_test() {
    std::lock_guard<std::mutex> lock(mtx_);
    verified_in_test_ = true;
}

} // namespace act
} // namespace photon_kernel
