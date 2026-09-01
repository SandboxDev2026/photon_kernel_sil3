#ifndef PHOTON_KERNEL_ACT_SELF_DIAGNOSIS_HPP
#define PHOTON_KERNEL_ACT_SELF_DIAGNOSIS_HPP

// 第十四条 —— 硬件自诊断
// 涉及物理执行器的系统须在每次推理前检查关键物理传感器；云原生环境须检查
// 容器资源节流与内存分配状态。

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace photon_kernel {
namespace act {

struct SensorInfo {
    std::string name;
    bool ok;
    std::string reading;  // 读数摘要（脱敏后）
};

struct SelfDiagnosisResult {
    bool ok = false;
    std::vector<SensorInfo> sensors;  // 物理传感器状态
    bool container_checked = false;
    bool container_throttled = false;
    double memory_watermark = 0.0;    // 0~1（当前/上限）
    bool degraded = false;            // 非 Linux / 无 cgroup：软件模拟降级路径
    std::string message;
};

class HardwareSelfDiagnosis {
public:
    // 注册关键物理传感器（物理执行器系统）
    void register_sensor(const std::string& name, bool ok, const std::string& reading);

    // 每次推理前调用：物理传感器 + 容器资源自诊断
    SelfDiagnosisResult pre_inference_check();

    // 仅容器资源检查（云原生环境，无物理执行器时）
    SelfDiagnosisResult check_container_resources();

    // 手工上报传感器状态（模拟读数，供测试/注入）
    void set_sensor_status(const std::string& name, bool ok, const std::string& reading);

    // 第十四条合规自检：高风险（物理执行器）系统已注册传感器检查能力
    [[nodiscard]] bool self_check_pass() const;
    void mark_verified_in_test();

private:
    std::vector<SensorInfo> sensors_;
    bool has_sensors_ = false;
    bool verified_in_test_ = false;
    mutable std::mutex mtx_;
};

} // namespace act
} // namespace photon_kernel

#endif
