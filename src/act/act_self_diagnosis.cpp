#include "photon_kernel/act/act_self_diagnosis.hpp"

#include <cstdio>
#include <fstream>
#include <mutex>

#include "photon_kernel/act/act_audit_events.hpp"

namespace photon_kernel {
namespace act {

namespace {
// 读取 cgroup v2 文件；不存在/不可读返回空
std::string read_file(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return {};
    std::string line;
    std::getline(f, line);
    return line;
}

// 解析 "key value" 形式
double parse_kv(const std::string& line, const std::string& key) {
    if (line.compare(0, key.size(), key) != 0) return -1.0;
    auto pos = line.find(' ');
    if (pos == std::string::npos) return -1.0;
    return std::atof(line.substr(pos + 1).c_str());
}
} // namespace

void HardwareSelfDiagnosis::register_sensor(const std::string& name, bool ok,
                                            const std::string& reading) {
    std::lock_guard<std::mutex> lock(mtx_);
    sensors_.push_back({name, ok, reading});
    has_sensors_ = true;
}

void HardwareSelfDiagnosis::set_sensor_status(const std::string& name, bool ok,
                                              const std::string& reading) {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto& s : sensors_) {
        if (s.name == name) {
            s.ok = ok;
            s.reading = reading;
            return;
        }
    }
    sensors_.push_back({name, ok, reading});
    has_sensors_ = true;
}

SelfDiagnosisResult HardwareSelfDiagnosis::check_container_resources() {
    SelfDiagnosisResult r;
    r.container_checked = true;
#ifndef __linux__
    // 非 Linux 平台：无 cgroup v2，走软件模拟降级路径（不误报失败）
    r.degraded = true;
    r.memory_watermark = 0.0;   // 软件模拟：无法实测，标记为 0（名义水位）
    r.container_throttled = false;
    r.ok = true;
    r.message = "non-Linux platform: container check degraded (software-simulated)";
    return r;
#else
    // 云原生：检查容器资源节流（cgroup v2 cpu.stat 的 throttled_time 增长即节流）
    // 与内存分配状态（memory.current / memory.max）
    const std::string cpu_stat = read_file("/sys/fs/cgroup/cpu.stat");
    if (!cpu_stat.empty()) {
        // throttled_time 非零表示发生过 CPU 节流
        double throttled = -1.0;
        std::ifstream f("/sys/fs/cgroup/cpu.stat");
        std::string line;
        while (std::getline(f, line)) {
            double v = parse_kv(line, "throttled_time");
            if (v >= 0.0) throttled = v;
        }
        r.container_throttled = throttled > 0.0;
    } else {
        // Linux 但无 cgroup 挂载（非容器/权限不足）：软件模拟降级路径
        r.degraded = true;
        r.container_checked = false;
    }
    double cur = std::atof(read_file("/sys/fs/cgroup/memory.current").c_str());
    double max = std::atof(read_file("/sys/fs/cgroup/memory.max").c_str());
    if (max > 0.0) {
        r.memory_watermark = cur / max;
        r.container_checked = true;
    } else if (r.container_checked) {
        // cgroup 存在但 memory.max 不可读：降级为名义水位
        r.degraded = true;
        r.memory_watermark = 0.0;
    } else {
        r.memory_watermark = 0.0;
    }
    r.ok = !r.container_throttled && r.memory_watermark < 0.90;
    r.message = r.ok ? (r.degraded
                            ? "container check degraded (cgroup unavailable, simulated)"
                            : "container resources nominal")
                     : "container resource threshold exceeded";
    if (!r.ok) {
        // 第十五条：执行器反馈超阈值事件
        ActAuditRecorder().record(AuditEventType::EXECUTOR_FEEDBACK_THRESHOLD,
                                  r.message,
                                  "\"mem_watermark\":" + std::to_string(r.memory_watermark));
    }
    return r;
#endif
}
SelfDiagnosisResult HardwareSelfDiagnosis::pre_inference_check() {
    SelfDiagnosisResult r;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        r.sensors = sensors_;
    }
    r.ok = true;
    for (const auto& s : r.sensors) {
        if (!s.ok) {
            r.ok = false;
            r.message = "sensor fault: " + s.name;
            // 第十五条：执行器反馈超阈值事件
            ActAuditRecorder().record(AuditEventType::EXECUTOR_FEEDBACK_THRESHOLD,
                                      r.message,
                                      "\"sensor\":\"" + s.name + "\"");
            break;
        }
    }
    if (r.ok && r.message.empty()) {
        r.message = "all sensors nominal";
    }
    return r;
}

bool HardwareSelfDiagnosis::self_check_pass() const {
    std::lock_guard<std::mutex> lock(mtx_);
    // 第十四条：物理执行器系统须具备每次推理前传感器检查能力
    return has_sensors_ && verified_in_test_;
}

void HardwareSelfDiagnosis::mark_verified_in_test() {
    std::lock_guard<std::mutex> lock(mtx_);
    verified_in_test_ = true;
}

} // namespace act
} // namespace photon_kernel
