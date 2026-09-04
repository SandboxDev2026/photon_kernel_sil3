#ifndef PHOTON_KERNEL_SANDBOX_RISK_LEVEL_HPP
#define PHOTON_KERNEL_SANDBOX_RISK_LEVEL_HPP
// 统一风险等级定义（避免多文件重复定义导致编译冲突）
//
// 风险等级用于：
//   - TaskSpec 风险评估
//   - Metrics 风险分数分布统计
//   - StrongPool 调度决策（HIGH/CRITICAL 必须 MicroVM）
//   - 安全域分配（TRUSTED / UNTRUSTED / SANDBOX_ONCE）
namespace photon_kernel {
namespace sandbox {
enum class RiskLevel {
    LOW,       // 可信代码，纯计算，无 IO → DOMAIN_TRUSTED + LightPool
    MEDIUM,    // 有文件/网络访问但可控 → DOMAIN_TRUSTED + LightPool
    HIGH,      // 有进程/提权/逃逸尝试 → DOMAIN_UNTRUSTED + StrongPool (MicroVM)
    CRITICAL,  // 明确恶意（挖矿/数据外泄/内核攻击）→ DOMAIN_SANDBOX_ONCE + 一次性销毁
    INFO,      // 信息性，建议优化（安全态势检测专用）
    SAFE,      // 已防护，无风险（安全态势检测专用）
};
inline const char* risk_level_name(RiskLevel r) {
    switch (r) {
        case RiskLevel::LOW: return "low";
        case RiskLevel::MEDIUM: return "medium";
        case RiskLevel::HIGH: return "high";
        case RiskLevel::CRITICAL: return "critical";
        case RiskLevel::INFO: return "info";
        case RiskLevel::SAFE: return "safe";
    }
    return "unknown";
}
} // namespace sandbox
} // namespace photon_kernel
#endif // PHOTON_KERNEL_SANDBOX_RISK_LEVEL_HPP
