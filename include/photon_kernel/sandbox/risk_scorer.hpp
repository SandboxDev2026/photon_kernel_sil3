#ifndef PHOTON_KERNEL_SANDBOX_RISK_SCORER_HPP
#define PHOTON_KERNEL_SANDBOX_RISK_SCORER_HPP
// RiskScorer —— 输入代码片段，输出风险等级，自动选择安全域和运行时后端。
// 基于静态特征扫描（不执行代码），检测危险模式：
//   - 网络访问（socket/urllib/requests/http）
//   - 文件系统访问（/etc/passwd、/proc、写系统目录）
//   - 进程操作（fork/exec/system/subprocess/popen）
//   - 提权尝试（setuid/chmod/sudo/capabilities）
//   - 逃逸尝试（seccomp/prctl/ptrace/内核模块）
//   - 加密挖矿（cryptominer 特征、大量 CPU 循环）
//   - 数据外泄（大文件读取+网络发送组合）
#include <string>
#include <vector>
#include <regex>
namespace photon_kernel {
namespace sandbox {
enum class RiskLevel {
    LOW,       // 可信代码，纯计算，无 IO → DOMAIN_TRUSTED + LightPool
    MEDIUM,    // 有文件/网络访问但可控 → DOMAIN_TRUSTED + LightPool
    HIGH,      // 有进程/提权/逃逸尝试 → DOMAIN_UNTRUSTED + StrongPool (MicroVM)
    CRITICAL,  // 明确恶意（挖矿/数据外泄/内核攻击）→ DOMAIN_SANDBOX_ONCE + 一次性销毁
};
struct RiskScanResult {
    RiskLevel level = RiskLevel::LOW;
    int score = 0;                          // 0-100
    std::vector<std::string> detected_patterns;  // 检测到的危险模式
    std::string recommended_domain;         // 推荐安全域
    std::string recommended_backend;        // 推荐运行时后端
    std::string reason;                     // 风险判断理由
};
class RiskScorer {
public:
    RiskScorer();
    // 扫描代码，返回风险评估结果
    RiskScanResult scan(const std::string& code, const std::string& language = "python") const;
    // 根据风险等级推荐安全域
    static std::string domain_for(RiskLevel level);
    // 根据风险等级推荐运行时后端
    static std::string backend_for(RiskLevel level);
    // 获取风险等级名称
    static std::string level_name(RiskLevel level);
private:
    struct Pattern {
        std::regex re;
        std::string name;
        int weight;
        RiskLevel min_level;
    };
    std::vector<Pattern> patterns_;
    void init_patterns();
};
} // namespace sandbox
} // namespace photon_kernel
#endif
