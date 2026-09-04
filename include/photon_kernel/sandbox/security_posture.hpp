// PhotonBox 运行时安全态势检测模块
// 覆盖三类深层威胁：
//   1. 内核 0day 逃逸（Process/LightPool 后端共享宿主机内核）
//   2. 侧信道攻击（Spectre/Meltdown/L1TF/MDS/SRSO 等）
//   3. 硬件级攻击（Rowhammer/比特翻转/物理内存攻击）
//
// 设计原则：
//   - 检测优先：运行时探测宿主机防护状态，给出风险分级
//   - 纵深防御：沙盒代码层限制 + 宿主机配置建议 + 硬件依赖提示
//   - 不可替代：本模块不能替代内核补丁和硬件防护，只能检测和建议
#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <cstdint>
#include "photon_kernel/sandbox/risk_level.hpp"

namespace photon_kernel {
namespace sandbox {

// ========== 检测项结构 ==========
struct SecurityCheckItem {
    std::string id;              // 唯一标识，如 "KERNEL-001"
    std::string category;        // 分类：kernel_0day / side_channel / hardware
    std::string name;            // 检测项名称
    std::string description;     // 详细描述
    RiskLevel risk_if_unprotected; // 未防护时的风险等级
    RiskLevel current_risk;      // 当前实际风险等级
    bool is_protected;           // 是否已防护
    std::string detected_value;  // 检测到的实际值
    std::string expected_value;  // 期望值
    std::string remediation;     // 修复建议
    std::string reference;       // 参考链接/CVE编号
};

// ========== 安全态势报告 ==========
struct SecurityPostureReport {
    std::string generated_at;            // 生成时间（ISO 8601）
    std::string hostname;                // 主机名
    std::string kernel_version;          // 内核版本
    std::string cpu_vendor;              // CPU 厂商
    std::string cpu_model;               // CPU 型号
    uint64_t total_memory_mb;            // 总内存（MB）
    bool is_virtualized;                 // 是否运行在虚拟机中
    bool has_ecc_memory;                 // 是否有 ECC 内存
    bool smt_enabled;                    // 是否启用 SMT/超线程

    std::vector<SecurityCheckItem> items; // 所有检测项

    // 统计
    int critical_count = 0;
    int high_count = 0;
    int medium_count = 0;
    int low_count = 0;
    int safe_count = 0;
    int total_count = 0;

    // 总体评分（0-100，越高越安全）
    int overall_score = 0;

    // 分类评分
    int kernel_0day_score = 0;
    int side_channel_score = 0;
    int hardware_attack_score = 0;

    std::string to_json() const;
    std::string to_markdown() const;
};

// ========== 内核 0day 逃逸防护检测 ==========
class Kernel0dayChecker {
public:
    // 检测内核版本和已知 CVE
    static SecurityCheckItem check_kernel_version();

    // 检测内核命令行安全参数（如 slab_nomerge, init_on_alloc, page_poison 等）
    static SecurityCheckItem check_kernel_cmdline();

    // 检测已加载内核模块（是否有不必要的高风险模块）
    static SecurityCheckItem check_loaded_modules();

    // 检测内核 livepatch 状态
    static SecurityCheckItem check_kernel_livepatch();

    // 检测 seccomp 支持状态
    static SecurityCheckItem check_seccomp_support();

    // 检测 Landlock 支持状态
    static SecurityCheckItem check_landlock_support();

    // 检测命名空间隔离支持
    static SecurityCheckItem check_namespace_support();

    // 检测内核未授权模块加载防护（module.sig_enforce）
    static SecurityCheckItem check_module_signature();

    // 运行全部检测
    static std::vector<SecurityCheckItem> run_all_checks();
};

// ========== 侧信道攻击防护检测 ==========
class SideChannelChecker {
public:
    // 检测 CPU 漏洞状态（读取 /sys/devices/system/cpu/vulnerabilities/）
    static SecurityCheckItem check_spectre_v1();
    static SecurityCheckItem check_spectre_v2();
    static SecurityCheckItem check_spectre_v4();
    static SecurityCheckItem check_meltdown();
    static SecurityCheckItem check_l1tf();
    static SecurityCheckItem check_mds();
    static SecurityCheckItem check_swapgs();
    static SecurityCheckItem check_srso();       // AMD
    static SecurityCheckItem check_gds();        // Intel Gather Data Sampling

    // 检测微码版本
    static SecurityCheckItem check_microcode_version();

    // 检测 SMT/超线程状态（侧信道攻击的重要因素）
    static SecurityCheckItem check_smt_status();

    // 检测 KPTI（内核页表隔离）
    static SecurityCheckItem check_kpti();

    // 检测 retpoline 支持
    static SecurityCheckItem check_retpoline();

    // 检测 perf_event_open 限制（防止 perf 侧信道）
    static SecurityCheckItem check_perf_event_restriction();

    // 运行全部检测
    static std::vector<SecurityCheckItem> run_all_checks();

    // 读取 /sys/devices/system/cpu/vulnerabilities/ 下的文件
    static std::optional<std::string> read_vulnerability_state(const std::string& name);

    // 解析漏洞状态字符串，判断是否已缓解
    static bool is_vulnerability_mitigated(const std::string& state);

private:
};

// ========== 硬件级攻击防护检测 ==========
class HardwareAttackChecker {
public:
    // 检测 ECC 内存
    static SecurityCheckItem check_ecc_memory();

    // 检测 Rowhammer 防护（TRR 目标行刷新）
    static SecurityCheckItem check_rowhammer_protection();

    // 检测 hugepages 使用（Rowhammer 攻击面）
    static SecurityCheckItem check_hugepages_usage();

    // 检测内存清零（init_on_free / init_on_alloc）
    static SecurityCheckItem check_memory_zeroing();

    // 检测 cgroup 内存隔离配置
    static SecurityCheckItem check_cgroup_memory_isolation();

    // 检测 IOMMU（DMA 攻击防护）
    static SecurityCheckItem check_iommu();

    // 检测 Secure Boot（防 bootkit）
    static SecurityCheckItem check_secure_boot();

    // 检测 TPM（可信平台模块）
    static SecurityCheckItem check_tpm();

    // 运行全部检测
    static std::vector<SecurityCheckItem> run_all_checks();
};

// ========== 统一安全态势评估器 ==========
class SecurityPostureEvaluator {
public:
    // 运行全部三类检测，生成完整报告
    static SecurityPostureReport evaluate();

    // 只运行指定分类的检测
    static SecurityPostureReport evaluate_category(const std::string& category);

    // 生成宿主机加固脚本（shell）
    static std::string generate_hardening_script(const SecurityPostureReport& report);

    // 生成沙盒 seccomp 额外限制建议（针对侧信道和硬件攻击）
    static std::vector<std::string> get_extra_seccomp_restrictions(const SecurityPostureReport& report);

private:
    // 计算总体评分
    static void calculate_scores(SecurityPostureReport& report);

    // 获取系统基本信息
    static void collect_system_info(SecurityPostureReport& report);
};

} // namespace sandbox
} // namespace photon_kernel
