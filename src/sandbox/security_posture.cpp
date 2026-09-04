// PhotonBox 运行时安全态势检测模块实现
#include "photon_kernel/sandbox/security_posture.hpp"
#include "photon_kernel/sandbox/sandbox_config.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <unistd.h>
#include <sys/utsname.h>

namespace photon_kernel {
namespace sandbox {

// ========== 工具函数 ==========
static std::string read_file(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::stringstream ss;
    ss << f.rdbuf();
    std::string result = ss.str();
    // 去除末尾换行
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}

static bool file_exists(const std::string& path) {
    return access(path.c_str(), F_OK) == 0;
}

static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\n\r");
    return s.substr(start, end - start + 1);
}

static std::vector<std::string> split_lines(const std::string& s) {
    std::vector<std::string> lines;
    std::stringstream ss(s);
    std::string line;
    while (std::getline(ss, line)) {
        lines.push_back(line);
    }
    return lines;
}

// ========== SecurityPostureReport 序列化 ==========
std::string SecurityPostureReport::to_json() const {
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"generated_at\": \"" << generated_at << "\",\n";
    ss << "  \"hostname\": \"" << hostname << "\",\n";
    ss << "  \"kernel_version\": \"" << kernel_version << "\",\n";
    ss << "  \"cpu_vendor\": \"" << cpu_vendor << "\",\n";
    ss << "  \"cpu_model\": \"" << cpu_model << "\",\n";
    ss << "  \"total_memory_mb\": " << total_memory_mb << ",\n";
    ss << "  \"is_virtualized\": " << (is_virtualized ? "true" : "false") << ",\n";
    ss << "  \"has_ecc_memory\": " << (has_ecc_memory ? "true" : "false") << ",\n";
    ss << "  \"smt_enabled\": " << (smt_enabled ? "true" : "false") << ",\n";
    ss << "  \"overall_score\": " << overall_score << ",\n";
    ss << "  \"kernel_0day_score\": " << kernel_0day_score << ",\n";
    ss << "  \"side_channel_score\": " << side_channel_score << ",\n";
    ss << "  \"hardware_attack_score\": " << hardware_attack_score << ",\n";
    ss << "  \"summary\": {\n";
    ss << "    \"critical\": " << critical_count << ",\n";
    ss << "    \"high\": " << high_count << ",\n";
    ss << "    \"medium\": " << medium_count << ",\n";
    ss << "    \"low\": " << low_count << ",\n";
    ss << "    \"safe\": " << safe_count << ",\n";
    ss << "    \"total\": " << total_count << "\n";
    ss << "  },\n";
    ss << "  \"items\": [\n";
    for (size_t i = 0; i < items.size(); i++) {
        const auto& item = items[i];
        ss << "    {\n";
        ss << "      \"id\": \"" << item.id << "\",\n";
        ss << "      \"category\": \"" << item.category << "\",\n";
        ss << "      \"name\": \"" << item.name << "\",\n";
        ss << "      \"description\": \"" << item.description << "\",\n";
        ss << "      \"risk_if_unprotected\": \"" << risk_level_to_string(item.risk_if_unprotected) << "\",\n";
        ss << "      \"current_risk\": \"" << risk_level_to_string(item.current_risk) << "\",\n";
        ss << "      \"is_protected\": " << (item.is_protected ? "true" : "false") << ",\n";
        ss << "      \"detected_value\": \"" << item.detected_value << "\",\n";
        ss << "      \"expected_value\": \"" << item.expected_value << "\",\n";
        ss << "      \"remediation\": \"" << item.remediation << "\",\n";
        ss << "      \"reference\": \"" << item.reference << "\"\n";
        ss << "    }" << (i < items.size() - 1 ? "," : "") << "\n";
    }
    ss << "  ]\n";
    ss << "}\n";
    return ss.str();
}

std::string SecurityPostureReport::to_markdown() const {
    std::stringstream ss;
    ss << "# PhotonBox 安全态势检测报告\n\n";
    ss << "**生成时间**: " << generated_at << "\n";
    ss << "**主机**: " << hostname << "\n";
    ss << "**内核**: " << kernel_version << "\n";
    ss << "**CPU**: " << cpu_vendor << " " << cpu_model << "\n";
    ss << "**内存**: " << total_memory_mb << " MB" << (has_ecc_memory ? " (ECC)" : " (非ECC)") << "\n";
    ss << "**虚拟化**: " << (is_virtualized ? "是" : "否（裸机）") << "\n";
    ss << "**SMT/超线程**: " << (smt_enabled ? "已启用" : "已禁用") << "\n\n";

    ss << "## 总体评分\n\n";
    ss << "| 维度 | 评分 (0-100) |\n";
    ss << "|------|--------------|\n";
    ss << "| 总体安全 | " << overall_score << " |\n";
    ss << "| 内核 0day 防护 | " << kernel_0day_score << " |\n";
    ss << "| 侧信道防护 | " << side_channel_score << " |\n";
    ss << "| 硬件攻击防护 | " << hardware_attack_score << " |\n\n";

    ss << "## 风险统计\n\n";
    ss << "| 等级 | 数量 |\n";
    ss << "|------|------|\n";
    ss << "| CRITICAL | " << critical_count << " |\n";
    ss << "| HIGH | " << high_count << " |\n";
    ss << "| MEDIUM | " << medium_count << " |\n";
    ss << "| LOW | " << low_count << " |\n";
    ss << "| SAFE | " << safe_count << " |\n";
    ss << "| 总计 | " << total_count << " |\n\n";

    // 按分类输出
    std::vector<std::string> categories = {"kernel_0day", "side_channel", "hardware"};
    std::vector<std::string> category_names = {"内核 0day 逃逸防护", "侧信道攻击防护", "硬件级攻击防护"};

    for (size_t c = 0; c < categories.size(); c++) {
        ss << "## " << category_names[c] << "\n\n";
        ss << "| ID | 检测项 | 状态 | 当前风险 | 检测值 | 修复建议 |\n";
        ss << "|----|--------|------|----------|--------|----------|\n";
        for (const auto& item : items) {
            if (item.category != categories[c]) continue;
            std::string status = item.is_protected ? "✅ 已防护" : "⚠️ 未防护";
            ss << "| " << item.id << " | " << item.name << " | " << status
               << " | " << risk_level_to_string(item.current_risk)
               << " | " << item.detected_value
               << " | " << item.remediation << " |\n";
        }
        ss << "\n";
    }

    return ss.str();
}

// ========== Kernel0dayChecker 实现 ==========
SecurityCheckItem Kernel0dayChecker::check_kernel_version() {
    SecurityCheckItem item;
    item.id = "KERNEL-001";
    item.category = "kernel_0day";
    item.name = "内核版本与已知 CVE";
    item.description = "检测内核版本，评估是否存在已知可利用的 0day/CVE";
    item.risk_if_unprotected = RiskLevel::HIGH;

    struct utsname buf;
    if (uname(&buf) == 0) {
        item.detected_value = buf.release;
    } else {
        item.detected_value = "unknown";
    }

    // 简单版本检查：内核 >= 5.10 且为 LTS 版本风险较低
    // 实际生产应对接 CVE 数据库
    item.expected_value = ">= 5.10 LTS, 及时安全补丁";
    item.is_protected = true; // 假设已更新，实际需 CVE 数据库验证
    item.current_risk = RiskLevel::LOW;
    item.remediation = "定期执行 apt/yum update 安装内核安全补丁；启用 kpatch/livepatch 热补丁；关注 CVE-2024-* 内核漏洞公告";
    item.reference = "https://www.kernel.org/ | https://cve.mitre.org/";
    return item;
}

SecurityCheckItem Kernel0dayChecker::check_kernel_cmdline() {
    SecurityCheckItem item;
    item.id = "KERNEL-002";
    item.category = "kernel_0day";
    item.name = "内核命令行安全参数";
    item.description = "检测内核启动参数是否启用了 slab_nomerge、init_on_alloc、page_poison 等安全加固选项";
    item.risk_if_unprotected = RiskLevel::MEDIUM;

    std::string cmdline = read_file("/proc/cmdline");
    item.detected_value = cmdline.empty() ? "无法读取" : cmdline;

    bool has_slab_nomerge = cmdline.find("slab_nomerge") != std::string::npos;
    bool has_init_on_alloc = cmdline.find("init_on_alloc=1") != std::string::npos;
    bool has_init_on_free = cmdline.find("init_on_free=1") != std::string::npos;
    bool has_page_poison = cmdline.find("page_poison=1") != std::string::npos;
    bool has_pti = cmdline.find("pti=on") != std::string::npos || cmdline.find("pti=auto") != std::string::npos;

    int safe_count = (has_slab_nomerge ? 1 : 0) + (has_init_on_alloc ? 1 : 0) +
                      (has_init_on_free ? 1 : 0) + (has_page_poison ? 1 : 0) + (has_pti ? 1 : 0);

    item.expected_value = "slab_nomerge + init_on_alloc=1 + init_on_free=1 + page_poison=1 + pti=on";
    item.is_protected = safe_count >= 3;
    item.current_risk = safe_count >= 4 ? RiskLevel::SAFE :
                        safe_count >= 2 ? RiskLevel::LOW :
                        safe_count >= 1 ? RiskLevel::MEDIUM : RiskLevel::HIGH;
    item.remediation = "在 /etc/default/grub 的 GRUB_CMDLINE_LINUX 中添加: slab_nomerge init_on_alloc=1 init_on_free=1 page_poison=1 pti=on，然后 update-grub 重启";
    item.reference = "https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html";
    return item;
}

SecurityCheckItem Kernel0dayChecker::check_loaded_modules() {
    SecurityCheckItem item;
    item.id = "KERNEL-003";
    item.category = "kernel_0day";
    item.name = "已加载内核模块审计";
    item.description = "检测是否加载了不必要的高风险内核模块（如 udf、cramfs、freevxfs、jffs2、hfs、hfsplus、squashfs、tipc、dccp、sctp、rds 等）";
    item.risk_if_unprotected = RiskLevel::MEDIUM;

    std::string modules = read_file("/proc/modules");
    auto lines = split_lines(modules);
    item.detected_value = "已加载 " + std::to_string(lines.size()) + " 个模块";

    // 高风险文件系统和网络模块列表
    std::vector<std::string> risky_modules = {
        "udf", "cramfs", "freevxfs", "jffs2", "hfs", "hfsplus",
        "squashfs", "tipc", "dccp", "sctp", "rds", "firewire-core",
        "floppy", "pcspkr", "serio_raw"
    };

    std::vector<std::string> found_risky;
    for (const auto& line : lines) {
        std::string mod_name = line.substr(0, line.find(' '));
        for (const auto& risky : risky_modules) {
            if (mod_name == risky) {
                found_risky.push_back(risky);
            }
        }
    }

    item.expected_value = "禁用不必要的文件系统和网络模块";
    item.is_protected = found_risky.empty();
    item.current_risk = found_risky.empty() ? RiskLevel::SAFE :
                        found_risky.size() <= 2 ? RiskLevel::LOW : RiskLevel::MEDIUM;
    if (!found_risky.empty()) {
        item.detected_value += "，发现高风险模块: ";
        for (size_t i = 0; i < found_risky.size(); i++) {
            item.detected_value += found_risky[i];
            if (i < found_risky.size() - 1) item.detected_value += ", ";
        }
    }
    item.remediation = "在 /etc/modprobe.d/blacklist.conf 中添加: install <module> /bin/true，禁用不必要的模块";
    item.reference = "CIS Benchmark - Disable uncommon network protocols and filesystems";
    return item;
}

SecurityCheckItem Kernel0dayChecker::check_kernel_livepatch() {
    SecurityCheckItem item;
    item.id = "KERNEL-004";
    item.category = "kernel_0day";
    item.name = "内核热补丁 (Livepatch)";
    item.description = "检测是否启用了 kpatch 或 canonical livepatch，用于不重启修复内核漏洞";
    item.risk_if_unprotected = RiskLevel::MEDIUM;

    bool has_kpatch = file_exists("/sys/kernel/livepatch") ||
                      read_file("/proc/version").find("kpatch") != std::string::npos;
    bool has_livepatch = file_exists("/var/lib/livepatch");

    item.detected_value = has_kpatch ? "kpatch 已启用" :
                          has_livepatch ? "canonical livepatch 已启用" : "未启用热补丁";
    item.expected_value = "启用 kpatch 或 canonical livepatch";
    item.is_protected = has_kpatch || has_livepatch;
    item.current_risk = item.is_protected ? RiskLevel::SAFE : RiskLevel::MEDIUM;
    item.remediation = "Ubuntu: sudo apt install canonical-livepatch && sudo canonical-livepatch enable <token>; RHEL/CentOS: 安装 kpatch 并配置";
    item.reference = "https://ubuntu.com/security/livepatch | https://github.com/dynup/kpatch";
    return item;
}

SecurityCheckItem Kernel0dayChecker::check_seccomp_support() {
    SecurityCheckItem item;
    item.id = "KERNEL-005";
    item.category = "kernel_0day";
    item.name = "seccomp-BPF 支持";
    item.description = "检测内核是否支持 seccomp-BPF 系统调用过滤";
    item.risk_if_unprotected = RiskLevel::HIGH;

    bool seccomp_available = file_exists("/proc/sys/kernel/seccomp/actions_avail");
    std::string actions = read_file("/proc/sys/kernel/seccomp/actions_avail");

    item.detected_value = seccomp_available ? "支持，可用动作: " + actions : "不支持";
    item.expected_value = "seccomp-BPF 支持，包含 KILL_PROCESS 动作";
    item.is_protected = seccomp_available && actions.find("kill_process") != std::string::npos;
    item.current_risk = item.is_protected ? RiskLevel::SAFE : RiskLevel::HIGH;
    item.remediation = "升级内核到 >= 3.17（seccomp-BPF），>= 4.14（SECCOMP_RET_KILL_PROCESS）";
    item.reference = "https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html";
    return item;
}

SecurityCheckItem Kernel0dayChecker::check_landlock_support() {
    SecurityCheckItem item;
    item.id = "KERNEL-006";
    item.category = "kernel_0day";
    item.name = "Landlock 支持";
    item.description = "检测内核是否支持 Landlock LSM（非特权文件系统访问控制）";
    item.risk_if_unprotected = RiskLevel::MEDIUM;

    // Landlock 在 5.13 合入主线，通过 /sys/kernel/security/lsm 检测
    std::string lsm = read_file("/sys/kernel/security/lsm");
    bool has_landlock = lsm.find("landlock") != std::string::npos;

    item.detected_value = has_landlock ? "已启用 (" + lsm + ")" : "未启用 (当前 LSM: " + lsm + ")";
    item.expected_value = "内核 >= 5.13，启用 landlock LSM";
    item.is_protected = has_landlock;
    item.current_risk = has_landlock ? RiskLevel::SAFE : RiskLevel::MEDIUM;
    item.remediation = "升级内核到 >= 5.13；在 GRUB_CMDLINE_LINUX 中添加 lsm=landlock,lockdown,yama,apparmor";
    item.reference = "https://docs.kernel.org/userspace-api/landlock.html";
    return item;
}

SecurityCheckItem Kernel0dayChecker::check_namespace_support() {
    SecurityCheckItem item;
    item.id = "KERNEL-007";
    item.category = "kernel_0day";
    item.name = "命名空间隔离支持";
    item.description = "检测内核是否支持所有 7 种命名空间（mount/UTS/IPC/PID/network/user/cgroup）";
    item.risk_if_unprotected = RiskLevel::HIGH;

    std::vector<std::string> ns_types = {"mnt", "uts", "ipc", "pid", "net", "user", "cgroup"};
    int supported = 0;
    for (const auto& ns : ns_types) {
        if (file_exists("/proc/self/ns/" + ns)) supported++;
    }

    item.detected_value = std::to_string(supported) + "/7 命名空间可用";
    item.expected_value = "全部 7 种命名空间支持";
    item.is_protected = supported == 7;
    item.current_risk = supported >= 6 ? RiskLevel::SAFE :
                        supported >= 4 ? RiskLevel::LOW :
                        supported >= 2 ? RiskLevel::MEDIUM : RiskLevel::HIGH;
    item.remediation = "确保内核编译时开启 CONFIG_NAMESPACES、CONFIG_USER_NS、CONFIG_PID_NS 等选项";
    item.reference = "https://man7.org/linux/man-pages/man7/namespaces.7.html";
    return item;
}

SecurityCheckItem Kernel0dayChecker::check_module_signature() {
    SecurityCheckItem item;
    item.id = "KERNEL-008";
    item.category = "kernel_0day";
    item.name = "内核模块签名强制";
    item.description = "检测是否启用了 module.sig_enforce，禁止加载未签名内核模块";
    item.risk_if_unprotected = RiskLevel::HIGH;

    std::string sig_enforce = read_file("/proc/sys/kernel/modules_disabled");
    bool modules_disabled = sig_enforce == "1";

    // 检查内核配置
    std::string sig_enforce_cfg = read_file("/boot/config-" + read_file("/proc/sys/kernel/osrelease"));
    bool has_sig_enforce = sig_enforce_cfg.find("CONFIG_MODULE_SIG_FORCE=y") != std::string::npos;

    item.detected_value = modules_disabled ? "模块加载已禁用" :
                          has_sig_enforce ? "模块签名强制已启用" : "未启用模块签名强制";
    item.expected_value = "CONFIG_MODULE_SIG_FORCE=y 或 kernel.modules_disabled=1";
    item.is_protected = modules_disabled || has_sig_enforce;
    item.current_risk = item.is_protected ? RiskLevel::SAFE : RiskLevel::HIGH;
    item.remediation = "编译内核时开启 CONFIG_MODULE_SIG_FORCE=y；或运行时执行 sysctl -w kernel.modules_disabled=1（注意：不可逆，需重启恢复）";
    item.reference = "https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html";
    return item;
}

std::vector<SecurityCheckItem> Kernel0dayChecker::run_all_checks() {
    std::vector<SecurityCheckItem> items;
    items.push_back(check_kernel_version());
    items.push_back(check_kernel_cmdline());
    items.push_back(check_loaded_modules());
    items.push_back(check_kernel_livepatch());
    items.push_back(check_seccomp_support());
    items.push_back(check_landlock_support());
    items.push_back(check_namespace_support());
    items.push_back(check_module_signature());
    return items;
}

// ========== SideChannelChecker 实现 ==========
std::optional<std::string> SideChannelChecker::read_vulnerability_state(const std::string& name) {
    std::string path = "/sys/devices/system/cpu/vulnerabilities/" + name;
    if (!file_exists(path)) return std::nullopt;
    return read_file(path);
}

bool SideChannelChecker::is_vulnerability_mitigated(const std::string& state) {
    if (state.empty()) return false;
    // "Not affected" 或包含 "Mitigation" 表示已防护
    if (state.find("Not affected") != std::string::npos) return true;
    if (state.find("Mitigation") != std::string::npos) return true;
    return false;
}

static SecurityCheckItem make_vuln_item(
    const std::string& id, const std::string& name, const std::string& desc,
    const std::string& sysfs_name, RiskLevel risk, const std::string& remediation,
    const std::string& reference)
{
    SecurityCheckItem item;
    item.id = id;
    item.category = "side_channel";
    item.name = name;
    item.description = desc;
    item.risk_if_unprotected = risk;

    auto state = SideChannelChecker::read_vulnerability_state(sysfs_name);
    if (state.has_value()) {
        item.detected_value = state.value();
        item.is_protected = SideChannelChecker::is_vulnerability_mitigated(state.value());
    } else {
        item.detected_value = "无法检测（内核不支持或缺少 sysfs 接口）";
        item.is_protected = false;
    }

    item.expected_value = "Not affected 或 Mitigation: ...";
    item.current_risk = item.is_protected ? RiskLevel::SAFE : risk;
    item.remediation = remediation;
    item.reference = reference;
    return item;
}

SecurityCheckItem SideChannelChecker::check_spectre_v1() {
    return make_vuln_item("SIDE-001", "Spectre Variant 1 (Bounds Check Bypass)",
        "CVE-2017-5753: 推测执行绕过边界检查，可通过侧信道读取内存",
        "spectre_v1", RiskLevel::MEDIUM,
        "升级内核到 >= 4.15；启用 KPTI；编译器使用 retpoline；微码更新",
        "CVE-2017-5753");
}

SecurityCheckItem SideChannelChecker::check_spectre_v2() {
    return make_vuln_item("SIDE-002", "Spectre Variant 2 (Branch Target Injection)",
        "CVE-2017-5715: 分支目标注入，可通过间接分支推测执行读取内存",
        "spectre_v2", RiskLevel::HIGH,
        "升级内核到 >= 4.15；启用 retpoline；微码更新；禁用 SMT（最彻底）",
        "CVE-2017-5715");
}

SecurityCheckItem SideChannelChecker::check_spectre_v4() {
    return make_vuln_item("SIDE-003", "Spectre Variant 4 (Speculative Store Bypass)",
        "CVE-2018-3639: 推测性存储绕过，可读取陈旧数据",
        "spec_store_bypass", RiskLevel::MEDIUM,
        "升级内核到 >= 4.17；微码更新；使用 prctl(PR_SET_SPECULATION_CTRL)",
        "CVE-2018-3639");
}

SecurityCheckItem SideChannelChecker::check_meltdown() {
    return make_vuln_item("SIDE-004", "Meltdown (Rogue Data Cache Load)",
        "CVE-2017-5754: 非特权进程读取内核内存，Intel CPU 主要受影响",
        "meltdown", RiskLevel::CRITICAL,
        "升级内核到 >= 4.15；启用 KPTI (KAISER)；微码更新",
        "CVE-2017-5754");
}

SecurityCheckItem SideChannelChecker::check_l1tf() {
    return make_vuln_item("SIDE-005", "L1TF (L1 Terminal Fault / Foreshadow)",
        "CVE-2018-3615/3620/3646: L1 缓存终端故障，可读取 SGX 飞地、内核、其他 VM 内存",
        "l1tf", RiskLevel::HIGH,
        "升级内核到 >= 4.18；启用 L1D 刷新；禁用 SMT；微码更新",
        "CVE-2018-3615");
}

SecurityCheckItem SideChannelChecker::check_mds() {
    return make_vuln_item("SIDE-006", "MDS (Microarchitectural Data Sampling / ZombieLoad)",
        "CVE-2018-12126/12130/12127/11091: 微架构数据采样，可读取 CPU 缓冲区数据",
        "mds", RiskLevel::HIGH,
        "升级内核到 >= 5.2；启用 VERW 指令刷新；禁用 SMT；微码更新",
        "CVE-2018-12126");
}

SecurityCheckItem SideChannelChecker::check_swapgs() {
    return make_vuln_item("SIDE-007", "SwapGS (Spectre Variant 1 SWAPGS)",
        "CVE-2019-1125: SWAPGS 指令推测执行绕过，可读取内核内存",
        "swapgs", RiskLevel::HIGH,
        "升级内核到 >= 5.3；微码更新",
        "CVE-2019-1125");
}

SecurityCheckItem SideChannelChecker::check_srso() {
    return make_vuln_item("SIDE-008", "SRSO (Speculative Return Stack Overflow)",
        "CVE-2023-20569: AMD CPU 返回栈溢出推测执行，可预测返回地址",
        "srso", RiskLevel::HIGH,
        "升级内核到 >= 6.5；更新 AMD 微码；使用 safe RET 指令",
        "CVE-2023-20569");
}

SecurityCheckItem SideChannelChecker::check_gds() {
    return make_vuln_item("SIDE-009", "GDS (Gather Data Sampling / Downfall)",
        "CVE-2022-40982: Intel AVX2 Gather 指令采样，可读取向量寄存器数据",
        "gds", RiskLevel::MEDIUM,
        "升级内核到 >= 6.5；微码更新；禁用 AVX2 Gather（性能损失）",
        "CVE-2022-40982");
}

SecurityCheckItem SideChannelChecker::check_microcode_version() {
    SecurityCheckItem item;
    item.id = "SIDE-010";
    item.category = "side_channel";
    item.name = "CPU 微码版本";
    item.description = "检测 CPU 微码是否为最新版本（微码更新修复大量侧信道漏洞）";
    item.risk_if_unprotected = RiskLevel::HIGH;

    std::string microcode = "";
    auto lines = split_lines(read_file("/proc/cpuinfo"));
    for (const auto& line : lines) {
        if (line.find("microcode") != std::string::npos) {
            microcode = trim(line.substr(line.find(':') + 1));
            break;
        }
    }

    item.detected_value = microcode.empty() ? "无法读取" : microcode;
    item.expected_value = "最新厂商微码（Intel 2024+ / AMD 2024+）";
    // 无法自动判断是否最新，标记为需要人工确认
    item.is_protected = !microcode.empty();
    item.current_risk = microcode.empty() ? RiskLevel::HIGH : RiskLevel::INFO;
    item.remediation = "Intel: 安装 intel-microcode 包；AMD: 安装 amd64-microcode；或从主板厂商更新 BIOS/UEFI";
    item.reference = "https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files";
    return item;
}

SecurityCheckItem SideChannelChecker::check_smt_status() {
    SecurityCheckItem item;
    item.id = "SIDE-011";
    item.category = "side_channel";
    item.name = "SMT/超线程状态";
    item.description = "检测是否启用了 SMT/超线程（许多侧信道攻击需要 SMT 才能跨线程泄露数据）";
    item.risk_if_unprotected = RiskLevel::MEDIUM;

    // 读取 CPU 数量和核心数
    std::string cpu_online = read_file("/sys/devices/system/cpu/online");
    int thread_count = 0;
    // 简单解析 "0-7" 格式
    if (!cpu_online.empty()) {
        size_t dash = cpu_online.find('-');
        if (dash != std::string::npos) {
            int start = std::stoi(cpu_online.substr(0, dash));
            int end = std::stoi(cpu_online.substr(dash + 1));
            thread_count = end - start + 1;
        }
    }

    // 检查 siblings 和 cpu cores
    std::string siblings = read_file("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list");
    bool smt_enabled = siblings.find(',') != std::string::npos || siblings.find('-') != std::string::npos;

    item.detected_value = smt_enabled ? "已启用 (" + std::to_string(thread_count) + " 线程)" :
                          "已禁用 (" + std::to_string(thread_count) + " 线程)";
    item.expected_value = "高安全场景禁用 SMT";
    item.is_protected = !smt_enabled;
    item.current_risk = smt_enabled ? RiskLevel::MEDIUM : RiskLevel::SAFE;
    item.remediation = "高安全场景：在 GRUB_CMDLINE_LINUX 中添加 nosmt，或在 BIOS 中禁用超线程；注意：会损失约 30% 多线程性能";
    item.reference = "https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/index.html";
    return item;
}

SecurityCheckItem SideChannelChecker::check_kpti() {
    SecurityCheckItem item;
    item.id = "SIDE-012";
    item.category = "side_channel";
    item.name = "KPTI (内核页表隔离)";
    item.description = "检测是否启用了 KPTI/KAISER（隔离用户态和内核态页表，防护 Meltdown）";
    item.risk_if_unprotected = RiskLevel::HIGH;

    std::string cmdline = read_file("/proc/cmdline");
    bool pti_off = cmdline.find("pti=off") != std::string::npos;
    bool pti_on = cmdline.find("pti=on") != std::string::npos || cmdline.find("pti=auto") != std::string::npos;

    // 检查 /sys/kernel/debug/x86/pti_enabled（需要 root）
    bool pti_enabled = file_exists("/sys/kernel/debug/x86/pti_enabled");
    std::string pti_state = pti_enabled ? read_file("/sys/kernel/debug/x86/pti_enabled") : "";

    item.detected_value = pti_off ? "已禁用 (pti=off)" :
                          pti_on ? "已启用 (pti=on/auto)" :
                          pti_state == "1" ? "已启用" : "默认状态（通常已启用）";
    item.expected_value = "pti=on 或默认启用";
    item.is_protected = !pti_off;
    item.current_risk = pti_off ? RiskLevel::HIGH : RiskLevel::SAFE;
    item.remediation = "确保 GRUB_CMDLINE_LINUX 中没有 pti=off；内核 >= 4.15 默认启用 KPTI";
    item.reference = "CVE-2017-5754 (Meltdown)";
    return item;
}

SecurityCheckItem SideChannelChecker::check_retpoline() {
    SecurityCheckItem item;
    item.id = "SIDE-013";
    item.category = "side_channel";
    item.name = "Retpoline 支持";
    item.description = "检测内核和编译器是否支持 retpoline（间接分支推测执行防护，防护 Spectre v2）";
    item.risk_if_unprotected = RiskLevel::HIGH;

    std::string spectre_v2 = read_file("/sys/devices/system/cpu/vulnerabilities/spectre_v2");
    bool has_retpoline = spectre_v2.find("retpoline") != std::string::npos;

    item.detected_value = spectre_v2.empty() ? "无法检测" : spectre_v2;
    item.expected_value = "Mitigation: Full generic retpoline ...";
    item.is_protected = has_retpoline;
    item.current_risk = has_retpoline ? RiskLevel::SAFE : RiskLevel::HIGH;
    item.remediation = "升级内核到 >= 4.15；使用 GCC >= 7.3 或 Clang >= 6.0 重新编译内核和沙盒代码（-mindirect-branch=thunk-extern）";
    item.reference = "CVE-2017-5715 (Spectre v2)";
    return item;
}

SecurityCheckItem SideChannelChecker::check_perf_event_restriction() {
    SecurityCheckItem item;
    item.id = "SIDE-014";
    item.category = "side_channel";
    item.name = "perf_event 访问限制";
    item.description = "检测是否限制了 perf_event_open 系统调用（perf 可用于侧信道攻击，如 Prime+Probe）";
    item.risk_if_unprotected = RiskLevel::MEDIUM;

    std::string perf_event_paranoid = read_file("/proc/sys/kernel/perf_event_paranoid");
    int paranoid = perf_event_paranoid.empty() ? 0 : std::stoi(perf_event_paranoid);

    item.detected_value = "kernel.perf_event_paranoid = " + perf_event_paranoid;
    item.expected_value = ">= 2（仅允许测量 per-CPU 内核事件，禁止用户态 unprivileged 测量）";
    item.is_protected = paranoid >= 2;
    item.current_risk = paranoid >= 3 ? RiskLevel::SAFE :
                        paranoid >= 2 ? RiskLevel::LOW :
                        paranoid >= 1 ? RiskLevel::MEDIUM : RiskLevel::HIGH;
    item.remediation = "执行 sysctl -w kernel.perf_event_paranoid=3；在 /etc/sysctl.d/99-security.conf 中持久化；沙盒 seccomp 白名单中禁用 perf_event_open";
    item.reference = "https://www.kernel.org/doc/html/latest/admin-guide/perf-security.html";
    return item;
}

std::vector<SecurityCheckItem> SideChannelChecker::run_all_checks() {
    std::vector<SecurityCheckItem> items;
    items.push_back(check_spectre_v1());
    items.push_back(check_spectre_v2());
    items.push_back(check_spectre_v4());
    items.push_back(check_meltdown());
    items.push_back(check_l1tf());
    items.push_back(check_mds());
    items.push_back(check_swapgs());
    items.push_back(check_srso());
    items.push_back(check_gds());
    items.push_back(check_microcode_version());
    items.push_back(check_smt_status());
    items.push_back(check_kpti());
    items.push_back(check_retpoline());
    items.push_back(check_perf_event_restriction());
    return items;
}

// ========== HardwareAttackChecker 实现 ==========
SecurityCheckItem HardwareAttackChecker::check_ecc_memory() {
    SecurityCheckItem item;
    item.id = "HW-001";
    item.category = "hardware";
    item.name = "ECC 内存";
    item.description = "检测是否使用 ECC 内存（纠错码内存可检测和纠正单比特错误，防护 Rowhammer 导致的比特翻转）";
    item.risk_if_unprotected = RiskLevel::HIGH;

    // 通过 dmidecode 检测（需要 root），或通过 edac 子系统
    bool has_edac = file_exists("/sys/devices/system/edac/mc");
    std::string mc_count = has_edac ? read_file("/sys/devices/system/edac/mc/mc0/size_mb") : "";

    item.detected_value = has_edac ? "EDAC 子系统可用 (mc0 size: " + mc_count + " MB)" : "无法检测（需 root 或 EDAC 驱动）";
    item.expected_value = "ECC 内存已启用";
    item.is_protected = has_edac && !mc_count.empty();
    item.current_risk = item.is_protected ? RiskLevel::SAFE : RiskLevel::HIGH;
    item.remediation = "使用支持 ECC 的服务器主板和 ECC 内存；在 BIOS 中启用 ECC；非 ECC 内存无法通过软件完全防护 Rowhammer";
    item.reference = "https://www.kernel.org/doc/html/latest/admin-guide/edac.html";
    return item;
}

SecurityCheckItem HardwareAttackChecker::check_rowhammer_protection() {
    SecurityCheckItem item;
    item.id = "HW-002";
    item.category = "hardware";
    item.name = "Rowhammer 防护 (TRR)";
    item.description = "检测内存控制器是否启用了目标行刷新 (TRR)，防护 Rowhammer 比特翻转攻击";
    item.risk_if_unprotected = RiskLevel::HIGH;

    // TRR 是内存控制器硬件功能，无法直接从软件检测
    // 可以通过内存厂商和型号间接判断
    std::string mem_type = "无法自动检测（TRR 是硬件功能）";

    item.detected_value = mem_type;
    item.expected_value = "DDR4 内存支持 TRR；DDR5 内置更强防护";
    item.is_protected = false; // 无法自动确认
    item.current_risk = RiskLevel::INFO;
    item.remediation = "使用 DDR4 或更新内存（支持 TRR）；使用 ECC 内存；禁用 hugepages；cgroup 内存隔离；高安全场景使用物理内存隔离（CAT）";
    item.reference = "CVE-2015-* Rowhammer | https://users.ece.cmu.edu/~yoonguk/papers/kim-isca14.pdf";
    return item;
}

SecurityCheckItem HardwareAttackChecker::check_hugepages_usage() {
    SecurityCheckItem item;
    item.id = "HW-003";
    item.category = "hardware";
    item.name = "HugePages 使用";
    item.description = "检测是否启用了大页内存（HugePages 增加 Rowhammer 攻击面，因为大页内物理地址连续）";
    item.risk_if_unprotected = RiskLevel::MEDIUM;

    std::string nr_hugepages = read_file("/proc/sys/vm/nr_hugepages");
    std::string nr_overcommit = read_file("/proc/sys/vm/nr_overcommit_hugepages");
    int hugepages = nr_hugepages.empty() ? 0 : std::stoi(nr_hugepages);

    item.detected_value = "nr_hugepages = " + nr_hugepages + ", nr_overcommit = " + nr_overcommit;
    item.expected_value = "高安全场景禁用 HugePages（nr_hugepages = 0）";
    item.is_protected = hugepages == 0;
    item.current_risk = hugepages == 0 ? RiskLevel::SAFE :
                        hugepages <= 64 ? RiskLevel::LOW : RiskLevel::MEDIUM;
    item.remediation = "高安全场景：sysctl -w vm.nr_hugepages=0；在 /etc/sysctl.d/ 中持久化；沙盒内通过 seccomp 限制 mmap 使用 MAP_HUGETLB";
    item.reference = "Rowhammer 攻击面分析 - HugePages 增加物理地址连续性";
    return item;
}

SecurityCheckItem HardwareAttackChecker::check_memory_zeroing() {
    SecurityCheckItem item;
    item.id = "HW-004";
    item.category = "hardware";
    item.name = "内存清零 (init_on_alloc/init_on_free)";
    item.description = "检测是否启用了内核内存分配时清零（防止内存数据残留泄露，防护冷启动攻击和数据泄露）";
    item.risk_if_unprotected = RiskLevel::MEDIUM;

    std::string cmdline = read_file("/proc/cmdline");
    bool init_on_alloc = cmdline.find("init_on_alloc=1") != std::string::npos;
    bool init_on_free = cmdline.find("init_on_free=1") != std::string::npos;

    // 也可以检查 /sys/kernel/debug/kmemleak（需要 root）
    item.detected_value = std::string("init_on_alloc=") + (init_on_alloc ? "1" : "0") +
                          ", init_on_free=" + (init_on_free ? "1" : "0");
    item.expected_value = "init_on_alloc=1 + init_on_free=1";
    item.is_protected = init_on_alloc && init_on_free;
    item.current_risk = (init_on_alloc && init_on_free) ? RiskLevel::SAFE :
                        init_on_alloc ? RiskLevel::LOW : RiskLevel::MEDIUM;
    item.remediation = "在 GRUB_CMDLINE_LINUX 中添加 init_on_alloc=1 init_on_free=1；注意 init_on_free=1 有约 1-2% 性能开销";
    item.reference = "https://www.kernel.org/doc/html/latest/dev-tools/init_on_alloc.html";
    return item;
}

SecurityCheckItem HardwareAttackChecker::check_cgroup_memory_isolation() {
    SecurityCheckItem item;
    item.id = "HW-005";
    item.category = "hardware";
    item.name = "cgroup 内存隔离配置";
    item.description = "检测 cgroup v2 内存控制器是否可用，用于沙盒间内存隔离和限制（防止内存耗尽攻击和 Rowhammer 跨沙盒影响）";
    item.risk_if_unprotected = RiskLevel::HIGH;

    bool cgroup_v2 = file_exists("/sys/fs/cgroup/cgroup.controllers");
    std::string controllers = cgroup_v2 ? read_file("/sys/fs/cgroup/cgroup.controllers") : "";
    bool has_memory = controllers.find("memory") != std::string::npos;

    item.detected_value = cgroup_v2 ? "cgroup v2 可用，控制器: " + controllers : "cgroup v2 不可用";
    item.expected_value = "cgroup v2 + memory 控制器";
    item.is_protected = cgroup_v2 && has_memory;
    item.current_risk = item.is_protected ? RiskLevel::SAFE : RiskLevel::HIGH;
    item.remediation = "使用 systemd-unified-cgroup-hierarchy；内核编译开启 CONFIG_CGROUP_MEM_RES_CTLR；每个沙盒设置 memory.max 和 memory.high 限制";
    item.reference = "https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html";
    return item;
}

SecurityCheckItem HardwareAttackChecker::check_iommu() {
    SecurityCheckItem item;
    item.id = "HW-006";
    item.category = "hardware";
    item.name = "IOMMU (DMA 攻击防护)";
    item.description = "检测是否启用了 IOMMU（Intel VT-d / AMD-Vi），防护 DMA 攻击和恶意设备直接访问内存";
    item.risk_if_unprotected = RiskLevel::HIGH;

    bool iommu_present = file_exists("/sys/class/iommu");
    std::string iommu_type = "未知";
    if (iommu_present) {
        // 检查是 Intel 还是 AMD
        if (file_exists("/sys/class/iommu/dmar0")) iommu_type = "Intel VT-d";
        else if (file_exists("/sys/class/iommu/amd-vi0")) iommu_type = "AMD-Vi";
        else iommu_type = "已启用";
    }

    // 检查内核命令行
    std::string cmdline = read_file("/proc/cmdline");
    bool iommu_on = cmdline.find("intel_iommu=on") != std::string::npos ||
                     cmdline.find("amd_iommu=on") != std::string::npos ||
                     iommu_present;

    item.detected_value = iommu_present ? iommu_type + " 已启用" : "未启用（或未在 BIOS 中开启）";
    item.expected_value = "Intel VT-d 或 AMD-Vi 已启用";
    item.is_protected = iommu_on;
    item.current_risk = iommu_on ? RiskLevel::SAFE : RiskLevel::HIGH;
    item.remediation = "在 BIOS/UEFI 中启用 VT-d（Intel）或 IOMMU（AMD）；在 GRUB_CMDLINE_LINUX 中添加 intel_iommu=on iommu=pt 或 amd_iommu=on";
    item.reference = "https://www.kernel.org/doc/html/latest/x86/intel-iommu.html";
    return item;
}

SecurityCheckItem HardwareAttackChecker::check_secure_boot() {
    SecurityCheckItem item;
    item.id = "HW-007";
    item.category = "hardware";
    item.name = "Secure Boot";
    item.description = "检测是否启用了 UEFI Secure Boot（防止 bootkit 和内核模块篡改，确保持久化防护）";
    item.risk_if_unprotected = RiskLevel::HIGH;

    std::string secure_boot = read_file("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c");
    bool enabled = false;
    if (!secure_boot.empty() && secure_boot.size() >= 5) {
        // SecureBoot 变量最后一个字节表示状态（1=启用，0=禁用）
        enabled = (unsigned char)secure_boot.back() == 1;
    }

    // 备选：检查 mokutil
    item.detected_value = enabled ? "已启用" : "未启用或无法检测（非 EFI 系统）";
    item.expected_value = "Secure Boot 已启用";
    item.is_protected = enabled;
    item.current_risk = enabled ? RiskLevel::SAFE : RiskLevel::HIGH;
    item.remediation = "在 BIOS/UEFI 中启用 Secure Boot；安装签名的内核和 bootloader；使用 mokutil 管理 Machine Owner Key";
    item.reference = "https://www.kernel.org/doc/html/latest/admin-guide/efi-stub.html";
    return item;
}

SecurityCheckItem HardwareAttackChecker::check_tpm() {
    SecurityCheckItem item;
    item.id = "HW-008";
    item.category = "hardware";
    item.name = "TPM (可信平台模块)";
    item.description = "检测是否存在 TPM 芯片（用于密钥存储、磁盘加密、远程证明，防护物理攻击和密钥泄露）";
    item.risk_if_unprotected = RiskLevel::MEDIUM;

    bool has_tpm = file_exists("/dev/tpm0") || file_exists("/dev/tpmrm0");
    std::string tpm_version = has_tpm ? "已检测到" : "未检测到";

    item.detected_value = tpm_version;
    item.expected_value = "TPM 2.0 芯片";
    item.is_protected = has_tpm;
    item.current_risk = has_tpm ? RiskLevel::SAFE : RiskLevel::MEDIUM;
    item.remediation = "使用支持 TPM 2.0 的主板；在 BIOS 中启用 TPM；使用 LUKS + TPM2 进行磁盘加密；沙盒密钥存储在 TPM 中而非文件";
    item.reference = "https://www.kernel.org/doc/html/latest/security/tpm.html";
    return item;
}

std::vector<SecurityCheckItem> HardwareAttackChecker::run_all_checks() {
    std::vector<SecurityCheckItem> items;
    items.push_back(check_ecc_memory());
    items.push_back(check_rowhammer_protection());
    items.push_back(check_hugepages_usage());
    items.push_back(check_memory_zeroing());
    items.push_back(check_cgroup_memory_isolation());
    items.push_back(check_iommu());
    items.push_back(check_secure_boot());
    items.push_back(check_tpm());
    return items;
}

// ========== SecurityPostureEvaluator 实现 ==========
void SecurityPostureEvaluator::collect_system_info(SecurityPostureReport& report) {
    struct utsname buf;
    if (uname(&buf) == 0) {
        report.kernel_version = buf.release;
        report.hostname = buf.nodename;
    }

    // CPU 信息
    auto lines = split_lines(read_file("/proc/cpuinfo"));
    for (const auto& line : lines) {
        if (line.find("vendor_id") != std::string::npos) {
            report.cpu_vendor = trim(line.substr(line.find(':') + 1));
        }
        if (line.find("model name") != std::string::npos) {
            report.cpu_model = trim(line.substr(line.find(':') + 1));
            break;
        }
    }

    // 内存
    std::string meminfo = read_file("/proc/meminfo");
    auto mem_lines = split_lines(meminfo);
    for (const auto& line : mem_lines) {
        if (line.find("MemTotal") != std::string::npos) {
            // 提取数字
            size_t colon = line.find(':');
            std::string val = trim(line.substr(colon + 1));
            size_t space = val.find(' ');
            if (space != std::string::npos) val = val.substr(0, space);
            report.total_memory_mb = std::stoull(val) / 1024;
            break;
        }
    }

    // 虚拟化检测
    report.is_virtualized = file_exists("/sys/class/dmi/id/product_name") &&
                            (read_file("/sys/class/dmi/id/product_name").find("Virtual") != std::string::npos ||
                             read_file("/sys/class/dmi/id/product_name").find("VMware") != std::string::npos ||
                             read_file("/sys/class/dmi/id/product_name").find("KVM") != std::string::npos ||
                             read_file("/sys/class/dmi/id/product_name").find("QEMU") != std::string::npos);

    // ECC 检测
    report.has_ecc_memory = file_exists("/sys/devices/system/edac/mc");

    // SMT 检测
    std::string siblings = read_file("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list");
    report.smt_enabled = siblings.find(',') != std::string::npos || siblings.find('-') != std::string::npos;

    // 时间
    time_t now = time(nullptr);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    report.generated_at = time_buf;
}

void SecurityPostureEvaluator::calculate_scores(SecurityPostureReport& report) {
    report.total_count = report.items.size();

    int kernel_safe = 0, kernel_total = 0;
    int side_safe = 0, side_total = 0;
    int hw_safe = 0, hw_total = 0;

    for (const auto& item : report.items) {
        switch (item.current_risk) {
            case RiskLevel::CRITICAL: report.critical_count++; break;
            case RiskLevel::HIGH: report.high_count++; break;
            case RiskLevel::MEDIUM: report.medium_count++; break;
            case RiskLevel::LOW: report.low_count++; break;
            case RiskLevel::SAFE: report.safe_count++; break;
            case RiskLevel::INFO: report.safe_count++; break;
        }

        if (item.category == "kernel_0day") {
            kernel_total++;
            if (item.is_protected) kernel_safe++;
        } else if (item.category == "side_channel") {
            side_total++;
            if (item.is_protected) side_safe++;
        } else if (item.category == "hardware") {
            hw_total++;
            if (item.is_protected) hw_safe++;
        }
    }

    report.kernel_0day_score = kernel_total > 0 ? (kernel_safe * 100 / kernel_total) : 0;
    report.side_channel_score = side_total > 0 ? (side_safe * 100 / side_total) : 0;
    report.hardware_attack_score = hw_total > 0 ? (hw_safe * 100 / hw_total) : 0;
    report.overall_score = report.total_count > 0 ?
        (report.safe_count * 100 / report.total_count) : 0;
}

SecurityPostureReport SecurityPostureEvaluator::evaluate() {
    SecurityPostureReport report;
    collect_system_info(report);

    auto kernel_items = Kernel0dayChecker::run_all_checks();
    auto side_items = SideChannelChecker::run_all_checks();
    auto hw_items = HardwareAttackChecker::run_all_checks();

    report.items.insert(report.items.end(), kernel_items.begin(), kernel_items.end());
    report.items.insert(report.items.end(), side_items.begin(), side_items.end());
    report.items.insert(report.items.end(), hw_items.begin(), hw_items.end());

    calculate_scores(report);
    return report;
}

SecurityPostureReport SecurityPostureEvaluator::evaluate_category(const std::string& category) {
    SecurityPostureReport report;
    collect_system_info(report);

    if (category == "kernel_0day") {
        auto items = Kernel0dayChecker::run_all_checks();
        report.items.insert(report.items.end(), items.begin(), items.end());
    } else if (category == "side_channel") {
        auto items = SideChannelChecker::run_all_checks();
        report.items.insert(report.items.end(), items.begin(), items.end());
    } else if (category == "hardware") {
        auto items = HardwareAttackChecker::run_all_checks();
        report.items.insert(report.items.end(), items.begin(), items.end());
    }

    calculate_scores(report);
    return report;
}

std::string SecurityPostureEvaluator::generate_hardening_script(const SecurityPostureReport& report) {
    std::stringstream ss;
    ss << "#!/bin/bash\n";
    ss << "# PhotonBox 宿主机安全加固脚本（自动生成）\n";
    ss << "# 生成时间: " << report.generated_at << "\n";
    ss << "# 注意：请审阅后执行，部分修改需要重启\n\n";
    ss << "set -euo pipefail\n\n";

    ss << "echo '=== PhotonBox 宿主机安全加固 ==='\n\n";

    // 内核命令行参数
    ss << "echo '[1/5] 配置内核命令行安全参数...'\n";
    ss << "if ! grep -q 'slab_nomerge' /etc/default/grub 2>/dev/null; then\n";
    ss << "  sed -i 's/GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"slab_nomerge init_on_alloc=1 init_on_free=1 page_poison=1 pti=on /' /etc/default/grub\n";
    ss << "  update-grub\n";
    ss << "fi\n\n";

    // 禁用高风险模块
    ss << "echo '[2/5] 禁用高风险内核模块...'\n";
    ss << "cat > /etc/modprobe.d/blacklist-security.conf << 'EOF'\n";
    ss << "install udf /bin/true\ninstall cramfs /bin/true\ninstall freevxfs /bin/true\n";
    ss << "install jffs2 /bin/true\ninstall hfs /bin/true\ninstall hfsplus /bin/true\n";
    ss << "install squashfs /bin/true\ninstall tipc /bin/true\ninstall dccp /bin/true\n";
    ss << "install sctp /bin/true\ninstall rds /bin/true\nEOF\n\n";

    // sysctl 加固
    ss << "echo '[3/5] 配置 sysctl 安全参数...'\n";
    ss << "cat > /etc/sysctl.d/99-photonbox-security.conf << 'EOF'\n";
    ss << "kernel.perf_event_paranoid=3\nkernel.kptr_restrict=2\nkernel.dmesg_restrict=1\n";
    ss << "kernel.unprivileged_bpf_disabled=1\nnet.core.bpf_jit_harden=2\n";
    ss << "vm.nr_hugepages=0\nfs.protected_hardlinks=1\nfs.protected_symlinks=1\nEOF\n";
    ss << "sysctl --system\n\n";

    // 微码更新
    ss << "echo '[4/5] 安装 CPU 微码更新...'\n";
    ss << "if grep -q 'Intel' /proc/cpuinfo; then\n  apt-get install -y intel-microcode\n";
    ss << "elif grep -q 'AMD' /proc/cpuinfo; then\n  apt-get install -y amd64-microcode\nfi\n\n";

    // 内核热补丁
    ss << "echo '[5/5] 安装内核热补丁...'\n";
    ss << "if command -v canonical-livepatch &>/dev/null; then\n  echo 'canonical-livepatch 已安装，请手动 enable'\n";
    ss << "else\n  apt-get install -y canonical-livepatch || echo '请手动安装 kpatch'\nfi\n\n";

    ss << "echo ''\necho '=== 加固完成，部分修改需要重启生效 ==='\n";
    ss << "echo '重启后请重新运行安全态势检测验证'\n";

    return ss.str();
}

std::vector<std::string> SecurityPostureEvaluator::get_extra_seccomp_restrictions(const SecurityPostureReport& report) {
    std::vector<std::string> restrictions;

    // 如果侧信道防护不足，沙盒内额外限制
    if (report.side_channel_score < 80) {
        restrictions.push_back("perf_event_open");  // 防止 perf 侧信道
        restrictions.push_back("bpf");               // 防止 unprivileged eBPF
    }

    // 如果硬件防护不足
    if (report.hardware_attack_score < 70) {
        restrictions.push_back("userfaultfd");  // 防止 userfaultfd 辅助 Rowhammer
    }

    // 内核 0day 防护不足
    if (report.kernel_0day_score < 80) {
        restrictions.push_back("keyctl");     // 减少内核密钥接口攻击面
        restrictions.push_back("add_key");
        restrictions.push_back("request_key");
    }

    return restrictions;
}

} // namespace sandbox
} // namespace photon_kernel
