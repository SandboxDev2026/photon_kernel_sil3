// 运行时选型器实现
#include "photon_kernel/sandbox/runtime_selector.hpp"
#include <sstream>
#include <algorithm>
#include <sys/stat.h>
#include <unistd.h>
namespace photon_kernel {
namespace sandbox {
std::string runtime_type_name(RuntimeType type) {
    switch (type) {
        case RuntimeType::CONTAINER: return "Container";
        case RuntimeType::GVISOR: return "gVisor";
        case RuntimeType::MICROVM: return "MicroVM";
        case RuntimeType::WASM: return "Wasm";
    }
    return "Unknown";
}
RuntimeSelector::RuntimeSelector() {
    // Container 画像
    RuntimeProfile container;
    container.type = RuntimeType::CONTAINER;
    container.name = "Container";
    container.isolation_strength = 30;
    container.cold_start_speed = 70;
    container.concurrency_density = 85;
    container.linux_compatibility = 100;
    container.state_recovery = 60;
    container.cost_efficiency = 90;
    container.typical_cold_start_ms = 100;
    container.typical_memory_mb = 10;
    container.requires_root = true;
    container.requires_userns = true;
    container.description = "容器运行时，namespace+cgroup 隔离，共享宿主内核。适合可信内部代码。";
    profiles_[RuntimeType::CONTAINER] = container;
    // gVisor 画像
    RuntimeProfile gvisor;
    gvisor.type = RuntimeType::GVISOR;
    gvisor.name = "gVisor";
    gvisor.isolation_strength = 60;
    gvisor.cold_start_speed = 50;
    gvisor.concurrency_density = 65;
    gvisor.linux_compatibility = 80;
    gvisor.state_recovery = 50;
    gvisor.cost_efficiency = 70;
    gvisor.typical_cold_start_ms = 200;
    gvisor.typical_memory_mb = 30;
    gvisor.requires_root = true;
    gvisor.description = "gVisor 用户态内核，拦截全部系统调用。不需要 KVM，普通容器即可运行。适合半可信多租户。";
    profiles_[RuntimeType::GVISOR] = gvisor;
    // MicroVM 画像
    RuntimeProfile microvm;
    microvm.type = RuntimeType::MICROVM;
    microvm.name = "MicroVM";
    microvm.isolation_strength = 95;
    microvm.cold_start_speed = 65;
    microvm.concurrency_density = 35;
    microvm.linux_compatibility = 100;
    microvm.state_recovery = 85;
    microvm.cost_efficiency = 40;
    microvm.typical_cold_start_ms = 125;
    microvm.typical_memory_mb = 50;
    microvm.requires_kvm = true;
    microvm.requires_root = true;
    microvm.description = "Firecracker MicroVM，独立客户内核，KVM 硬件虚拟化。适合公网完全不可信代码。";
    profiles_[RuntimeType::MICROVM] = microvm;
    // Wasm 画像
    RuntimeProfile wasm;
    wasm.type = RuntimeType::WASM;
    wasm.name = "Wasm";
    wasm.isolation_strength = 90;
    wasm.cold_start_speed = 100;
    wasm.concurrency_density = 100;
    wasm.linux_compatibility = 30;
    wasm.state_recovery = 95;
    wasm.cost_efficiency = 100;
    wasm.typical_cold_start_ms = 1;
    wasm.typical_memory_mb = 1;
    wasm.description = "WebAssembly 沙箱，WASI 接口。冷启动<1ms，并发密度极高。适合无状态函数计算。";
    profiles_[RuntimeType::WASM] = wasm;
}
RuntimeSelector& RuntimeSelector::instance() {
    static RuntimeSelector selector;
    return selector;
}
std::vector<RuntimeProfile> RuntimeSelector::all_profiles() const {
    std::vector<RuntimeProfile> result;
    for (const auto& [type, profile] : profiles_) {
        result.push_back(profile);
    }
    return result;
}
RuntimeProfile RuntimeSelector::profile(RuntimeType type) const {
    auto it = profiles_.find(type);
    return it == profiles_.end() ? RuntimeProfile{} : it->second;
}
int RuntimeSelector::score_runtime(const RuntimeProfile& p,
                                    const WorkloadProfile& w) const {
    int score = 0;
    // 硬约束：需要完整 Linux 工具但运行时兼容性低，大幅扣分
    if (w.needs_full_linux_tools && p.linux_compatibility < 50) {
        score -= 150;  // Wasm 等低兼容性运行时不适合需要完整 Linux 工具的场景
    }
    // 隔离强度：代码/租户可信度越低，越需要强隔离
    int trust_avg = (w.code_trust_level + w.tenant_trust_level) / 2;
    int isolation_weight = 100 - trust_avg;  // 越不可信，隔离权重越高
    score += p.isolation_strength * isolation_weight / 100;
    // Linux 兼容性：需要完整工具链时权重高
    int linux_weight = w.needs_full_linux_tools ? 80 : 20;
    score += p.linux_compatibility * linux_weight / 100;
    // 冷启动：敏感度越高权重越高
    score += p.cold_start_speed * w.cold_start_sensitivity / 100;
    // 并发密度：要求越高权重越高
    score += p.concurrency_density * w.concurrency_requirement / 100;
    // 状态恢复：需要时权重高
    int recovery_weight = w.needs_state_recovery ? 70 : 10;
    score += p.state_recovery * recovery_weight / 100;
    // 成本：敏感度越高权重越高
    score += p.cost_efficiency * w.cost_sensitivity / 100;
    return score;
}
RuntimeSelection RuntimeSelector::select(const WorkloadProfile& workload) const {
    RuntimeSelection result;
    // 计算所有运行时评分
    std::vector<std::pair<RuntimeType, int>> scored;
    for (const auto& [type, profile] : profiles_) {
        int s = score_runtime(profile, workload);
        scored.push_back({type, s});
        result.scores[type] = s;
    }
    // 按评分排序
    std::sort(scored.begin(), scored.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    result.selected = scored[0].first;
    result.fallback = scored.size() > 1 ? scored[1].first : scored[0].first;
    // 生成原因
    const auto& best = profiles_.at(result.selected);
    std::ostringstream reason;
    reason << "选择 " << best.name << "（评分 " << scored[0].second << "）：";
    int trust_avg = (workload.code_trust_level + workload.tenant_trust_level) / 2;
    if (trust_avg < 30) {
        reason << "代码/租户低可信度(" << trust_avg << "%)，需要强隔离；";
    } else if (trust_avg > 70) {
        reason << "代码/租户高可信度(" << trust_avg << "%)，可接受轻量隔离；";
    }
    if (workload.needs_full_linux_tools) {
        reason << "需要完整Linux工具链；";
    }
    if (workload.cold_start_sensitivity > 70) {
        reason << "高冷启动敏感度(" << workload.cold_start_sensitivity << "%)；";
    }
    if (workload.concurrency_requirement > 70) {
        reason << "高并发密度要求(" << workload.concurrency_requirement << "%)；";
    }
    result.reason = reason.str();
    // 风险提示
    if (result.selected == RuntimeType::CONTAINER && trust_avg < 50) {
        result.warnings.push_back("容器共享宿主内核，低可信度代码存在内核漏洞逃逸风险，建议升级到 MicroVM");
    }
    if (result.selected == RuntimeType::WASM && workload.needs_full_linux_tools) {
        result.warnings.push_back("Wasm 仅支持 WASI 接口，无法运行完整 Linux 工具链，建议改用 Container/MicroVM");
    }
    if (result.selected == RuntimeType::MICROVM) {
        result.warnings.push_back("MicroVM 需要 KVM 硬件虚拟化，普通 Docker 容器无法运行，会自动降级");
    }
    return result;
}
bool RuntimeSelector::is_available(RuntimeType type) const {
    switch (type) {
        case RuntimeType::CONTAINER:
            // 检查 namespace 支持
            return true;  // 进程沙盒始终可用
        case RuntimeType::GVISOR:
            return system("command -v runsc >/dev/null 2>&1") == 0;
        case RuntimeType::MICROVM: {
            struct stat st;
            if (stat("/dev/kvm", &st) != 0) return false;
            return system("command -v firecracker >/dev/null 2>&1") == 0;
        }
        case RuntimeType::WASM:
            return system("command -v wasmtime >/dev/null 2>&1") == 0 ||
                   system("command -v wasmer >/dev/null 2>&1") == 0;
    }
    return false;
}
std::vector<RuntimeType> RuntimeSelector::available_runtimes() const {
    std::vector<RuntimeType> result;
    for (const auto& [type, _] : profiles_) {
        if (is_available(type)) result.push_back(type);
    }
    return result;
}
std::string RuntimeSelector::comparison_table() const {
    std::ostringstream oss;
    oss << "| 运行时 | 隔离强度 | 冷启动 | 并发密度 | Linux兼容 | 状态恢复 | 成本 | 适用场景 |\n";
    oss << "|--------|----------|--------|----------|-----------|----------|------|----------|\n";
    for (const auto& [type, p] : profiles_) {
        oss << "| " << p.name << " | " << p.isolation_strength << "/100 | "
            << p.typical_cold_start_ms << "ms | " << p.concurrency_density << "/100 | "
            << p.linux_compatibility << "/100 | " << p.state_recovery << "/100 | "
            << p.cost_efficiency << "/100 | " << p.description.substr(0, 20) << "... |\n";
    }
    return oss.str();
}
} // namespace sandbox
} // namespace photon_kernel
