// StrongPool (MicroVM) 工程落地实现
#include "photon_kernel/sandbox/strong_pool.hpp"
#include "photon_kernel/sandbox/risk_scorer.hpp"
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>
namespace photon_kernel {
namespace sandbox {
// ==================== KvmCapabilities ====================
std::string KvmCapabilities::to_string() const {
    std::ostringstream oss;
    oss << "KVM Capabilities:\n";
    oss << "  kvm_available: " << (kvm_available ? "yes" : "no") << "\n";
    oss << "  firecracker_available: " << (firecracker_available ? "yes" : "no") << "\n";
    oss << "  cpu_virtualization: " << (cpu_virtualization ? "yes" : "no") << "\n";
    oss << "  nested_vm: " << (is_nested_vm ? "YES (debug only)" : "no") << "\n";
    oss << "  production_acceptance: " << (production_acceptance_valid ? "valid" : "INVALID (nested env)") << "\n";
    if (!nested_warning.empty()) {
        oss << "  WARNING: " << nested_warning << "\n";
    }
    oss << "  message: " << message;
    return oss.str();
}
// ==================== KvmDetector ====================
bool KvmDetector::kvm_available(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return false;
    // 尝试打开（需要权限）
    FILE* f = fopen(path.c_str(), "r");
    if (f) {
        fclose(f);
        return true;
    }
    return false;
}
bool KvmDetector::cpu_supports_virtualization() {
    // 检查 /proc/cpuinfo 中的 vmx/svm 标志
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (!cpuinfo.is_open()) return false;
    std::string line;
    while (std::getline(cpuinfo, line)) {
        if (line.find("vmx") != std::string::npos ||
            line.find("svm") != std::string::npos) {
            return true;
        }
    }
    return false;
}
bool KvmDetector::firecracker_available(const std::string& binary) {
    // 检查 PATH 中是否有 firecracker
    std::string cmd = "which " + binary + " > /dev/null 2>&1";
    return system(cmd.c_str()) == 0;
}

bool KvmDetector::detect_hypervisor_bit() {
    // 检测 CPUID hypervisor 位（是否运行在虚拟机中）
    // 方法1：检查 /proc/cpuinfo 中的 hypervisor 标志
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (cpuinfo.is_open()) {
        std::string line;
        while (std::getline(cpuinfo, line)) {
            if (line.find("hypervisor") != std::string::npos) {
                return true;
            }
        }
    }
    // 方法2：检查 systemd-detect-virt（如果可用）
    std::string cmd = "systemd-detect-virt --vm 2>/dev/null | grep -qv none";
    if (system(cmd.c_str()) == 0) {
        return true;
    }
    // 方法3：检查 DMI product name
    std::ifstream dmi("/sys/class/dmi/id/product_name");
    if (dmi.is_open()) {
        std::string product;
        std::getline(dmi, product);
        if (product.find("VMware") != std::string::npos ||
            product.find("VirtualBox") != std::string::npos ||
            product.find("KVM") != std::string::npos ||
            product.find("QEMU") != std::string::npos ||
            product.find("Virtual") != std::string::npos ||
            product.find("Hyper-V") != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool KvmDetector::detect_nested_vm() {
    // 嵌套虚拟化检测：
    // 1. CPUID hypervisor 位 = 1（运行在虚拟机中）
    // 2. CPU 有 vmx/svm 标志（客户机可见虚拟化扩展）
    // 3. /dev/kvm 存在（嵌套 KVM 已开启）
    // 同时满足以上条件 = 嵌套虚拟化环境
    bool in_vm = detect_hypervisor_bit();
    bool has_virt = cpu_supports_virtualization();
    bool has_kvm = kvm_available("/dev/kvm");

    // 检查 KVM 嵌套参数
    bool kvm_nested_enabled = false;
    std::ifstream nested_intel("/sys/module/kvm_intel/parameters/nested");
    if (nested_intel.is_open()) {
        std::string val;
        std::getline(nested_intel, val);
        kvm_nested_enabled = (val == "Y" || val == "1");
    }
    std::ifstream nested_amd("/sys/module/kvm_amd/parameters/nested");
    if (nested_amd.is_open()) {
        std::string val;
        std::getline(nested_amd, val);
        kvm_nested_enabled = (val == "Y" || val == "1");
    }

    // 嵌套虚拟化判定：在虚拟机中 + 有虚拟化标志 + 有 /dev/kvm
    return in_vm && has_virt && has_kvm;
}
KvmCapabilities KvmDetector::detect() {
    return detect(StrongPoolConfig());
}

KvmCapabilities KvmDetector::detect(const StrongPoolConfig& config) {
    KvmCapabilities caps;
    caps.kvm_path = config.kvm_device;
    caps.kvm_available = kvm_available(config.kvm_device);
    caps.cpu_virtualization = cpu_supports_virtualization();
    caps.firecracker_available = firecracker_available(config.firecracker_binary);
    if (caps.firecracker_available) {
        // 获取完整路径
        char path[1024];
        std::string cmd = "which " + config.firecracker_binary;
        FILE* p = popen(cmd.c_str(), "r");
        if (p) {
            if (fgets(path, sizeof(path), p)) {
                caps.firecracker_path = path;
                // 去掉换行
                while (!caps.firecracker_path.empty() &&
                       (caps.firecracker_path.back() == '\n' ||
                        caps.firecracker_path.back() == '\r')) {
                    caps.firecracker_path.pop_back();
                }
            }
            pclose(p);
        }
    }
    // 嵌套虚拟化检测（仅限调试，禁止生产安全验收）
    caps.hypervisor_bit_detected = detect_hypervisor_bit();
    caps.is_nested_vm = detect_nested_vm();
    if (caps.is_nested_vm) {
        caps.production_acceptance_valid = false;
        caps.nested_warning = "Running inside nested virtualization! "
                              "Security & performance results are NOT valid for production acceptance. "
                              "Use only for development and debugging.";
    } else if (caps.hypervisor_bit_detected && !caps.kvm_available) {
        caps.nested_warning = "Running inside a VM without nested KVM enabled. "
                              "StrongPool (Firecracker/KVM) cannot start. "
                              "Enable nested virtualization for development only.";
    }

    if (caps.kvm_available && caps.firecracker_available && caps.cpu_virtualization) {
        caps.message = "MicroVM fully available";
        if (caps.is_nested_vm) {
            caps.message += " (NESTED VM - DEBUG ONLY, NOT for production acceptance)";
        }
    } else if (!caps.kvm_available) {
        caps.message = "KVM not available: " + config.kvm_device +
                       " missing or no permission. MicroVM disabled.";
    } else if (!caps.firecracker_available) {
        caps.message = "firecracker binary not found in PATH. MicroVM disabled.";
    } else if (!caps.cpu_virtualization) {
        caps.message = "CPU does not support hardware virtualization (vmx/svm). MicroVM disabled.";
    }
    return caps;
}
// ==================== StrongPoolScheduler ====================
StrongPoolScheduler::StrongPoolScheduler() : StrongPoolScheduler(StrongPoolConfig()) {}

StrongPoolScheduler::StrongPoolScheduler(const StrongPoolConfig& config)
    : config_(config) {
    capabilities_ = KvmDetector::detect(config);
}
StrongPoolScheduler::~StrongPoolScheduler() {
    // 清理所有VM
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto& [id, vm] : vms_) {
        if (vm_destroyer_ && vm->state != VmInstanceState::TERMINATED) {
            vm_destroyer_(vm);
        }
    }
}
std::string StrongPoolScheduler::generate_vm_id() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
    std::ostringstream oss;
    oss << "vm-" << std::hex << std::setfill('0')
        << std::setw(8) << dis(gen) << std::setw(8) << dis(gen);
    return oss.str();
}
bool StrongPoolScheduler::has_memory_for(size_t memory_mb) const {
    if (config_.total_memory_limit_mb == 0) return true;
    return current_memory_mb() + memory_mb <= config_.total_memory_limit_mb;
}
size_t StrongPoolScheduler::current_memory_mb() const {
    size_t total = 0;
    for (const auto& [id, vm] : vms_) {
        if (vm->state == VmInstanceState::RUNNING ||
            vm->state == VmInstanceState::STARTING ||
            vm->state == VmInstanceState::EXPORTING) {
            total += vm->memory_mb;
        }
    }
    return total;
}
SchedulingResult StrongPoolScheduler::schedule(
    const std::string& task_id, const std::string& tenant_id,
    RiskLevel risk_level, size_t memory_mb) {
    std::lock_guard<std::mutex> lock(mtx_);
    SchedulingResult result;
    // 1. KVM 检查（限制1：关键安全点）
    if (!capabilities_.kvm_available || !capabilities_.firecracker_available) {
        // 高风险任务：直接拒绝，绝不降级（安全关键点）
        if (risk_level == RiskLevel::HIGH || risk_level == RiskLevel::CRITICAL) {
            if (config_.reject_high_risk_without_kvm) {
                result.decision = SchedulingDecision::REJECT_NO_KVM;
                result.reason = "High-risk task requires MicroVM, but KVM/firecracker not available. "
                                "Refusing to silently downgrade (security policy).";
                rejected_++;
                return result;
            }
        }
        // 低风险任务：允许降级到 LightPool（如果配置允许）
        if (risk_level == RiskLevel::LOW && config_.allow_low_risk_fallback) {
            result.decision = SchedulingDecision::FALLBACK_PROCESS;
            result.reason = "KVM not available, falling back to process sandbox (low-risk only).";
            fallback_++;
            return result;
        }
        // 中风险任务：默认不允许降级
        if (risk_level == RiskLevel::MEDIUM && !config_.allow_medium_risk_fallback) {
            result.decision = SchedulingDecision::REJECT_NO_KVM;
            result.reason = "Medium-risk task requires MicroVM, KVM not available and fallback not enabled.";
            rejected_++;
            return result;
        }
        // 中风险且允许降级
        if (risk_level == RiskLevel::MEDIUM && config_.allow_medium_risk_fallback) {
            result.decision = SchedulingDecision::FALLBACK_PROCESS;
            result.reason = "KVM not available, falling back to process sandbox (medium-risk, fallback enabled).";
            fallback_++;
            return result;
        }
    }
    // 2. 内存检查
    size_t vm_memory = memory_mb > 0 ? memory_mb : config_.default_vm_memory_mb;
    if (vm_memory > config_.max_vm_memory_mb) {
        vm_memory = config_.max_vm_memory_mb;
    }
    if (!has_memory_for(vm_memory)) {
        // 内存不足，尝试排队
        if (pending_queue_.size() >= config_.max_queue_size) {
            result.decision = SchedulingDecision::REJECT_QUEUE_FULL;
            result.reason = "Memory limit reached and queue full.";
            rejected_++;
            return result;
        }
        // 排队
        auto vm = std::make_shared<VmInstance>();
        vm->vm_id = generate_vm_id();
        vm->task_id = task_id;
        vm->tenant_id = tenant_id;
        vm->risk_level = risk_level;
        vm->memory_mb = vm_memory;
        vm->state = VmInstanceState::PENDING;
        vm->created_at = std::chrono::system_clock::now();
        pending_queue_.push(vm);
        vms_[vm->vm_id] = vm;
        result.decision = SchedulingDecision::QUEUED;
        result.reason = "Memory limit reached, queued.";
        result.vm_id = vm->vm_id;
        return result;
    }
    // 3. 并发上限检查
    size_t active = 0;
    for (const auto& [id, vm] : vms_) {
        if (vm->state == VmInstanceState::RUNNING ||
            vm->state == VmInstanceState::STARTING) {
            active++;
        }
    }
    if (active >= config_.max_concurrent_vms) {
        if (pending_queue_.size() >= config_.max_queue_size) {
            result.decision = SchedulingDecision::REJECT_QUEUE_FULL;
            result.reason = "Max concurrent VMs reached and queue full.";
            rejected_++;
            return result;
        }
        // 排队
        auto vm = std::make_shared<VmInstance>();
        vm->vm_id = generate_vm_id();
        vm->task_id = task_id;
        vm->tenant_id = tenant_id;
        vm->risk_level = risk_level;
        vm->memory_mb = vm_memory;
        vm->state = VmInstanceState::PENDING;
        vm->created_at = std::chrono::system_clock::now();
        pending_queue_.push(vm);
        vms_[vm->vm_id] = vm;
        result.decision = SchedulingDecision::QUEUED;
        result.reason = "Max concurrent VMs reached, queued.";
        result.vm_id = vm->vm_id;
        return result;
    }
    // 4. 可以运行 MicroVM
    auto vm = std::make_shared<VmInstance>();
    vm->vm_id = generate_vm_id();
    vm->task_id = task_id;
    vm->tenant_id = tenant_id;
    vm->risk_level = risk_level;
    vm->memory_mb = vm_memory;
    vm->state = VmInstanceState::STARTING;
    vm->created_at = std::chrono::system_clock::now();
    vm->started_at = std::chrono::system_clock::now();
    vm->expires_at = vm->started_at + config_.max_ttl;
    vm->socket_path = "/tmp/photon-" + vm->vm_id + ".socket";
    vms_[vm->vm_id] = vm;
    // 调用 VM 创建器（外部实现实际 Firecracker 启动）
    if (vm_creator_) {
        bool ok = vm_creator_(vm);
        if (ok) {
            vm->state = VmInstanceState::RUNNING;
        } else {
            vm->state = VmInstanceState::FAILED;
            failed_++;
            result.decision = SchedulingDecision::REJECT_NO_KVM;
            result.reason = "Failed to create MicroVM instance.";
            return result;
        }
    } else {
        // 没有设置创建器，标记为运行（模拟/测试模式）
        vm->state = VmInstanceState::RUNNING;
    }
    result.decision = SchedulingDecision::RUN_MICROVM;
    result.reason = "MicroVM scheduled.";
    result.vm_id = vm->vm_id;
    return result;
}
void StrongPoolScheduler::complete(const std::string& vm_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = vms_.find(vm_id);
    if (it == vms_.end()) return;
    auto& vm = it->second;
    vm->state = VmInstanceState::TERMINATING;
    if (vm_destroyer_) {
        vm_destroyer_(vm);
    }
    vm->state = VmInstanceState::TERMINATED;
    completed_++;
    // 尝试启动队列中的下一个
    try_process_queue();
}
void StrongPoolScheduler::fail(const std::string& vm_id, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = vms_.find(vm_id);
    if (it == vms_.end()) return;
    auto& vm = it->second;
    vm->state = VmInstanceState::FAILED;
    if (vm_destroyer_) {
        vm_destroyer_(vm);
    }
    failed_++;
    try_process_queue();
}
size_t StrongPoolScheduler::enforce_ttl() {
    std::lock_guard<std::mutex> lock(mtx_);
    auto now = std::chrono::system_clock::now();
    size_t terminated = 0;
    for (auto& [id, vm] : vms_) {
        if ((vm->state == VmInstanceState::RUNNING ||
             vm->state == VmInstanceState::STARTING) &&
            now >= vm->expires_at) {
            vm->state = VmInstanceState::TERMINATING;
            if (vm_destroyer_) {
                vm_destroyer_(vm);
            }
            vm->state = VmInstanceState::TERMINATED;
            terminated++;
            completed_++;
        }
    }
    if (terminated > 0) {
        try_process_queue();
    }
    return terminated;
}
void StrongPoolScheduler::try_process_queue() {
    // 调用时已持有锁
    while (!pending_queue_.empty()) {
        // 检查并发和内存
        size_t active = 0;
        for (const auto& [id, vm] : vms_) {
            if (vm->state == VmInstanceState::RUNNING ||
                vm->state == VmInstanceState::STARTING) {
                active++;
            }
        }
        if (active >= config_.max_concurrent_vms) break;
        auto next = pending_queue_.front();
        if (!has_memory_for(next->memory_mb)) break;
        pending_queue_.pop();
        next->state = VmInstanceState::STARTING;
        next->started_at = std::chrono::system_clock::now();
        next->expires_at = next->started_at + config_.max_ttl;
        if (vm_creator_) {
            if (vm_creator_(next)) {
                next->state = VmInstanceState::RUNNING;
            } else {
                next->state = VmInstanceState::FAILED;
                failed_++;
            }
        } else {
            next->state = VmInstanceState::RUNNING;
        }
    }
}
StrongPoolScheduler::PoolStatus StrongPoolScheduler::status() const {
    std::lock_guard<std::mutex> lock(mtx_);
    PoolStatus s;
    for (const auto& [id, vm] : vms_) {
        if (vm->state == VmInstanceState::RUNNING ||
            vm->state == VmInstanceState::STARTING ||
            vm->state == VmInstanceState::EXPORTING) {
            s.active_vms++;
            s.total_memory_mb += vm->memory_mb;
        }
    }
    s.queued_tasks = pending_queue_.size();
    s.completed_tasks = completed_.load();
    s.failed_tasks = failed_.load();
    s.rejected_tasks = rejected_.load();
    s.fallback_tasks = fallback_.load();
    s.kvm_available = capabilities_.kvm_available && capabilities_.firecracker_available;
    s.message = capabilities_.message;
    return s;
}
std::shared_ptr<VmInstance> StrongPoolScheduler::get_vm(const std::string& vm_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = vms_.find(vm_id);
    if (it == vms_.end()) return nullptr;
    return it->second;
}
std::vector<std::shared_ptr<VmInstance>> StrongPoolScheduler::active_vms() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<std::shared_ptr<VmInstance>> result;
    for (const auto& [id, vm] : vms_) {
        if (vm->state == VmInstanceState::RUNNING ||
            vm->state == VmInstanceState::STARTING) {
            result.push_back(vm);
        }
    }
    return result;
}
} // namespace sandbox
} // namespace photon_kernel
