"""
嵌套虚拟化环境检测器（Nested VM Detector）

参考开源项目：
- kvm-unit-tests (GPL-2.0): 嵌套虚拟化探测逻辑，cpuid 判断 hypervisor 位
- firecracker (Apache-2.0): 嵌套环境下跳过安全测试的逻辑，告警输出
- libvirt (LGPL-2.1): CPU 虚拟化能力探测逻辑
- criu (GPL-2.0): 嵌套 VM 快照用例跳过策略
- bpftool (GPL-2.0): BTF 完整性检测

目标场景：在虚拟机内部跑 PhotonBox StrongPool(Firecracker/KVM) 做开发调试；
不能做生产安全验收。

核心能力：
1. 检测是否运行在虚拟机中（CPUID hypervisor bit / DMI 信息）
2. 检测是否支持嵌套虚拟化（/dev/kvm + CPU vmx/svm 标志）
3. 检测 KVM 嵌套参数（/sys/module/kvm_intel/parameters/nested）
4. 检测 BTF 完整性（eBPF 用，bpftool 逻辑）
5. 输出环境标记 RUNNING_IN_NESTED_VM
6. 提供 StrongPool/eBPF/CRIU 的嵌套环境建议和警告

许可证：Apache-2.0（仅复用 shell 逻辑和算法思路，不直接拷贝 GPL C 代码）
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
import os
import subprocess
import platform
import re


class VMType(Enum):
    """虚拟机类型"""
    BARE_METAL = "bare_metal"          # 物理裸机
    KVM = "kvm"                        # KVM 虚拟机
    VMWARE = "vmware"                  # VMware
    VIRTUALBOX = "virtualbox"          # VirtualBox
    HYPER_V = "hyper_v"                # Hyper-V
    XEN = "xen"                        # Xen
    QEMU = "qemu"                      # QEMU
    UNKNOWN_VM = "unknown_vm"          # 未知虚拟机
    CONTAINER = "container"            # 容器（Docker/LXC）


class NestedStatus(Enum):
    """嵌套虚拟化状态"""
    BARE_METAL = "bare_metal"                    # 物理裸机，无嵌套
    VM_WITHOUT_NESTED = "vm_without_nested"      # 虚拟机但未开启嵌套虚拟化
    VM_WITH_NESTED = "vm_with_nested"            # 虚拟机且开启嵌套虚拟化，/dev/kvm 可用
    UNKNOWN = "unknown"                            # 未知


class ModuleAdvice(Enum):
    """模块在嵌套环境下的使用建议"""
    FULLY_SUPPORTED = "fully_supported"          # 完全支持，可用于生产验收
    DEV_ONLY = "dev_only"                        # 仅开发调试，不可用于生产验收
    DEGRADED = "degraded"                        # 功能降级，部分特性不可用
    SKIP_SECURITY_TESTS = "skip_security_tests"  # 跳过安全测试，仅功能测试
    NOT_RECOMMENDED = "not_recommended"          # 不推荐使用


@dataclass
class NestedVMReport:
    """嵌套虚拟化环境检测报告"""
    is_virtual_machine: bool = False
    vm_type: VMType = VMType.BARE_METAL
    nested_status: NestedStatus = NestedStatus.UNKNOWN
    kvm_available: bool = False
    kvm_device: Optional[str] = None
    kvm_nested_enabled: Optional[bool] = None
    cpu_virtualization_flags: List[str] = field(default_factory=list)
    btf_available: bool = False
    btf_path: Optional[str] = None
    hypervisor_vendor: Optional[str] = None
    running_in_container: bool = False
    warnings: List[str] = field(default_factory=list)
    module_advice: Dict[str, ModuleAdvice] = field(default_factory=dict)
    environment_markers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（JSON 可序列化）"""
        return {
            "is_virtual_machine": self.is_virtual_machine,
            "vm_type": self.vm_type.value,
            "nested_status": self.nested_status.value,
            "kvm_available": self.kvm_available,
            "kvm_device": self.kvm_device,
            "kvm_nested_enabled": self.kvm_nested_enabled,
            "cpu_virtualization_flags": self.cpu_virtualization_flags,
            "btf_available": self.btf_available,
            "btf_path": self.btf_path,
            "hypervisor_vendor": self.hypervisor_vendor,
            "running_in_container": self.running_in_container,
            "warnings": self.warnings,
            "module_advice": {k: v.value for k, v in self.module_advice.items()},
            "environment_markers": self.environment_markers,
        }

    def is_nested_vm(self) -> bool:
        """是否运行在嵌套虚拟化环境中（虚拟机 + /dev/kvm 可用）"""
        return self.nested_status == NestedStatus.VM_WITH_NESTED

    def can_run_strong_pool(self) -> bool:
        """是否可以运行 StrongPool（Firecracker/KVM）"""
        return self.kvm_available and self.kvm_device is not None

    def should_skip_security_tests(self) -> bool:
        """是否应该跳过安全测试（嵌套环境下）"""
        return self.is_nested_vm()

    def get_production_acceptance_status(self) -> str:
        """获取生产验收状态"""
        if self.nested_status == NestedStatus.BARE_METAL:
            return "VALID_FOR_PRODUCTION_ACCEPTANCE"
        elif self.nested_status == NestedStatus.VM_WITH_NESTED:
            return "DEV_ONLY_NOT_VALID_FOR_PRODUCTION_ACCEPTANCE"
        else:
            return "CANNOT_RUN_STRONG_POOL"


class NestedVMDetector:
    """
    嵌套虚拟化环境检测器

    参考 kvm-unit-tests 的探测方法：
    1. CPU 有 vmx/svm 标志（有虚拟化能力）
    2. CPUID 指令检测 hypervisor 位 = 当前运行在虚拟机里 → 判定嵌套虚拟化环境
    3. 输出环境标记 RUNNING_IN_NESTED_VM=TRUE
    """

    # 已知 hypervisor vendor 字符串（CPUID 0x40000000 返回）
    HYPERVISOR_VENDORS = {
        "VMwareVMware": VMType.VMWARE,
        "KVMKVMKVM": VMType.KVM,
        "Microsoft Hv": VMType.HYPER_V,
        "XenVMMXenVMM": VMType.XEN,
        "VBoxVBoxVBox": VMType.VIRTUALBOX,
        "TCGTCGTCGTCG": VMType.QEMU,
    }

    def __init__(self):
        self.report = NestedVMReport()

    def detect(self) -> NestedVMReport:
        """执行完整的嵌套虚拟化环境检测"""
        self._detect_container()
        self._detect_virtual_machine()
        self._detect_cpu_virtualization()
        self._detect_kvm()
        self._detect_kvm_nested()
        self._detect_btf()
        self._determine_nested_status()
        self._generate_warnings()
        self._generate_module_advice()
        self._generate_environment_markers()
        return self.report

    def _detect_container(self) -> None:
        """检测是否运行在容器中"""
        # 检查 /.dockerenv（Docker）
        if os.path.exists("/.dockerenv"):
            self.report.running_in_container = True
            return
        # 检查 /proc/1/cgroup 中的容器标识
        try:
            with open("/proc/1/cgroup") as f:
                cgroup_content = f.read()
                if any(x in cgroup_content for x in ["docker", "lxc", "containerd", "kubepods"]):
                    self.report.running_in_container = True
                    return
        except Exception:
            pass
        self.report.running_in_container = False

    def _detect_virtual_machine(self) -> None:
        """检测是否运行在虚拟机中"""
        # 方法1：检查 /proc/cpuinfo 中的 hypervisor 标志
        try:
            with open("/proc/cpuinfo") as f:
                cpuinfo = f.read()
                if "hypervisor" in cpuinfo.lower():
                    self.report.is_virtual_machine = True
        except Exception:
            pass

        # 方法2：使用 cpuid 命令检测 hypervisor 位（如果可用）
        if not self.report.is_virtual_machine:
            try:
                result = subprocess.run(
                    ["cpuid", "-1"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if "hypervisor" in result.stdout.lower():
                    self.report.is_virtual_machine = True
            except Exception:
                pass

        # 方法3：检查 DMI / sysfs 信息
        if not self.report.is_virtual_machine:
            self._detect_vm_type_from_dmi()

        # 检测 hypervisor vendor
        if self.report.is_virtual_machine:
            self._detect_hypervisor_vendor()

    def _detect_vm_type_from_dmi(self) -> None:
        """从 DMI 信息检测虚拟机类型"""
        dmi_paths = [
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/board_vendor",
        ]
        for path in dmi_paths:
            try:
                with open(path) as f:
                    content = f.read().strip().lower()
                    if any(x in content for x in ["vmware", "virtualbox", "kvm", "qemu", "xen", "hyper-v", "microsoft"]):
                        self.report.is_virtual_machine = True
                        if "vmware" in content:
                            self.report.vm_type = VMType.VMWARE
                        elif "virtualbox" in content:
                            self.report.vm_type = VMType.VIRTUALBOX
                        elif "kvm" in content or "qemu" in content:
                            self.report.vm_type = VMType.KVM
                        elif "xen" in content:
                            self.report.vm_type = VMType.XEN
                        elif "hyper-v" in content or "microsoft" in content:
                            self.report.vm_type = VMType.HYPER_V
                        return
            except Exception:
                continue

    def _detect_hypervisor_vendor(self) -> None:
        """检测 hypervisor vendor（CPUID 0x40000000）"""
        try:
            result = subprocess.run(
                ["cpuid", "-l", "0x40000000"],
                capture_output=True,
                text=True,
                timeout=5
            )
            for vendor, vm_type in self.HYPERVISOR_VENDORS.items():
                if vendor in result.stdout:
                    self.report.hypervisor_vendor = vendor
                    self.report.vm_type = vm_type
                    return
        except Exception:
            pass

    def _detect_cpu_virtualization(self) -> None:
        """检测 CPU 虚拟化扩展标志（vmx/svm）"""
        try:
            with open("/proc/cpuinfo") as f:
                cpuinfo = f.read()
                flags_match = re.search(r'flags\s*:\s*(.+)', cpuinfo)
                if flags_match:
                    flags = flags_match.group(1).split()
                    if "vmx" in flags:
                        self.report.cpu_virtualization_flags.append("vmx")
                    if "svm" in flags:
                        self.report.cpu_virtualization_flags.append("svm")
        except Exception:
            pass

    def _detect_kvm(self) -> None:
        """检测 KVM 设备是否可用"""
        kvm_paths = ["/dev/kvm", "/dev/kvm_intel", "/dev/kvm_amd"]
        for path in kvm_paths:
            if os.path.exists(path):
                self.report.kvm_device = path
                # 检查是否可读写
                if os.access(path, os.R_OK | os.W_OK):
                    self.report.kvm_available = True
                else:
                    self.report.kvm_available = False
                    self.report.warnings.append(f"KVM device {path} exists but not readable/writable")
                return
        self.report.kvm_available = False

    def _detect_kvm_nested(self) -> None:
        """检测 KVM 嵌套虚拟化是否启用"""
        nested_paths = [
            "/sys/module/kvm_intel/parameters/nested",
            "/sys/module/kvm_amd/parameters/nested",
        ]
        for path in nested_paths:
            if os.path.exists(path):
                try:
                    with open(path) as f:
                        content = f.read().strip()
                        self.report.kvm_nested_enabled = content in ["Y", "1", "y"]
                        return
                except Exception:
                    continue
        self.report.kvm_nested_enabled = None

    def _detect_btf(self) -> None:
        """检测 BTF（BPF Type Format）是否可用（eBPF 用）"""
        btf_path = "/sys/kernel/btf/vmlinux"
        if os.path.exists(btf_path):
            self.report.btf_available = True
            self.report.btf_path = btf_path
        else:
            self.report.btf_available = False

    def _determine_nested_status(self) -> None:
        """确定嵌套虚拟化状态"""
        if not self.report.is_virtual_machine and not self.report.running_in_container:
            self.report.nested_status = NestedStatus.BARE_METAL
            self.report.vm_type = VMType.BARE_METAL
        elif self.report.is_virtual_machine and self.report.kvm_available:
            self.report.nested_status = NestedStatus.VM_WITH_NESTED
        elif self.report.is_virtual_machine and not self.report.kvm_available:
            self.report.nested_status = NestedStatus.VM_WITHOUT_NESTED
        elif self.report.running_in_container:
            self.report.vm_type = VMType.CONTAINER
            self.report.nested_status = NestedStatus.VM_WITHOUT_NESTED
        else:
            self.report.nested_status = NestedStatus.UNKNOWN

    def _generate_warnings(self) -> None:
        """生成警告信息"""
        if self.report.is_nested_vm():
            self.report.warnings.append(
                "RUNNING_IN_NESTED_VM=TRUE: 运行在嵌套虚拟化环境中，"
                "安全测试和性能基准结果仅供开发调试，不可用于生产验收"
            )
            self.report.warnings.append(
                "嵌套虚拟化有显著 CPU 退出开销，延迟指标（目标<2ms预热命中）会失真，"
                "不能作为性能基准验证"
            )
            self.report.warnings.append(
                "部分 hypervisor 可能拦截 bpf 系统调用，BTF 完整性不一定 100% 和裸机一致"
            )
            self.report.warnings.append(
                "CRIU 快照在嵌套 VT 环境下可能偶现失败，快照不一定可在裸机恢复"
            )

        if self.report.is_virtual_machine and not self.report.kvm_available:
            self.report.warnings.append(
                "运行在虚拟机中但 KVM 不可用（未开启嵌套虚拟化），"
                "StrongPool(Firecracker/KVM) 无法启动"
            )

        if not self.report.btf_available and self.report.is_nested_vm():
            self.report.warnings.append(
                "嵌套环境中 BTF 不可用，eBPF 网络防护模块功能降级"
            )

    def _generate_module_advice(self) -> None:
        """生成各模块在当前环境下的使用建议"""
        if self.report.nested_status == NestedStatus.BARE_METAL:
            # 裸机环境，所有模块完全支持
            self.report.module_advice = {
                "StrongPool": ModuleAdvice.FULLY_SUPPORTED,
                "eBPF": ModuleAdvice.FULLY_SUPPORTED,
                "CRIU": ModuleAdvice.FULLY_SUPPORTED,
                "namespace": ModuleAdvice.FULLY_SUPPORTED,
                "security_tests": ModuleAdvice.FULLY_SUPPORTED,
                "performance_benchmark": ModuleAdvice.FULLY_SUPPORTED,
            }
        elif self.report.nested_status == NestedStatus.VM_WITH_NESTED:
            # 嵌套虚拟化环境，仅开发调试
            self.report.module_advice = {
                "StrongPool": ModuleAdvice.DEV_ONLY,
                "eBPF": ModuleAdvice.DEGRADED if not self.report.btf_available else ModuleAdvice.DEV_ONLY,
                "CRIU": ModuleAdvice.DEV_ONLY,
                "namespace": ModuleAdvice.DEV_ONLY,
                "security_tests": ModuleAdvice.SKIP_SECURITY_TESTS,
                "performance_benchmark": ModuleAdvice.NOT_RECOMMENDED,
            }
        else:
            # 无 KVM 环境，StrongPool 不可用
            self.report.module_advice = {
                "StrongPool": ModuleAdvice.NOT_RECOMMENDED,
                "eBPF": ModuleAdvice.NOT_RECOMMENDED,
                "CRIU": ModuleAdvice.NOT_RECOMMENDED,
                "namespace": ModuleAdvice.DEV_ONLY,
                "security_tests": ModuleAdvice.NOT_RECOMMENDED,
                "performance_benchmark": ModuleAdvice.NOT_RECOMMENDED,
            }

    def _generate_environment_markers(self) -> None:
        """生成环境标记（用于 shell 脚本和 CI）"""
        self.report.environment_markers = {
            "RUNNING_IN_NESTED_VM": "TRUE" if self.report.is_nested_vm() else "FALSE",
            "KVM_AVAILABLE": "TRUE" if self.report.kvm_available else "FALSE",
            "BTF_AVAILABLE": "TRUE" if self.report.btf_available else "FALSE",
            "VM_TYPE": self.report.vm_type.value,
            "NESTED_STATUS": self.report.nested_status.value,
            "PRODUCTION_ACCEPTANCE": self.report.get_production_acceptance_status(),
            "CPU_VIRT_FLAGS": ",".join(self.report.cpu_virtualization_flags) or "none",
        }

    def print_report(self) -> None:
        """打印人类可读的检测报告"""
        r = self.report
        print("=" * 60)
        print("  PhotonBox 嵌套虚拟化环境检测报告")
        print("=" * 60)
        print(f"  环境类型: {r.vm_type.value}")
        print(f"  嵌套状态: {r.nested_status.value}")
        print(f"  运行在虚拟机: {'是' if r.is_virtual_machine else '否'}")
        print(f"  运行在容器: {'是' if r.running_in_container else '否'}")
        print(f"  KVM 可用: {'是' if r.kvm_available else '否'}")
        if r.kvm_device:
            print(f"  KVM 设备: {r.kvm_device}")
        if r.kvm_nested_enabled is not None:
            print(f"  KVM 嵌套启用: {'是' if r.kvm_nested_enabled else '否'}")
        print(f"  CPU 虚拟化标志: {', '.join(r.cpu_virtualization_flags) or '无'}")
        print(f"  BTF 可用: {'是' if r.btf_available else '否'}")
        if r.hypervisor_vendor:
            print(f"  Hypervisor 厂商: {r.hypervisor_vendor}")
        print()
        print("  环境标记:")
        for key, value in r.environment_markers.items():
            print(f"    {key}={value}")
        print()
        print("  模块使用建议:")
        for module, advice in r.module_advice.items():
            print(f"    {module}: {advice.value}")
        print()
        if r.warnings:
            print("  警告:")
            for warning in r.warnings:
                print(f"    ⚠️  {warning}")
        print()
        print(f"  生产验收状态: {r.get_production_acceptance_status()}")
        print("=" * 60)


def detect_nested_vm() -> NestedVMReport:
    """便捷函数：执行嵌套虚拟化环境检测"""
    detector = NestedVMDetector()
    return detector.detect()


if __name__ == "__main__":
    report = detect_nested_vm()
    detector = NestedVMDetector()
    detector.report = report
    detector.print_report()
