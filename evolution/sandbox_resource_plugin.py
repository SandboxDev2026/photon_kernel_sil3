"""
沙盒资源上报插件（借鉴 openFuyao DRA 设备插件模型）

参考 openFuyao 的 DRA (Dynamic Resource Allocation) 设备插件模型，
实现 PhotonBox 沙盒资源上报插件，上报沙盒能力：StrongPool/LightPool可用配额、KVM是否可用。

借鉴点：
1. DRA设备插件模型: 异构硬件资源上报、配额、硬切分
2. 资源上报范式: 节点资源发现、容量报告、健康检查
3. 插件化架构: 资源插件热插拔，不修改主调度器
4. 多级资源池: LightPool/StrongPool 独立配额管理
5. 能力探测: 自动探测 KVM/CAP_BPF/CRIU 等能力，上报可用状态

许可证: Apache-2.0（与 openFuyao 一致）
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Tuple
from enum import Enum
import time
import threading
import os


class ResourceType(Enum):
    """资源类型"""
    LIGHT_POOL = "light_pool"        # LightPool 进程沙盒
    STRONG_POOL = "strong_pool"      # StrongPool KVM MicroVM
    EBPF = "ebpf"                    # eBPF 网络过滤
    CRIU = "criu"                    # CRIU 快照
    GRPC = "grpc"                    # gRPC 服务
    K8S_OPERATOR = "k8s_operator"    # K8s Operator


class ResourceHealth(Enum):
    """资源健康状态"""
    HEALTHY = "healthy"              # 健康
    DEGRADED = "degraded"            # 降级（部分功能不可用）
    UNAVAILABLE = "unavailable"      # 不可用
    UNKNOWN = "unknown"              # 未知


@dataclass
class ResourceCapacity:
    """资源容量"""
    resource_type: ResourceType
    total: int = 0                   # 总容量
    used: int = 0                    # 已使用
    available: int = 0               # 可用
    reserved: int = 0                # 预留
    unit: str = "instances"          # 单位
    health: ResourceHealth = ResourceHealth.UNKNOWN
    last_heartbeat: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def utilization_percent(self) -> float:
        """利用率百分比"""
        if self.total == 0:
            return 0.0
        return (self.used / self.total) * 100

    def update_available(self) -> None:
        """更新可用容量"""
        self.available = max(0, self.total - self.used - self.reserved)


@dataclass
class NodeCapability:
    """节点能力探测结果"""
    node_id: str
    kvm_available: bool = False       # KVM 硬件虚拟化是否可用
    kvm_device: Optional[str] = None  # KVM 设备路径
    cap_bpf_available: bool = False   # CAP_BPF 是否可用
    criu_available: bool = False      # CRIU 是否可用
    criu_binary: Optional[str] = None # CRIU 二进制路径
    cgroup_v2_available: bool = False # cgroup v2 是否可用
    landlock_available: bool = False  # Landlock 是否可用
    namespace_available: bool = False # Namespace 是否可用
    kernel_version: str = ""          # 内核版本
    cpu_cores: int = 0                # CPU 核数
    memory_mb: int = 0                # 内存大小
    detected_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "node_id": self.node_id,
            "kvm_available": self.kvm_available,
            "kvm_device": self.kvm_device,
            "cap_bpf_available": self.cap_bpf_available,
            "criu_available": self.criu_available,
            "criu_binary": self.criu_binary,
            "cgroup_v2_available": self.cgroup_v2_available,
            "landlock_available": self.landlock_available,
            "namespace_available": self.namespace_available,
            "kernel_version": self.kernel_version,
            "cpu_cores": self.cpu_cores,
            "memory_mb": self.memory_mb,
            "detected_at": self.detected_at,
        }


class CapabilityDetector:
    """
    节点能力探测器

    自动探测 KVM/CAP_BPF/CRIU/cgroup v2/Landlock/Namespace 等能力，
    上报可用状态。借鉴 openFuyao 的设备发现机制。
    """

    def __init__(self, node_id: Optional[str] = None):
        self.node_id = node_id or f"node_{os.getpid()}"
        self.capability: Optional[NodeCapability] = None

    def detect_all(self) -> NodeCapability:
        """探测所有能力"""
        cap = NodeCapability(node_id=self.node_id)

        # 探测 KVM
        cap.kvm_available, cap.kvm_device = self._detect_kvm()

        # 探测 CAP_BPF（简化：检查 /proc/sys/kernel/unprivileged_bpf_disabled）
        cap.cap_bpf_available = self._detect_cap_bpf()

        # 探测 CRIU
        cap.criu_available, cap.criu_binary = self._detect_criu()

        # 探测 cgroup v2
        cap.cgroup_v2_available = self._detect_cgroup_v2()

        # 探测 Landlock
        cap.landlock_available = self._detect_landlock()

        # 探测 Namespace
        cap.namespace_available = self._detect_namespace()

        # 探测内核版本
        cap.kernel_version = self._detect_kernel_version()

        # 探测 CPU 和内存
        cap.cpu_cores = os.cpu_count() or 0
        cap.memory_mb = self._detect_memory()

        self.capability = cap
        return cap

    def _detect_kvm(self) -> Tuple[bool, Optional[str]]:
        """探测 KVM 硬件虚拟化"""
        kvm_paths = ["/dev/kvm", "/dev/kvm_intel", "/dev/kvm_amd"]
        for path in kvm_paths:
            if os.path.exists(path):
                # 检查是否可读写
                if os.access(path, os.R_OK | os.W_OK):
                    return True, path
                return True, path  # 设备存在但权限不足
        # 检查 CPU 虚拟化支持
        try:
            with open("/proc/cpuinfo") as f:
                cpuinfo = f.read()
                if "vmx" in cpuinfo.lower() or "svm" in cpuinfo.lower():
                    return True, None  # CPU 支持但 /dev/kvm 不存在（可能未加载模块）
        except Exception:
            pass
        return False, None

    def _detect_cap_bpf(self) -> bool:
        """探测 CAP_BPF（简化）"""
        # 检查内核版本 >= 5.8（CAP_BPF 引入版本）
        try:
            with open("/proc/sys/kernel/osrelease") as f:
                version = f.read().strip()
                parts = version.split(".")
                if len(parts) >= 2:
                    major = int(parts[0])
                    minor = int(parts[1])
                    if major > 5 or (major == 5 and minor >= 8):
                        return True
        except Exception:
            pass
        return False

    def _detect_criu(self) -> Tuple[bool, Optional[str]]:
        """探测 CRIU"""
        criu_paths = ["/usr/bin/criu", "/usr/local/bin/criu", "/sbin/criu"]
        for path in criu_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return True, path
        return False, None

    def _detect_cgroup_v2(self) -> bool:
        """探测 cgroup v2"""
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    if "cgroup2" in line:
                        return True
        except Exception:
            pass
        return os.path.exists("/sys/fs/cgroup/cgroup.controllers")

    def _detect_landlock(self) -> bool:
        """探测 Landlock（简化：检查内核版本 >= 5.13）"""
        try:
            with open("/proc/sys/kernel/osrelease") as f:
                version = f.read().strip()
                parts = version.split(".")
                if len(parts) >= 2:
                    major = int(parts[0])
                    minor = int(parts[1])
                    if major > 5 or (major == 5 and minor >= 13):
                        return True
        except Exception:
            pass
        return False

    def _detect_namespace(self) -> bool:
        """探测 Namespace（简化：检查 /proc/self/ns）"""
        return os.path.exists("/proc/self/ns")

    def _detect_kernel_version(self) -> str:
        """探测内核版本"""
        try:
            with open("/proc/sys/kernel/osrelease") as f:
                return f.read().strip()
        except Exception:
            return "unknown"

    def _detect_memory(self) -> int:
        """探测内存大小（MB）"""
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return int(parts[1]) // 1024  # KB -> MB
        except Exception:
            pass
        return 0


class SandboxResourcePlugin:
    """
    沙盒资源上报插件（借鉴 openFuyao DRA 设备插件模型）

    核心能力：
    1. 资源上报: 上报 LightPool/StrongPool/eBPF/CRIU 等资源容量
    2. 配额管理: 独立配额管理，硬切分，防止资源抢占
    3. 健康检查: 定期检查资源健康状态
    4. 能力探测: 自动探测节点能力，上报可用状态
    5. 插件化: 资源插件热插拔，不修改主调度器

    适用场景：
    - K8s 节点资源上报（类似 device plugin）
    - 沙盒集群容量管理
    - 调度器资源感知
    """

    def __init__(self, node_id: Optional[str] = None):
        self.node_id = node_id or f"node_{os.getpid()}"
        self.resources: Dict[ResourceType, ResourceCapacity] = {}
        self.detector = CapabilityDetector(self.node_id)
        self.capability: Optional[NodeCapability] = None
        self._lock = threading.Lock()
        self._health_check_interval = 30  # 秒
        self._last_health_check = 0.0
        self._callbacks: List[Callable[[Dict[str, Any]], None]] = []

    def register_resource(self, capacity: ResourceCapacity) -> None:
        """注册资源（插件注册）"""
        with self._lock:
            capacity.update_available()
            self.resources[capacity.resource_type] = capacity

    def unregister_resource(self, resource_type: ResourceType) -> None:
        """注销资源"""
        with self._lock:
            if resource_type in self.resources:
                del self.resources[resource_type]

    def allocate_resource(self, resource_type: ResourceType, amount: int = 1) -> bool:
        """分配资源"""
        with self._lock:
            resource = self.resources.get(resource_type)
            if not resource:
                return False
            if resource.available < amount:
                return False
            resource.used += amount
            resource.update_available()
            resource.last_heartbeat = time.time()
            return True

    def release_resource(self, resource_type: ResourceType, amount: int = 1) -> None:
        """释放资源"""
        with self._lock:
            resource = self.resources.get(resource_type)
            if not resource:
                return
            resource.used = max(0, resource.used - amount)
            resource.update_available()
            resource.last_heartbeat = time.time()

    def detect_capabilities(self) -> NodeCapability:
        """探测节点能力"""
        self.capability = self.detector.detect_all()
        return self.capability

    def auto_register_resources(self) -> None:
        """
        基于能力探测自动注册资源

        根据探测到的能力，自动注册可用的资源插件。
        """
        if not self.capability:
            self.detect_capabilities()

        # LightPool 总是可用（进程沙盒，不需要特殊权限）
        self.register_resource(ResourceCapacity(
            resource_type=ResourceType.LIGHT_POOL,
            total=100,  # 默认 100 个并发实例
            unit="instances",
            health=ResourceHealth.HEALTHY,
            metadata={"isolation": "process", "kernel_shared": True},
        ))

        # StrongPool 需要 KVM
        if self.capability.kvm_available:
            self.register_resource(ResourceCapacity(
                resource_type=ResourceType.STRONG_POOL,
                total=32,  # 默认 32 个并发 VM
                unit="vm_instances",
                health=ResourceHealth.HEALTHY,
                metadata={
                    "isolation": "microvm",
                    "kernel_independent": True,
                    "kvm_device": self.capability.kvm_device,
                    "requires_kvm": True,
                },
            ))
        else:
            self.register_resource(ResourceCapacity(
                resource_type=ResourceType.STRONG_POOL,
                total=0,
                unit="vm_instances",
                health=ResourceHealth.UNAVAILABLE,
                metadata={"reason": "KVM not available", "requires_kvm": True},
            ))

        # eBPF 需要 CAP_BPF
        if self.capability.cap_bpf_available:
            self.register_resource(ResourceCapacity(
                resource_type=ResourceType.EBPF,
                total=1,
                unit="hooks",
                health=ResourceHealth.HEALTHY,
                metadata={"requires_cap_bpf": True},
            ))
        else:
            self.register_resource(ResourceCapacity(
                resource_type=ResourceType.EBPF,
                total=0,
                unit="hooks",
                health=ResourceHealth.UNAVAILABLE,
                metadata={"reason": "CAP_BPF not available"},
            ))

        # CRIU 需要 criu 二进制
        if self.capability.criu_available:
            self.register_resource(ResourceCapacity(
                resource_type=ResourceType.CRIU,
                total=10,
                unit="snapshots",
                health=ResourceHealth.HEALTHY,
                metadata={"criu_binary": self.capability.criu_binary},
            ))
        else:
            self.register_resource(ResourceCapacity(
                resource_type=ResourceType.CRIU,
                total=0,
                unit="snapshots",
                health=ResourceHealth.UNAVAILABLE,
                metadata={"reason": "CRIU binary not found"},
            ))

    def health_check(self) -> Dict[str, ResourceHealth]:
        """健康检查"""
        with self._lock:
            self._last_health_check = time.time()
            health_status = {}
            for resource_type, resource in self.resources.items():
                # 简化：检查心跳是否超时
                if time.time() - resource.last_heartbeat > self._health_check_interval * 3:
                    resource.health = ResourceHealth.DEGRADED
                health_status[resource_type.value] = resource.health
            return health_status

    def get_resource_report(self) -> Dict[str, Any]:
        """获取资源上报报告（DRA 范式）"""
        with self._lock:
            report = {
                "node_id": self.node_id,
                "timestamp": time.time(),
                "capability": self.capability.to_dict() if self.capability else None,
                "resources": {},
                "summary": {
                    "total_resources": len(self.resources),
                    "healthy_resources": 0,
                    "degraded_resources": 0,
                    "unavailable_resources": 0,
                },
            }

            for resource_type, resource in self.resources.items():
                resource.update_available()
                report["resources"][resource_type.value] = {
                    "total": resource.total,
                    "used": resource.used,
                    "available": resource.available,
                    "reserved": resource.reserved,
                    "utilization_percent": round(resource.utilization_percent, 2),
                    "unit": resource.unit,
                    "health": resource.health.value,
                    "metadata": resource.metadata,
                }

                if resource.health == ResourceHealth.HEALTHY:
                    report["summary"]["healthy_resources"] += 1
                elif resource.health == ResourceHealth.DEGRADED:
                    report["summary"]["degraded_resources"] += 1
                else:
                    report["summary"]["unavailable_resources"] += 1

            return report

    def register_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """注册资源变更回调（插件事件通知）"""
        self._callbacks.append(callback)

    def _notify_callbacks(self, event: Dict[str, Any]) -> None:
        """通知回调"""
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception:
                pass
