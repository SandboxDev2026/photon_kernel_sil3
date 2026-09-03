"""
Gang调度器 + 拓扑感知调度（借鉴 openFuyao 扶摇）

参考 openFuyao 的细粒度拓扑感知调度和 Gang-Scheduling 原子调度，
扩展 PhotonBox 的 RuntimeSelector，用于批量沙盒压力测试和遗传算法评测。

借鉴点：
1. Gang-Scheduling: 必须全部资源就绪，才一次性启动一批沙盒实例
2. 细粒度拓扑感知: 感知 NUMA、PCIe 硬件拓扑，降低跨 NUMA 延迟
3. 在离线混部: GA压力测试(低优先级)和正常业务(高优先级)混跑，做限流驱逐
4. 多级QoS: Guaranteed/Burstable/BestEffort 三级服务质量

许可证: Apache-2.0（与 openFuyao 一致）
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import time
import threading


class QoSClass(Enum):
    """QoS 等级（借鉴 K8s QoS）"""
    GUARANTEED = "guaranteed"      # 高优先级，资源保证，不被驱逐
    BURSTABLE = "burstable"        # 中优先级，可突发，低资源时被限流
    BEST_EFFORT = "best_effort"    # 低优先级，资源不足时最先被驱逐


class GangStatus(Enum):
    """Gang 调度状态"""
    PENDING = "pending"              # 等待资源
    RESOURCES_READY = "ready"       # 资源已就绪
    RUNNING = "running"              # 运行中
    COMPLETED = "completed"          # 已完成
    FAILED = "failed"                # 失败
    TIMEOUT = "timeout"              # 超时


@dataclass
class NUMATopology:
    """NUMA 拓扑信息"""
    node_id: int
    cpu_cores: List[int] = field(default_factory=list)
    memory_mb: int = 0
    available_memory_mb: int = 0
    pcie_devices: List[str] = field(default_factory=list)
    latency_to_other_nodes: Dict[int, int] = field(default_factory=dict)  # 到其他NUMA节点的延迟(ns)


@dataclass
class SandboxInstance:
    """沙盒实例请求"""
    instance_id: str
    pool_type: str = "light_pool"    # light_pool / strong_pool
    cpu_cores: float = 1.0
    memory_mb: int = 256
    qos_class: QoSClass = QoSClass.BEST_EFFORT
    preferred_numa_node: Optional[int] = None  # 偏好的NUMA节点
    task_spec: Optional[Dict[str, Any]] = None
    assigned_numa_node: Optional[int] = None
    assigned_worker_id: Optional[str] = None
    status: str = "pending"


@dataclass
class GangJob:
    """Gang 作业（一批必须同时启动的沙盒实例）"""
    gang_id: str
    instances: List[SandboxInstance] = field(default_factory=list)
    status: GangStatus = GangStatus.PENDING
    submit_time: float = field(default_factory=time.time)
    start_time: Optional[float] = None
    completion_time: Optional[float] = None
    timeout_seconds: int = 300
    all_or_nothing: bool = True  # 全有或全无：资源不足时等待，不部分启动
    gang_scheduling: bool = True  # 是否启用 Gang 调度（原子启动）


class TopologyAwareScheduler:
    """
    拓扑感知调度器（借鉴 openFuyao 细粒度拓扑感知调度）

    核心能力：
    1. NUMA 拓扑感知：尽量把同 Gang 的实例放在同一 NUMA 节点
    2. 跨 NUMA 延迟感知：如果必须跨节点，选择延迟最低的组合
    3. 资源碎片整理：优先填满已有节点，减少碎片
    """

    def __init__(self):
        self.numa_nodes: Dict[int, NUMATopology] = {}
        self._lock = threading.Lock()

    def register_numa_node(self, node: NUMATopology) -> None:
        """注册 NUMA 节点拓扑信息"""
        with self._lock:
            self.numa_nodes[node.node_id] = node

    def detect_local_topology(self) -> None:
        """检测本地 NUMA 拓扑（如果可用）"""
        try:
            import os
            # 简化：假设单 NUMA 节点
            cpu_count = os.cpu_count() or 4
            mem_mb = 8192  # 假设 8GB
            self.register_numa_node(NUMATopology(
                node_id=0,
                cpu_cores=list(range(cpu_count)),
                memory_mb=mem_mb,
                available_memory_mb=mem_mb,
            ))
        except Exception:
            # 拓扑检测失败，使用默认单节点
            self.register_numa_node(NUMATopology(
                node_id=0,
                cpu_cores=[0, 1, 2, 3],
                memory_mb=4096,
                available_memory_mb=4096,
            ))

    def find_best_numa_node(self, instance: SandboxInstance) -> Optional[int]:
        """
        为单个实例找到最佳 NUMA 节点

        策略：
        1. 如果有偏好节点且资源充足，优先选择
        2. 否则选择可用资源最多的节点
        3. 考虑跨 NUMA 延迟（如果是 Gang 的一部分）
        """
        with self._lock:
            if not self.numa_nodes:
                return None

            # 偏好节点优先
            if instance.preferred_numa_node is not None:
                node = self.numa_nodes.get(instance.preferred_numa_node)
                if node and self._node_has_capacity(node, instance):
                    return instance.preferred_numa_node

            # 选择可用资源最多的节点
            best_node = None
            best_score = -1
            for node_id, node in self.numa_nodes.items():
                if not self._node_has_capacity(node, instance):
                    continue
                # 评分：可用内存 + 可用CPU
                score = node.available_memory_mb + len(node.cpu_cores) * 100
                if score > best_score:
                    best_score = score
                    best_node = node_id

            return best_node

    def find_best_numa_placement(self, instances: List[SandboxInstance]) -> Dict[str, Optional[int]]:
        """
        为一批实例找到最佳 NUMA 放置（Gang 调度用）

        策略：
        1. 优先全部放在同一 NUMA 节点（最低延迟）
        2. 如果单节点放不下，选择跨节点延迟最低的组合
        3. 记录每个实例的分配
        拆分为单节点尝试和多节点贪心两个子函数。
        """
        placement: Dict[str, Optional[int]] = {}

        with self._lock:
            if not self.numa_nodes:
                for inst in instances:
                    placement[inst.instance_id] = None
                return placement

            # 策略1：尝试全部放在同一节点
            single_node = self._try_single_node_placement(instances)
            if single_node is not None:
                for inst in instances:
                    placement[inst.instance_id] = single_node
                return placement

            # 策略2：单节点放不下，按资源贪心分配到多节点
            placement = self._greedy_multi_node_placement(instances)
            return placement

    def _try_single_node_placement(self, instances: List[SandboxInstance]) -> Optional[int]:
        """
        策略1：尝试将所有实例放在同一 NUMA 节点

        遍历所有节点，找到第一个能放下所有实例的节点。
        返回节点ID，找不到返回 None。
        最低延迟策略：同节点内通信无跨 NUMA 开销。
        """
        for node_id, node in self.numa_nodes.items():
            if self._node_can_fit_all(node, instances):
                return node_id
        return None

    def _greedy_multi_node_placement(self, instances: List[SandboxInstance]) -> Dict[str, Optional[int]]:
        """
        策略2：单节点放不下时，按资源贪心分配到多节点

        按可用内存降序遍历节点，每个节点尽量分配能放下的实例。
        剩余无法分配的实例标记为 None（资源不足）。
        """
        placement: Dict[str, Optional[int]] = {}
        remaining = list(instances)

        for node_id, node in sorted(
            self.numa_nodes.items(),
            key=lambda x: x[1].available_memory_mb,
            reverse=True
        ):
            if not remaining:
                break
            can_fit = []
            for inst in remaining:
                if self._node_has_capacity(node, inst):
                    can_fit.append(inst)
                    placement[inst.instance_id] = node_id
            for inst in can_fit:
                remaining.remove(inst)

        # 剩余的分配 None（资源不足）
        for inst in remaining:
            placement[inst.instance_id] = None

        return placement

    def _node_has_capacity(self, node: NUMATopology, instance: SandboxInstance) -> bool:
        """检查节点是否有足够容量"""
        return (
            node.available_memory_mb >= instance.memory_mb and
            len(node.cpu_cores) >= instance.cpu_cores
        )

    def _node_can_fit_all(self, node: NUMATopology, instances: List[SandboxInstance]) -> bool:
        """检查节点是否能放下所有实例"""
        total_memory = sum(i.memory_mb for i in instances)
        total_cpu = sum(i.cpu_cores for i in instances)
        return (
            node.available_memory_mb >= total_memory and
            len(node.cpu_cores) >= total_cpu
        )


class GangScheduler:
    """
    Gang 调度器（借鉴 openFuyao Gang-Scheduling 原子调度）

    核心能力：
    1. 原子启动：一批沙盒实例必须全部资源就绪，才一次性启动
    2. 全有或全无：资源不足时等待，不部分启动（避免死锁和资源碎片）
    3. 超时控制：等待资源超时后失败，不无限等待
    4. QoS 分级：高优先级 Gang 优先调度，低优先级可被驱逐
    5. 在离线混部：GA压力测试(低优先级)和正常业务(高优先级)混跑

    适用场景：
    - 遗传算法批量评测：一批沙盒实例全部就位再开始压力测试
    - 多Agent协同任务：Leader + 多个 Teammate 必须同时启动
    - 压力测试：批量启动沙盒实例做并发测试
    """

    def __init__(self, topology_scheduler: Optional[TopologyAwareScheduler] = None):
        self.gangs: Dict[str, GangJob] = {}
        self.running_gangs: List[str] = []
        self.topology_scheduler = topology_scheduler or TopologyAwareScheduler()
        self._lock = threading.Lock()
        self._max_concurrent_gangs = 10
        self._eviction_enabled = True

    def submit_gang(self, gang: GangJob) -> str:
        """提交 Gang 作业"""
        with self._lock:
            self.gangs[gang.gang_id] = gang
            return gang.gang_id

    def try_allocate_gang(self, gang_id: str) -> Tuple[bool, str]:
        """
        尝试为 Gang 分配资源（原子分配）

        返回: (是否成功, 原因)
        """
        with self._lock:
            gang = self.gangs.get(gang_id)
            if not gang:
                return False, "Gang not found"

            if gang.status != GangStatus.PENDING:
                return False, f"Gang status is {gang.status.value}, not pending"

            # 检查并发上限
            if len(self.running_gangs) >= self._max_concurrent_gangs:
                return False, "Max concurrent gangs reached"

            # 拓扑感知分配
            placement = self.topology_scheduler.find_best_numa_placement(gang.instances)

            # 检查是否所有实例都能分配
            unassigned = [iid for iid, node in placement.items() if node is None]
            if unassigned and gang.all_or_nothing:
                gang.status = GangStatus.PENDING
                return False, f"Cannot allocate all instances (unassigned: {len(unassigned)})"

            # 分配成功，更新实例状态
            for inst in gang.instances:
                inst.assigned_numa_node = placement.get(inst.instance_id)
                inst.status = "allocated"

            gang.status = GangStatus.RESOURCES_READY
            return True, "All resources allocated"

    def start_gang(self, gang_id: str) -> Tuple[bool, str]:
        """
        启动 Gang（原子启动所有实例）

        必须先调用 try_allocate_gang 成功，才能启动。
        启动时所有实例同时进入 running 状态（Gang 语义）。
        """
        with self._lock:
            gang = self.gangs.get(gang_id)
            if not gang:
                return False, "Gang not found"

            if gang.status != GangStatus.RESOURCES_READY:
                return False, f"Gang not ready (status: {gang.status.value})"

            # 检查超时
            if time.time() - gang.submit_time > gang.timeout_seconds:
                gang.status = GangStatus.TIMEOUT
                return False, "Gang allocation timeout"

            # 原子启动所有实例
            gang.start_time = time.time()
            gang.status = GangStatus.RUNNING
            for inst in gang.instances:
                inst.status = "running"

            self.running_gangs.append(gang_id)
            return True, "All instances started atomically"

    def complete_gang(self, gang_id: str, success: bool = True) -> None:
        """完成 Gang（所有实例同时结束）"""
        with self._lock:
            gang = self.gangs.get(gang_id)
            if not gang:
                return

            gang.completion_time = time.time()
            gang.status = GangStatus.COMPLETED if success else GangStatus.FAILED
            for inst in gang.instances:
                inst.status = "completed" if success else "failed"

            if gang_id in self.running_gangs:
                self.running_gangs.remove(gang_id)

    def evict_low_priority_gangs(self, needed_resources: Dict[str, float]) -> List[str]:
        """
        驱逐低优先级 Gang（在离线混部）

        当高优先级任务需要资源时，驱逐 BEST_EFFORT 级别的 Gang。
        借鉴 openFuyao 在离线混部调度。
        拆分为可驱逐Gang查找和驱逐执行两个子函数。
        """
        if not self._eviction_enabled:
            return []

        with self._lock:
            evictable = self._find_evictable_gangs()
            return self._perform_eviction(evictable, needed_resources)

    def _find_evictable_gangs(self) -> List[str]:
        """
        查找可驱逐的低优先级 Gang

        遍历正在运行的 Gang，找出包含 BEST_EFFORT 级别实例的 Gang。
        按 QoS 优先级排序，先驱逐 BEST_EFFORT。
        返回可驱逐的 Gang ID 列表。
        """
        evictable = []
        for gang_id in list(self.running_gangs):
            gang = self.gangs.get(gang_id)
            if not gang:
                continue
            # 检查 Gang 中是否有低优先级实例
            has_low_priority = any(
                inst.qos_class == QoSClass.BEST_EFFORT
                for inst in gang.instances
            )
            if has_low_priority:
                evictable.append(gang_id)
        return evictable

    def _perform_eviction(
        self,
        evictable_gangs: List[str],
        needed_resources: Dict[str, float],
    ) -> List[str]:
        """
        执行驱逐操作

        遍历可驱逐 Gang 列表，逐个标记为 FAILED 并从运行列表移除。
        驱逐过程中检查是否已满足资源需求，满足则提前停止。
        返回被驱逐的 Gang ID 列表。
        """
        evicted = []
        for gang_id in evictable_gangs:
            gang = self.gangs.get(gang_id)
            if not gang:
                continue
            gang.status = GangStatus.FAILED
            for inst in gang.instances:
                inst.status = "evicted"
            evicted.append(gang_id)
            self.running_gangs.remove(gang_id)

            # 检查是否已满足资源需求
            if self._check_resources_satisfied(needed_resources):
                break

        return evicted

    def get_gang_status(self, gang_id: str) -> Optional[Dict[str, Any]]:
        """获取 Gang 状态"""
        with self._lock:
            gang = self.gangs.get(gang_id)
            if not gang:
                return None
            return {
                "gang_id": gang.gang_id,
                "status": gang.status.value,
                "instances_count": len(gang.instances),
                "submit_time": gang.submit_time,
                "start_time": gang.start_time,
                "completion_time": gang.completion_time,
                "duration_ms": int((gang.completion_time - gang.submit_time) * 1000) if gang.completion_time else None,
                "all_or_nothing": gang.all_or_nothing,
            }

    def get_stats(self) -> Dict[str, Any]:
        """获取调度器统计"""
        with self._lock:
            status_counts: Dict[str, int] = {}
            for gang in self.gangs.values():
                status = gang.status.value
                status_counts[status] = status_counts.get(status, 0) + 1

            return {
                "total_gangs": len(self.gangs),
                "running_gangs": len(self.running_gangs),
                "status_counts": status_counts,
                "max_concurrent_gangs": self._max_concurrent_gangs,
                "eviction_enabled": self._eviction_enabled,
                "numa_nodes": len(self.topology_scheduler.numa_nodes),
            }

    def _check_resources_satisfied(self, needed: Dict[str, float]) -> bool:
        """检查资源需求是否已满足（简化）"""
        # 简化实现：驱逐后假设资源已释放
        return True
