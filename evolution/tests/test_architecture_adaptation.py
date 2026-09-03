"""
架构借鉴落地测试（灵衢UnifiedBus / openFuyao扶摇 / JiuwenSwarm蜂群）

测试模块：
- gang_scheduler: Gang调度 + 拓扑感知调度（借鉴openFuyao）
- leader_teammate: Leader-Teammate团队模型（借鉴JiuwenSwarm）
- sandbox_resource_plugin: 沙盒资源上报插件（借鉴openFuyao DRA）
"""

import unittest
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from evolution.gang_scheduler import (
    GangScheduler, GangJob, GangStatus, SandboxInstance,
    QoSClass, TopologyAwareScheduler, NUMATopology
)
from evolution.leader_teammate import (
    LeaderAgent, TeammateAgent, AgentRole, AgentStatus, AgentPermission,
    SharedWorkspace, TaskResult, LoopPhase
)
from evolution.sandbox_resource_plugin import (
    SandboxResourcePlugin, ResourceType, ResourceCapacity,
    ResourceHealth, CapabilityDetector, NodeCapability
)


class TestGangScheduler(unittest.TestCase):
    """Gang 调度器测试（借鉴 openFuyao）"""

    def setUp(self):
        self.scheduler = GangScheduler()
        self.scheduler.topology_scheduler.detect_local_topology()

    def test_gang_job_creation(self):
        """测试 Gang 作业创建"""
        instances = [
            SandboxInstance(instance_id=f"inst_{i}", cpu_cores=1.0, memory_mb=256)
            for i in range(5)
        ]
        gang = GangJob(gang_id="gang_001", instances=instances)
        self.assertEqual(gang.gang_id, "gang_001")
        self.assertEqual(len(gang.instances), 5)
        self.assertEqual(gang.status, GangStatus.PENDING)
        self.assertTrue(gang.all_or_nothing)
        self.assertTrue(gang.gang_scheduling)

    def test_submit_gang(self):
        """测试提交 Gang 作业"""
        gang = GangJob(gang_id="gang_submit", instances=[
            SandboxInstance(instance_id="inst_1")
        ])
        gang_id = self.scheduler.submit_gang(gang)
        self.assertEqual(gang_id, "gang_submit")
        self.assertIn("gang_submit", self.scheduler.gangs)

    def test_gang_allocation(self):
        """测试 Gang 资源分配（原子分配）"""
        instances = [
            SandboxInstance(instance_id=f"inst_{i}", cpu_cores=0.5, memory_mb=128)
            for i in range(3)
        ]
        gang = GangJob(gang_id="gang_alloc", instances=instances)
        self.scheduler.submit_gang(gang)
        success, reason = self.scheduler.try_allocate_gang("gang_alloc")
        # 单NUMA节点应该能分配
        self.assertTrue(success)
        self.assertEqual(gang.status, GangStatus.RESOURCES_READY)

    def test_gang_atomic_start(self):
        """测试 Gang 原子启动（所有实例同时启动）"""
        instances = [
            SandboxInstance(instance_id=f"inst_{i}", cpu_cores=0.5, memory_mb=128)
            for i in range(3)
        ]
        gang = GangJob(gang_id="gang_start", instances=instances)
        self.scheduler.submit_gang(gang)
        self.scheduler.try_allocate_gang("gang_start")
        success, reason = self.scheduler.start_gang("gang_start")
        self.assertTrue(success)
        self.assertEqual(gang.status, GangStatus.RUNNING)
        # 所有实例同时进入 running
        for inst in gang.instances:
            self.assertEqual(inst.status, "running")

    def test_gang_completion(self):
        """测试 Gang 完成"""
        gang = GangJob(gang_id="gang_complete", instances=[
            SandboxInstance(instance_id="inst_1")
        ])
        self.scheduler.submit_gang(gang)
        self.scheduler.try_allocate_gang("gang_complete")
        self.scheduler.start_gang("gang_complete")
        self.scheduler.complete_gang("gang_complete", success=True)
        self.assertEqual(gang.status, GangStatus.COMPLETED)

    def test_qos_classes(self):
        """测试 QoS 等级"""
        self.assertEqual(QoSClass.GUARANTEED.value, "guaranteed")
        self.assertEqual(QoSClass.BURSTABLE.value, "burstable")
        self.assertEqual(QoSClass.BEST_EFFORT.value, "best_effort")

    def test_eviction_low_priority(self):
        """测试低优先级驱逐（在离线混部）"""
        # 先启动一个低优先级 Gang
        instances = [
            SandboxInstance(instance_id="inst_low", qos_class=QoSClass.BEST_EFFORT)
        ]
        gang = GangJob(gang_id="gang_low", instances=instances)
        self.scheduler.submit_gang(gang)
        self.scheduler.try_allocate_gang("gang_low")
        self.scheduler.start_gang("gang_low")
        self.assertIn("gang_low", self.scheduler.running_gangs)

        # 驱逐低优先级
        evicted = self.scheduler.evict_low_priority_gangs({"memory_mb": 1024})
        self.assertIn("gang_low", evicted)
        self.assertEqual(gang.status, GangStatus.FAILED)

    def test_scheduler_stats(self):
        """测试调度器统计"""
        stats = self.scheduler.get_stats()
        self.assertIn("total_gangs", stats)
        self.assertIn("running_gangs", stats)
        self.assertIn("numa_nodes", stats)
        self.assertGreaterEqual(stats["numa_nodes"], 1)


class TestTopologyAwareScheduler(unittest.TestCase):
    """拓扑感知调度器测试（借鉴 openFuyao 细粒度拓扑感知）"""

    def setUp(self):
        self.scheduler = TopologyAwareScheduler()
        self.scheduler.detect_local_topology()

    def test_numa_node_registration(self):
        """测试 NUMA 节点注册"""
        node = NUMATopology(node_id=0, cpu_cores=[0, 1], memory_mb=4096)
        self.scheduler.register_numa_node(node)
        self.assertIn(0, self.scheduler.numa_nodes)

    def test_find_best_numa_node(self):
        """测试查找最佳 NUMA 节点"""
        instance = SandboxInstance(instance_id="inst_1", cpu_cores=1.0, memory_mb=256)
        node_id = self.scheduler.find_best_numa_node(instance)
        # 单节点环境应该返回 0
        self.assertIsNotNone(node_id)

    def test_find_best_numa_placement(self):
        """测试批量 NUMA 放置（Gang 调度用）"""
        instances = [
            SandboxInstance(instance_id=f"inst_{i}", cpu_cores=0.5, memory_mb=128)
            for i in range(3)
        ]
        placement = self.scheduler.find_best_numa_placement(instances)
        self.assertEqual(len(placement), 3)
        # 单节点环境所有实例应该放在同一节点
        for node_id in placement.values():
            self.assertIsNotNone(node_id)

    def test_preferred_numa_node(self):
        """测试偏好 NUMA 节点"""
        instance = SandboxInstance(
            instance_id="inst_pref",
            cpu_cores=0.5,
            memory_mb=128,
            preferred_numa_node=0
        )
        node_id = self.scheduler.find_best_numa_node(instance)
        self.assertEqual(node_id, 0)


class TestLeaderTeammate(unittest.TestCase):
    """Leader-Teammate 团队模型测试（借鉴 JiuwenSwarm）"""

    def setUp(self):
        self.leader = LeaderAgent(name="test_leader")

    def test_leader_creation(self):
        """测试 Leader 创建"""
        self.assertEqual(self.leader.name, "test_leader")
        self.assertEqual(self.leader.role, AgentRole.LEADER)
        self.assertEqual(len(self.leader.teammates), 0)

    def test_teammate_registration(self):
        """测试 Teammate 注册（动态注册中心）"""
        teammate = TeammateAgent(agent_id="tm_001", name="worker_1")
        agent_id = self.leader.register_teammate(teammate)
        self.assertEqual(agent_id, "tm_001")
        self.assertIn("tm_001", self.leader.teammates)

    def test_teammate_unregistration(self):
        """测试 Teammate 注销"""
        teammate = TeammateAgent(agent_id="tm_002", name="worker_2")
        self.leader.register_teammate(teammate)
        self.leader.unregister_teammate("tm_002")
        self.assertNotIn("tm_002", self.leader.teammates)

    def test_task_decomposition_ga_evaluation(self):
        """测试遗传算法评测任务拆解"""
        task = {
            "task_id": "ga_eval",
            "type": "ga_evaluation",
            "population": [f"ind_{i}" for i in range(25)],
            "batch_size": 10,
        }
        subtasks = self.leader.decompose_task(task)
        # 25个个体，batch_size=10，应该拆成3个子任务
        self.assertEqual(len(subtasks), 3)
        self.assertEqual(subtasks[0]["type"], "ga_batch_evaluation")

    def test_task_decomposition_code_audit(self):
        """测试代码审计任务拆解"""
        task = {
            "task_id": "audit_001",
            "type": "code_audit",
        }
        subtasks = self.leader.decompose_task(task)
        # 代码审计应该拆成 SAST、渗透、漏洞评估 3 个子任务
        self.assertEqual(len(subtasks), 3)
        types = [s["type"] for s in subtasks]
        self.assertIn("sast_scan", types)
        self.assertIn("penetration_test", types)
        self.assertIn("vulnerability_assessment", types)

    def test_task_assignment(self):
        """测试任务分配"""
        teammate = TeammateAgent(
            agent_id="tm_003",
            name="worker_3",
            skills=["code_evaluation", "sandbox_execution"],
        )
        self.leader.register_teammate(teammate)
        subtask = {
            "task_id": "sub_001",
            "required_skills": ["code_evaluation"],
            "requires_strong_pool": False,
        }
        agent_id = self.leader.assign_task(subtask)
        self.assertEqual(agent_id, "tm_003")
        self.assertEqual(teammate.status, AgentStatus.BUSY)

    def test_inner_loop_execution(self):
        """测试 Inner Loop 执行（单 Agent 循环）"""
        teammate = TeammateAgent(agent_id="tm_004", name="worker_4")
        self.leader.register_teammate(teammate)
        subtask = {"task_id": "inner_001", "expected_success": True}
        result = self.leader.execute_inner_loop("tm_004", subtask)
        self.assertTrue(result.success)
        self.assertEqual(result.task_id, "inner_001")
        self.assertIn("inner_loop_phases", result.metrics)

    def test_outer_loop_execution(self):
        """测试 Outer Loop 执行（团队进化循环）"""
        # 注册一个能处理任务的 Teammate
        teammate = TeammateAgent(
            agent_id="tm_005",
            name="worker_5",
            skills=["sast"],
        )
        self.leader.register_teammate(teammate)
        task = {
            "task_id": "outer_001",
            "type": "code_audit",
            "description": "Test audit",
        }
        result = self.leader.execute_outer_loop(task)
        self.assertIn("total_subtasks", result)
        self.assertIn("success_rate", result)
        self.assertIn("outer_loop_phases", result)

    def test_agent_permission_model(self):
        """测试 Agent 权限模型（细粒度权限隔离）"""
        perm = AgentPermission(
            can_access_light_pool=True,
            can_access_strong_pool=False,
            can_access_network=False,
        )
        self.assertTrue(perm.can_access_light_pool)
        self.assertFalse(perm.can_access_strong_pool)
        self.assertFalse(perm.can_access_network)

    def test_teammate_can_handle_task(self):
        """测试 Teammate 任务处理能力检查"""
        teammate = TeammateAgent(
            agent_id="tm_006",
            name="worker_6",
            permission=AgentPermission(can_access_strong_pool=False),
            skills=["sast"],
        )
        # 需要 StrongPool 的任务应该被拒绝
        self.assertFalse(teammate.can_handle_task({"requires_strong_pool": True}))
        # 不需要 StrongPool 的任务应该被接受
        self.assertTrue(teammate.can_handle_task({"requires_strong_pool": False, "required_skills": ["sast"]}))
        # 缺少技能的任务应该被拒绝
        self.assertFalse(teammate.can_handle_task({"required_skills": ["pentest"]}))

    def test_shared_workspace(self):
        """测试共享工作空间"""
        ws = SharedWorkspace(workspace_id="ws_001")
        ws.add_artifact("agent_1", "/tmp/artifact_1.txt")
        ws.add_log("agent_1", "Task completed")
        ws.set_shared_data("key_1", "value_1")
        self.assertEqual(len(ws.get_all_artifacts()), 1)
        self.assertEqual(ws.get_shared_data("key_1"), "value_1")

    def test_leader_stats(self):
        """测试 Leader 统计"""
        stats = self.leader.get_stats()
        self.assertIn("leader_id", stats)
        self.assertIn("total_teammates", stats)
        self.assertIn("outer_loop_phase", stats)


class TestSandboxResourcePlugin(unittest.TestCase):
    """沙盒资源上报插件测试（借鉴 openFuyao DRA）"""

    def setUp(self):
        self.plugin = SandboxResourcePlugin(node_id="test_node")

    def test_plugin_creation(self):
        """测试插件创建"""
        self.assertEqual(self.plugin.node_id, "test_node")
        self.assertEqual(len(self.plugin.resources), 0)

    def test_resource_registration(self):
        """测试资源注册"""
        capacity = ResourceCapacity(
            resource_type=ResourceType.LIGHT_POOL,
            total=100,
            unit="instances",
        )
        self.plugin.register_resource(capacity)
        self.assertIn(ResourceType.LIGHT_POOL, self.plugin.resources)
        self.assertEqual(self.plugin.resources[ResourceType.LIGHT_POOL].available, 100)

    def test_resource_allocation(self):
        """测试资源分配"""
        capacity = ResourceCapacity(
            resource_type=ResourceType.LIGHT_POOL,
            total=10,
        )
        self.plugin.register_resource(capacity)
        self.assertTrue(self.plugin.allocate_resource(ResourceType.LIGHT_POOL, 3))
        self.assertEqual(self.plugin.resources[ResourceType.LIGHT_POOL].used, 3)
        self.assertEqual(self.plugin.resources[ResourceType.LIGHT_POOL].available, 7)

    def test_resource_allocation_failure(self):
        """测试资源分配失败（资源不足）"""
        capacity = ResourceCapacity(
            resource_type=ResourceType.LIGHT_POOL,
            total=5,
        )
        self.plugin.register_resource(capacity)
        self.assertFalse(self.plugin.allocate_resource(ResourceType.LIGHT_POOL, 10))

    def test_resource_release(self):
        """测试资源释放"""
        capacity = ResourceCapacity(
            resource_type=ResourceType.LIGHT_POOL,
            total=10,
        )
        self.plugin.register_resource(capacity)
        self.plugin.allocate_resource(ResourceType.LIGHT_POOL, 3)
        self.plugin.release_resource(ResourceType.LIGHT_POOL, 2)
        self.assertEqual(self.plugin.resources[ResourceType.LIGHT_POOL].used, 1)
        self.assertEqual(self.plugin.resources[ResourceType.LIGHT_POOL].available, 9)

    def test_capability_detection(self):
        """测试节点能力探测"""
        cap = self.plugin.detect_capabilities()
        self.assertIsInstance(cap, NodeCapability)
        self.assertEqual(cap.node_id, "test_node")
        self.assertIsNotNone(cap.kernel_version)
        self.assertGreater(cap.cpu_cores, 0)

    def test_auto_register_resources(self):
        """测试自动注册资源（基于能力探测）"""
        self.plugin.detect_capabilities()
        self.plugin.auto_register_resources()
        # LightPool 应该总是可用
        self.assertIn(ResourceType.LIGHT_POOL, self.plugin.resources)
        # StrongPool 取决于 KVM 是否可用
        self.assertIn(ResourceType.STRONG_POOL, self.plugin.resources)

    def test_resource_report(self):
        """测试资源上报报告（DRA 范式）"""
        self.plugin.detect_capabilities()
        self.plugin.auto_register_resources()
        report = self.plugin.get_resource_report()
        self.assertIn("node_id", report)
        self.assertIn("capability", report)
        self.assertIn("resources", report)
        self.assertIn("summary", report)
        self.assertIn("total_resources", report["summary"])

    def test_resource_health(self):
        """测试资源健康状态"""
        capacity = ResourceCapacity(
            resource_type=ResourceType.LIGHT_POOL,
            total=10,
            health=ResourceHealth.HEALTHY,
        )
        self.plugin.register_resource(capacity)
        health = self.plugin.health_check()
        self.assertEqual(health["light_pool"], ResourceHealth.HEALTHY)

    def test_resource_type_enum(self):
        """测试资源类型枚举"""
        self.assertEqual(ResourceType.LIGHT_POOL.value, "light_pool")
        self.assertEqual(ResourceType.STRONG_POOL.value, "strong_pool")
        self.assertEqual(ResourceType.EBPF.value, "ebpf")
        self.assertEqual(ResourceType.CRIU.value, "criu")

    def test_capacity_utilization(self):
        """测试容量利用率计算"""
        capacity = ResourceCapacity(
            resource_type=ResourceType.LIGHT_POOL,
            total=100,
            used=25,
        )
        capacity.update_available()
        self.assertEqual(capacity.utilization_percent, 25.0)
        self.assertEqual(capacity.available, 75)


if __name__ == '__main__':
    unittest.main()
