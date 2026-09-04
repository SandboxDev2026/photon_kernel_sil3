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
import json
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from evolution.gang_scheduler import (
    GangScheduler, GangJob, GangStatus, SandboxInstance,
    QoSClass, TopologyAwareScheduler, NUMATopology
)
from evolution.leader_teammate import (
    LeaderAgent, TeammateAgent, AgentRole, AgentStatus, AgentPermission,
    SharedWorkspace, TaskResult, LoopPhase
)
from evolution.island_ga import AdaptiveMutationController
from evolution.log_consumer import (
    FileTailConsumer, GrpcStreamConsumer, LogConsumerManager, ConsumerMode
)
from evolution.defense_enforcer import (
    DefenseRuleEnforcer, ConfigUpdate, ConfigTarget, ChangeAction
)
from evolution.poc_event_library import (
    PocEventLibrary, PocEvent, PocCategory, PocSeverity
)
from evolution.real_data_adapter import (
    RealDataAdapter, SecurityEvent, EventSource, AnomalyType,
    SeccompViolationParser, KvmVmExitParser, AuditChainAnomalyDetector
)
from evolution.red_blue_adversary import (
    RedBlueAdversaryTrainer as RBATrainer,
    RedAgent, BlueAgent, RedBlueAdversaryTrainer,
    AttackCase, DefenseRule, AdversaryRound,
    AttackType, DefenseType, AdversaryRole
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


class TestAdaptiveMutationController(unittest.TestCase):
    """自适应变异算子控制器测试（借鉴Grounded Agent Forge）"""

    def setUp(self):
        self.controller = AdaptiveMutationController(
            initial_mutation_rate=0.3,
            initial_crossover_rate=0.7,
            stagnation_threshold=3,
            novelty_search_threshold=5,
            adaptation_rate=0.1,
        )

    def test_controller_initialization(self):
        """测试控制器初始化参数"""
        params = self.controller.get_current_params()
        self.assertEqual(params["mutation_rate"], 0.3)
        self.assertEqual(params["crossover_rate"], 0.7)
        self.assertEqual(params["stagnation_count"], 0)
        self.assertFalse(params["novelty_search_enabled"])

    def test_evolution_phase_decreases_mutation(self):
        """测试进化阶段降低变异率"""
        # 模拟适应度持续提升
        fitnesses = [0.1, 0.2, 0.3, 0.4, 0.5]
        for f in fitnesses:
            self.controller.update(f)
        params = self.controller.get_current_params()
        # 进化阶段应该降低变异率
        self.assertLess(params["mutation_rate"], 0.3)
        self.assertGreater(params["crossover_rate"], 0.7)

    def test_stagnation_phase_increases_mutation(self):
        """测试停滞阶段提高变异率"""
        # 模拟适应度停滞（连续相同值）
        for _ in range(5):
            self.controller.update(0.5)
        params = self.controller.get_current_params()
        # 停滞阶段应该提高变异率
        self.assertGreater(params["mutation_rate"], 0.3)
        self.assertLess(params["crossover_rate"], 0.7)

    def test_novelty_search_triggered(self):
        """测试长期停滞触发新奇搜索"""
        # 模拟长期停滞（超过novelty_search_threshold）
        for _ in range(10):
            result = self.controller.update(0.5)
        params = self.controller.get_current_params()
        self.assertTrue(params["novelty_search_enabled"])
        # 新奇搜索应该将变异率设为最大值
        self.assertEqual(params["mutation_rate"], self.controller.max_mutation_rate)

    def test_mutation_rate_bounds(self):
        """测试变异率边界限制"""
        # 极端停滞
        for _ in range(20):
            self.controller.update(0.5)
        params = self.controller.get_current_params()
        self.assertLessEqual(params["mutation_rate"], self.controller.max_mutation_rate)
        self.assertGreaterEqual(params["mutation_rate"], self.controller.min_mutation_rate)

    def test_adjustment_history_recorded(self):
        """测试调整历史记录"""
        for i in range(5):
            self.controller.update(0.1 * i)
        params = self.controller.get_current_params()
        self.assertEqual(params["total_adjustments"], 5)
        self.assertEqual(len(self.controller.adjustment_history), 5)

    def test_reset_clears_state(self):
        """测试重置清除状态"""
        for _ in range(5):
            self.controller.update(0.5)
        self.controller.reset()
        params = self.controller.get_current_params()
        self.assertEqual(params["stagnation_count"], 0)
        self.assertFalse(params["novelty_search_enabled"])
        self.assertEqual(params["total_adjustments"], 0)

    def test_stagnation_detection_threshold(self):
        """测试停滞检测阈值"""
        # 前3代提升，不应该判定停滞
        self.controller.update(0.1)
        self.controller.update(0.2)
        self.controller.update(0.3)
        self.assertEqual(self.controller.stagnation_count, 0)

        # 接下来3代停滞，应该开始计数
        self.controller.update(0.3)
        self.controller.update(0.3)
        self.controller.update(0.3)
        self.assertGreater(self.controller.stagnation_count, 0)

    def test_update_returns_adjustment_info(self):
        """测试update返回调整信息"""
        result = self.controller.update(0.5)
        self.assertIn("new_mutation_rate", result)
        self.assertIn("new_crossover_rate", result)
        self.assertIn("action", result)
        self.assertIn("is_stagnant", result)
        self.assertIn("generation", result)
        self.assertIn("current_best_fitness", result)


class TestRedBlueAdversary(unittest.TestCase):
    """多智能体红蓝对抗框架测试（借鉴DeepMind红队自博弈+港大OpenSpace自进化）"""

    def setUp(self):
        self.trainer = RedBlueAdversaryTrainer(max_rounds=10)

    def test_red_agent_initialization(self):
        """测试红方Agent初始化"""
        red = RedAgent()
        self.assertEqual(len(red.attack_cases), 16)
        self.assertEqual(len(red.strategy_weights), len(AttackType))

    def test_blue_agent_initialization(self):
        """测试蓝方Agent初始化"""
        blue = BlueAgent()
        self.assertEqual(len(blue.defense_rules), 8)

    def test_attack_case_creation(self):
        """测试攻击用例创建"""
        case = AttackCase(
            case_id="TEST_001",
            attack_type=AttackType.NAMESPACE_ESCAPE,
            description="测试攻击",
            payload="test payload",
            target_component="namespace",
        )
        self.assertEqual(case.get_success_rate(), 0.0)
        case.record_result(True)
        case.record_result(False)
        self.assertEqual(case.success_count, 1)
        self.assertEqual(case.failure_count, 1)
        self.assertEqual(case.get_success_rate(), 0.5)

    def test_defense_rule_creation(self):
        """测试防御规则创建"""
        rule = DefenseRule(
            rule_id="DR_TEST",
            defense_type=DefenseType.SYSTEM_CALL_MONITOR,
            description="测试规则",
            target_attack_types=[AttackType.SECCOMP_BYPASS],
            detection_logic="test logic",
        )
        self.assertEqual(rule.get_precision(), 1.0)
        rule.record_trigger(True)
        rule.record_trigger(False)
        self.assertEqual(rule.trigger_count, 2)
        self.assertEqual(rule.false_positive_count, 1)
        self.assertEqual(rule.get_precision(), 0.5)

    def test_red_agent_select_attack(self):
        """测试红方选择攻击用例"""
        red = RedAgent()
        case = red.select_attack_case()
        self.assertIsInstance(case, AttackCase)
        self.assertIn(case, red.attack_cases)

    def test_red_agent_mutate_attack(self):
        """测试红方变异攻击用例"""
        red = RedAgent()
        base_case = red.attack_cases[0]
        original_count = len(red.attack_cases)
        new_case = red.mutate_attack_case(base_case)
        self.assertEqual(len(red.attack_cases), original_count + 1)
        self.assertNotEqual(new_case.case_id, base_case.case_id)

    def test_blue_agent_detect_attack(self):
        """测试蓝方检测攻击"""
        blue = BlueAgent()
        case = AttackCase(
            case_id="TEST",
            attack_type=AttackType.NAMESPACE_ESCAPE,
            description="test",
            payload="test",
            target_component="namespace",
            difficulty=0.1,  # 低难度，容易被检测
        )
        detected, rules, delay = blue.detect_attack(case)
        self.assertIsInstance(detected, bool)
        self.assertIsInstance(rules, list)
        self.assertGreaterEqual(delay, 0)

    def test_blue_agent_evolve_rule(self):
        """测试蓝方进化防御规则"""
        blue = BlueAgent()
        base_rule = blue.defense_rules[0]
        original_count = len(blue.defense_rules)
        new_rule = blue.evolve_defense_rule(base_rule)
        self.assertEqual(len(blue.defense_rules), original_count + 1)
        self.assertNotEqual(new_rule.rule_id, base_rule.rule_id)

    def test_single_round(self):
        """测试单轮对抗"""
        trainer = RedBlueAdversaryTrainer(max_rounds=1)
        round_record = trainer.run_single_round(0)
        self.assertIsInstance(round_record, AdversaryRound)
        self.assertEqual(round_record.round_id, 0)
        self.assertIsInstance(round_record.attack_success, bool)
        self.assertIsInstance(round_record.defense_success, bool)

    def test_full_training(self):
        """测试完整对抗训练"""
        trainer = RedBlueAdversaryTrainer(max_rounds=20, enable_evolution=False)
        stats = trainer.run_training(num_rounds=20)
        self.assertEqual(stats["total_rounds"], 20)
        self.assertEqual(stats["red_wins"] + stats["blue_wins"], 20)
        self.assertGreaterEqual(stats["red_win_rate"], 0)
        self.assertLessEqual(stats["red_win_rate"], 1)

    def test_institutional_red_team_test(self):
        """测试制度性红队测试"""
        trainer = RedBlueAdversaryTrainer()
        result = trainer.run_institutional_red_team_test()
        self.assertIn("results", result)
        self.assertEqual(len(result["results"]), 5)  # 5个测试维度
        self.assertIn("overall_pass_rate", result)
        self.assertGreaterEqual(result["overall_pass_rate"], 0)
        self.assertLessEqual(result["overall_pass_rate"], 1)

    def test_training_statistics(self):
        """测试训练统计信息"""
        trainer = RedBlueAdversaryTrainer(max_rounds=5)
        trainer.run_training()
        stats = trainer.get_training_statistics()
        self.assertIn("red_agent_stats", stats)
        self.assertIn("blue_agent_stats", stats)
        self.assertIn("total_rounds", stats)
        self.assertEqual(stats["total_rounds"], 5)

    def test_export_report(self):
        """测试导出完整对抗报告"""
        trainer = RedBlueAdversaryTrainer(max_rounds=5)
        trainer.run_training()
        trainer.run_institutional_red_team_test()
        report = trainer.export_report()
        self.assertIn("training_statistics", report)
        self.assertIn("recent_rounds", report)
        self.assertIn("institutional_test_results", report)
        self.assertIn("recommendations", report)
        self.assertIsInstance(report["recommendations"], list)

    def test_attack_type_enum(self):
        """测试攻击类型枚举"""
        self.assertEqual(len(AttackType), 10)
        self.assertEqual(AttackType.NAMESPACE_ESCAPE.value, "namespace_escape")

    def test_defense_type_enum(self):
        """测试防御类型枚举"""
        self.assertEqual(len(DefenseType), 8)
        self.assertEqual(DefenseType.SYSTEM_CALL_MONITOR.value, "syscall_monitor")




class TestRealDataAdapter(unittest.TestCase):
    """真实数据适配器测试（对接seccomp违规日志/KVM VM-Exit/HMAC审计链）"""

    def setUp(self):
        self.adapter = RealDataAdapter()
        self.test_dir = "/tmp/photon_real_data_test"
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_adapter_initialization(self):
        """测试适配器初始化"""
        self.assertIsNotNone(self.adapter.seccomp_parser)
        self.assertIsNotNone(self.adapter.kvm_parser)
        self.assertIsNotNone(self.adapter.audit_detector)
        self.assertEqual(len(self.adapter.all_events), 0)

    def test_generate_realistic_test_data(self):
        """测试生成真实格式测试数据"""
        generated = self.adapter.generate_realistic_test_data(self.test_dir, num_events=50)
        self.assertIn("seccomp_log", generated)
        self.assertIn("kvm_vm_exit", generated)
        self.assertIn("audit_chain", generated)
        self.assertTrue(os.path.exists(generated["seccomp_log"]))
        self.assertTrue(os.path.exists(generated["kvm_vm_exit"]))
        self.assertTrue(os.path.exists(generated["audit_chain"]))

    def test_load_seccomp_log(self):
        """测试加载seccomp违规日志"""
        generated = self.adapter.generate_realistic_test_data(self.test_dir, num_events=30)
        count = self.adapter.load_seccomp_log(generated["seccomp_log"])
        self.assertGreater(count, 0)
        self.assertEqual(len(self.adapter.seccomp_parser.parsed_events), count)

    def test_seccomp_violation_parsing(self):
        """测试seccomp违规事件解析"""
        parser = SeccompViolationParser()
        event_json = json.dumps({
            "event_id": "test_001",
            "event_type": "SECCOMP_VIOLATION",
            "timestamp": 1234567890.0,
            "sandbox_id": "sandbox_1",
            "syscall": "ptrace",
            "syscall_num": 101,
            "arch": "x86_64",
            "pid": 12345,
            "action": "KILL",
        })
        event = parser.parse_line(event_json)
        self.assertIsNotNone(event)
        self.assertEqual(event.source, EventSource.SECCOMP_VIOLATION)
        self.assertEqual(event.severity, "critical")  # ptrace是高危
        self.assertEqual(event.payload["syscall"], "ptrace")

    def test_seccomp_non_violation_ignored(self):
        """测试非seccomp事件被忽略"""
        parser = SeccompViolationParser()
        event_json = json.dumps({
            "event_id": "test_002",
            "event_type": "NORMAL_EXECUTION",
            "timestamp": 1234567890.0,
        })
        event = parser.parse_line(event_json)
        self.assertIsNone(event)

    def test_load_kvm_vm_exit(self):
        """测试加载KVM VM-Exit事件"""
        generated = self.adapter.generate_realistic_test_data(self.test_dir, num_events=30)
        count = self.adapter.load_kvm_vm_exit_metrics(generated["kvm_vm_exit"])
        self.assertGreater(count, 0)
        self.assertEqual(len(self.adapter.kvm_parser.parsed_events), count)

    def test_kvm_vm_exit_parsing(self):
        """测试KVM VM-Exit事件解析"""
        parser = KvmVmExitParser()
        event = parser.parse_event({
            "event_id": "vmexit_001",
            "vm_id": "vm_1",
            "exit_reason": "VMCALL",
            "timestamp": 1234567890.0,
            "vcpu_id": 0,
            "guest_rip": "0xffff8000",
        })
        self.assertIsNotNone(event)
        self.assertEqual(event.source, EventSource.KVM_VM_EXIT)
        self.assertEqual(event.severity, "high")  # VMCALL是高风险
        self.assertEqual(event.payload["exit_reason"], "VMCALL")

    def test_kvm_high_risk_exit_reasons(self):
        """测试KVM高风险VM-Exit原因识别"""
        parser = KvmVmExitParser()
        high_risk_reasons = ["VMCALL", "VMMCALL", "CPUID", "RDMSR", "WRMSR", "XSETBV"]
        for reason in high_risk_reasons:
            event = parser.parse_event({
                "vm_id": "vm_1",
                "exit_reason": reason,
                "timestamp": time.time(),
            })
            self.assertEqual(event.severity, "high", f"{reason} should be high severity")

    def test_load_audit_chain(self):
        """测试加载HMAC审计链并检测异常"""
        generated = self.adapter.generate_realistic_test_data(self.test_dir, num_events=50)
        valid_count, anomaly_count = self.adapter.load_audit_chain(generated["audit_chain"])
        self.assertGreater(valid_count, 0)
        # 每20条插入一个异常，50条应该有2个异常
        self.assertGreaterEqual(anomaly_count, 1)

    def test_audit_chain_hash_break_detection(self):
        """测试审计链哈希断裂检测"""
        # 使用 hmac_secret=None 跳过 HMAC 验证，专注测试哈希链断裂
        detector = AuditChainAnomalyDetector(hmac_secret=None)
        # 第一条记录（创世），包含hash字段用于链验证
        line1 = json.dumps({"seq": 0, "prev_hash": "0" * 64, "hash": "a" * 64, "timestamp": 1.0})
        valid1, anomaly1 = detector.verify_and_detect(line1)
        self.assertTrue(valid1)
        self.assertIsNone(anomaly1)

        # 第二条记录（prev_hash错误，模拟哈希断裂）
        line2 = json.dumps({"seq": 1, "prev_hash": "wrong_hash", "hash": "b" * 64, "timestamp": 2.0})
        valid2, anomaly2 = detector.verify_and_detect(line2)
        # 行本身有效（JSON格式正确），但检测到异常
        self.assertTrue(valid2)
        self.assertIsNotNone(anomaly2)
        self.assertEqual(anomaly2.anomaly_type, AnomalyType.HASH_CHAIN_BREAK)

    def test_audit_chain_sequence_gap_detection(self):
        """测试审计链序列号不连续检测"""
        # 使用 hmac_secret=None 跳过 HMAC 验证，专注测试序列号不连续
        detector = AuditChainAnomalyDetector(hmac_secret=None)
        # seq=0，包含hash字段
        line1 = json.dumps({"seq": 0, "prev_hash": "0" * 64, "hash": "a" * 64, "timestamp": 1.0})
        detector.verify_and_detect(line1)
        # seq=5（跳过了1-4，应该检测到missing events），prev_hash与line1的hash匹配
        line2 = json.dumps({"seq": 5, "prev_hash": "a" * 64, "hash": "b" * 64, "timestamp": 2.0})
        valid, anomaly = detector.verify_and_detect(line2)
        self.assertIsNotNone(anomaly)
        self.assertEqual(anomaly.anomaly_type, AnomalyType.MISSING_EVENTS)

    def test_ingest_real_event(self):
        """测试红蓝对抗框架摄入真实事件"""
        trainer = RedBlueAdversaryTrainer()
        event = SecurityEvent(
            event_id="test_real_001",
            source=EventSource.SECCOMP_VIOLATION,
            timestamp=time.time(),
            sandbox_id="sandbox_1",
            severity="high",
            description="测试seccomp违规",
            payload={"syscall": "ptrace"},
        )
        result = trainer.ingest_real_event(event)
        self.assertTrue(result["ingested"])
        self.assertIn("新增攻击用例", result["actions"][0])
        self.assertEqual(len(trainer.real_event_history), 1)

    def test_ingest_real_events_batch(self):
        """测试批量摄入真实事件"""
        trainer = RedBlueAdversaryTrainer()
        events = [
            SecurityEvent(
                event_id=f"batch_{i}",
                source=EventSource.SECCOMP_VIOLATION,
                timestamp=time.time(),
                sandbox_id=f"sandbox_{i}",
                severity="high" if i % 2 == 0 else "medium",
                description=f"测试事件{i}",
                payload={"syscall": "ptrace"},
            )
            for i in range(5)
        ]
        result = trainer.ingest_real_events(events)
        self.assertEqual(result["total_ingested"], 5)
        self.assertEqual(result["high_severity"], 3)
        self.assertEqual(len(trainer.real_event_history), 5)

    def test_anomaly_event_triggers_evolution(self):
        """测试异常事件触发达尔文进化"""
        trainer = RedBlueAdversaryTrainer()
        event = SecurityEvent(
            event_id="anomaly_001",
            source=EventSource.SECCOMP_VIOLATION,
            timestamp=time.time(),
            sandbox_id="sandbox_1",
            severity="critical",
            description="异常seccomp违规",
            payload={"syscall": "ptrace"},
            anomaly_type=AnomalyType.FREQUENCY_SPIKE,
            anomaly_score=0.8,
        )
        result = trainer.ingest_real_event(event)
        self.assertTrue(result["triggered_evolution"])
        # 应该有多个动作：新增攻击用例 + 进化防御规则 + 调整策略权重
        self.assertGreaterEqual(len(result["actions"]), 2)

    def test_get_statistics(self):
        """测试适配器统计信息"""
        generated = self.adapter.generate_realistic_test_data(self.test_dir, num_events=20)
        self.adapter.load_seccomp_log(generated["seccomp_log"])
        self.adapter.load_kvm_vm_exit_metrics(generated["kvm_vm_exit"])
        stats = self.adapter.get_statistics()
        self.assertIn("total_events", stats)
        self.assertIn("seccomp_violations", stats)
        self.assertIn("kvm_vm_exits", stats)
        self.assertIn("top_seccomp_violations", stats)
        self.assertGreater(stats["total_events"], 0)

    def test_get_high_risk_events(self):
        """测试获取高风险事件"""
        parser = SeccompViolationParser()
        # ptrace是critical
        parser.parse_line(json.dumps({
            "event_type": "SECCOMP_VIOLATION",
            "syscall": "ptrace",
            "sandbox_id": "s1",
            "timestamp": time.time(),
        }))
        # socket是high
        parser.parse_line(json.dumps({
            "event_type": "SECCOMP_VIOLATION",
            "syscall": "socket",
            "sandbox_id": "s2",
            "timestamp": time.time(),
        }))
        self.adapter.all_events.extend(parser.parsed_events)
        high_risk = self.adapter.get_high_risk_events()
        self.assertEqual(len(high_risk), 2)

    def test_event_source_enum(self):
        """测试事件来源枚举"""
        self.assertEqual(len(EventSource), 6)
        self.assertEqual(EventSource.SECCOMP_VIOLATION.value, "seccomp_violation")
        self.assertEqual(EventSource.KVM_VM_EXIT.value, "kvm_vm_exit")
        self.assertEqual(EventSource.AUDIT_CHAIN_ANOMALY.value, "audit_chain_anomaly")

    def test_anomaly_type_enum(self):
        """测试异常类型枚举"""
        self.assertEqual(len(AnomalyType), 6)
        self.assertEqual(AnomalyType.HASH_CHAIN_BREAK.value, "hash_chain_break")
        self.assertEqual(AnomalyType.FREQUENCY_SPIKE.value, "frequency_spike")




class TestLogConsumer(unittest.TestCase):
    """日志消费层测试（文件tail/gRPC流）"""

    def setUp(self):
        self.test_dir = "/tmp/photon_log_consumer_test"
        os.makedirs(self.test_dir, exist_ok=True)
        self.adapter = RealDataAdapter()

    def tearDown(self):
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_file_tail_consumer_creation(self):
        """测试文件tail消费者创建"""
        log_path = os.path.join(self.test_dir, "test.jsonl")
        with open(log_path, 'w') as f:
            f.write('{"event_type":"SECCOMP_VIOLATION","syscall":"ptrace"}\n')
        consumer = FileTailConsumer(
            file_path=log_path,
            adapter=self.adapter,
            source_type=EventSource.SECCOMP_VIOLATION,
            from_beginning=True,
        )
        self.assertFalse(consumer.is_running())
        self.assertEqual(consumer.get_stats().total_consumed, 0)

    def test_file_tail_consumer_start_stop(self):
        """测试文件tail消费者启动停止"""
        log_path = os.path.join(self.test_dir, "test.jsonl")
        with open(log_path, 'w') as f:
            f.write('{"event_type":"SECCOMP_VIOLATION","syscall":"ptrace"}\n')
        consumer = FileTailConsumer(
            file_path=log_path,
            adapter=self.adapter,
            source_type=EventSource.SECCOMP_VIOLATION,
            from_beginning=True,
            poll_interval=0.05,
        )
        consumer.start()
        time.sleep(0.3)
        self.assertTrue(consumer.is_running())
        consumer.stop(timeout=2.0)
        self.assertFalse(consumer.is_running())

    def test_consumer_mode_enum(self):
        """测试消费模式枚举"""
        self.assertEqual(len(ConsumerMode), 3)
        self.assertEqual(ConsumerMode.FILE_TAIL.value, "file_tail")
        self.assertEqual(ConsumerMode.GRPC_STREAM.value, "grpc_stream")

    def test_grpc_consumer_creation(self):
        """测试gRPC流消费者创建"""
        consumer = GrpcStreamConsumer(
            grpc_target="localhost:50051",
            adapter=self.adapter,
        )
        self.assertIsNotNone(consumer)
        self.assertFalse(consumer.is_running())

    def test_consumer_manager(self):
        """测试消费管理器"""
        manager = LogConsumerManager(adapter=self.adapter)
        log_path = os.path.join(self.test_dir, "test.jsonl")
        with open(log_path, 'w') as f:
            f.write('{"event_type":"SECCOMP_VIOLATION","syscall":"ptrace"}\n')
        consumer = manager.add_file_tail(
            name="test_seccomp",
            file_path=log_path,
            source_type=EventSource.SECCOMP_VIOLATION,
            from_beginning=True,
            poll_interval=0.05,
        )
        self.assertIn("test_seccomp", manager.consumers)
        manager.start_all()
        time.sleep(0.2)
        manager.stop_all(timeout=2.0)
        stats = manager.get_stats()
        self.assertIn("_total", stats)


class TestDefenseEnforcer(unittest.TestCase):
    """防御规则下发层测试"""

    def setUp(self):
        self.enforcer = DefenseRuleEnforcer(
            config_dir="/tmp/photon_enforcer_test",
            dry_run=True,
        )

    def test_enforcer_creation(self):
        """测试下发器创建"""
        self.assertTrue(self.enforcer.dry_run)
        self.assertEqual(len(self.enforcer.pending_updates), 0)

    def test_config_target_enum(self):
        """测试配置目标枚举"""
        self.assertEqual(len(ConfigTarget), 5)
        self.assertEqual(ConfigTarget.LIGHTPOOL_SECCOMP.value, "lightpool_seccomp")
        self.assertEqual(ConfigTarget.STRONGPOOL_CONFIG.value, "strongpool_config")

    def test_change_action_enum(self):
        """测试变更动作枚举"""
        self.assertEqual(len(ChangeAction), 5)

    def test_generate_seccomp_updates(self):
        """测试生成seccomp配置更新"""
        rule = DefenseRule(
            rule_id="test_rule",
            defense_type=DefenseType.SYSTEM_CALL_MONITOR,
            description="测试规则",
            target_attack_types=[AttackType.SECCOMP_BYPASS],
            detection_logic="test",
        )
        event = SecurityEvent(
            event_id="test_event",
            source=EventSource.SECCOMP_VIOLATION,
            timestamp=time.time(),
            sandbox_id="s1",
            severity="high",
            description="测试事件",
            payload={"syscall": "ptrace"},
        )
        updates = self.enforcer.generate_updates_from_rule(rule, event)
        self.assertGreater(len(updates), 0)
        # 应该包含ptrace黑名单
        ptrace_updates = [u for u in updates if "ptrace" in u.config_key]
        self.assertGreater(len(ptrace_updates), 0)

    def test_generate_network_updates(self):
        """测试生成网络配置更新"""
        rule = DefenseRule(
            rule_id="net_rule",
            defense_type=DefenseType.NETWORK_FILTER,
            description="网络隔离",
            target_attack_types=[AttackType.NETWORK_TUNNEL],
            detection_logic="test",
        )
        updates = self.enforcer.generate_updates_from_rule(rule)
        self.assertGreater(len(updates), 0)
        # 应该包含内网CIDR黑名单
        cidr_updates = [u for u in updates if "10.0.0.0/8" in u.config_key]
        self.assertGreater(len(cidr_updates), 0)

    def test_enqueue_and_apply_dry_run(self):
        """测试入队和dry-run应用"""
        update = ConfigUpdate(
            update_id="test_update",
            target=ConfigTarget.LIGHTPOOL_SECCOMP,
            action=ChangeAction.ADD,
            description="测试更新",
            config_key="test.key",
            config_value="test_value",
            priority="high",
        )
        self.enforcer.enqueue_update(update)
        self.assertEqual(len(self.enforcer.pending_updates), 1)
        result = self.enforcer.apply_pending()
        self.assertEqual(result["applied"], 1)
        self.assertTrue(result["dry_run"])
        self.assertEqual(len(self.enforcer.pending_updates), 0)

    def test_security_boundary(self):
        """测试安全边界声明"""
        report = self.enforcer.generate_update_report()
        self.assertIn("security_boundary", report)
        self.assertIn("warning", report["security_boundary"])
        self.assertIn("production_requirements", report["security_boundary"])

    def test_generate_update_report(self):
        """测试生成配置更新报告"""
        report = self.enforcer.generate_update_report()
        self.assertIn("stats", report)
        self.assertIn("dry_run", report)
        self.assertIn("config_targets", report)


class TestPocEventLibrary(unittest.TestCase):
    """真实漏洞POC事件样本库测试"""

    def setUp(self):
        self.library = PocEventLibrary()

    def test_library_creation(self):
        """测试POC库创建"""
        self.assertGreater(len(self.library.get_all_pocs()), 0)

    def test_poc_category_enum(self):
        """测试POC类别枚举"""
        self.assertEqual(len(PocCategory), 8)

    def test_poc_severity_enum(self):
        """测试POC严重程度枚举"""
        self.assertEqual(len(PocSeverity), 4)

    def test_get_poc_by_id(self):
        """测试按ID获取POC"""
        poc = self.library.get_poc_by_id("NS-001")
        self.assertIsNotNone(poc)
        self.assertEqual(poc.poc_id, "NS-001")

    def test_get_pocs_by_category(self):
        """测试按类别获取POC"""
        namespace_pocs = self.library.get_pocs_by_category(PocCategory.NAMESPACE_ESCAPE)
        self.assertGreater(len(namespace_pocs), 0)
        for poc in namespace_pocs:
            self.assertEqual(poc.category, PocCategory.NAMESPACE_ESCAPE)

    def test_get_critical_pocs(self):
        """测试获取严重级别POC"""
        critical = self.library.get_critical_pocs()
        self.assertGreater(len(critical), 0)
        for poc in critical:
            self.assertEqual(poc.severity, PocSeverity.CRITICAL)

    def test_poc_to_security_event(self):
        """测试POC转换为SecurityEvent"""
        poc = self.library.get_poc_by_id("KE-001")
        event = poc.to_security_event()
        self.assertIsInstance(event, SecurityEvent)
        self.assertEqual(event.severity, "critical")
        self.assertIsNotNone(event.anomaly_type)
        self.assertGreater(event.anomaly_score, 0.5)

    def test_generate_test_events(self):
        """测试生成测试事件"""
        events = self.library.generate_test_events()
        self.assertEqual(len(events), len(self.library.get_all_pocs()))
        for event in events:
            self.assertIsInstance(event, SecurityEvent)

    def test_generate_detection_rules(self):
        """测试生成检测规则"""
        rules = self.library.generate_detection_rules()
        self.assertGreater(len(rules), 0)
        for rule in rules:
            self.assertIn("type", rule)
            self.assertIn("poc_id", rule)

    def test_generate_seccomp_blacklist(self):
        """测试生成seccomp黑名单"""
        blacklist = self.library.generate_seccomp_blacklist()
        self.assertGreater(len(blacklist), 0)
        self.assertIn("setns", blacklist)
        self.assertIn("unshare", blacklist)
        self.assertIn("fsconfig", blacklist)

    def test_get_statistics(self):
        """测试获取统计信息"""
        stats = self.library.get_statistics()
        self.assertIn("total_pocs", stats)
        self.assertIn("by_category", stats)
        self.assertIn("by_severity", stats)
        self.assertIn("critical_count", stats)
        self.assertGreater(stats["total_pocs"], 0)

    def test_closed_loop_test(self):
        """测试闭环测试（POC→适配器→红蓝对抗→防御下发）"""
        from evolution.real_data_adapter import RealDataAdapter
        from evolution.red_blue_adversary import RedBlueAdversaryTrainer

        adapter = RealDataAdapter()
        trainer = RedBlueAdversaryTrainer()
        enforcer = DefenseRuleEnforcer(dry_run=True)

        result = self.library.run_closed_loop_test(adapter, trainer, enforcer)
        self.assertGreater(result["injected_events"], 0)
        self.assertGreater(result["detected_anomalies"], 0)
        self.assertGreater(result["triggered_evolution"], 0)
        self.assertGreater(result["generated_defense_rules"], 0)
        self.assertTrue(result["closed_loop_success"])

    def test_cve_pocs_exist(self):
        """测试CVE POC存在"""
        cve_pocs = [p for p in self.library.get_all_pocs() if p.cve_id]
        self.assertGreater(len(cve_pocs), 0)
        # 应该包含CVE-2022-0185和CVE-2021-4034
        cve_ids = [p.cve_id for p in cve_pocs]
        self.assertIn("CVE-2022-0185", cve_ids)
        self.assertIn("CVE-2021-4034", cve_ids)




if __name__ == '__main__':


    unittest.main()
