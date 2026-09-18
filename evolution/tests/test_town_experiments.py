"""
town_experiments 单元测试
覆盖：微内核调度、时间线分叉、可插拔规划器、A/B 对照实验
"""
import unittest, sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evolution.sandbox_town import SandboxTown, LocationType
from evolution.town_experiments import (
    TimelineManager, ABExperiment, ExperimentConfig,
    DefaultMemory, NoisyMemory, DefaultPlanner, RandomPlanner,
)


class TestMicrokernelScheduling(unittest.TestCase):
    """Agent-Kernel 微内核：活跃/休眠分层"""

    def test_default_active_ratio(self):
        t = SandboxTown(num_residents=10, seed=1)
        self.assertEqual(t.active_ratio, 0.7)

    def test_active_count(self):
        t = SandboxTown(num_residents=10, seed=2, active_ratio=0.5)
        active = t._select_active_residents(0)
        self.assertEqual(len(active), 5)

    def test_active_rotation(self):
        t = SandboxTown(num_residents=8, seed=3, active_ratio=0.5)
        a0 = {r.name for r in t._select_active_residents(0)}
        a8 = {r.name for r in t._select_active_residents(8)}
        # 8 tick 后应该轮换
        self.assertNotEqual(a0, a8)

    def test_step_runs_with_ratio(self):
        t = SandboxTown(num_residents=6, seed=4, active_ratio=0.5)
        for i in range(5):
            result = t.step(i)
        self.assertIsInstance(result, dict)


class TestTimeLineFork(unittest.TestCase):
    """OpenStory 时间线分叉"""

    def test_add_branch(self):
        mgr = TimelineManager(base_seed=42, num_residents=4)
        mgr.add_branch("baseline", seed=42)
        self.assertIn("baseline", mgr.branches)

    def test_run_all_branches(self):
        mgr = TimelineManager(base_seed=42, num_residents=4)
        mgr.add_branch("a", seed=42)
        mgr.add_branch("b", seed=43)
        mgr.run(num_ticks=5)
        self.assertIsNotNone(mgr.branches["a"].result)

    def test_inject_events(self):
        mgr = TimelineManager(base_seed=42, num_residents=4)
        mgr.add_branch("fire", seed=42, injected=[("fire", 2)])
        mgr.run(num_ticks=5)
        # 注入火灾后应有 incident 事件
        fire_town = mgr.branches["fire"].town
        fire_events = [e for e in fire_town.event_log if e.event_type == "incident"]
        self.assertGreaterEqual(len(fire_events), 1)

    def test_compare_branches(self):
        mgr = TimelineManager(base_seed=42, num_residents=4)
        mgr.add_branch("base", seed=42)
        mgr.add_branch("gossip", seed=42, injected=[("gossip", 3)])
        mgr.run(num_ticks=8)
        diff = mgr.compare()
        self.assertIn("branches", diff)

    def test_empty_manager_compare(self):
        mgr = TimelineManager()
        self.assertEqual(mgr.compare(), {})


class TestPluggablePlanner(unittest.TestCase):
    """AgentSims 可插拔规划器"""

    def test_default_planner(self):
        p = DefaultPlanner()
        t = SandboxTown(num_residents=3, seed=10)
        r = t.residents[0]
        loc = p.plan(r, 0, t.locations)
        self.assertEqual(loc.loc_type, LocationType.FACTORY)

    def test_random_planner(self):
        p = RandomPlanner(seed=42)
        t = SandboxTown(num_residents=3, seed=10)
        r = t.residents[0]
        loc = p.plan(r, 0, t.locations)
        self.assertIn(loc.loc_id, t.locations)

    def test_town_accepts_planner(self):
        t = SandboxTown(num_residents=3, seed=11, planner=RandomPlanner(seed=1))
        t.step(0)
        self.assertIsNotNone(t.planner)

    def test_default_planner_is_none(self):
        t = SandboxTown(num_residents=3, seed=12)
        self.assertIsNone(t.planner)


class TestMemoryBackends(unittest.TestCase):
    def test_default_memory_add(self):
        m = DefaultMemory(max_items=10)
        mid = m.add("测试记忆", importance=0.7, tags=["test"])
        self.assertTrue(mid)
        self.assertEqual(len(m), 1)

    def test_default_recall(self):
        m = DefaultMemory()
        m.add("第一条")
        m.add("第二条")
        recent = m.recall_recent(5)
        self.assertIn("第二条", recent)

    def test_noisy_memory_drops(self):
        m = NoisyMemory(drop_rate=0.9)
        for i in range(50):
            m.add(f"事件{i}")
        # 90% 丢弃率，保留的应该远少于50
        self.assertLess(len(m), 50)

    def test_noisy_memory_recall(self):
        m = NoisyMemory(drop_rate=0.0)  # 不丢
        m.add("保留")
        self.assertEqual(len(m.recall_recent()), 1)


class TestABExperiment(unittest.TestCase):
    """A/B 对照实验"""

    def test_run_two_configs(self):
        exp = ABExperiment(
            A=ExperimentConfig("有日程", seed=42, planner="default"),
            B=ExperimentConfig("随机走", seed=42, planner="random"),
        )
        result = exp.run(num_ticks=8)
        self.assertIn("A", result)
        self.assertIn("B", result)
        self.assertIn("delta", result)

    def test_delta_is_numeric(self):
        exp = ABExperiment(
            A=ExperimentConfig("A", seed=1, planner="default"),
            B=ExperimentConfig("B", seed=1, planner="random"),
        )
        result = exp.run(num_ticks=5)
        self.assertIsInstance(result["delta"]["total_events"], int)

    def test_schedule_produces_more_social(self):
        """有日程的居民会在固定地点聚集，社交更多"""
        exp = ABExperiment(
            A=ExperimentConfig("有日程", seed=42, planner="default"),
            B=ExperimentConfig("随机走", seed=42, planner="random"),
        )
        result = exp.run(num_ticks=10)
        # 有日程应该比随机走产生更多社交
        self.assertGreater(result["A"]["social"], result["B"]["social"])


class TestBoundary(unittest.TestCase):
    def test_tiny_town_experiment(self):
        exp = ABExperiment(
            A=ExperimentConfig("A", seed=1, num_residents=2),
            B=ExperimentConfig("B", seed=2, num_residents=2),
        )
        result = exp.run(num_ticks=3)
        self.assertIsNotNone(result)

    def test_single_branch(self):
        mgr = TimelineManager(num_residents=3)
        mgr.add_branch("only", seed=1)
        mgr.run(num_ticks=3)
        self.assertIsNotNone(mgr.branches["only"].result)

    def test_many_ticks(self):
        t = SandboxTown(num_residents=4, seed=99, active_ratio=0.5)
        for i in range(30):
            t.step(i)
        self.assertEqual(t.tick_count, 29)


if __name__ == "__main__":
    unittest.main(verbosity=2)
