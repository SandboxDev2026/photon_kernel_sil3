"""
evolution.tests.test_wiki_skill — WikiSkill 三层架构测试

覆盖：
- RawLayer 原始轨迹层（记录、查询、完整性校验）
- WikiLayer 维基知识层（模式、日志、Skill影响、永不回滚）
- WikiSkillEvolver 三层集成（四角色闭环）
"""
import unittest
import time
import tempfile
import os
import json

from evolution.raw_layer import RawLayer, RawTrajectory
from evolution.wiki_layer import (
    WikiLayer, WikiPattern, PatternType, PatternSeverity,
    WikiLogEntry, SkillImpactRecord,
)
from evolution.wiki_skill_evolver import (
    WikiSkillEvolver, WikiSkillEvolutionResult, EvolutionPhase,
)
from evolution.skill_library import Skill, SkillLibrary


class TestRawLayer(unittest.TestCase):
    """RawLayer 原始轨迹层测试"""

    def setUp(self):
        self.raw = RawLayer(max_trajectories=100)

    def test_record_trajectory(self):
        """记录轨迹"""
        traj = self.raw.record(
            skill_id="code_gen",
            task="生成排序函数",
            input_data={"language": "python"},
            output_data={"code": "def sort(): pass"},
            success=True,
            duration_ms=1500,
        )
        self.assertIsNotNone(traj.trajectory_id)
        self.assertEqual(traj.skill_id, "code_gen")
        self.assertTrue(traj.success)
        self.assertEqual(len(self.raw.get_all()), 1)

    def test_record_failure(self):
        """记录失败轨迹"""
        traj = self.raw.record(
            skill_id="code_gen",
            task="生成排序函数",
            success=False,
            error="IndentationError",
            error_type="logic_error",
        )
        self.assertFalse(traj.success)
        self.assertEqual(traj.error, "IndentationError")
        self.assertEqual(traj.error_type, "logic_error")

    def test_get_by_skill(self):
        """按 Skill 查询轨迹"""
        self.raw.record(skill_id="skill_a", task="t1", success=True)
        self.raw.record(skill_id="skill_b", task="t2", success=True)
        self.raw.record(skill_id="skill_a", task="t3", success=False)

        a_trajectories = self.raw.get_by_skill("skill_a")
        self.assertEqual(len(a_trajectories), 2)
        b_trajectories = self.raw.get_by_skill("skill_b")
        self.assertEqual(len(b_trajectories), 1)

    def test_get_failures(self):
        """获取失败轨迹"""
        self.raw.record(skill_id="s1", task="t1", success=True)
        self.raw.record(skill_id="s1", task="t2", success=False)
        self.raw.record(skill_id="s2", task="t3", success=False)

        all_failures = self.raw.get_failures()
        self.assertEqual(len(all_failures), 2)

        s1_failures = self.raw.get_failures(skill_id="s1")
        self.assertEqual(len(s1_failures), 1)

    def test_get_success_rate(self):
        """计算成功率"""
        for i in range(7):
            self.raw.record(skill_id="s1", task=f"t{i}", success=True)
        for i in range(3):
            self.raw.record(skill_id="s1", task=f"f{i}", success=False)

        rate = self.raw.get_success_rate("s1")
        self.assertAlmostEqual(rate, 0.7, places=1)

    def test_trajectory_integrity(self):
        """轨迹完整性校验（防篡改）"""
        traj = self.raw.record(
            skill_id="s1",
            task="test",
            success=True,
        )
        self.assertTrue(traj.verify_integrity())

        # 验证所有轨迹
        self.assertTrue(self.raw.verify_all())

    def test_max_trajectories(self):
        """最大轨迹数量限制"""
        raw = RawLayer(max_trajectories=5)
        for i in range(10):
            raw.record(skill_id="s1", task=f"t{i}", success=True)
        self.assertEqual(len(raw.get_all()), 5)

    def test_get_stats(self):
        """获取统计信息"""
        self.raw.record(skill_id="s1", task="t1", success=True)
        self.raw.record(skill_id="s1", task="t2", success=False)
        self.raw.record(skill_id="s2", task="t3", success=True)

        stats = self.raw.get_stats()
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["success"], 2)
        self.assertEqual(stats["failure"], 1)
        self.assertIn("s1", stats["skill_stats"])
        self.assertIn("s2", stats["skill_stats"])

    def test_persistence(self):
        """轨迹持久化"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            persist_path = f.name

        try:
            raw1 = RawLayer(persist_path=persist_path)
            raw1.record(skill_id="s1", task="test", success=True)

            # 重新加载
            raw2 = RawLayer(persist_path=persist_path)
            self.assertEqual(len(raw2.get_all()), 1)
            self.assertEqual(raw2.get_all()[0].skill_id, "s1")
        finally:
            os.unlink(persist_path)


class TestWikiLayer(unittest.TestCase):
    """WikiLayer 维基知识层测试"""

    def setUp(self):
        self.wiki = WikiLayer()

    def test_add_pattern(self):
        """添加知识模式"""
        pattern = self.wiki.add_pattern(
            title="Python 缩进错误",
            pattern_type=PatternType.FAILURE_PATTERN,
            severity=PatternSeverity.HIGH,
            description="生成的代码使用了空格和制表符混合缩进",
            root_cause="LLM 生成代码时缩进不一致",
            fix_strategy="统一使用4空格缩进",
            affected_skills=["code_gen"],
        )
        self.assertIsNotNone(pattern.pattern_id)
        self.assertEqual(pattern.title, "Python 缩进错误")
        self.assertEqual(pattern.pattern_type, PatternType.FAILURE_PATTERN)
        self.assertEqual(len(self.wiki.get_all_patterns()), 1)

    def test_pattern_dedup(self):
        """模式去重（相同标题增加发生次数）"""
        p1 = self.wiki.add_pattern(title="测试错误", affected_skills=["s1"])
        p2 = self.wiki.add_pattern(title="测试错误", affected_skills=["s2"])

        self.assertEqual(p1.pattern_id, p2.pattern_id)
        self.assertEqual(p2.occurrence_count, 2)
        self.assertEqual(len(self.wiki.get_all_patterns()), 1)

    def test_get_patterns_for_skill(self):
        """获取影响指定 Skill 的模式"""
        self.wiki.add_pattern(title="错误1", affected_skills=["s1"])
        self.wiki.add_pattern(title="错误2", affected_skills=["s2"])
        self.wiki.add_pattern(title="错误3", affected_skills=["s1", "s2"])

        s1_patterns = self.wiki.get_patterns_for_skill("s1")
        self.assertEqual(len(s1_patterns), 2)

    def test_failure_and_success_patterns(self):
        """获取失败模式和成功策略"""
        self.wiki.add_pattern(title="失败1", pattern_type=PatternType.FAILURE_PATTERN)
        self.wiki.add_pattern(title="成功1", pattern_type=PatternType.SUCCESS_PATTERN)
        self.wiki.add_pattern(title="最佳实践1", pattern_type=PatternType.BEST_PRACTICE)

        self.assertEqual(len(self.wiki.get_failure_patterns()), 1)
        self.assertEqual(len(self.wiki.get_success_patterns()), 2)

    def test_resolve_pattern(self):
        """标记模式为已解决"""
        pattern = self.wiki.add_pattern(title="测试错误")
        self.assertEqual(pattern.status, "active")

        result = self.wiki.resolve_pattern(pattern.pattern_id, "已修复缩进问题")
        self.assertTrue(result)
        self.assertEqual(pattern.status, "resolved")
        self.assertEqual(pattern.resolution, "已修复缩进问题")

    def test_record_skill_impact(self):
        """记录 Skill 改动影响"""
        record = self.wiki.record_skill_impact(
            skill_id="code_gen",
            change_type="modify",
            old_version="v1",
            new_version="v2",
            validation_result="accepted",
            description="优化代码生成逻辑",
        )
        self.assertIsNotNone(record.impact_id)
        self.assertEqual(record.validation_result, "accepted")
        self.assertEqual(len(self.wiki.get_skill_impact_history("code_gen")), 1)

    def test_rejected_changes_preserved(self):
        """被拒绝的改动仍然保留（Wiki 永不回滚核心设计）"""
        # 记录一个被拒绝的改动
        self.wiki.record_skill_impact(
            skill_id="s1",
            change_type="modify",
            validation_result="rejected",
            rejection_reason="成功率下降",
        )

        # 被拒绝的改动应该仍然在历史中
        history = self.wiki.get_skill_impact_history("s1")
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].validation_result, "rejected")

        # 可以查询被拒绝的改动
        rejected = self.wiki.get_rejected_changes("s1")
        self.assertEqual(len(rejected), 1)

    def test_compile_from_trajectories(self):
        """从原始轨迹编译知识"""
        # 创建模拟轨迹
        class MockTrajectory:
            def __init__(self, skill_id, success, error_type="", error="", trajectory_id="t1"):
                self.skill_id = skill_id
                self.success = success
                self.error_type = error_type
                self.error = error
                self.trajectory_id = trajectory_id

        trajectories = [
            MockTrajectory("s1", False, "logic_error", "IndentationError"),
            MockTrajectory("s1", False, "timeout", "Execution timeout"),
            MockTrajectory("s1", True),
            MockTrajectory("s1", True),
            MockTrajectory("s1", True),
        ]

        patterns = self.wiki.compile_from_trajectories(trajectories)
        self.assertGreater(len(patterns), 0)

        # 应该有失败模式
        failure_patterns = self.wiki.get_failure_patterns()
        self.assertGreater(len(failure_patterns), 0)

    def test_get_knowledge_for_skill_evolution(self):
        """获取用于 Skill 进化的知识包"""
        self.wiki.add_pattern(title="失败1", pattern_type=PatternType.FAILURE_PATTERN, affected_skills=["s1"])
        self.wiki.add_pattern(title="成功1", pattern_type=PatternType.SUCCESS_PATTERN, affected_skills=["s1"])
        self.wiki.record_skill_impact(skill_id="s1", change_type="modify", validation_result="rejected")

        knowledge = self.wiki.get_knowledge_for_skill_evolution("s1")
        self.assertEqual(knowledge["skill_id"], "s1")
        self.assertEqual(len(knowledge["failure_patterns"]), 1)
        self.assertEqual(len(knowledge["success_patterns"]), 1)
        self.assertEqual(len(knowledge["rejected_changes"]), 1)

    def test_wiki_never_rollback_flag(self):
        """Wiki 永不回滚标志"""
        stats = self.wiki.get_stats()
        self.assertTrue(stats["wiki_never_rollback"])

    def test_pattern_to_markdown(self):
        """模式转换为 Markdown"""
        pattern = self.wiki.add_pattern(
            title="测试错误",
            pattern_type=PatternType.FAILURE_PATTERN,
            root_cause="测试根因",
            fix_strategy="测试修复",
            fix_example="示例代码",
        )
        md = pattern.to_markdown()
        self.assertIn("测试错误", md)
        self.assertIn("测试根因", md)
        self.assertIn("测试修复", md)

    def test_export_markdown(self):
        """导出 Wiki 为 Markdown"""
        self.wiki.add_pattern(title="测试模式", affected_skills=["s1"])
        self.wiki.record_skill_impact(skill_id="s1", change_type="modify", validation_result="accepted")

        md = self.wiki.export_markdown()
        self.assertIn("Wiki 知识库", md)
        self.assertIn("测试模式", md)


class TestWikiSkillEvolver(unittest.TestCase):
    """WikiSkillEvolver 三层集成测试"""

    def setUp(self):
        self.skill_lib = SkillLibrary()
        # 添加一个测试 Skill
        skill = Skill(
            id="code_gen",
            name="代码生成",
            description="生成代码",
            version="v1",
            code="def generate(): pass",
        )
        self.skill_lib.add(skill)

        self.evolver = WikiSkillEvolver(
            skill_library=self.skill_lib,
            failure_threshold=2,
            min_executions_before_evolve=2,
        )

    def test_record_execution(self):
        """记录执行轨迹"""
        traj = self.evolver.record_execution(
            skill_id="code_gen",
            task="生成排序函数",
            success=True,
            duration_ms=1000,
        )
        self.assertIsNotNone(traj)
        self.assertEqual(traj.skill_id, "code_gen")

    def test_consecutive_failures_trigger(self):
        """连续失败触发进化"""
        # 记录2次失败（达到阈值）
        self.evolver.record_execution(
            skill_id="code_gen", task="t1", success=False, error_type="logic_error")
        self.evolver.record_execution(
            skill_id="code_gen", task="t2", success=False, error_type="timeout")

        self.assertTrue(self.evolver.should_evolve("code_gen"))

    def test_no_trigger_without_failures(self):
        """没有失败不触发进化"""
        self.evolver.record_execution(
            skill_id="code_gen", task="t1", success=True)
        self.assertFalse(self.evolver.should_evolve("code_gen"))

    def test_compile_knowledge(self):
        """编译知识"""
        self.evolver.record_execution(
            skill_id="code_gen", task="t1", success=False, error_type="logic_error", error="IndentationError")
        self.evolver.record_execution(
            skill_id="code_gen", task="t2", success=False, error_type="timeout", error="Timeout")

        patterns = self.evolver.compile_knowledge("code_gen")
        self.assertGreater(len(patterns), 0)

    def test_evolve_skill(self):
        """进化 Skill"""
        # 记录失败触发进化
        self.evolver.record_execution(
            skill_id="code_gen", task="t1", success=False, error_type="logic_error", error="IndentationError")
        self.evolver.record_execution(
            skill_id="code_gen", task="t2", success=False, error_type="timeout", error="Timeout")

        result = self.evolver.evolve_skill("code_gen", trigger="test")
        self.assertIsInstance(result, WikiSkillEvolutionResult)
        self.assertEqual(result.skill_id, "code_gen")
        self.assertGreater(result.patterns_discovered, 0)

    def test_evolve_skipped_without_trigger(self):
        """未达到触发条件时跳过进化"""
        self.evolver.record_execution(
            skill_id="code_gen", task="t1", success=True)
        result = self.evolver.evolve_skill("code_gen")
        self.assertEqual(result.validation_result, "skipped")

    def test_force_evolve(self):
        """强制进化"""
        self.evolver.record_execution(
            skill_id="code_gen", task="t1", success=True)
        result = self.evolver.evolve_skill("code_gen", force=True)
        self.assertNotEqual(result.validation_result, "skipped")

    def test_wiki_knowledge_preserved_after_rejection(self):
        """Skill 被拒绝后 Wiki 知识仍然保留（核心设计）"""
        # 记录失败
        self.evolver.record_execution(
            skill_id="code_gen", task="t1", success=False, error_type="logic_error", error="Error1")
        self.evolver.record_execution(
            skill_id="code_gen", task="t2", success=False, error_type="timeout", error="Error2")

        # 进化（可能被接受或拒绝）
        result = self.evolver.evolve_skill("code_gen")

        # 无论 Skill 是否被接受，Wiki 知识都应该保留
        wiki_knowledge = self.evolver.get_wiki_knowledge("code_gen")
        self.assertGreater(len(wiki_knowledge["all_patterns"]), 0)

        # Wiki 层的 Skill 影响历史应该保留
        stats = self.evolver.get_stats()
        self.assertGreater(stats["wiki_layer"]["total_skill_impacts"], 0)

    def test_get_wiki_knowledge(self):
        """获取 Wiki 知识包"""
        self.evolver.record_execution(
            skill_id="code_gen", task="t1", success=False, error_type="logic_error", error="Error")
        self.evolver.compile_knowledge("code_gen")

        knowledge = self.evolver.get_wiki_knowledge("code_gen")
        self.assertEqual(knowledge["skill_id"], "code_gen")
        self.assertIn("failure_patterns", knowledge)
        self.assertIn("success_patterns", knowledge)
        self.assertIn("rejected_changes", knowledge)

    def test_evolution_history(self):
        """进化历史"""
        self.evolver.record_execution(
            skill_id="code_gen", task="t1", success=False, error_type="logic_error", error="Error")
        self.evolver.record_execution(
            skill_id="code_gen", task="t2", success=False, error_type="timeout", error="Error")
        self.evolver.evolve_skill("code_gen")

        history = self.evolver.get_evolution_history("code_gen")
        self.assertEqual(len(history), 1)

    def test_get_stats(self):
        """获取三层架构统计"""
        stats = self.evolver.get_stats()
        self.assertIn("raw_layer", stats)
        self.assertIn("wiki_layer", stats)
        self.assertIn("skill_layer", stats)
        self.assertTrue(stats["wiki_never_rollback"])
        self.assertTrue(stats["use_wiki_knowledge"])

    def test_start_new_iteration(self):
        """开始新一轮迭代"""
        initial_iteration = self.evolver.wiki_layer._iteration
        self.evolver.start_new_iteration()
        self.assertEqual(self.evolver.wiki_layer._iteration, initial_iteration + 1)

    def test_export_wiki_markdown(self):
        """导出 Wiki Markdown"""
        self.evolver.record_execution(
            skill_id="code_gen", task="t1", success=False, error_type="logic_error", error="Error")
        self.evolver.compile_knowledge("code_gen")

        md = self.evolver.export_wiki_markdown()
        self.assertIn("Wiki 知识库", md)


class TestWikiSkillIntegration(unittest.TestCase):
    """WikiSkill 完整集成测试（四角色闭环）"""

    def test_full_evolution_cycle(self):
        """完整进化周期：执行 → 编译 → 进化 → 验证"""
        skill_lib = SkillLibrary()
        skill = Skill(id="test_skill", name="测试", version="v1", code="pass")
        skill_lib.add(skill)

        evolver = WikiSkillEvolver(skill_lib, failure_threshold=2, min_executions_before_evolve=2)

        # 1. Executor：执行任务并记录轨迹
        for i in range(3):
            evolver.record_execution(
                skill_id="test_skill",
                task=f"任务{i}",
                success=False,
                error_type="logic_error",
                error=f"错误{i}",
            )

        # 2. Compiler：编译知识
        patterns = evolver.compile_knowledge("test_skill")
        self.assertGreater(len(patterns), 0)

        # 3. Evolver：进化技能
        result = evolver.evolve_skill("test_skill", trigger="integration_test")

        # 4. Validator：验证结果
        self.assertIsNotNone(result.validation_result)
        self.assertIn(result.validation_result, ["accepted", "rejected"])

        # 验证 Wiki 知识保留（即使被拒绝）
        knowledge = evolver.get_wiki_knowledge("test_skill")
        self.assertGreater(len(knowledge["all_patterns"]), 0)

    def test_wiki_never_rollback_demonstration(self):
        """演示 Wiki 永不回滚：多次失败进化后知识持续积累"""
        skill_lib = SkillLibrary()
        skill = Skill(id="s1", name="s1", version="v1", code="pass")
        skill_lib.add(skill)

        evolver = WikiSkillEvolver(skill_lib, failure_threshold=1, min_executions_before_evolve=1)

        total_patterns = 0
        for round_num in range(3):
            evolver.start_new_iteration()
            # 每次记录不同的错误
            evolver.record_execution(
                skill_id="s1",
                task=f"round{round_num}",
                success=False,
                error_type=f"error_type_{round_num}",
                error=f"error_{round_num}",
            )
            result = evolver.evolve_skill("s1", force=True)
            total_patterns += result.patterns_discovered

        # 三轮后 Wiki 知识应该持续积累
        stats = evolver.get_stats()
        self.assertGreater(stats["wiki_layer"]["total_patterns"], 0)
        self.assertEqual(stats["wiki_layer"]["current_iteration"], 4)  # 初始化1轮+测试3轮=4轮

        # 进化历史应该有3条
        history = evolver.get_evolution_history("s1")
        self.assertEqual(len(history), 3)


if __name__ == "__main__":
    unittest.main()
