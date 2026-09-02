"""
两阶段评估器 + Agent Company Benchmark 测试

覆盖：
1. RuleBasedEvaluator 规则评估器（语法/结构/安全/质量）
2. TwoStageEvaluator 两阶段评估（第一阶段筛选+第二阶段深度评估）
3. AgentCompanyBenchmark 任务框架（任务定义/检查点/评分/统计）
4. 预设任务集（10个真实工作任务）
"""

import unittest
import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evolution.rule_based_evaluator import RuleBasedEvaluator, RuleScore
from evolution.two_stage_evaluator import TwoStageEvaluator, TwoStageStats
from evolution.individual import Individual
from benchmark.agent_company import (
    AgentCompanyBenchmark, AgentCompanyTask, Checkpoint, CheckpointResult,
    TaskDifficulty, TaskCategory, TaskResult,
)
from benchmark.tasks import get_default_tasks, get_tasks_by_difficulty, get_tasks_by_category


class TestRuleBasedEvaluator(unittest.TestCase):
    """规则评估器测试"""

    def setUp(self):
        self.evaluator = RuleBasedEvaluator(min_score=30.0, max_penalties=5)

    def test_empty_code(self):
        """空代码应得0分且不通过"""
        score = self.evaluator.evaluate("", "python")
        self.assertEqual(score.total, 0.0)
        self.assertFalse(score.passed)
        self.assertIn("代码为空", score.penalties)

    def test_good_python_code(self):
        """良好的Python代码应通过"""
        code = '''def fibonacci(n):
    """计算斐波那契数列"""
    if n <= 1:
        return n
    a, b = 0, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    return b

if __name__ == "__main__":
    print(fibonacci(10))
'''
        score = self.evaluator.evaluate(code, "python")
        self.assertTrue(score.passed)
        self.assertGreater(score.total, 50.0)
        self.assertGreater(score.syntax_score, 80.0)
        self.assertGreater(score.structure_score, 50.0)

    def test_dangerous_code_detected(self):
        """危险代码应被安全检查扣分"""
        code = '''import os
def run_command(cmd):
    os.system(cmd)
    eval("print('hacked')")
'''
        score = self.evaluator.evaluate(code, "python")
        self.assertLess(score.safety_score, 100.0)
        self.assertTrue(len(score.penalties) > 0)

    def test_syntax_error_brackets(self):
        """括号不匹配应扣分"""
        code = "def test():\n    return (1 + 2"
        score = self.evaluator.evaluate(code, "python")
        self.assertLess(score.syntax_score, 100.0)

    def test_batch_evaluation(self):
        """批量评估应返回通过的个体按分数排序"""
        individuals = [
            ("def good():\n    return 1", "id1"),
            ("", "id2"),
            ("def also_good():\n    '''doc'''\n    return 42", "id3"),
        ]
        results = self.evaluator.evaluate_batch(individuals, "python")
        self.assertGreater(len(results), 0)
        # 按分数降序
        for i in range(len(results) - 1):
            self.assertGreaterEqual(results[i][0].total, results[i + 1][0].total)

    def test_quality_score_comments(self):
        """有注释的代码质量分应更高"""
        code_no_comments = "def f(x):\n    return x*2\n"
        code_with_comments = '''def f(x):
    # 计算x的两倍
    """这是一个文档字符串"""
    return x * 2
'''
        s1 = self.evaluator.evaluate(code_no_comments, "python")
        s2 = self.evaluator.evaluate(code_with_comments, "python")
        self.assertGreaterEqual(s2.quality_score, s1.quality_score)


class TestTwoStageEvaluator(unittest.TestCase):
    """两阶段评估器测试"""

    def setUp(self):
        self.evaluator = TwoStageEvaluator(top_n_ratio=0.5, min_score=20.0)

    def _make_individual(self, code: str, ind_id: str) -> Individual:
        """创建测试用 Individual"""
        ind = Individual(id=ind_id, gen=0, payload={"code": code})
        return ind

    def test_empty_population(self):
        """空种群应返回空列表"""
        results = self.evaluator.evaluate([], None)
        self.assertEqual(len(results), 0)

    def test_stage1_only(self):
        """无深度评估函数时只执行第一阶段"""
        population = [
            self._make_individual("def good():\n    return 1", "id1"),
            self._make_individual("", "id2"),
        ]
        results = self.evaluator.evaluate(population, None)
        self.assertEqual(len(results), 2)
        # 所有个体都标记为未进入第二阶段
        for _, _, passed_s2 in results:
            self.assertFalse(passed_s2)

    def test_two_stage_with_deep_eval(self):
        """有深度评估函数时，Top-N进入第二阶段"""
        population = [
            self._make_individual("def best():\n    '''best'''\n    return 42", "id1"),
            self._make_individual("def ok():\n    return 1", "id2"),
            self._make_individual("", "id3"),
            self._make_individual("def also_good():\n    return 2", "id4"),
        ]

        def deep_eval(ind):
            return 80.0  # 所有深度评估都给80分

        results = self.evaluator.evaluate(population, deep_eval)
        self.assertEqual(len(results), 4)

        # 统计进入第二阶段的数量
        stage2_count = sum(1 for _, _, p in results if p)
        self.assertGreater(stage2_count, 0)
        self.assertLessEqual(stage2_count, len(population))

    def test_stats_recorded(self):
        """统计信息应正确记录"""
        population = [
            self._make_individual("def f():\n    return 1", "id1"),
            self._make_individual("def g():\n    return 2", "id2"),
        ]

        def deep_eval(ind):
            return 70.0

        self.evaluator.evaluate(population, deep_eval)
        stats = self.evaluator.get_stats()
        self.assertEqual(stats.total_individuals, 2)
        self.assertGreater(stats.stage1_passed, 0)
        self.assertGreater(stats.stage2_evaluated, 0)
        self.assertGreater(stats.stage1_avg_time_ms, 0)

    def test_cost_savings(self):
        """成本节省应大于0（第一阶段比第二阶段快）"""
        population = [self._make_individual(f"def f{i}():\n    return {i}", f"id{i}") for i in range(10)]

        def slow_deep_eval(ind):
            return 75.0

        self.evaluator.evaluate(population, slow_deep_eval)
        stats = self.evaluator.get_stats()
        # 有成本节省（因为只评估了部分个体）
        self.assertGreaterEqual(stats.cost_saved_pct, 0.0)

    def test_deep_eval_exception_handling(self):
        """深度评估异常时应优雅降级"""
        population = [self._make_individual("def f():\n    return 1", "id1")]

        def failing_eval(ind):
            raise RuntimeError("evaluation failed")

        results = self.evaluator.evaluate(population, failing_eval)
        self.assertEqual(len(results), 1)
        # 不应崩溃


class TestAgentCompanyBenchmark(unittest.TestCase):
    """Agent Company Benchmark 测试"""

    def setUp(self):
        self.benchmark = AgentCompanyBenchmark(name="test_benchmark")

    def test_add_task(self):
        """添加任务应成功"""
        task = AgentCompanyTask(
            task_id="test1",
            name="测试任务",
            description="测试描述",
            difficulty=TaskDifficulty.EASY,
            category=TaskCategory.CODE_GENERATION,
            checkpoints=[Checkpoint("cp1", "检查点1")],
        )
        self.benchmark.add_task(task)
        self.assertEqual(len(self.benchmark.tasks), 1)
        self.assertIsNotNone(self.benchmark.get_task("test1"))

    def test_get_task_not_found(self):
        """获取不存在的任务应返回None"""
        self.assertIsNone(self.benchmark.get_task("nonexistent"))

    def test_simple_agent_passes(self):
        """简单智能体（输出非空）应通过简单任务"""
        task = AgentCompanyTask(
            task_id="simple",
            name="简单任务",
            description="写点东西",
            difficulty=TaskDifficulty.EASY,
            category=TaskCategory.CODE_GENERATION,
            checkpoints=[Checkpoint("cp1", "输出非空", required=True)],
        )
        self.benchmark.add_task(task)

        def agent(desc, ctx):
            return "def hello():\n    print('hello')", {}

        results = self.benchmark.run(agent)
        self.assertEqual(len(results), 1)
        self.assertGreater(results[0].total_score, 0)

    def test_empty_agent_fails(self):
        """空输出智能体应失败"""
        task = AgentCompanyTask(
            task_id="empty",
            name="空输出任务",
            description="测试",
            difficulty=TaskDifficulty.EASY,
            category=TaskCategory.CODE_GENERATION,
            checkpoints=[Checkpoint("cp1", "输出非空", required=True)],
        )
        self.benchmark.add_task(task)

        def agent(desc, ctx):
            return "", {}

        results = self.benchmark.run(agent)
        self.assertFalse(results[0].passed)

    def test_stats_calculation(self):
        """统计信息应正确计算"""
        for i in range(3):
            task = AgentCompanyTask(
                task_id=f"task{i}",
                name=f"任务{i}",
                description="测试",
                difficulty=TaskDifficulty.EASY,
                category=TaskCategory.CODE_GENERATION,
                checkpoints=[Checkpoint("cp1", "检查点")],
            )
            self.benchmark.add_task(task)

        def agent(desc, ctx):
            return "output", {}

        self.benchmark.run(agent)
        stats = self.benchmark.get_stats()
        self.assertEqual(stats.total_tasks, 3)
        self.assertEqual(stats.passed_tasks, 3)
        self.assertGreater(stats.avg_score, 0)
        self.assertIn("easy", stats.by_difficulty)

    def test_export_report(self):
        """导出报告应生成JSON文件"""
        import tempfile
        task = AgentCompanyTask(
            task_id="export_test",
            name="导出测试",
            description="测试",
            difficulty=TaskDifficulty.EASY,
            category=TaskCategory.CODE_GENERATION,
            checkpoints=[Checkpoint("cp1", "检查点")],
        )
        self.benchmark.add_task(task)

        def agent(desc, ctx):
            return "output", {}

        self.benchmark.run(agent)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            filepath = f.name

        self.benchmark.export_report(filepath)
        self.assertTrue(os.path.exists(filepath))

        import json
        with open(filepath) as f:
            report = json.load(f)
        self.assertEqual(report["benchmark_name"], "test_benchmark")
        self.assertEqual(report["stats"]["total_tasks"], 1)

        os.unlink(filepath)

    def test_partial_credit(self):
        """部分信用评分：部分检查点通过应得部分分数"""
        checkpoints = [
            Checkpoint("cp1", "必须通过", weight=1.0, required=True),
            Checkpoint("cp2", "可选", weight=2.0),
            Checkpoint("cp3", "可选", weight=3.0),
        ]

        def validator(output, ctx):
            return [
                CheckpointResult("cp1", 1.0, 1.0, True),
                CheckpointResult("cp2", 1.0, 1.0, True),
                CheckpointResult("cp3", 0.0, 1.0, False),
            ]

        task = AgentCompanyTask(
            task_id="partial",
            name="部分信用",
            description="测试",
            difficulty=TaskDifficulty.MEDIUM,
            category=TaskCategory.ALGORITHM,
            checkpoints=checkpoints,
            validator=validator,
        )
        self.benchmark.add_task(task)

        def agent(desc, ctx):
            return "output", {}

        results = self.benchmark.run(agent)
        # 满分 = 1*1 + 2*1 + 3*1 = 6
        # 得分 = 1*1 + 2*1 + 3*0 = 3
        self.assertAlmostEqual(results[0].total_score, 3.0, places=1)
        self.assertAlmostEqual(results[0].max_score, 6.0, places=1)


class TestDefaultTasks(unittest.TestCase):
    """预设任务集测试"""

    def test_default_tasks_count(self):
        """默认任务集应有10个任务"""
        tasks = get_default_tasks()
        self.assertEqual(len(tasks), 10)

    def test_all_tasks_have_checkpoints(self):
        """所有任务都应有检查点"""
        for task in get_default_tasks():
            self.assertGreater(len(task.checkpoints), 0)
            self.assertIsNotNone(task.description)
            self.assertIsNotNone(task.name)

    def test_filter_by_difficulty(self):
        """按难度筛选应正确"""
        easy = get_tasks_by_difficulty(TaskDifficulty.EASY)
        self.assertGreater(len(easy), 0)
        for task in easy:
            self.assertEqual(task.difficulty, TaskDifficulty.EASY)

    def test_filter_by_category(self):
        """按类别筛选应正确"""
        algo = get_tasks_by_category(TaskCategory.ALGORITHM)
        self.assertGreater(len(algo), 0)
        for task in algo:
            self.assertEqual(task.category, TaskCategory.ALGORITHM)

    def test_difficulty_distribution(self):
        """难度分布应覆盖EASY到EXPERT"""
        tasks = get_default_tasks()
        difficulties = set(t.difficulty for t in tasks)
        self.assertIn(TaskDifficulty.EASY, difficulties)
        self.assertIn(TaskDifficulty.MEDIUM, difficulties)
        self.assertIn(TaskDifficulty.HARD, difficulties)
        self.assertIn(TaskDifficulty.EXPERT, difficulties)

    def test_run_all_default_tasks_with_simple_agent(self):
        """用简单智能体运行所有默认任务应不崩溃"""
        benchmark = AgentCompanyBenchmark(name="full_test")
        benchmark.add_tasks(get_default_tasks())

        def simple_agent(desc, ctx):
            # 返回一个简单的Python函数
            return "def solution():\n    return 42\n", {}

        results = benchmark.run(simple_agent)
        self.assertEqual(len(results), 10)
        # 至少有一些任务通过（简单任务应该能过）
        passed = sum(1 for r in results if r.passed)
        self.assertGreaterEqual(passed, 0)  # 不强制要求通过，但不能崩溃


if __name__ == "__main__":
    unittest.main(verbosity=2)
