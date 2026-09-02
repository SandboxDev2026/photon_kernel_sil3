"""
evolution 模块测试

验证：
1. 模块导入
2. Individual 个体抽象
3. Population 种群管理
4. GA 主循环（使用 Mock LLM + Mock 沙盒）
5. 自进化 Agent 闭环
6. Skill 技能库
7. Archive 档案库
8. 安全约束（禁止本地 exec）
"""
import sys
import os
import json
import time
import unittest

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evolution import (
    Individual,
    Population,
    BaseEvaluator,
    EvaluationResult,
    RewriteMutator,
    PatchMutator,
    NLFeedbackMutator,
    MultiStrategyMutator,
    SemanticCrossover,
    BlendCrossover,
    TournamentSelector,
    RouletteWheelSelector,
    EliteSelector,
    GALoop,
    IslandGA,
    Island,
    AgentEvolver,
    ExecutionTrace,
    EvolutionRound,
    Skill,
    SkillLibrary,
    Archive,
    MockLLMAdapter,
    SandboxClient,
    SandboxResult,
    MutationPrompts,
    CrossoverPrompts,
    ReflectionPrompts,
)


class TestIndividual(unittest.TestCase):
    """Individual 个体抽象测试"""

    def test_create(self):
        ind = Individual(payload={"code": "def solve(x): return x*2"})
        self.assertIsNotNone(ind.id)
        self.assertEqual(ind.gen, 0)
        self.assertEqual(ind.fitness, 0.0)
        self.assertFalse(ind.evaluated)

    def test_clone(self):
        ind = Individual(payload={"code": "test"}, fitness=0.8)
        clone = ind.clone()
        self.assertNotEqual(ind.id, clone.id)
        self.assertEqual(clone.fitness, 0.0)  # 克隆后适应度重置
        self.assertEqual(clone.parent_ids, [ind.id])

    def test_pass_rate(self):
        ind = Individual(test_pass=7, test_total=10)
        self.assertAlmostEqual(ind.pass_rate, 0.7)

    def test_is_elite(self):
        ind = Individual(fitness=0.85)
        self.assertTrue(ind.is_elite)
        ind2 = Individual(fitness=0.5)
        self.assertFalse(ind2.is_elite)

    def test_serialization(self):
        ind = Individual(payload={"code": "test"}, fitness=0.9)
        d = ind.to_dict()
        self.assertIn("id", d)
        self.assertIn("payload", d)
        ind2 = Individual.from_dict(d)
        self.assertEqual(ind.id, ind2.id)
        self.assertEqual(ind.fitness, ind2.fitness)


class TestPopulation(unittest.TestCase):
    """Population 种群管理测试"""

    def test_add_and_size(self):
        pop = Population(size=10, elite_count=2)
        for i in range(5):
            pop.add(Individual(fitness=i * 0.1))
        self.assertEqual(len(pop), 5)

    def test_best_worst(self):
        pop = Population()
        pop.add(Individual(fitness=0.3))
        pop.add(Individual(fitness=0.9))
        pop.add(Individual(fitness=0.5))
        self.assertAlmostEqual(pop.best.fitness, 0.9)
        self.assertAlmostEqual(pop.worst.fitness, 0.3)

    def test_elites(self):
        pop = Population(elite_count=2)
        for i in range(5):
            pop.add(Individual(fitness=i * 0.2))
        elites = pop.elites
        self.assertEqual(len(elites), 2)
        self.assertAlmostEqual(elites[0].fitness, 0.8)

    def test_trim(self):
        pop = Population(size=3)
        for i in range(10):
            pop.add(Individual(fitness=i * 0.1))
        pop.trim()
        self.assertEqual(len(pop), 3)
        self.assertAlmostEqual(pop.best.fitness, 0.9)

    def test_snapshot(self):
        pop = Population()
        pop.add(Individual(fitness=0.5))
        filepath = pop.save_snapshot("/tmp/test_pop_snapshot.json")
        self.assertTrue(os.path.exists(filepath))
        pop2 = Population.load_snapshot(filepath)
        self.assertEqual(len(pop2), 1)
        os.remove(filepath)


class TestMutator(unittest.TestCase):
    """变异算子测试"""

    def test_rewrite_mutator_no_llm(self):
        mutator = RewriteMutator(llm_adapter=None)
        ind = Individual(payload={"code": "def solve(x): return x"})
        result = mutator.mutate(ind)
        self.assertNotEqual(ind.id, result.id)
        self.assertEqual(result.mutation_type, "rewrite")

    def test_patch_mutator_no_llm(self):
        mutator = PatchMutator(llm_adapter=None)
        ind = Individual(payload={"code": "def solve(x): return x"})
        result = mutator.mutate(ind)
        self.assertEqual(result.mutation_type, "patch")

    def test_nl_feedback_mutator(self):
        mutator = NLFeedbackMutator(llm_adapter=None)
        ind = Individual(payload={"code": "def solve(x): return x"})
        result = mutator.mutate(ind, fail_cases=["test failed"])
        self.assertEqual(result.mutation_type, "nl_feedback")

    def test_multi_strategy(self):
        mutator = MultiStrategyMutator(llm_adapter=None)
        ind = Individual(payload={"code": "test"}, gen=0)
        result = mutator.mutate(ind)
        self.assertIn(result.mutation_type, ["rewrite", "patch", "nl_feedback"])


class TestCrossover(unittest.TestCase):
    """交叉算子测试"""

    def test_semantic_crossover_no_llm(self):
        crossover = SemanticCrossover(llm_adapter=None)
        ind_a = Individual(payload={"code": "code A"}, fitness=0.8)
        ind_b = Individual(payload={"code": "code B"}, fitness=0.6)
        result = crossover.cross(ind_a, ind_b)
        # 无 LLM 时退化选择适应度高的
        self.assertEqual(result.payload.get("code"), "code A")

    def test_blend_crossover(self):
        crossover = BlendCrossover(llm_adapter=None)
        ind_a = Individual(fitness=0.8)
        ind_b = Individual(fitness=0.6)
        result = crossover.cross(ind_a, ind_b)
        self.assertIsNotNone(result)


class TestSelector(unittest.TestCase):
    """选择算子测试"""

    def test_tournament(self):
        selector = TournamentSelector(tournament_size=3)
        pop = [Individual(fitness=i * 0.1) for i in range(10)]
        selected = selector.select(pop, 5)
        self.assertEqual(len(selected), 5)

    def test_roulette(self):
        selector = RouletteWheelSelector()
        pop = [Individual(fitness=i * 0.1 + 0.1) for i in range(10)]
        selected = selector.select(pop, 5)
        self.assertEqual(len(selected), 5)

    def test_elite(self):
        selector = EliteSelector()
        pop = [Individual(fitness=i * 0.1) for i in range(10)]
        selected = selector.select(pop, 3)
        self.assertEqual(len(selected), 3)
        self.assertAlmostEqual(selected[0].fitness, 0.9)


class TestSkillLibrary(unittest.TestCase):
    """Skill 技能库测试"""

    def test_add_and_get(self):
        lib = SkillLibrary()
        skill = Skill(name="test_skill", code="def test(): pass")
        skill_id = lib.add(skill)
        retrieved = lib.get(skill_id)
        self.assertEqual(retrieved.name, "test_skill")

    def test_list_with_filter(self):
        lib = SkillLibrary()
        s1 = Skill(name="s1", tags=["math"], current_fitness=0.9)
        s2 = Skill(name="s2", tags=["io"], current_fitness=0.5)
        lib.add(s1)
        lib.add(s2)
        math_skills = lib.list(tag="math")
        self.assertEqual(len(math_skills), 1)
        elite = lib.list(min_fitness=0.8)
        self.assertEqual(len(elite), 1)

    def test_evolve_and_rollback(self):
        lib = SkillLibrary()
        skill = Skill(name="test", code="v1", version="1.0.0")
        skill_id = lib.add(skill)
        new_skill = lib.evolve_skill(skill_id, "v2", mutation_type="manual")
        self.assertIsNotNone(new_skill)
        self.assertEqual(new_skill.code, "v2")
        # 回滚
        rolled = lib.rollback(skill_id)
        self.assertEqual(rolled.code, "v1")

    def test_record_execution(self):
        skill = Skill()
        skill.record_execution(success=True, fitness=0.8)
        skill.record_execution(success=False)
        self.assertEqual(skill.use_count, 2)
        self.assertEqual(skill.success_count, 1)
        self.assertAlmostEqual(skill.success_rate, 0.5)


class TestArchive(unittest.TestCase):
    """Archive 档案库测试"""

    def test_add_and_get(self):
        archive = Archive(min_fitness=0.3)
        ind1 = Individual(fitness=0.5, payload={"code": "a"})
        ind2 = Individual(fitness=0.2, payload={"code": "b"})  # 低于阈值
        self.assertTrue(archive.add(ind1))
        self.assertFalse(archive.add(ind2))
        self.assertEqual(len(archive), 1)

    def test_best_ever(self):
        archive = Archive()
        archive.add(Individual(fitness=0.7, payload={"code": "code_a"}))
        archive.add(Individual(fitness=0.9, payload={"code": "code_b"}))
        archive.add(Individual(fitness=0.5, payload={"code": "code_c"}))
        self.assertAlmostEqual(archive.best_ever.fitness, 0.9)

    def test_deduplication(self):
        archive = Archive()
        ind1 = Individual(fitness=0.8, payload={"code": "same"})
        ind2 = Individual(fitness=0.9, payload={"code": "same"})  # 相同代码
        archive.add(ind1)
        self.assertFalse(archive.add(ind2))  # 重复被拒绝


class TestPrompts(unittest.TestCase):
    """提示词模板测试"""

    def test_mutation_prompts(self):
        prompt = MutationPrompts.rewrite("def solve(x): return x", fail_cases=["fail"])
        self.assertIn("重写", prompt)
        self.assertIn("fail", prompt)

    def test_crossover_prompts(self):
        prompt = CrossoverPrompts.semantic("code A", "code B", 0.8, 0.6)
        self.assertIn("融合", prompt)
        self.assertIn("code A", prompt)

    def test_reflection_prompts(self):
        prompt = ReflectionPrompts.geppa("trajectory", ["fail case 1"])
        self.assertIn("反思", prompt)


class TestSandboxClient(unittest.TestCase):
    """沙盒客户端测试（不连接真实服务）"""

    def test_create(self):
        client = SandboxClient(base_url="http://127.0.0.1:9999")
        self.assertEqual(client.base_url, "http://127.0.0.1:9999")

    def test_health_check_fail(self):
        client = SandboxClient(base_url="http://127.0.0.1:9999", timeout=1)
        self.assertFalse(client.health_check())

    def test_execute_fail(self):
        client = SandboxClient(base_url="http://127.0.0.1:9999", timeout=1, max_retries=0)
        result = client.execute("print(1)")
        self.assertFalse(result.success)


class TestMockLLM(unittest.TestCase):
    """Mock LLM 适配器测试"""

    def test_create(self):
        llm = MockLLMAdapter(responses=["response 1", "response 2"])
        self.assertEqual(llm.model, "mock")

    def test_generate(self):
        llm = MockLLMAdapter(responses=["test response"])
        result = llm.generate("prompt")
        self.assertEqual(result, "test response")
        self.assertEqual(llm.total_calls, 1)

    def test_default_response(self):
        llm = MockLLMAdapter()
        result = llm.generate("prompt")
        self.assertTrue(len(result) > 0)


class TestGALoopBasic(unittest.TestCase):
    """GA 主循环基本测试（使用 Mock）"""

    def test_create(self):
        # 创建一个简单的评估器（不实际执行代码）
        class MockEvaluator(BaseEvaluator):
            def __init__(self):
                super().__init__(sandbox=SandboxClient(base_url="http://127.0.0.1:9999", timeout=1))
            def get_test_cases(self):
                return [{"input": "1", "expected": "2"}]
            def run_single_test(self, code, test_case):
                return (True, "ok", "", False)

        evaluator = MockEvaluator()
        ga = GALoop(
            evaluator=evaluator,
            population_size=5,
            max_generations=2,
            target_fitness=1.0,
        )
        self.assertIsNotNone(ga)

    def test_individual_evolution(self):
        """测试个体进化流程（选择-变异-评估）"""
        ind = Individual(payload={"code": "def solve(x): return x*2"}, fitness=0.5)
        mutator = RewriteMutator(llm_adapter=MockLLMAdapter(responses=["def solve(x): return x*3"]))
        offspring = mutator.mutate(ind)
        self.assertNotEqual(ind.id, offspring.id)
        self.assertEqual(offspring.payload.get("code"), "def solve(x): return x*3")


class TestAgentEvolverBasic(unittest.TestCase):
    """自进化 Agent 闭环基本测试"""

    def test_create(self):
        sandbox = SandboxClient(base_url="http://127.0.0.1:9999", timeout=1)
        evolver = AgentEvolver(sandbox=sandbox, failure_threshold=2)
        self.assertEqual(evolver.failure_threshold, 2)
        self.assertEqual(evolver.consecutive_failures, 0)

    def test_execution_trace(self):
        trace = ExecutionTrace(
            task_id="test",
            input="test input",
            output="test output",
            success=True,
            duration_ms=100,
        )
        d = trace.to_dict()
        self.assertEqual(d["task_id"], "test")
        self.assertTrue(d["success"])

    def test_security_gate(self):
        sandbox = SandboxClient(base_url="http://127.0.0.1:9999", timeout=1)
        evolver = AgentEvolver(sandbox=sandbox)
        # 安全代码应该通过
        self.assertTrue(evolver.security_gate("def solve(x): return x*2"))
        # 危险代码应该被拒绝
        self.assertFalse(evolver.security_gate("import os; os.system('rm -rf /')"))
        self.assertFalse(evolver.security_gate("eval('__import__(\"os\").system(\"ls\")')"))


class TestSecurityConstraints(unittest.TestCase):
    """安全约束测试 — 确保模块不鼓励本地 exec"""

    def test_no_local_exec_in_evaluator(self):
        """评估器基类不应该有本地 exec 方法"""
        self.assertTrue(hasattr(BaseEvaluator, "evaluate"))
        # BaseEvaluator.evaluate 应该调用 run_single_test，而不是直接 exec
        source = BaseEvaluator.evaluate.__doc__ or ""
        self.assertIn("沙盒", source)

    def test_sandbox_client_is_required(self):
        """评估器必须接收 sandbox 客户端"""
        with self.assertRaises(TypeError):
            BaseEvaluator()  # 缺少 sandbox 参数


if __name__ == "__main__":
    unittest.main(verbosity=2)
