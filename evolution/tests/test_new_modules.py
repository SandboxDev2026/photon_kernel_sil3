import sys, os, time, random, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evolution import (SkillEvolver, AutoGeneticMemory, ShortTermMemory, MidTermMemory, MemoryItem, JiuwenSwarm, SwarmAgent, AgentRole, Skill, SkillLibrary, MockLLMAdapter)

class TestSkillEvolver(unittest.TestCase):
    def setUp(self):
        self.library = SkillLibrary()
        self.skill = Skill(name='test_skill', code='def solve(x): return x*2')
        self.library.add(self.skill)
        self.evolver = SkillEvolver(skill_library=self.library, llm=MockLLMAdapter(responses=['def solve(x): return x*3']), failure_threshold=2, min_executions_before_evolve=2, evolution_cooldown_seconds=0)
    def test_execute_success(self):
        r = self.evolver.execute_skill(self.skill.id, 't', lambda s,t: (True,'ok',''))
        self.assertTrue(r.success)
    def test_consecutive_failures_trigger(self):
        for i in range(3): self.evolver.execute_skill(self.skill.id, f't{i}', lambda s,t: (False,'','fail'))
        should, reason = self.evolver.should_evolve(self.skill.id)
        self.assertTrue(should)
    def test_evolve_modify(self):
        for i in range(3): self.evolver.execute_skill(self.skill.id, f't{i}', lambda s,t: (False,'','fail'))
        event = self.evolver.evolve_skill(self.skill.id)
        self.assertIsNotNone(event)
    def test_security_gate(self):
        self.assertFalse(SkillEvolver._default_security_gate('os.system(\"rm\")'))
        self.assertTrue(SkillEvolver._default_security_gate('def f(): pass'))

class TestShortTermMemory(unittest.TestCase):
    def test_add_get(self):
        m = ShortTermMemory(max_items=10)
        mid = m.add('test', importance=0.8)
        self.assertIsNotNone(m.get(mid))
    def test_lru_evict(self):
        m = ShortTermMemory(max_items=3)
        ids = [m.add(f'c{i}') for i in range(5)]
        self.assertIsNone(m.get(ids[0]))
    def test_search(self):
        m = ShortTermMemory()
        m.add('python code', tags=['python'])
        self.assertEqual(len(m.search('python')), 1)

class TestAutoGeneticMemory(unittest.TestCase):
    def test_remember(self):
        mem = AutoGeneticMemory()
        self.assertIsNotNone(mem.remember('test', tags=['t']))
    def test_recall(self):
        mem = AutoGeneticMemory()
        mem.remember('python programming', tags=['python'])
        self.assertGreater(len(mem.recall('python')), 0)
    def test_sanitize(self):
        mem = AutoGeneticMemory()
        mem.remember('key sk-abc123def456ghi789jkl012mno345pqr678')
        results = mem.recall('key')
        if results: self.assertNotIn('sk-abc123', results[0]['content'])
    def test_compress(self):
        mem = AutoGeneticMemory(compression_threshold=5)
        for i in range(10): mem.remember(f'item {i} ' * 10)
        self.assertGreater(mem.compressions_done, 0)
    def test_stats(self):
        mem = AutoGeneticMemory()
        mem.remember('test')
        self.assertEqual(mem.get_stats()['short_term']['items'], 1)

class TestSwarmAgent(unittest.TestCase):
    def test_create(self):
        a = SwarmAgent(name='t', role=AgentRole.EMPLOYED)
        self.assertEqual(a.name, 't')
    def test_record(self):
        a = SwarmAgent()
        a.record_task(True, 1.0)
        a.record_task(False, 0.0)
        self.assertAlmostEqual(a.success_rate, 0.5)
    def test_clone(self):
        a = SwarmAgent(name='p', skills=['s1'])
        c = a.clone()
        self.assertEqual(c.generation, 1)
        self.assertEqual(c.skills, ['s1'])

class TestJiuwenSwarm(unittest.TestCase):
    def setUp(self):
        self.lib = SkillLibrary()
        self.sk = Skill(name='ts', code='def f(): pass')
        self.lib.add(self.sk)
        self.swarm = JiuwenSwarm(skill_library=self.lib, llm=MockLLMAdapter(), population_size=10, elite_count=2)
    def test_initialize(self):
        self.swarm.initialize(seed_skills=[self.sk.id])
        self.assertEqual(len(self.swarm.agents), 10)
    def test_submit_task(self):
        self.assertIsNotNone(self.swarm.submit_task('task'))
    def test_assign_execute(self):
        self.swarm.initialize(seed_skills=[self.sk.id])
        self.swarm.submit_task('t1')
        self.swarm.assign_tasks()
        completed = self.swarm.execute_assignments()
        self.assertGreater(len(completed), 0)
    def test_evolve(self):
        self.swarm.initialize(seed_skills=[self.sk.id])
        for a in self.swarm.agents: a.fitness = random.uniform(0,1)
        self.swarm.evolve_population()
        self.assertEqual(self.swarm.generations_run, 1)
    def test_run_cycle(self):
        self.swarm.initialize(seed_skills=[self.sk.id])
        self.swarm.submit_task('t1')
        stats = self.swarm.run_cycle()
        self.assertIn('population_size', stats)
    def test_stats(self):
        self.swarm.initialize(seed_skills=[self.sk.id])
        self.assertEqual(self.swarm.get_stats()['population_size'], 10)

if __name__ == '__main__':
    unittest.main(verbosity=2)
