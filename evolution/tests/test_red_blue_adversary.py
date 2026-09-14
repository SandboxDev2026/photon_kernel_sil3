"""
red_blue_adversary 单元测试（核心层）

覆盖：AttackCase/DefenseRule数据类、RedAgent、BlueAgent、RedBlueAdversaryTrainer。
"""
import unittest, sys, os, time, random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evolution.red_blue_adversary import (
    AdversaryRole, AttackType, DefenseType,
    AttackCase, DefenseRule, RedAgent, BlueAgent, RedBlueAdversaryTrainer,
)


class TestAttackCase(unittest.TestCase):
    def test_create(self):
        c = AttackCase(case_id="AC1", attack_type=AttackType.PRIVILEGE_ESCALATION,
                       description="test", payload="x", target_component="kernel")
        self.assertEqual(c.case_id, "AC1")
        self.assertEqual(c.success_count, 0)

    def test_success_rate_no_attempts(self):
        c = AttackCase(case_id="AC2", attack_type=AttackType.PRIVILEGE_ESCALATION,
                       description="", payload="", target_component="")
        self.assertEqual(c.get_success_rate(), 0.0)

    def test_record_success(self):
        c = AttackCase(case_id="AC3", attack_type=AttackType.PRIVILEGE_ESCALATION,
                       description="", payload="", target_component="")
        c.record_result(True)
        c.record_result(True)
        c.record_result(False)
        self.assertEqual(c.success_count, 2)
        self.assertEqual(c.failure_count, 1)
        self.assertAlmostEqual(c.get_success_rate(), 2/3, places=2)


class TestDefenseRule(unittest.TestCase):
    def test_create(self):
        r = DefenseRule(rule_id="DR1", defense_type=DefenseType.SYSTEM_CALL_MONITOR,
                        description="test", target_attack_types=[AttackType.PRIVILEGE_ESCALATION],
                        detection_logic="test")
        self.assertEqual(r.rule_id, "DR1")
        self.assertEqual(r.effectiveness, 0.5)

    def test_precision_no_triggers(self):
        r = DefenseRule(rule_id="DR2", defense_type=DefenseType.SYSTEM_CALL_MONITOR,
                        description="", target_attack_types=[], detection_logic="")
        self.assertEqual(r.get_precision(), 1.0)

    def test_record_trigger(self):
        r = DefenseRule(rule_id="DR3", defense_type=DefenseType.SYSTEM_CALL_MONITOR,
                        description="", target_attack_types=[], detection_logic="")
        r.record_trigger(True)
        r.record_trigger(False)
        self.assertEqual(r.trigger_count, 2)
        self.assertEqual(r.false_positive_count, 1)


class TestRedAgent(unittest.TestCase):
    def setUp(self):
        self.red = RedAgent(agent_id="test_red")

    def test_initial_cases(self):
        self.assertGreater(len(self.red.attack_cases), 10)

    def test_strategy_weights(self):
        self.assertGreater(len(self.red.strategy_weights), 0)
        for wt in self.red.strategy_weights.values():
            self.assertGreater(wt, 0)

    def test_select_attack(self):
        case = self.red.select_attack_case()
        self.assertIsInstance(case, AttackCase)

    def test_select_multiple(self):
        for _ in range(10):
            case = self.red.select_attack_case()
            self.assertIsNotNone(case)

    def test_mutate_attack_case(self):
        base = self.red.attack_cases[0]
        mutated = self.red.mutate_attack_case(base)
        self.assertIsInstance(mutated, AttackCase)

    def test_record_attack_result(self):
        case = self.red.attack_cases[0]
        self.red.record_attack_result(case, success=True)
        self.assertGreater(case.success_count, 0)

    def test_statistics(self):
        stats = self.red.get_statistics()
        self.assertIsInstance(stats, dict)
        self.assertIn("total_attacks", stats)


class TestBlueAgent(unittest.TestCase):
    def setUp(self):
        self.blue = BlueAgent(agent_id="test_blue")

    def test_initial_rules(self):
        self.assertGreater(len(self.blue.defense_rules), 5)

    def test_detect_attack(self):
        red = RedAgent()
        case = red.attack_cases[0]
        detected, rules, delay = self.blue.detect_attack(case)
        self.assertIsInstance(detected, bool)
        self.assertIsInstance(rules, list)
        self.assertGreaterEqual(delay, 0)

    def test_detect_unknown_attack(self):
        # 构造一个未知攻击类型
        case = AttackCase(case_id="X", attack_type=AttackType.DOS_ATTACK,
                          description="", payload="", target_component="", difficulty=0.9)
        detected, rules, delay = self.blue.detect_attack(case)
        self.assertIsInstance(detected, bool)

    def test_evolve_rule(self):
        base = self.blue.defense_rules[0]
        evolved = self.blue.evolve_defense_rule(base)
        self.assertIsInstance(evolved, DefenseRule)

    def test_record_defense_result(self):
        rule = self.blue.defense_rules[0]
        self.blue.record_defense_result([rule], attack_success=False, is_true_positive=True)

    def test_statistics(self):
        stats = self.blue.get_statistics()
        self.assertIsInstance(stats, dict)


class TestTrainer(unittest.TestCase):
    def setUp(self):
        self.trainer = RedBlueAdversaryTrainer(max_rounds=3)

    def test_create_trainer(self):
        self.assertIsNotNone(self.trainer)

    def test_single_round(self):
        result = self.trainer.run_single_round(round_id=1)
        self.assertIsNotNone(result)

    def test_run_training(self):
        result = self.trainer.run_training(num_rounds=2)
        self.assertIsInstance(result, dict)

    def test_stats_after_training(self):
        self.trainer.run_training(num_rounds=2)
        # 检查轮次记录
        self.assertGreater(len(self.trainer.rounds), 0)


class TestBoundary(unittest.TestCase):
    def test_red_agent_custom_id(self):
        r = RedAgent(agent_id="custom_red")
        self.assertEqual(r.agent_id, "custom_red")

    def test_blue_agent_custom_id(self):
        b = BlueAgent(agent_id="custom_blue")
        self.assertEqual(b.agent_id, "custom_blue")

    def test_attack_case_zero_difficulty(self):
        c = AttackCase(case_id="Z", attack_type=AttackType.PRIVILEGE_ESCALATION,
                       description="", payload="", target_component="", difficulty=0.0)
        self.assertEqual(c.difficulty, 0.0)

    def test_attack_case_max_difficulty(self):
        c = AttackCase(case_id="M", attack_type=AttackType.PRIVILEGE_ESCALATION,
                       description="", payload="", target_component="", difficulty=1.0)
        self.assertEqual(c.difficulty, 1.0)

    def test_all_attack_types_covered(self):
        red = RedAgent()
        types_used = set(c.attack_type for c in red.attack_cases)
        self.assertGreater(len(types_used), 3)

    def test_all_defense_types_covered(self):
        blue = BlueAgent()
        types_used = set(r.defense_type for r in blue.defense_rules)
        self.assertGreaterEqual(len(types_used), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
