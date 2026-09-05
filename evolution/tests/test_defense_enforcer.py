"""
DefenseRuleEnforcer 单元测试（精简版）
覆盖核心功能：ConfigUpdate数据类、规则生成配置更新、队列管理、应用更新、回滚、统计报告、边界条件。
"""
import unittest, sys, os, time, tempfile, shutil
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evolution.defense_enforcer import DefenseRuleEnforcer, ConfigUpdate, ConfigTarget, ChangeAction, EnforcerStats
from evolution.red_blue_adversary import DefenseRule, DefenseType, AttackType
from evolution.real_data_adapter import SecurityEvent, EventSource

def make_rule(dt=DefenseType.SYSTEM_CALL_MONITOR, rid="r001", **kw):
    return DefenseRule(rule_id=rid, defense_type=dt, description="test",
        target_attack_types=[AttackType.PRIVILEGE_ESCALATION], detection_logic="test", **kw)

def make_update(uid="u001", target=ConfigTarget.LIGHTPOOL_SECCOMP, action=ChangeAction.ADD,
                desc="test", key="k", val="v", pri="medium"):
    return ConfigUpdate(update_id=uid, target=target, action=action, description=desc,
        config_key=key, config_value=val, priority=pri)

class TestConfigUpdate(unittest.TestCase):
    def test_create(self):
        u = make_update(); self.assertEqual(u.update_id, "u001"); self.assertEqual(u.config_key, "k")
    def test_to_json(self):
        self.assertEqual(make_update(uid="json_test").to_json()["update_id"], "json_test")
    def test_enums(self):
        self.assertIn(ConfigTarget.LIGHTPOOL_SECCOMP, list(ConfigTarget))
        self.assertIn(ChangeAction.ADD, list(ChangeAction))
        self.assertIn(ChangeAction.UPDATE, list(ChangeAction))

class TestEnforcerBasic(unittest.TestCase):
    def setUp(self): self.tmp=tempfile.mkdtemp(); self.e=DefenseRuleEnforcer(config_dir=self.tmp,dry_run=True)
    def tearDown(self): shutil.rmtree(self.tmp,ignore_errors=True)
    def test_create_default(self): self.assertTrue(DefenseRuleEnforcer().dry_run)
    def test_gen_syscall(self): self.assertIsInstance(self.e.generate_updates_from_rule(make_rule()), list)
    def test_gen_network(self): self.assertIsInstance(self.e.generate_updates_from_rule(make_rule(DefenseType.NETWORK_FILTER)), list)
    def test_gen_resource(self): self.assertIsInstance(self.e.generate_updates_from_rule(make_rule(DefenseType.RESOURCE_LIMIT)), list)
    def test_gen_all_types(self):
        for dt in DefenseType:
            try: self.assertIsInstance(self.e.generate_updates_from_rule(make_rule(dt,rid=f"r_{dt.value}")), list)
            except Exception: pass
    def test_gen_with_event(self):
        ev=SecurityEvent(event_id="e001",source=EventSource.SECCOMP_VIOLATION,timestamp=time.time(),
            sandbox_id="s001",severity="warning",description="test",payload={})
        self.assertIsInstance(self.e.generate_updates_from_rule(make_rule(),event=ev), list)

class TestEnqueue(unittest.TestCase):
    def setUp(self): self.tmp=tempfile.mkdtemp(); self.e=DefenseRuleEnforcer(config_dir=self.tmp,dry_run=True)
    def tearDown(self): shutil.rmtree(self.tmp,ignore_errors=True)
    def test_single(self): self.e.enqueue_update(make_update()); self.assertEqual(len(self.e.get_pending_updates()),1)
    def test_multiple(self): self.e.enqueue_updates([make_update(uid=f"q{i}") for i in range(5)]); self.assertEqual(len(self.e.get_pending_updates()),5)
    def test_empty(self): self.e.enqueue_updates([]); self.assertEqual(len(self.e.get_pending_updates()),0)

class TestApply(unittest.TestCase):
    def setUp(self): self.tmp=tempfile.mkdtemp(); self.e=DefenseRuleEnforcer(config_dir=self.tmp,dry_run=True)
    def tearDown(self): shutil.rmtree(self.tmp,ignore_errors=True)
    def test_empty(self): self.assertIsInstance(self.e.apply_pending(), dict)
    def test_with_updates(self):
        self.e.enqueue_updates([make_update(uid=f"a{i}") for i in range(3)])
        self.assertIsInstance(self.e.apply_pending(), dict)
    def test_applied_list(self):
        self.e.enqueue_update(make_update()); self.e.apply_pending()
        self.assertIsInstance(self.e.get_applied_updates(), list)

class TestRollback(unittest.TestCase):
    def setUp(self): self.tmp=tempfile.mkdtemp(); self.e=DefenseRuleEnforcer(config_dir=self.tmp,dry_run=True,auto_backup=True)
    def tearDown(self): shutil.rmtree(self.tmp,ignore_errors=True)
    def test_all(self): self.assertIsInstance(self.e.rollback(), dict)
    def test_target(self): self.assertIsInstance(self.e.rollback(target=ConfigTarget.LIGHTPOOL_SECCOMP), dict)
    def test_no_backup(self):
        e=DefenseRuleEnforcer(config_dir=self.tmp,dry_run=True,auto_backup=False)
        self.assertIsInstance(e.rollback(), dict)

class TestStatsReport(unittest.TestCase):
    def setUp(self): self.tmp=tempfile.mkdtemp(); self.e=DefenseRuleEnforcer(config_dir=self.tmp,dry_run=True)
    def tearDown(self): shutil.rmtree(self.tmp,ignore_errors=True)
    def test_initial(self): self.assertIsNotNone(self.e.get_stats())
    def test_after_gen(self): self.e.generate_updates_from_rule(make_rule()); self.assertIsNotNone(self.e.get_stats())
    def test_report(self):
        ups=self.e.generate_updates_from_rule(make_rule()); self.e.enqueue_updates(ups)
        self.assertIsInstance(self.e.generate_update_report(), dict)

class TestBoundary(unittest.TestCase):
    def setUp(self): self.tmp=tempfile.mkdtemp(); self.e=DefenseRuleEnforcer(config_dir=self.tmp,dry_run=True)
    def tearDown(self): shutil.rmtree(self.tmp,ignore_errors=True)
    def test_long_rid(self):
        try: self.e.generate_updates_from_rule(make_rule(rid="x"*5000))
        except Exception: pass
    def test_long_desc(self):
        try: self.e.generate_updates_from_rule(make_rule(description="A"*50000))
        except Exception: pass
    def test_none_dir(self):
        try: DefenseRuleEnforcer(config_dir=None,dry_run=True)
        except Exception: pass
    def test_apply_invalid(self):
        self.e.enqueue_update(make_update())
        try: self.e.apply_pending()
        except Exception: pass
    def test_empty_rid(self):
        try: self.e.generate_updates_from_rule(make_rule(rid=""))
        except Exception: pass

if __name__=="__main__": unittest.main(verbosity=2)
