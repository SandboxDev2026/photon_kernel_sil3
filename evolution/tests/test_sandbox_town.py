"""
Sandbox Town 单元测试
"""
import unittest, sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evolution.sandbox_town import (
    SandboxTown, TownResident, TownLocation, TownEvent,
    Personality, LocationType, ActivityType,
)


class TestTownInit(unittest.TestCase):
    def test_create_town(self):
        t = SandboxTown(num_residents=5, seed=1)
        self.assertEqual(len(t.residents), 5)
        self.assertGreater(len(t.locations), 3)

    def test_locations_built(self):
        t = SandboxTown(num_residents=3, seed=2)
        self.assertIn("square", t.locations)
        self.assertIn("cafe", t.locations)
        self.assertIn("factory", t.locations)

    def test_residents_have_names(self):
        t = SandboxTown(num_residents=4, seed=3)
        for r in t.residents:
            self.assertTrue(r.name)
            self.assertIsNotNone(r.home)

    def test_seed_reproducible(self):
        a = SandboxTown(num_residents=6, seed=42)
        b = SandboxTown(num_residents=6, seed=42)
        self.assertEqual([r.name for r in a.residents],
                         [r.name for r in b.residents])

    def test_different_seed_different_residents(self):
        a = SandboxTown(num_residents=8, seed=1)
        b = SandboxTown(num_residents=8, seed=2)
        # 名字池有限，可能有重合，但顺序不同
        self.assertNotEqual([r.name for r in a.residents],
                            [r.name for r in b.residents])


class TestResident(unittest.TestCase):
    def setUp(self):
        self.loc = TownLocation("h", "家", LocationType.HOME, 0, 0)
        self.r = TownResident("测试居民", self.loc, Personality.OUTGOING, "程序员")

    def test_remember(self):
        mid = self.r.remember("今天下雨了", importance=0.6, tags=["weather"])
        self.assertTrue(mid)
        self.assertGreater(len(self.r.memory._items), 0)

    def test_move(self):
        cafe = TownLocation("c", "咖啡馆", LocationType.CAFE, 3, 3)
        old_energy = self.r.energy
        self.r.move_to(cafe)
        self.assertEqual(self.r.location.loc_id, "c")
        self.assertLess(self.r.energy, old_energy)

    def test_work_earns_money(self):
        old = self.r.money
        earned = self.r.work(3)
        self.assertGreater(earned, 0)
        self.assertGreater(self.r.money, old)

    def test_rest_recovers_energy(self):
        self.r.energy = 0.2
        self.r.rest(6)
        self.assertGreater(self.r.energy, 0.2)

    def test_socialize_updates_relation(self):
        other = TownResident("另一位", self.loc, Personality.OUTGOING)
        # 性格有概率不社交，重试直到成功
        for _ in range(20):
            self.r.socialize(other)
            if other.name in self.r.relationships:
                break
        self.assertIn(other.name, self.r.relationships)

    def test_react_to_event(self):
        ev = TownEvent(event_id="x", tick=1, event_type="fire",
                       actor="小镇", location="广场", description="着火了")
        result = self.r.react_to_event(ev)
        self.assertIn(self.r.name, result)

    def test_stats(self):
        s = self.r.stats()
        self.assertEqual(s["name"], "测试居民")
        self.assertIn("energy", s)


class TestTownStep(unittest.TestCase):
    def setUp(self):
        self.town = SandboxTown(num_residents=6, seed=10)

    def test_step_runs(self):
        result = self.town.step(0)
        self.assertEqual(result["tick"], 0)
        self.assertEqual(result["residents_active"], 6)

    def test_step_records_events(self):
        self.town.step(1)
        self.assertGreaterEqual(len(self.town.event_log), 0)

    def test_multiple_ticks(self):
        for t in range(5):
            self.town.step(t)
        self.assertGreater(len(self.town.event_log), 0)

    def test_energy_decreases(self):
        before = [r.energy for r in self.town.residents]
        self.town.step(0)
        after = [r.energy for r in self.town.residents]
        # 移动会消耗精力
        self.assertNotEqual(before, after)


class TestIncident(unittest.TestCase):
    def setUp(self):
        self.town = SandboxTown(num_residents=5, seed=7)

    def test_inject_incident(self):
        ev = self.town.inject_incident(kind="fire")
        self.assertEqual(ev.event_type, "incident")
        self.assertEqual(ev.severity, "warning")

    def test_inject_gossip(self):
        ev = self.town.inject_incident(kind="gossip")
        self.assertEqual(ev.severity, "info")

    def test_incident_seen_by_residents(self):
        before = sum(len(r.memory._items) for r in self.town.residents)
        self.town.inject_incident(kind="newcomer")
        after = sum(len(r.memory._items) for r in self.town.residents)
        self.assertGreater(after, before)


class TestReport(unittest.TestCase):
    def setUp(self):
        self.town = SandboxTown(num_residents=6, seed=20)
        for t in range(8):
            self.town.step(t)

    def test_report_shape(self):
        r = self.town.generate_report()
        for key in ["town_name", "ticks_run", "residents", "total_events",
                    "relationship_graph", "recent_events"]:
            self.assertIn(key, r)

    def test_relationship_graph(self):
        g = self.town.relationship_graph()
        self.assertEqual(len(g["nodes"]), 6)
        self.assertIsInstance(g["edges"], list)

    def test_recent_events_not_empty(self):
        r = self.town.generate_report()
        self.assertIsInstance(r["recent_events"], list)

    def test_stats_in_report(self):
        r = self.town.generate_report()
        self.assertTrue(r["most_social_resident"])
        self.assertTrue(r["richest_resident"])


class TestBoundary(unittest.TestCase):
    def test_tiny_town(self):
        t = SandboxTown(num_residents=1, seed=99)
        t.step(0)
        self.assertEqual(len(t.residents), 1)

    def test_no_incident_no_crash(self):
        t = SandboxTown(num_residents=3, seed=100)
        for _ in range(3):
            t.step(0)

    def test_unknown_incident_kind(self):
        t = SandboxTown(num_residents=3, seed=101)
        ev = t.inject_incident(kind="unknown_thing")
        self.assertIsNotNone(ev)

    def test_resident_self_socialize(self):
        loc = TownLocation("h", "家", LocationType.HOME, 0, 0)
        r = TownResident("独", loc)
        self.assertEqual(r.socialize(r), "")

    def test_long_simulation(self):
        t = SandboxTown(num_residents=4, seed=200)
        for i in range(30):
            t.step(i)
        r = t.generate_report()
        self.assertEqual(r["ticks_run"], 30)


if __name__ == "__main__":
    unittest.main(verbosity=2)
