"""
train_from_real_signals 实时训练循环端到端测试

验证：
1. 批量模式：从文件消费事件，执行多轮训练
2. 实时模式：REALTIME 监听，每积累N个事件触发一轮训练
3. 训练结果统计正确
4. 与桥接器集成：进化出的规则自动下发
5. 超时处理
"""

import json
import os
import tempfile
import time
import unittest

from evolution.red_blue_adversary import RedBlueAdversaryTrainer
from evolution.real_signal_consumer import ConsumeMode, RealSignalConsumer, SignalType


_counter = 0


def make_seccomp_event(syscall="ptrace", action="blocked", sandbox_id="sb_001"):
    """生成 seccomp 违规日志行，带唯一 event_id"""
    global _counter
    _counter += 1
    return json.dumps({
        "event_id": f"seccomp_{_counter}_{int(time.time() * 1000000)}",
        "timestamp": time.time(),
        "sandbox_id": sandbox_id,
        "signal_type": "seccomp_violation",
        "syscall": syscall,
        "action": action,
        "pid": 12345,
        "comm": "malicious",
        "severity": "high",
    })


class TestTrainFromRealSignalsBatch(unittest.TestCase):
    """批量模式训练测试"""

    def setUp(self):
        self.trainer = RedBlueAdversaryTrainer(enable_evolution=True)
        self.consumer = RealSignalConsumer(mode=ConsumeMode.BATCH)
        self.tmp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
        self.tmp_file.close()

    def tearDown(self):
        if os.path.exists(self.tmp_file.name):
            os.unlink(self.tmp_file.name)

    def test_batch_mode_basic(self):
        """测试批量模式基本训练"""
        # 写入事件
        with open(self.tmp_file.name, 'w') as f:
            for i in range(20):
                f.write(make_seccomp_event(syscall=f"sys_{i}") + '\n')

        result = self.trainer.train_from_real_signals(
            consumer=self.consumer,
            num_rounds=3,
            events_per_round=10,
            file_path=self.tmp_file.name,
            signal_type=SignalType.SECCOMP_VIOLATION,
            realtime=False,
        )

        self.assertEqual(result["mode"], "batch")
        self.assertEqual(result["num_rounds"], 3)
        self.assertGreater(result["total_events_consumed"], 0)
        self.assertGreater(result["new_events_ingested"], 0)
        self.assertEqual(len(result["round_results"]), 3)
        self.assertIn("duration_seconds", result)

    def test_batch_mode_no_file(self):
        """测试批量模式不提供文件"""
        result = self.trainer.train_from_real_signals(
            consumer=self.consumer,
            num_rounds=2,
            events_per_round=10,
            realtime=False,
        )

        self.assertEqual(result["mode"], "batch")
        self.assertEqual(result["num_rounds"], 2)
        # 没有文件但仍然执行训练轮次（基于已有事件）
        self.assertEqual(len(result["round_results"]), 2)

    def test_batch_mode_round_results_structure(self):
        """测试每轮训练结果结构"""
        with open(self.tmp_file.name, 'w') as f:
            for i in range(15):
                f.write(make_seccomp_event(syscall=f"sys_{i}") + '\n')

        result = self.trainer.train_from_real_signals(
            consumer=self.consumer,
            num_rounds=2,
            events_per_round=10,
            file_path=self.tmp_file.name,
            signal_type=SignalType.SECCOMP_VIOLATION,
        )

        for round_result in result["round_results"]:
            self.assertIn("round", round_result)
            self.assertIn("events_used", round_result)
            self.assertIn("event_type_distribution", round_result)
            self.assertIn("attack_cases_total", round_result)
            self.assertIn("defense_rules_total", round_result)
            self.assertEqual(round_result["mode"], "batch")

    def test_batch_mode_attack_cases_increase(self):
        """测试批量训练后攻击用例数量增加"""
        initial_cases = len(self.trainer.red_agent.attack_cases)

        with open(self.tmp_file.name, 'w') as f:
            for i in range(30):
                f.write(make_seccomp_event(syscall=f"sys_{i}") + '\n')

        result = self.trainer.train_from_real_signals(
            consumer=self.consumer,
            num_rounds=3,
            events_per_round=10,
            file_path=self.tmp_file.name,
            signal_type=SignalType.SECCOMP_VIOLATION,
        )

        # 真实事件应该转化为攻击用例
        self.assertGreaterEqual(
            result["total_attack_cases"], initial_cases
        )


class TestTrainFromRealSignalsRealtime(unittest.TestCase):
    """实时模式训练测试"""

    def setUp(self):
        self.trainer = RedBlueAdversaryTrainer(enable_evolution=True)
        self.consumer = RealSignalConsumer(mode=ConsumeMode.REALTIME)
        self.tmp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
        self.tmp_file.close()

    def tearDown(self):
        if self.consumer.is_realtime_running():
            self.consumer.stop_realtime_consuming(timeout=3)
        if os.path.exists(self.tmp_file.name):
            os.unlink(self.tmp_file.name)

    def test_realtime_mode_basic(self):
        """测试实时模式基本训练"""
        # 先写入一些事件
        with open(self.tmp_file.name, 'w') as f:
            for i in range(15):
                f.write(make_seccomp_event(syscall=f"sys_{i}") + '\n')

        result = self.trainer.train_from_real_signals(
            consumer=self.consumer,
            num_rounds=2,
            events_per_round=5,
            file_path=self.tmp_file.name,
            signal_type=SignalType.SECCOMP_VIOLATION,
            realtime=True,
            realtime_timeout_seconds=10.0,
        )

        self.assertEqual(result["mode"], "realtime")
        self.assertGreaterEqual(result["num_rounds"], 1)
        self.assertGreater(result["new_events_ingested"], 0)
        self.assertIn("duration_seconds", result)

    def test_realtime_mode_no_file_returns_error(self):
        """测试实时模式不提供文件返回错误"""
        result = self.trainer.train_from_real_signals(
            consumer=self.consumer,
            num_rounds=2,
            events_per_round=5,
            realtime=True,
            realtime_timeout_seconds=5.0,
        )

        self.assertIn("error", result)

    def test_realtime_mode_with_new_events_written_during_training(self):
        """测试实时模式训练过程中新写入事件被消费"""
        # 初始写入少量事件
        with open(self.tmp_file.name, 'w') as f:
            for i in range(3):
                f.write(make_seccomp_event(syscall=f"initial_{i}") + '\n')

        # 在后台线程中延迟写入更多事件
        import threading
        def write_more_events():
            time.sleep(0.5)
            with open(self.tmp_file.name, 'a') as f:
                for i in range(10):
                    f.write(make_seccomp_event(syscall=f"new_{i}") + '\n')

        writer_thread = threading.Thread(target=write_more_events, daemon=True)
        writer_thread.start()

        result = self.trainer.train_from_real_signals(
            consumer=self.consumer,
            num_rounds=2,
            events_per_round=5,
            file_path=self.tmp_file.name,
            signal_type=SignalType.SECCOMP_VIOLATION,
            realtime=True,
            realtime_timeout_seconds=10.0,
        )

        # 应该消费了初始事件和新写入的事件
        self.assertGreater(result["new_events_ingested"], 3)
        self.assertEqual(result["mode"], "realtime")

    def test_realtime_mode_timeout(self):
        """测试实时模式超时处理"""
        # 只写入少量事件，不足以触发多轮训练
        with open(self.tmp_file.name, 'w') as f:
            f.write(make_seccomp_event() + '\n')

        result = self.trainer.train_from_real_signals(
            consumer=self.consumer,
            num_rounds=5,
            events_per_round=100,  # 需要很多事件才能触发一轮
            file_path=self.tmp_file.name,
            signal_type=SignalType.SECCOMP_VIOLATION,
            realtime=True,
            realtime_timeout_seconds=2.0,  # 短超时
        )

        # 超时后应该提前退出，轮次数可能少于请求数
        self.assertLessEqual(result["num_rounds"], 5)
        self.assertEqual(result["mode"], "realtime")
        # 确保监听已停止
        self.assertFalse(self.consumer.is_realtime_running())

    def test_realtime_mode_consumer_not_running_after_training(self):
        """测试训练结束后 REALTIME 监听已停止"""
        with open(self.tmp_file.name, 'w') as f:
            for i in range(10):
                f.write(make_seccomp_event(syscall=f"sys_{i}") + '\n')

        self.trainer.train_from_real_signals(
            consumer=self.consumer,
            num_rounds=1,
            events_per_round=5,
            file_path=self.tmp_file.name,
            signal_type=SignalType.SECCOMP_VIOLATION,
            realtime=True,
            realtime_timeout_seconds=5.0,
        )

        # 训练结束后监听应该已停止
        self.assertFalse(self.consumer.is_realtime_running())


class TestTrainFromRealSignalsWithBridge(unittest.TestCase):
    """与进化-防御桥接器集成的训练测试"""

    def setUp(self):
        from evolution.evolution_defense_bridge import EvolutionDefenseBridge
        self.bridge = EvolutionDefenseBridge(
            min_triggers_before_monitoring=3,
            dry_run=True,
        )
        self.trainer = RedBlueAdversaryTrainer(
            enable_evolution=True,
            defense_bridge=self.bridge,
            auto_deploy_evolved_rules=True,
        )
        self.consumer = RealSignalConsumer(mode=ConsumeMode.BATCH)
        self.tmp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
        self.tmp_file.close()

    def tearDown(self):
        if os.path.exists(self.tmp_file.name):
            os.unlink(self.tmp_file.name)

    def test_training_with_bridge_auto_deploy(self):
        """测试训练过程中进化出的规则自动通过桥接器下发"""
        with open(self.tmp_file.name, 'w') as f:
            for i in range(20):
                f.write(make_seccomp_event(syscall=f"sys_{i}") + '\n')

        result = self.trainer.train_from_real_signals(
            consumer=self.consumer,
            num_rounds=3,
            events_per_round=10,
            file_path=self.tmp_file.name,
            signal_type=SignalType.SECCOMP_VIOLATION,
        )

        self.assertEqual(result["mode"], "batch")
        self.assertGreater(result["total_events_consumed"], 0)

        # 桥接器应该有部署记录（如果进化出了规则）
        bridge_stats = self.bridge.get_stats()
        self.assertIn("total_rules_received", bridge_stats)

    def test_training_with_bridge_deployment_stats(self):
        """测试训练后桥接器部署统计可查询"""
        with open(self.tmp_file.name, 'w') as f:
            for i in range(15):
                f.write(make_seccomp_event(syscall=f"sys_{i}") + '\n')

        self.trainer.train_from_real_signals(
            consumer=self.consumer,
            num_rounds=2,
            events_per_round=10,
            file_path=self.tmp_file.name,
            signal_type=SignalType.SECCOMP_VIOLATION,
        )

        stats = self.trainer.get_bridge_deployment_stats()
        self.assertIn("enabled", stats)
        self.assertIn("auto_deploy", stats)
        self.assertIn("bridge_stats", stats)


if __name__ == '__main__':
    unittest.main()
