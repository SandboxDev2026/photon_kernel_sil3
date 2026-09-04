"""
RealSignalConsumer REALTIME 模式端到端测试

验证 tail -f 文件监听循环：
1. 启动监听 → 写入新行 → 自动消费
2. 文件旋转检测（截断/重新创建）
3. 停止监听
4. 从开头消费 vs 从末尾消费
5. 多信号类型自动检测
"""

import json
import os
import tempfile
import time
import unittest

from evolution.real_signal_consumer import ConsumeMode, RealSignalConsumer, SignalType


_event_counter = 0


def make_seccomp_event(syscall="ptrace", action="blocked", sandbox_id="sb_001"):
    """生成 seccomp 违规日志行（JSON 格式），带唯一 event_id"""
    global _event_counter
    _event_counter += 1
    return json.dumps({
        "event_id": f"seccomp_{_event_counter}_{int(time.time() * 1000000)}",
        "timestamp": time.time(),
        "sandbox_id": sandbox_id,
        "signal_type": "seccomp_violation",
        "syscall": syscall,
        "action": action,
        "pid": 12345,
        "comm": "malicious",
        "severity": "high",
    })


def make_vmexit_event(exit_reason="MSR_WRITE", sandbox_id="vm_001"):
    """生成 VM-Exit 事件日志行，带唯一 event_id"""
    global _event_counter
    _event_counter += 1
    return json.dumps({
        "event_id": f"vmexit_{_event_counter}_{int(time.time() * 1000000)}",
        "event_type": "VM_EXIT",
        "timestamp": time.time(),
        "sandbox_id": sandbox_id,
        "vm_id": sandbox_id,
        "signal_type": "vm_exit",
        "exit_reason": exit_reason,
        "exit_count": 5,
        "vcpu_id": 0,
        "severity": "medium",
    })


class TestRealtimeFileWatching(unittest.TestCase):
    """REALTIME 文件监听测试"""

    def setUp(self):
        self.consumer = RealSignalConsumer(mode=ConsumeMode.REALTIME)
        self.tmp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
        self.tmp_file.close()

    def tearDown(self):
        if self.consumer.is_realtime_running():
            self.consumer.stop_realtime_consuming(timeout=3)
        if os.path.exists(self.tmp_file.name):
            os.unlink(self.tmp_file.name)

    def test_start_stop_realtime(self):
        """测试启动和停止 REALTIME 监听"""
        result = self.consumer.start_realtime_consuming(self.tmp_file.name)
        self.assertTrue(result)
        self.assertTrue(self.consumer.is_realtime_running())

        status = self.consumer.get_realtime_status()
        self.assertTrue(status["running"])
        self.assertEqual(status["file_path"], self.tmp_file.name)

        stopped = self.consumer.stop_realtime_consuming(timeout=3)
        self.assertTrue(stopped)
        self.assertFalse(self.consumer.is_realtime_running())

    def test_start_twice_returns_false(self):
        """测试重复启动返回 False"""
        self.consumer.start_realtime_consuming(self.tmp_file.name)
        result = self.consumer.start_realtime_consuming(self.tmp_file.name)
        self.assertFalse(result)
        self.consumer.stop_realtime_consuming(timeout=3)

    def test_start_nonexistent_file(self):
        """测试启动不存在的文件"""
        result = self.consumer.start_realtime_consuming("/nonexistent/path/log.log")
        self.assertFalse(result)

    def test_consume_new_lines_realtime(self):
        """测试实时消费新写入的行"""
        consumed_events = []
        self.consumer.register_callback(lambda e: consumed_events.append(e))

        self.consumer.start_realtime_consuming(
            self.tmp_file.name,
            signal_type=SignalType.SECCOMP_VIOLATION,
            poll_interval=0.1,
        )

        # 等待监听启动
        time.sleep(0.3)

        # 写入新行
        with open(self.tmp_file.name, 'a') as f:
            f.write(make_seccomp_event(syscall="ptrace") + '\n')
            f.write(make_seccomp_event(syscall="mount") + '\n')
            f.flush()

        # 等待消费
        time.sleep(0.5)

        self.assertGreaterEqual(len(consumed_events), 2)
        self.consumer.stop_realtime_consuming(timeout=3)

    def test_consume_from_beginning(self):
        """测试从文件开头消费"""
        # 先写入一些行
        with open(self.tmp_file.name, 'w') as f:
            f.write(make_seccomp_event(syscall="ptrace") + '\n')
            f.write(make_seccomp_event(syscall="mount") + '\n')

        consumed_events = []
        self.consumer.register_callback(lambda e: consumed_events.append(e))

        # 从开头消费
        self.consumer.start_realtime_consuming(
            self.tmp_file.name,
            signal_type=SignalType.SECCOMP_VIOLATION,
            poll_interval=0.1,
            from_beginning=True,
        )

        time.sleep(0.5)

        self.assertGreaterEqual(len(consumed_events), 2)
        self.consumer.stop_realtime_consuming(timeout=3)

    def test_consume_from_end_skips_existing(self):
        """测试从末尾消费跳过已有行"""
        # 先写入一些行
        with open(self.tmp_file.name, 'w') as f:
            f.write(make_seccomp_event(syscall="ptrace") + '\n')
            f.write(make_seccomp_event(syscall="mount") + '\n')

        consumed_events = []
        self.consumer.register_callback(lambda e: consumed_events.append(e))

        # 从末尾消费（默认）
        self.consumer.start_realtime_consuming(
            self.tmp_file.name,
            signal_type=SignalType.SECCOMP_VIOLATION,
            poll_interval=0.1,
            from_beginning=False,
        )

        time.sleep(0.3)

        # 写入新行
        with open(self.tmp_file.name, 'a') as f:
            f.write(make_seccomp_event(syscall="unshare") + '\n')

        time.sleep(0.5)

        # 应该只消费了新写入的1行，跳过了已有的2行
        self.assertEqual(len(consumed_events), 1)
        self.consumer.stop_realtime_consuming(timeout=3)

    def test_file_truncation_detection(self):
        """测试文件截断检测（日志旋转）"""
        consumed_events = []
        self.consumer.register_callback(lambda e: consumed_events.append(e))

        self.consumer.start_realtime_consuming(
            self.tmp_file.name,
            signal_type=SignalType.SECCOMP_VIOLATION,
            poll_interval=0.1,
            from_beginning=True,
        )

        time.sleep(0.3)

        # 写入第一行
        with open(self.tmp_file.name, 'a') as f:
            f.write(make_seccomp_event(syscall="ptrace") + '\n')

        time.sleep(0.3)

        # 截断文件（模拟日志旋转）
        with open(self.tmp_file.name, 'w') as f:
            f.write(make_seccomp_event(syscall="mount") + '\n')

        # 等待事件消费（最多等待3秒，每0.1秒检查一次）
        for _ in range(30):
            if len(consumed_events) >= 2:
                break
            time.sleep(0.1)

        # 应该消费了2行（截断前1行 + 截断后1行）
        self.assertGreaterEqual(len(consumed_events), 2)
        self.consumer.stop_realtime_consuming(timeout=3)

    def test_auto_detect_signal_type(self):
        """测试自动检测信号类型（seccomp vs vm_exit）"""
        consumed_events = []
        self.consumer.register_callback(lambda e: consumed_events.append(e))

        self.consumer.start_realtime_consuming(
            self.tmp_file.name,
            signal_type=None,  # 自动检测
            poll_interval=0.1,
            from_beginning=True,
        )

        time.sleep(0.3)

        # 写入两种不同类型的事件
        with open(self.tmp_file.name, 'a') as f:
            f.write(make_seccomp_event(syscall="ptrace") + '\n')
            f.write(make_vmexit_event(exit_reason="MSR_WRITE") + '\n')

        time.sleep(0.5)

        self.assertGreaterEqual(len(consumed_events), 2)
        self.consumer.stop_realtime_consuming(timeout=3)

    def test_realtime_status(self):
        """测试获取 REALTIME 状态"""
        self.consumer.start_realtime_consuming(
            self.tmp_file.name,
            signal_type=SignalType.SECCOMP_VIOLATION,
            poll_interval=0.1,
        )

        time.sleep(0.2)

        status = self.consumer.get_realtime_status()
        self.assertTrue(status["running"])
        self.assertEqual(status["signal_type"], "seccomp_violation")
        self.assertEqual(status["poll_interval"], 0.1)
        self.assertTrue(status["thread_alive"])
        self.assertGreaterEqual(status["file_position"], 0)

        self.consumer.stop_realtime_consuming(timeout=3)

    def test_stop_not_running_returns_false(self):
        """测试停止未运行的监听返回 False"""
        result = self.consumer.stop_realtime_consuming()
        self.assertFalse(result)

    def test_realtime_lines_consumed_counter(self):
        """测试实时消费行数计数器"""
        self.consumer.start_realtime_consuming(
            self.tmp_file.name,
            signal_type=SignalType.SECCOMP_VIOLATION,
            poll_interval=0.1,
            from_beginning=True,
        )

        time.sleep(0.3)

        with open(self.tmp_file.name, 'a') as f:
            for i in range(5):
                f.write(make_seccomp_event(syscall=f"syscall_{i}") + '\n')

        time.sleep(0.5)

        status = self.consumer.get_realtime_status()
        self.assertGreaterEqual(status["lines_consumed"], 5)

        self.consumer.stop_realtime_consuming(timeout=3)

    def test_realtime_with_batch_callback(self):
        """测试 REALTIME 模式下批量回调"""
        batch_events = []
        self.consumer.register_batch_callback(lambda events: batch_events.extend(events))

        # 使用小批量大小以便快速触发
        consumer = RealSignalConsumer(
            mode=ConsumeMode.REALTIME,
            batch_size=3,
            batch_interval_seconds=1.0,
        )
        consumer.register_batch_callback(lambda events: batch_events.extend(events))

        consumer.start_realtime_consuming(
            self.tmp_file.name,
            signal_type=SignalType.SECCOMP_VIOLATION,
            poll_interval=0.1,
            from_beginning=True,
        )

        time.sleep(0.3)

        with open(self.tmp_file.name, 'a') as f:
            for i in range(5):
                f.write(make_seccomp_event(syscall=f"sys_{i}") + '\n')

        time.sleep(0.5)

        # 批量回调应该被触发（至少3个事件一批）
        self.assertGreaterEqual(len(batch_events), 3)

        consumer.stop_realtime_consuming(timeout=3)


class TestRealtimeIntegrationWithTrainer(unittest.TestCase):
    """REALTIME 模式与红蓝对抗训练器集成测试"""

    def setUp(self):
        self.consumer = RealSignalConsumer(mode=ConsumeMode.REALTIME)
        self.tmp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
        self.tmp_file.close()

    def tearDown(self):
        if self.consumer.is_realtime_running():
            self.consumer.stop_realtime_consuming(timeout=3)
        if os.path.exists(self.tmp_file.name):
            os.unlink(self.tmp_file.name)

    def test_realtime_events_trigger_trainer(self):
        """测试实时事件触发红蓝对抗训练"""
        from evolution.red_blue_adversary import RedBlueAdversaryTrainer

        trainer = RedBlueAdversaryTrainer(enable_evolution=True)
        trainer.connect_real_signal_consumer(self.consumer)

        self.consumer.start_realtime_consuming(
            self.tmp_file.name,
            signal_type=SignalType.SECCOMP_VIOLATION,
            poll_interval=0.1,
            from_beginning=True,
        )

        time.sleep(0.3)

        # 写入高风险事件
        with open(self.tmp_file.name, 'a') as f:
            f.write(make_seccomp_event(syscall="ptrace", action="blocked") + '\n')
            f.write(make_seccomp_event(syscall="mount", action="blocked") + '\n')

        time.sleep(0.5)

        # 训练器应该消费了事件
        stats = trainer.get_real_signal_stats()
        self.assertGreaterEqual(stats.get("total_real_signals", 0), 2)

        self.consumer.stop_realtime_consuming(timeout=3)


if __name__ == '__main__':
    unittest.main()
