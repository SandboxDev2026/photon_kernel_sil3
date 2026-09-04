"""
真实信号消费器端到端测试

验证从真实格式日志（seccomp 违规/VM-Exit 统计）到红蓝对抗框架的完整链路：
真实格式日志 → 解析为 EscapeEvent → RealSignalConsumer 消费 → RedBlueAdversaryTrainer 摄入 → 触发攻防进化

这是框架从"模拟闭环"升级为"真实数据驱动"的核心验证。
"""

import json
import os
import tempfile
import time
import unittest

from evolution.real_signal_consumer import (
    ConsumeMode,
    EscapeEvent,
    NetworkVector,
    RealSignalConsumer,
    SeccompLogParser,
    SignalType,
    VMExitStatsParser,
)
from evolution.red_blue_adversary import RedBlueAdversaryTrainer


class TestSeccompLogParser(unittest.TestCase):
    """seccomp 违规日志解析器测试"""

    def setUp(self):
        self.parser = SeccompLogParser()

    def _make_seccomp_log(self, syscall="ptrace", action="KILL", pid=1234, comm="malware"):
        """生成真实格式的 seccomp 违规日志"""
        return {
            "event_id": f"seccomp_{int(time.time() * 1000)}",
            "event_type": "SECCOMP_VIOLATION",
            "timestamp": time.time(),
            "sandbox_id": "sandbox_001",
            "syscall": syscall,
            "syscall_num": 101,
            "pid": pid,
            "comm": comm,
            "arch": "x86_64",
            "action": action,
            "args": ["0x1", "0x2", "0x3"],
        }

    def test_parse_ptrace_violation(self):
        """测试解析 ptrace 违规（高危逃逸尝试）"""
        log = self._make_seccomp_log(syscall="ptrace", action="KILL")
        line = json.dumps(log)
        event = self.parser.parse_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.signal_type, SignalType.SECCOMP_VIOLATION)
        self.assertEqual(event.syscall, "ptrace")
        self.assertEqual(event.severity, "critical")
        self.assertTrue(self.parser.is_escape_attempt(event))

    def test_parse_mount_violation(self):
        """测试解析 mount 违规（高危）"""
        log = self._make_seccomp_log(syscall="mount", action="ERRNO")
        line = json.dumps(log)
        event = self.parser.parse_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.syscall, "mount")
        self.assertEqual(event.severity, "high")
        self.assertTrue(self.parser.is_escape_attempt(event))

    def test_parse_low_risk_syscall(self):
        """测试解析低风险系统调用"""
        log = self._make_seccomp_log(syscall="read", action="ERRNO")
        line = json.dumps(log)
        event = self.parser.parse_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.syscall, "read")
        self.assertEqual(event.severity, "medium")
        self.assertFalse(self.parser.is_escape_attempt(event))

    def test_parse_invalid_json(self):
        """测试解析无效 JSON"""
        event = self.parser.parse_line("not a json")
        self.assertIsNone(event)

    def test_parse_empty_line(self):
        """测试解析空行"""
        event = self.parser.parse_line("")
        self.assertIsNone(event)

    def test_parse_non_seccomp_event(self):
        """测试解析非 seccomp 事件"""
        log = {"event_type": "OTHER_EVENT", "data": "test"}
        event = self.parser.parse_line(json.dumps(log))
        self.assertIsNone(event)

    def test_escape_event_to_dict(self):
        """测试 EscapeEvent 序列化"""
        log = self._make_seccomp_log(syscall="ptrace")
        event = self.parser.parse_line(json.dumps(log))
        d = event.to_dict()

        self.assertEqual(d["signal_type"], "seccomp_violation")
        self.assertEqual(d["syscall"], "ptrace")
        self.assertIn("payload", d)

    def test_escape_event_to_security_event(self):
        """测试 EscapeEvent 转换为 SecurityEvent"""
        log = self._make_seccomp_log(syscall="ptrace")
        event = self.parser.parse_line(json.dumps(log))
        security_event = event.to_security_event()

        self.assertEqual(security_event.event_id, event.event_id)
        self.assertEqual(security_event.severity, "critical")


class TestVMExitStatsParser(unittest.TestCase):
    """KVM VM-Exit 事件统计解析器测试"""

    def setUp(self):
        self.parser = VMExitStatsParser()

    def _make_vmexit_log(self, exit_reason="VMCALL", vm_id="vm_001", vcpu_id=0):
        """生成真实格式的 VM-Exit 事件日志"""
        return {
            "event_id": f"vmexit_{int(time.time() * 1000)}",
            "event_type": "KVM_VM_EXIT",
            "timestamp": time.time(),
            "vm_id": vm_id,
            "vcpu_id": vcpu_id,
            "exit_reason": exit_reason,
            "guest_rip": "0xffff800000000000",
            "exit_qualification": "0x0",
            "instruction_length": 3,
        }

    def test_parse_vmcall_exit(self):
        """测试解析 VMCALL VM-Exit（临界逃逸信号）"""
        log = self._make_vmexit_log(exit_reason="VMCALL")
        event = self.parser.parse_line(json.dumps(log))

        self.assertIsNotNone(event)
        self.assertEqual(event.signal_type, SignalType.KVM_VM_EXIT)
        self.assertEqual(event.vm_exit_reason, "VMCALL")
        self.assertEqual(event.severity, "critical")
        self.assertTrue(self.parser.is_suspicious(event))

    def test_parse_msr_write_exit(self):
        """测试解析 MSR_WRITE VM-Exit（高危）"""
        log = self._make_vmexit_log(exit_reason="MSR_WRITE")
        event = self.parser.parse_line(json.dumps(log))

        self.assertIsNotNone(event)
        self.assertEqual(event.severity, "high")
        self.assertTrue(self.parser.is_suspicious(event))

    def test_parse_normal_exit(self):
        """测试解析普通 VM-Exit（低风险）"""
        log = self._make_vmexit_log(exit_reason="HLT")
        event = self.parser.parse_line(json.dumps(log))

        self.assertIsNotNone(event)
        self.assertEqual(event.severity, "low")
        self.assertFalse(self.parser.is_suspicious(event))

    def test_parse_triple_fault(self):
        """测试解析 TRIPLE_FAULT（临界）"""
        log = self._make_vmexit_log(exit_reason="TRIPLE_FAULT")
        event = self.parser.parse_line(json.dumps(log))

        self.assertIsNotNone(event)
        self.assertEqual(event.severity, "critical")

    def test_parse_invalid_json(self):
        """测试解析无效 JSON"""
        event = self.parser.parse_line("invalid")
        self.assertIsNone(event)


class TestRealSignalConsumer(unittest.TestCase):
    """真实信号消费器测试"""

    def setUp(self):
        self.consumer = RealSignalConsumer(mode=ConsumeMode.BATCH)

    def _make_seccomp_log_line(self, syscall="ptrace"):
        return json.dumps({
            "event_id": f"seccomp_{int(time.time() * 1000)}_{syscall}",
            "event_type": "SECCOMP_VIOLATION",
            "timestamp": time.time(),
            "sandbox_id": "sandbox_001",
            "syscall": syscall,
            "syscall_num": 101,
            "pid": 1234,
            "comm": "test",
            "arch": "x86_64",
            "action": "KILL",
            "args": [],
        })

    def test_consume_seccomp_line(self):
        """测试消费单行 seccomp 日志"""
        line = self._make_seccomp_log_line("ptrace")
        event = self.consumer.consume_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.signal_type, SignalType.SECCOMP_VIOLATION)
        self.assertEqual(self.consumer.stats["total_parsed"], 1)
        self.assertEqual(self.consumer.stats["seccomp_events"], 1)
        self.assertEqual(self.consumer.stats["escape_attempts"], 1)

    def test_consume_vmexit_line(self):
        """测试消费单行 VM-Exit 日志"""
        line = json.dumps({
            "event_id": f"vmexit_{int(time.time() * 1000)}",
            "event_type": "KVM_VM_EXIT",
            "timestamp": time.time(),
            "vm_id": "vm_001",
            "vcpu_id": 0,
            "exit_reason": "VMCALL",
            "guest_rip": "0x0",
        })
        event = self.consumer.consume_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.signal_type, SignalType.KVM_VM_EXIT)
        self.assertEqual(self.consumer.stats["vmexit_events"], 1)

    def test_consume_file(self):
        """测试消费日志文件"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            for i in range(5):
                f.write(self._make_seccomp_log_line(f"syscall_{i}") + "\n")
            filepath = f.name

        try:
            consumed = self.consumer.consume_file(filepath)
            self.assertEqual(consumed, 5)
            self.assertEqual(self.consumer.stats["total_parsed"], 5)
        finally:
            os.unlink(filepath)

    def test_dedup(self):
        """测试事件去重"""
        line = self._make_seccomp_log_line("ptrace")
        event1 = self.consumer.consume_line(line)
        event2 = self.consumer.consume_line(line)  # 重复事件

        self.assertIsNotNone(event1)
        self.assertIsNone(event2)  # 去重后返回 None
        self.assertEqual(self.consumer.stats["total_deduped"], 1)

    def test_callback(self):
        """测试单事件回调"""
        received_events = []
        self.consumer.register_callback(lambda e: received_events.append(e))

        line = self._make_seccomp_log_line("ptrace")
        self.consumer.consume_line(line)

        self.assertEqual(len(received_events), 1)
        self.assertEqual(received_events[0].syscall, "ptrace")

    def test_batch_callback(self):
        """测试批量回调"""
        received_batches = []
        self.consumer.register_batch_callback(lambda batch: received_batches.append(batch))

        for i in range(3):
            self.consumer.consume_line(self._make_seccomp_log_line(f"syscall_{i}"))

        # BATCH 模式下 consume_file 才会触发 flush，手动 flush
        self.consumer._flush_batch()

        self.assertEqual(len(received_batches), 1)
        self.assertEqual(len(received_batches[0]), 3)

    def test_consume_events(self):
        """测试消费事件字典列表"""
        events = [
            {"event_id": "evt_001", "event_type": "SECCOMP_VIOLATION", "syscall": "ptrace", "action": "KILL", "sandbox_id": "s1"},
            {"event_id": "evt_002", "event_type": "SECCOMP_VIOLATION", "syscall": "mount", "action": "ERRNO", "sandbox_id": "s2"},
        ]
        consumed = self.consumer.consume_events(events, SignalType.SECCOMP_VIOLATION)
        self.assertEqual(consumed, 2)

    def test_get_stats(self):
        """测试获取统计信息"""
        self.consumer.consume_line(self._make_seccomp_log_line("ptrace"))
        stats = self.consumer.get_stats()

        self.assertEqual(stats["total_parsed"], 1)
        self.assertEqual(stats["seccomp_events"], 1)
        self.assertEqual(stats["escape_attempts"], 1)

    def test_reset(self):
        """测试重置消费器"""
        self.consumer.consume_line(self._make_seccomp_log_line("ptrace"))
        self.consumer.reset()

        stats = self.consumer.get_stats()
        self.assertEqual(stats["total_parsed"], 0)


class TestEndToEndRealSignalPipeline(unittest.TestCase):
    """端到端真实信号链路测试

    验证完整链路：真实格式日志 → 解析为 EscapeEvent → RealSignalConsumer 消费
    → RedBlueAdversaryTrainer 摄入 → 触发攻防进化
    """

    def setUp(self):
        self.trainer = RedBlueAdversaryTrainer()
        self.consumer = RealSignalConsumer(mode=ConsumeMode.BATCH)
        # 连接消费器到训练器
        self.trainer.connect_real_signal_consumer(self.consumer)

    def _make_seccomp_log(self, syscall="ptrace", sandbox_id="sandbox_001"):
        return {
            "event_id": f"seccomp_{int(time.time() * 1000)}_{syscall}_{sandbox_id}",
            "event_type": "SECCOMP_VIOLATION",
            "timestamp": time.time(),
            "sandbox_id": sandbox_id,
            "syscall": syscall,
            "syscall_num": 101,
            "pid": 1234,
            "comm": "malware",
            "arch": "x86_64",
            "action": "KILL",
            "args": [],
        }

    def test_seccomp_signal_triggers_evolution(self):
        """测试 seccomp 违规信号触发红蓝对抗进化"""
        log = self._make_seccomp_log(syscall="ptrace")
        line = json.dumps(log)

        # 消费真实信号（通过回调自动注入训练器）
        event = self.consumer.consume_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.severity, "critical")

        # 验证训练器已摄入真实事件
        stats = self.trainer.get_real_signal_stats()
        self.assertEqual(stats["total_real_signals"], 1)
        self.assertEqual(stats["high_severity_signals"], 1)
        self.assertTrue(stats["is_connected_to_consumer"])

    def test_multiple_signals_ingest(self):
        """测试多个真实信号批量摄入"""
        logs = [
            self._make_seccomp_log("ptrace", "s1"),
            self._make_seccomp_log("mount", "s2"),
            self._make_seccomp_log("kexec_load", "s3"),
        ]

        for log in logs:
            self.consumer.consume_line(json.dumps(log))

        stats = self.trainer.get_real_signal_stats()
        self.assertEqual(stats["total_real_signals"], 3)
        self.assertEqual(stats["high_severity_signals"], 3)

    def test_ingest_escape_event_directly(self):
        """测试直接摄入 EscapeEvent"""
        escape_event = EscapeEvent(
            event_id="test_escape_001",
            signal_type=SignalType.SECCOMP_VIOLATION,
            timestamp=time.time(),
            sandbox_id="sandbox_001",
            severity="critical",
            description="test ptrace violation",
            payload={"syscall": "ptrace"},
            syscall="ptrace",
        )

        result = self.trainer.ingest_escape_event(escape_event)

        self.assertTrue(result["ingested"])
        self.assertTrue(result["is_real_signal"])
        self.assertEqual(result["signal_type"], "seccomp_violation")
        self.assertEqual(result["syscall"], "ptrace")

    def test_ingest_escape_events_batch(self):
        """测试批量摄入 EscapeEvent"""
        events = [
            EscapeEvent(
                event_id=f"test_{i}",
                signal_type=SignalType.SECCOMP_VIOLATION,
                timestamp=time.time(),
                sandbox_id=f"sandbox_{i}",
                severity="high",
                description=f"test violation {i}",
                payload={},
                syscall="mount",
            )
            for i in range(5)
        ]

        result = self.trainer.ingest_escape_events(events)
        self.assertEqual(result["total_ingested"], 5)
        self.assertEqual(result["high_severity"], 5)

    def test_vmexit_signal_pipeline(self):
        """测试 VM-Exit 信号完整链路"""
        vmexit_log = {
            "event_id": f"vmexit_{int(time.time() * 1000)}",
            "event_type": "KVM_VM_EXIT",
            "timestamp": time.time(),
            "vm_id": "vm_001",
            "vcpu_id": 0,
            "exit_reason": "VMCALL",
            "guest_rip": "0xffff800000000000",
        }

        event = self.consumer.consume_line(json.dumps(vmexit_log))

        self.assertIsNotNone(event)
        self.assertEqual(event.signal_type, SignalType.KVM_VM_EXIT)
        self.assertEqual(event.vm_exit_reason, "VMCALL")
        self.assertEqual(event.severity, "critical")

        stats = self.trainer.get_real_signal_stats()
        self.assertEqual(stats["total_real_signals"], 1)

    def test_real_signal_file_pipeline(self):
        """测试从日志文件到红蓝框架的完整文件管道"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            for i in range(10):
                syscall = ["ptrace", "mount", "kexec_load", "read", "write"][i % 5]
                f.write(json.dumps(self._make_seccomp_log(syscall, f"sandbox_{i}")) + "\n")
            filepath = f.name

        try:
            consumed = self.consumer.consume_file(filepath)
            self.assertEqual(consumed, 10)

            stats = self.trainer.get_real_signal_stats()
            self.assertEqual(stats["total_real_signals"], 10)
            # ptrace/mount/kexec_load 是高危，read/write 是中低危
            self.assertTrue(stats["high_severity_signals"] >= 6)
        finally:
            os.unlink(filepath)

    def test_network_vector_in_escape_event(self):
        """测试 EscapeEvent 中的网络五元组"""
        vector = NetworkVector(
            src_ip="10.0.0.1", src_port=12345,
            dst_ip="169.254.169.254", dst_port=80,
            protocol="tcp",
        )
        event = EscapeEvent(
            event_id="net_001",
            signal_type=SignalType.NETWORK_BLOCK,
            timestamp=time.time(),
            sandbox_id="sandbox_001",
            severity="high",
            description="metadata service access attempt",
            network_vector=vector,
        )

        d = event.to_dict()
        self.assertEqual(d["network_vector"]["dst_ip"], "169.254.169.254")
        self.assertEqual(d["network_vector"]["dst_port"], 80)

    def test_train_from_real_signals(self):
        """测试从真实信号训练（完整训练流程）"""
        # 先摄入一些真实信号
        for i in range(20):
            syscall = ["ptrace", "mount", "read"][i % 3]
            self.consumer.consume_line(json.dumps(self._make_seccomp_log(syscall, f"s_{i}")))

        # 执行真实信号驱动的训练
        result = self.trainer.train_from_real_signals(
            self.consumer, num_rounds=5, events_per_round=10
        )

        self.assertEqual(result["num_rounds"], 5)
        self.assertTrue(result["total_attack_cases"] > 0)
        self.assertEqual(len(result["round_results"]), 5)

    def test_real_signal_marks_in_result(self):
        """测试真实信号结果中的标记字段"""
        escape_event = EscapeEvent(
            event_id="mark_test_001",
            signal_type=SignalType.SECCOMP_VIOLATION,
            timestamp=time.time(),
            sandbox_id="s1",
            severity="critical",
            description="test",
            syscall="ptrace",
        )
        result = self.trainer.ingest_escape_event(escape_event)

        self.assertTrue(result["is_real_signal"])
        self.assertEqual(result["signal_type"], "seccomp_violation")
        self.assertIn("syscall", result)


if __name__ == '__main__':
    unittest.main()
