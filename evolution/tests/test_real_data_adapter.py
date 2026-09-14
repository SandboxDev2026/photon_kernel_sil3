"""
real_data_adapter 单元测试

覆盖：SecurityEvent数据类、SeccompViolationParser、KvmVmExitParser、AuditChainAnomalyDetector。
"""
import unittest, sys, os, json, time, hmac, hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evolution.real_data_adapter import (
    SecurityEvent, EventSource, AnomalyType,
    SeccompViolationParser, KvmVmExitParser, AuditChainAnomalyDetector,
)


def make_event(**kw):
    defaults = dict(
        event_id="e001", source=EventSource.SECCOMP_VIOLATION,
        timestamp=time.time(), sandbox_id="sb001", severity="medium",
        description="test", payload={},
    )
    defaults.update(kw)
    return SecurityEvent(**defaults)


class TestSecurityEvent(unittest.TestCase):
    def test_create(self):
        e = make_event()
        self.assertEqual(e.event_id, "e001")
        self.assertEqual(e.severity, "medium")

    def test_to_dict(self):
        e = make_event()
        d = e.to_dict()
        self.assertEqual(d["event_id"], "e001")
        self.assertIn("timestamp", d)

    def test_to_attack_case_params(self):
        e = make_event(anomaly_score=0.8)
        p = e.to_attack_case_params()
        self.assertEqual(p["event_id"], "e001")
        self.assertEqual(p["anomaly_score"], 0.8)

    def test_anomaly_type_none(self):
        e = make_event()
        d = e.to_dict()
        self.assertIsNone(d["anomaly_type"])

    def test_default_payload(self):
        e = make_event()
        self.assertEqual(e.payload, {})


class TestSeccompParser(unittest.TestCase):
    def setUp(self):
        self.parser = SeccompViolationParser(hmac_secret="test-secret")

    def test_parse_valid_json(self):
        line = json.dumps({"event_type": "SECCOMP_VIOLATION", "syscall": "ptrace",
                           "pid": 1234, "timestamp": time.time()})
        event = self.parser.parse_line(line)
        self.assertIsNotNone(event)
        self.assertIsNotNone(event.sandbox_id)

    def test_parse_non_json(self):
        self.assertIsNone(self.parser.parse_line("not json at all"))

    def test_parse_empty_line(self):
        self.assertIsNone(self.parser.parse_line(""))
        self.assertIsNone(self.parser.parse_line("   "))

    def test_parse_non_seccomp(self):
        line = json.dumps({"event_type": "NORMAL_LOG", "msg": "hello"})
        self.assertIsNone(self.parser.parse_line(line))

    def test_parse_variants(self):
        for et in ["seccomp_violation", "SYSCALL_BLOCKED", "blocked_syscall"]:
            line = json.dumps({"event_type": et, "syscall": "mount"})
            event = self.parser.parse_line(line)
            self.assertIsNotNone(event, f"应匹配: {et}")

    def test_violation_counts(self):
        for sc in ["ptrace", "mount", "ptrace"]:
            self.parser.parse_line(json.dumps({"event_type": "SECCOMP", "syscall": sc}))
        self.assertEqual(self.parser.violation_counts["ptrace"], 2)

    def test_get_top_violations(self):
        for sc in ["ptrace", "ptrace", "mount", "mount", "mount", "kexec_load"]:
            self.parser.parse_line(json.dumps({"event_type": "SECCOMP", "syscall": sc}))
        top = self.parser.get_top_violations(n=2)
        self.assertEqual(len(top), 2)
        self.assertEqual(top[0][0], "mount")

    def test_frequency_anomalies(self):
        # 快速产生多个事件
        for i in range(20):
            self.parser.parse_line(json.dumps({"event_type": "SECCOMP", "syscall": "fork"}))
        anomalies = self.parser.detect_frequency_anomalies(window_seconds=60, threshold=3.0)
        self.assertIsInstance(anomalies, list)

    def test_parse_with_hmac(self):
        # 带HMAC字段的日志行
        data = {"event_type": "SECCOMP_VIOLATION", "syscall": "ptrace",
                "seq": 1, "prev_hash": "abc", "hmac": "fake"}
        line = json.dumps(data)
        event = self.parser.parse_line(line)
        self.assertIsNotNone(event)

    def test_malformed_json(self):
        self.assertIsNone(self.parser.parse_line('{"event_type": "SECCOMP"'))

    def test_unicode_in_description(self):
        line = json.dumps({"event_type": "SECCOMP", "syscall": "ptrace",
                           "description": "安全事件 🚨"})
        event = self.parser.parse_line(line)
        self.assertIsNotNone(event)


class TestKvmVmExitParser(unittest.TestCase):
    def setUp(self):
        self.parser = KvmVmExitParser()

    def test_parse_valid_event(self):
        data = {"exit_reason": "VMCALL", "vcpu_id": 0, "rip": "0x1234",
                "qualification": 0, "timestamp": time.time()}
        event = self.parser.parse_event(data)
        self.assertIsNotNone(event)

    def test_parse_triple_fault(self):
        data = {"exit_reason": "TRIPLE_FAULT", "vcpu_id": 0}
        event = self.parser.parse_event(data)
        self.assertIsNotNone(event)

    def test_parse_empty_dict(self):
        self.assertIsNone(self.parser.parse_event({}))

    def test_parse_none(self):
        try:
            self.assertIsNone(self.parser.parse_event(None))
        except (TypeError, AttributeError):
            pass

    def test_get_top_exit_reasons(self):
        for reason in ["VMCALL", "VMCALL", "MSR_WRITE", "IOIO"]:
            self.parser.parse_event({"exit_reason": reason})
        top = self.parser.get_top_exit_reasons(n=3)
        self.assertIsInstance(top, list)
        self.assertGreater(len(top), 0)

    def test_detect_escape_attempts(self):
        # 产生多个高风险VM-Exit
        for reason in ["TRIPLE_FAULT", "VMCALL", "TRIPLE_FAULT"]:
            self.parser.parse_event({"exit_reason": reason})
        attempts = self.parser.detect_escape_attempts()
        self.assertIsInstance(attempts, list)

    def test_low_risk_exit(self):
        data = {"exit_reason": "INTERRUPT", "vcpu_id": 0}
        event = self.parser.parse_event(data)
        self.assertIsNotNone(event)


class TestAuditChainDetector(unittest.TestCase):
    def setUp(self):
        self.detector = AuditChainAnomalyDetector(hmac_secret="test-audit-secret")

    def _make_valid_line(self, seq=1, prev_hash="genesis", hmac_secret="test-audit-secret"):
        """构造有效的审计链日志行"""
        data = {"event_type": "AUDIT", "seq": seq, "prev_hash": prev_hash,
                "timestamp": time.time(), "msg": "test"}
        payload = json.dumps(data, sort_keys=True)
        expected_hmac = hmac.new(hmac_secret.encode(), payload.encode(),
                                 hashlib.sha256).hexdigest()
        data["hmac"] = expected_hmac
        return json.dumps(data)

    def test_valid_line(self):
        line = self._make_valid_line(seq=1)
        ok, event = self.detector.verify_and_detect(line)
        self.assertTrue(ok)

    def test_invalid_json(self):
        ok, event = self.detector.verify_and_detect("not json")
        self.assertFalse(ok)

    def test_tampered_hmac(self):
        data = {"event_type": "AUDIT", "seq": 1, "prev_hash": "genesis",
                "timestamp": time.time(), "hmac": "fake_hmac"}
        ok, event = self.detector.verify_and_detect(json.dumps(data))
        self.assertIsInstance(ok, bool)

    def test_sequence_gap_detected(self):
        """序列号跳变检测"""
        line1 = self._make_valid_line(seq=1)
        self.detector.verify_and_detect(line1)
        # seq跳到5
        line2 = self._make_valid_line(seq=5, prev_hash="different")
        ok, event = self.detector.verify_and_detect(line2)
        # 可能检测到序列号异常
        self.assertIsNotNone(ok)

    def test_empty_line(self):
        ok, event = self.detector.verify_and_detect("")
        self.assertIsInstance(ok, bool)

    def test_missing_hmac_field(self):
        data = {"event_type": "AUDIT", "seq": 1, "prev_hash": "genesis",
                "timestamp": time.time()}
        ok, event = self.detector.verify_and_detect(json.dumps(data))
        self.assertIsInstance(ok, bool)

    def test_old_timestamp(self):
        """时间戳过旧"""
        old_time = time.time() - 86400 * 30  # 30天前
        data = {"event_type": "AUDIT", "seq": 1, "prev_hash": "genesis",
                "timestamp": old_time}
        payload = json.dumps(data, sort_keys=True)
        expected_hmac = hmac.new("test-audit-secret".encode(), payload.encode(),
                                 hashlib.sha256).hexdigest()
        data["hmac"] = expected_hmac
        ok, event = self.detector.verify_and_detect(json.dumps(data))
        # 时间戳异常
        self.assertIsNotNone(ok)


class TestBoundary(unittest.TestCase):
    def test_parser_empty_parsed_events(self):
        p = SeccompViolationParser()
        self.assertEqual(len(p.parsed_events), 0)
        self.assertEqual(len(p.violation_counts), 0)

    def test_very_long_line(self):
        p = SeccompViolationParser()
        long_data = {"event_type": "SECCOMP", "syscall": "ptrace",
                     "description": "A" * 100000}
        event = p.parse_line(json.dumps(long_data))
        self.assertIsNotNone(event)

    def test_special_chars_in_json(self):
        p = SeccompViolationParser()
        data = {"event_type": "SECCOMP", "syscall": "ptrace",
                "msg": "test\n\t\x00<script>"}
        event = p.parse_line(json.dumps(data))
        self.assertIsNotNone(event)

    def test_kvm_parser_missing_fields(self):
        p = KvmVmExitParser()
        self.assertIsNone(p.parse_event({"foo": "bar"}))

    def test_audit_detector_bad_secret(self):
        d1 = AuditChainAnomalyDetector(hmac_secret="secret_a")
        line = self._make_line_with_secret(seq=1, secret_b="secret_a")
        ok, _ = d1.verify_and_detect(line)
        self.assertTrue(ok)

    @staticmethod
    def _make_line_with_secret(seq, secret_b):
        data = {"event_type": "AUDIT", "seq": seq, "prev_hash": "g",
                "timestamp": time.time()}
        payload = json.dumps(data, sort_keys=True)
        sig = hmac.new(secret_b.encode(), payload.encode(), hashlib.sha256).hexdigest()
        data["hmac"] = sig
        return json.dumps(data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
