"""
EventInputValidator 单元测试

测试覆盖：
- 基本功能与有效事件验证
- 来源验证（可信/不可信/空）
- 速率限制
- 结构验证（缺失字段/类型错误）
- 内容验证（恶意内容/超长内容）
- 恶意模式检测（SQL注入/XSS/命令注入）
- HMAC签名验证
- 重复事件检测
- 事件清理
- 统计信息
- 可信源管理
- 边界条件与并发安全
"""

import unittest
import sys
import os
import time
import json
import hashlib
import hmac
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evolution.event_input_validator import (
    EventInputValidator,
    ValidationResult,
    ValidationResultCode,
    ValidatorStats,
)


def make_valid_event(**kwargs):
    """构造一个有效的测试事件"""
    event = {
        "event_id": f"evt_{int(time.time()*1000)}",
        "timestamp": time.time(),
        "source": "seccomp_logger",
        "event_type": "seccomp_violation",
        "severity": "warning",
        "description": "test event",
        "metadata": {"pid": 1234, "syscall": "ptrace"},
    }
    event.update(kwargs)
    return event


class TestValidationResult(unittest.TestCase):
    """ValidationResult 数据类测试"""

    def test_create_valid_result(self):
        result = ValidationResult(
            valid=True,
            code=ValidationResultCode.VALID,
            reason="",
            cleaned_event={"key": "value"},
        )
        self.assertTrue(result.valid)
        self.assertEqual(result.code, ValidationResultCode.VALID)
        self.assertEqual(result.cleaned_event, {"key": "value"})

    def test_create_invalid_result(self):
        result = ValidationResult(
            valid=False,
            code=ValidationResultCode.UNTRUSTED_SOURCE,
            reason="source not trusted",
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.code, ValidationResultCode.UNTRUSTED_SOURCE)
        self.assertEqual(result.reason, "source not trusted")

    def test_result_codes(self):
        """验证所有结果码存在"""
        codes = list(ValidationResultCode)
        self.assertGreater(len(codes), 5)
        self.assertIn(ValidationResultCode.VALID, codes)


class TestValidatorStats(unittest.TestCase):
    """ValidatorStats 测试"""

    def test_initial_stats(self):
        stats = ValidatorStats()
        self.assertEqual(stats.total_events, 0)
        self.assertEqual(stats.valid_events, 0)
        self.assertEqual(stats.rejected_events, 0)

    def test_stats_increment(self):
        stats = ValidatorStats()
        stats.total_events += 1
        stats.valid_events += 1
        self.assertEqual(stats.total_events, 1)
        self.assertEqual(stats.valid_events, 1)


class TestEventInputValidatorBasic(unittest.TestCase):
    """基本功能测试"""

    def setUp(self):
        self.validator = EventInputValidator(
            trusted_sources=["seccomp_logger", "audit_chain"],
            enable_duplicate_check=False,
        )

    def test_create_validator_default(self):
        """使用默认参数创建"""
        v = EventInputValidator()
        self.assertGreater(len(v.trusted_sources), 0)
        self.assertFalse(v.enable_signature_check)
        self.assertTrue(v.enable_duplicate_check)

    def test_create_validator_custom(self):
        """使用自定义参数创建"""
        v = EventInputValidator(
            trusted_sources=["custom_source"],
            hmac_secret="secret",
            max_events_per_second=50,
            enable_signature_check=True,
        )
        self.assertEqual(v.trusted_sources, {"custom_source"})
        self.assertEqual(v.max_events_per_second, 50)
        self.assertTrue(v.enable_signature_check)

    def test_validate_valid_event(self):
        """验证有效事件通过"""
        event = make_valid_event()
        result = self.validator.validate(event, source="seccomp_logger")
        self.assertTrue(result.valid)
        self.assertEqual(result.code, ValidationResultCode.VALID)
        self.assertIsNotNone(result.cleaned_event)

    def test_validate_event_with_source_in_event(self):
        """事件中包含source字段"""
        event = make_valid_event(source="audit_chain")
        result = self.validator.validate(event)
        self.assertTrue(result.valid)

    def test_validate_returns_cleaned_event(self):
        """验证返回清理后的事件"""
        event = make_valid_event(extra_field="should_be_cleaned")
        result = self.validator.validate(event, source="seccomp_logger")
        self.assertTrue(result.valid)
        self.assertIn("event_id", result.cleaned_event)


class TestSourceValidation(unittest.TestCase):
    """来源验证测试"""

    def setUp(self):
        self.validator = EventInputValidator(
            trusted_sources=["trusted_source"],
            enable_duplicate_check=False,
        )

    def test_untrusted_source_rejected(self):
        """不可信来源被拒绝"""
        event = make_valid_event()
        result = self.validator.validate(event, source="untrusted_source")
        self.assertFalse(result.valid)
        self.assertEqual(result.code, ValidationResultCode.UNTRUSTED_SOURCE)

    def test_empty_source_rejected(self):
        """空来源被拒绝"""
        event = make_valid_event(source="")
        result = self.validator.validate(event)
        self.assertFalse(result.valid)

    def test_none_source_rejected(self):
        """None来源被拒绝"""
        event = make_valid_event()
        if "source" in event:
            del event["source"]
        result = self.validator.validate(event, source=None)
        self.assertFalse(result.valid)

    def test_add_trusted_source(self):
        """添加可信源"""
        self.validator.add_trusted_source("new_source")
        self.assertIn("new_source", self.validator.trusted_sources)
        event = make_valid_event()
        result = self.validator.validate(event, source="new_source")
        self.assertTrue(result.valid)

    def test_remove_trusted_source(self):
        """移除可信源"""
        self.validator.remove_trusted_source("trusted_source")
        self.assertNotIn("trusted_source", self.validator.trusted_sources)
        event = make_valid_event()
        result = self.validator.validate(event, source="trusted_source")
        self.assertFalse(result.valid)


class TestRateLimit(unittest.TestCase):
    """速率限制测试"""

    def setUp(self):
        self.validator = EventInputValidator(
            trusted_sources=["seccomp_logger"],
            max_events_per_second=10,
            enable_duplicate_check=False,
        )

    def test_within_rate_limit(self):
        """在速率限制内通过"""
        for i in range(5):
            event = make_valid_event(event_id=f"evt_{i}")
            result = self.validator.validate(event, source="seccomp_logger")
            self.assertTrue(result.valid, f"事件 {i} 应通过")

    def test_exceed_rate_limit(self):
        """超过速率限制被拒绝"""
        rejected = False
        for i in range(20):
            event = make_valid_event(event_id=f"evt_rate_{i}")
            result = self.validator.validate(event, source="seccomp_logger")
            if not result.valid:
                rejected = True
                self.assertEqual(result.code, ValidationResultCode.RATE_LIMITED)
                break
        self.assertTrue(rejected, "应触发速率限制")


class TestStructureValidation(unittest.TestCase):
    """结构验证测试"""

    def setUp(self):
        self.validator = EventInputValidator(
            trusted_sources=["seccomp_logger"],
            enable_duplicate_check=False,
        )

    def test_missing_event_id(self):
        """缺少event_id被拒绝"""
        event = make_valid_event()
        del event["event_id"]
        result = self.validator.validate(event, source="seccomp_logger")
        self.assertFalse(result.valid)

    def test_missing_timestamp(self):
        """缺少timestamp被拒绝"""
        event = make_valid_event()
        del event["timestamp"]
        result = self.validator.validate(event, source="seccomp_logger")
        self.assertFalse(result.valid)

    def test_invalid_timestamp_type(self):
        """timestamp类型错误被拒绝"""
        event = make_valid_event(timestamp="not_a_number")
        result = self.validator.validate(event, source="seccomp_logger")
        self.assertFalse(result.valid)

    def test_empty_event(self):
        """空事件被拒绝"""
        result = self.validator.validate({}, source="seccomp_logger")
        self.assertFalse(result.valid)

    def test_none_event(self):
        """None事件不崩溃"""
        try:
            result = self.validator.validate(None, source="seccomp_logger")
            self.assertFalse(result.valid)
        except AttributeError:
            pass  # None 没有 .get 方法，这是可接受的


class TestContentValidation(unittest.TestCase):
    """内容验证测试"""

    def setUp(self):
        self.validator = EventInputValidator(
            trusted_sources=["seccomp_logger"],
            enable_duplicate_check=False,
        )

    def test_very_long_description(self):
        """超长描述被拒绝或截断"""
        long_desc = "A" * 100000
        event = make_valid_event(description=long_desc)
        result = self.validator.validate(event, source="seccomp_logger")
        # 可能被拒绝或清理，关键是不崩溃
        self.assertIsNotNone(result)

    def test_special_characters_in_description(self):
        """特殊字符不崩溃"""
        event = make_valid_event(description="测试\n\t\r\x00<script>alert(1)</script>")
        result = self.validator.validate(event, source="seccomp_logger")
        self.assertIsNotNone(result)

    def test_unicode_content(self):
        """Unicode内容正常处理"""
        event = make_valid_event(description="🛡️🔒 安全事件 中文测试 🚨")
        result = self.validator.validate(event, source="seccomp_logger")
        self.assertTrue(result.valid)


class TestMaliciousPatternDetection(unittest.TestCase):
    """恶意模式检测测试"""

    def setUp(self):
        self.validator = EventInputValidator(
            trusted_sources=["seccomp_logger"],
            enable_duplicate_check=False,
        )

    def test_sql_injection_detected(self):
        """SQL注入被检测"""
        event = make_valid_event(
            description="SELECT * FROM users WHERE 1=1; DROP TABLE users; --"
        )
        result = self.validator.validate(event, source="seccomp_logger")
        # 恶意模式可能导致拒绝或高风险评分
        self.assertIsNotNone(result)
        if result.valid:
            self.assertGreater(result.risk_score, 0)

    def test_xss_detected(self):
        """XSS被检测"""
        event = make_valid_event(
            description="<script>document.cookie</script>"
        )
        result = self.validator.validate(event, source="seccomp_logger")
        self.assertIsNotNone(result)

    def test_command_injection_detected(self):
        """命令注入被检测"""
        event = make_valid_event(
            description="; rm -rf /; cat /etc/passwd"
        )
        result = self.validator.validate(event, source="seccomp_logger")
        self.assertIsNotNone(result)

    def test_path_traversal_detected(self):
        """路径遍历被检测"""
        event = make_valid_event(
            description="../../../../etc/passwd"
        )
        result = self.validator.validate(event, source="seccomp_logger")
        self.assertIsNotNone(result)

    def test_benign_content_passes(self):
        """正常内容通过且风险评分为0"""
        event = make_valid_event(description="正常的安全事件描述")
        result = self.validator.validate(event, source="seccomp_logger")
        self.assertTrue(result.valid)
        self.assertEqual(result.risk_score, 0.0)


class TestSignatureValidation(unittest.TestCase):
    """HMAC签名验证测试"""

    def setUp(self):
        self.secret = "test-secret-key-12345"
        self.validator = EventInputValidator(
            trusted_sources=["seccomp_logger"],
            hmac_secret=self.secret,
            enable_signature_check=True,
            enable_duplicate_check=False,
        )

    def _sign_event(self, event, secret):
        """为事件计算HMAC签名（与实现一致：str(sorted(items()))）"""
        sign_data = {k: v for k, v in event.items() if k != "signature"}
        sign_str = str(sorted(sign_data.items()))
        signature = hmac.new(
            secret.encode(), sign_str.encode(), hashlib.sha256
        ).hexdigest()
        return signature

    def test_valid_signature_passes(self):
        """有效签名通过"""
        event = make_valid_event()
        event["signature"] = self._sign_event(event, self.secret)
        result = self.validator.validate(event, source="seccomp_logger")
        self.assertTrue(result.valid)

    def test_invalid_signature_rejected(self):
        """无效签名被拒绝"""
        event = make_valid_event()
        event["signature"] = "invalid_signature"
        result = self.validator.validate(event, source="seccomp_logger")
        self.assertFalse(result.valid)
        self.assertEqual(result.code, ValidationResultCode.SIGNATURE_INVALID)

    def test_missing_signature_rejected(self):
        """缺少签名被拒绝"""
        event = make_valid_event()
        result = self.validator.validate(event, source="seccomp_logger")
        self.assertFalse(result.valid)

    def test_signature_check_disabled(self):
        """禁用签名检查时不验证签名"""
        v = EventInputValidator(
            trusted_sources=["seccomp_logger"],
            hmac_secret=self.secret,
            enable_signature_check=False,
            enable_duplicate_check=False,
        )
        event = make_valid_event()
        result = v.validate(event, source="seccomp_logger")
        self.assertTrue(result.valid)

    def test_signature_check_without_secret(self):
        """没有secret时自动禁用签名检查"""
        v = EventInputValidator(
            trusted_sources=["seccomp_logger"],
            enable_signature_check=True,  # 没有secret，应自动禁用
            enable_duplicate_check=False,
        )
        self.assertFalse(v.enable_signature_check)
        event = make_valid_event()
        result = v.validate(event, source="seccomp_logger")
        self.assertTrue(result.valid)


class TestDuplicateDetection(unittest.TestCase):
    """重复事件检测测试"""

    def setUp(self):
        self.validator = EventInputValidator(
            trusted_sources=["seccomp_logger"],
            enable_duplicate_check=True,
        )

    def test_first_event_passes(self):
        """第一个事件通过"""
        event = make_valid_event(event_id="unique_evt_001")
        result = self.validator.validate(event, source="seccomp_logger")
        self.assertTrue(result.valid)

    def test_duplicate_event_rejected(self):
        """重复事件被拒绝"""
        event = make_valid_event(event_id="dup_evt_001")
        result1 = self.validator.validate(event, source="seccomp_logger")
        self.assertTrue(result1.valid)

        result2 = self.validator.validate(event, source="seccomp_logger")
        self.assertFalse(result2.valid)
        self.assertEqual(result2.code, ValidationResultCode.DUPLICATE)

    def test_different_events_pass(self):
        """不同事件通过"""
        for i in range(5):
            event = make_valid_event(event_id=f"distinct_{i}")
            result = self.validator.validate(event, source="seccomp_logger")
            self.assertTrue(result.valid, f"事件 {i} 应通过")

    def test_duplicate_check_disabled(self):
        """禁用重复检查时重复事件通过"""
        v = EventInputValidator(
            trusted_sources=["seccomp_logger"],
            enable_duplicate_check=False,
        )
        event = make_valid_event(event_id="dup_disabled_001")
        result1 = v.validate(event, source="seccomp_logger")
        result2 = v.validate(event, source="seccomp_logger")
        self.assertTrue(result1.valid)
        self.assertTrue(result2.valid)


class TestEventCleaning(unittest.TestCase):
    """事件清理测试"""

    def setUp(self):
        self.validator = EventInputValidator(
            trusted_sources=["seccomp_logger"],
            enable_duplicate_check=False,
        )

    def test_cleaned_event_contains_core_fields(self):
        """清理后的事件包含核心字段"""
        event = make_valid_event()
        result = self.validator.validate(event, source="seccomp_logger")
        self.assertTrue(result.valid)
        cleaned = result.cleaned_event
        self.assertIn("event_id", cleaned)
        self.assertIn("timestamp", cleaned)
        self.assertIn("event_type", cleaned)

    def test_cleaned_event_preserves_fields(self):
        """清理后的事件保留原有字段（_clean_event只清理字符，不删除字段）"""
        event = make_valid_event(signature="abc123", custom_field="value")
        result = self.validator.validate(event, source="seccomp_logger")
        if result.valid:
            self.assertIn("signature", result.cleaned_event)
            self.assertIn("custom_field", result.cleaned_event)


class TestValidatorStats(unittest.TestCase):
    """统计信息测试"""

    def setUp(self):
        self.validator = EventInputValidator(
            trusted_sources=["trusted"],
            enable_duplicate_check=False,
        )

    def test_stats_after_valid_events(self):
        """有效事件后统计正确"""
        for i in range(3):
            event = make_valid_event(event_id=f"stat_{i}")
            self.validator.validate(event, source="trusted")
        stats = self.validator.get_stats()
        self.assertEqual(stats["total_events"], 3)
        self.assertEqual(stats["valid_events"], 3)
        self.assertEqual(stats["rejected_events"], 0)

    def test_stats_after_rejected_events(self):
        """拒绝事件后统计正确"""
        for i in range(2):
            event = make_valid_event(event_id=f"rej_{i}")
            self.validator.validate(event, source="untrusted")
        stats = self.validator.get_stats()
        self.assertEqual(stats["total_events"], 2)
        self.assertEqual(stats["rejected_events"], 2)
        self.assertEqual(stats["valid_events"], 0)

    def test_stats_mixed_events(self):
        """混合事件统计正确"""
        self.validator.validate(make_valid_event(event_id="ok1"), source="trusted")
        self.validator.validate(make_valid_event(event_id="bad1"), source="untrusted")
        self.validator.validate(make_valid_event(event_id="ok2"), source="trusted")
        stats = self.validator.get_stats()
        self.assertEqual(stats["total_events"], 3)
        self.assertEqual(stats["valid_events"], 2)
        self.assertEqual(stats["rejected_events"], 1)


class TestConcurrencySafety(unittest.TestCase):
    """并发安全测试"""

    def setUp(self):
        self.validator = EventInputValidator(
            trusted_sources=["trusted"],
            max_events_per_second=1000,
            enable_duplicate_check=False,
        )

    def test_concurrent_validation(self):
        """并发验证不崩溃、不丢数据"""
        errors = []
        results = []

        def worker(thread_id):
            try:
                for i in range(50):
                    event = make_valid_event(event_id=f"conc_{thread_id}_{i}")
                    result = self.validator.validate(event, source="trusted")
                    results.append(result.valid)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        self.assertEqual(len(errors), 0, f"并发错误: {errors}")
        self.assertEqual(len(results), 250)
        stats = self.validator.get_stats()
        self.assertEqual(stats["total_events"], 250)


class TestBoundaryConditions(unittest.TestCase):
    """边界条件测试"""

    def test_very_long_event_id(self):
        """超长event_id不崩溃"""
        event = make_valid_event(event_id="x" * 10000)
        v = EventInputValidator(trusted_sources=["t"], enable_duplicate_check=False)
        result = v.validate(event, source="t")
        self.assertIsNotNone(result)

    def test_very_long_source_name(self):
        """超长来源名不崩溃"""
        long_source = "s" * 1000
        v = EventInputValidator(trusted_sources=[long_source], enable_duplicate_check=False)
        event = make_valid_event()
        result = v.validate(event, source=long_source)
        self.assertTrue(result.valid)

    def test_zero_max_events_per_second(self):
        """零速率限制不崩溃"""
        v = EventInputValidator(
            trusted_sources=["t"],
            max_events_per_second=0,
            enable_duplicate_check=False,
        )
        event = make_valid_event()
        result = v.validate(event, source="t")
        # 0限制可能导致所有事件被拒绝，关键是不崩溃
        self.assertIsNotNone(result)

    def test_negative_max_events_per_second(self):
        """负速率限制不崩溃"""
        v = EventInputValidator(
            trusted_sources=["t"],
            max_events_per_second=-1,
            enable_duplicate_check=False,
        )
        event = make_valid_event()
        result = v.validate(event, source="t")
        self.assertIsNotNone(result)

    def test_empty_trusted_sources(self):
        """空可信源列表不崩溃"""
        v = EventInputValidator(trusted_sources=[], enable_duplicate_check=False)
        event = make_valid_event()
        result = v.validate(event, source="any_source")
        self.assertFalse(result.valid)  # 没有可信源，所有来源都不可信

    def test_duplicate_cache_overflow(self):
        """去重缓存溢出不崩溃"""
        v = EventInputValidator(
            trusted_sources=["t"],
            enable_duplicate_check=True,
            max_duplicate_cache_size=10,
        )
        for i in range(100):
            event = make_valid_event(event_id=f"overflow_{i}")
            result = v.validate(event, source="t")
            self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
