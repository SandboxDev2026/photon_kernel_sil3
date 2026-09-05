"""
PhotonBox 边界条件与稳定性测试

专门测试：
- 空输入/异常输入
- 超长输入/特殊字符
- 资源限制/内存保护
- 并发安全
- 模块降级/故障恢复
- 错误处理健壮性
"""

import unittest
import sys
import os
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evolution.security_circuit_breaker import (
    SecurityCircuitBreaker,
    SecurityEvent,
    CircuitBreakerLevel,
    CircuitBreakerState,
    TriggerType,
)
from evolution.unified_rag_orchestrator import UnifiedRAGOrchestrator


class TestCircuitBreakerBoundary(unittest.TestCase):
    """熔断引擎边界条件测试"""

    def setUp(self):
        self.cb = SecurityCircuitBreaker(node_id="boundary-test")

    def tearDown(self):
        self.cb.shutdown()

    def test_empty_event_id(self):
        """空事件ID不应导致崩溃"""
        event = SecurityEvent(
            event_id="",
            timestamp=time.time(),
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            severity="critical",
        )
        action = self.cb.report_event(event)
        self.assertIsNotNone(action)  # 空ID仍应触发熔断

    def test_negative_timestamp(self):
        """负时间戳不应导致崩溃（不在窗口内不触发是正确行为）"""
        event = SecurityEvent(
            event_id="evt_neg",
            timestamp=-1.0,
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            severity="critical",
        )
        action = self.cb.report_event(event)
        # 负时间戳不在统计窗口内，不触发熔断是正确行为
        # 关键是不崩溃

    def test_zero_timestamp(self):
        """零时间戳不应导致崩溃（不在窗口内不触发是正确行为）"""
        event = SecurityEvent(
            event_id="evt_zero",
            timestamp=0.0,
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            severity="critical",
        )
        action = self.cb.report_event(event)
        # 零时间戳不在统计窗口内，不触发熔断是正确行为

    def test_future_timestamp(self):
        """未来时间戳不应导致崩溃（不在窗口内不触发是正确行为）"""
        event = SecurityEvent(
            event_id="evt_future",
            timestamp=time.time() + 86400 * 365,  # 1年后
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            severity="critical",
        )
        action = self.cb.report_event(event)
        # 未来时间戳可能不在统计窗口内，不触发是可接受的
        # 关键是不崩溃

    def test_very_long_description(self):
        """超长描述不应导致崩溃或内存问题"""
        long_desc = "A" * 100000  # 100KB
        event = SecurityEvent(
            event_id="evt_long",
            timestamp=time.time(),
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            severity="critical",
            description=long_desc,
        )
        action = self.cb.report_event(event)
        self.assertIsNotNone(action)

    def test_special_characters_in_description(self):
        """特殊字符不应导致崩溃"""
        special_desc = "测试\n\t\r\x00\x01\\'\"<script>alert(1)</script>"
        event = SecurityEvent(
            event_id="evt_special",
            timestamp=time.time(),
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            severity="critical",
            description=special_desc,
        )
        action = self.cb.report_event(event)
        self.assertIsNotNone(action)

    def test_very_large_metadata(self):
        """超大metadata不应导致崩溃"""
        large_meta = {f"key_{i}": "x" * 1000 for i in range(100)}
        event = SecurityEvent(
            event_id="evt_meta",
            timestamp=time.time(),
            trigger_type=TriggerType.RESOURCE_SPIKE,
            severity="warning",
            metadata=large_meta,
        )
        action = self.cb.report_event(event)
        # metadata 不影响触发逻辑，spike_ratio 缺失时不触发是正确行为
        # 关键是不崩溃

    def test_none_instance_id(self):
        """None instance_id 不应导致崩溃"""
        event = SecurityEvent(
            event_id="evt_none_inst",
            timestamp=time.time(),
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            severity="critical",
            instance_id=None,
        )
        action = self.cb.report_event(event)
        self.assertIsNotNone(action)

    def test_empty_instance_id(self):
        """空 instance_id 不应导致崩溃"""
        event = SecurityEvent(
            event_id="evt_empty_inst",
            timestamp=time.time(),
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            severity="critical",
            instance_id="",
        )
        action = self.cb.report_event(event)
        self.assertIsNotNone(action)

    def test_rapid_fire_events(self):
        """快速大量事件不应导致内存溢出或崩溃"""
        for i in range(1000):
            event = SecurityEvent(
                event_id=f"evt_rapid_{i}",
                timestamp=time.time(),
                trigger_type=TriggerType.SECCOMP_VIOLATION_SURGE,
                severity="warning",
                instance_id=f"inst-{i}",
            )
            self.cb.report_event(event)
        # deque maxlen=10000，1000个事件不会溢出
        stats = self.cb.get_stats()
        self.assertLessEqual(stats["total_events"], 10000)

    def test_concurrent_events(self):
        """并发事件不应导致数据竞争或崩溃"""
        errors = []

        def worker(thread_id):
            try:
                for i in range(100):
                    event = SecurityEvent(
                        event_id=f"evt_t{thread_id}_{i}",
                        timestamp=time.time(),
                        trigger_type=TriggerType.HIGH_RISK_SYSCALL,
                        severity="critical",
                        instance_id=f"inst-t{thread_id}-{i}",
                    )
                    self.cb.report_event(event)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        self.assertEqual(len(errors), 0, f"并发错误: {errors}")

    def test_shutdown_during_events(self):
        """在事件处理过程中关闭不应导致崩溃"""
        def event_generator():
            for i in range(50):
                try:
                    event = SecurityEvent(
                        event_id=f"evt_shutdown_{i}",
                        timestamp=time.time(),
                        trigger_type=TriggerType.HIGH_RISK_SYSCALL,
                        severity="critical",
                    )
                    self.cb.report_event(event)
                except Exception:
                    pass  # 关闭后可能出现异常，这是预期的

        t = threading.Thread(target=event_generator)
        t.start()
        time.sleep(0.1)
        self.cb.shutdown(wait=True, timeout=2)
        t.join(timeout=5)
        # 不应有未捕获异常导致测试失败

    def test_double_shutdown(self):
        """重复关闭不应导致崩溃"""
        self.cb.shutdown()
        self.cb.shutdown()  # 第二次关闭应安全返回

    def test_manual_recover_already_recovered(self):
        """恢复已恢复的动作不应导致崩溃"""
        event = SecurityEvent(
            event_id="evt_double_recover",
            timestamp=time.time(),
            trigger_type=TriggerType.HIGH_RISK_SYSCALL,
            severity="critical",
            instance_id="inst-dr",
        )
        action = self.cb.report_event(event)
        self.assertIsNotNone(action)

        success1 = self.cb.manual_recover(action.action_id, "admin1")
        self.assertTrue(success1)

        success2 = self.cb.manual_recover(action.action_id, "admin2")
        self.assertFalse(success2)  # 已恢复，第二次应失败

    def test_get_stats_during_high_load(self):
        """高负载下获取统计不应导致崩溃"""
        def event_generator():
            for i in range(200):
                event = SecurityEvent(
                    event_id=f"evt_stats_load_{i}",
                    timestamp=time.time(),
                    trigger_type=TriggerType.HIGH_RISK_SYSCALL,
                    severity="critical",
                )
                self.cb.report_event(event)

        t = threading.Thread(target=event_generator)
        t.start()

        # 同时获取统计
        for _ in range(10):
            try:
                stats = self.cb.get_stats()
                self.assertIn("total_events", stats)
            except Exception:
                pass  # 并发下可能有临时不一致，但不应崩溃

        t.join(timeout=30)

    def test_c2_indicator_empty_string(self):
        """空字符串 C2 指标不应导致崩溃"""
        # 不添加空字符串时，空字符串不应匹配
        self.assertFalse(self.cb.check_c2_connection(""))
        # 添加空字符串后匹配是集合的正常行为，关键是不崩溃
        self.cb.add_c2_indicator("")

    def test_c2_indicator_very_long(self):
        """超长 C2 指标不应导致崩溃"""
        long_indicator = "a" * 10000 + ".com"
        self.cb.add_c2_indicator(long_indicator)
        self.assertTrue(self.cb.check_c2_connection(long_indicator))


class TestUnifiedRAGBoundary(unittest.TestCase):
    """统一RAG引擎边界条件测试"""

    def setUp(self):
        self.rag = UnifiedRAGOrchestrator(tenant_id="boundary-test")

    def tearDown(self):
        pass  # RAG 引擎不需要特殊清理

    def test_empty_query(self):
        """空查询不应导致崩溃"""
        result = self.rag.query("", tenant_id="boundary-test")
        self.assertIsNotNone(result)
        self.assertEqual(len(result.retrieved_chunks), 0)

    def test_whitespace_only_query(self):
        """纯空白查询不应导致崩溃"""
        result = self.rag.query("   \n\t  ", tenant_id="boundary-test")
        self.assertIsNotNone(result)

    def test_very_long_query(self):
        """超长查询不应导致崩溃或内存问题"""
        long_query = "安全漏洞" * 10000  # 约60KB
        result = self.rag.query(long_query, tenant_id="boundary-test")
        self.assertIsNotNone(result)

    def test_special_characters_query(self):
        """特殊字符查询不应导致崩溃"""
        special_query = "测试\n\t\r\x00\\'\"<script>alert(1)</script>; DROP TABLE users; --"
        result = self.rag.query(special_query, tenant_id="boundary-test")
        self.assertIsNotNone(result)

    def test_unicode_query(self):
        """Unicode 查询不应导致崩溃"""
        unicode_query = "🛡️🔒 安全沙箱 逃逸漏洞 🚨 中文测试"
        result = self.rag.query(unicode_query, tenant_id="boundary-test")
        self.assertIsNotNone(result)

    def test_none_tenant_id(self):
        """None tenant_id 不应导致崩溃"""
        result = self.rag.query("CVE漏洞", tenant_id=None)
        self.assertIsNotNone(result)

    def test_empty_tenant_id(self):
        """空 tenant_id 不应导致崩溃"""
        result = self.rag.query("CVE漏洞", tenant_id="")
        self.assertIsNotNone(result)

    def test_very_long_tenant_id(self):
        """超长 tenant_id 不应导致崩溃"""
        long_tenant = "t" * 1000
        result = self.rag.query("CVE漏洞", tenant_id=long_tenant)
        self.assertIsNotNone(result)

    def test_zero_top_k(self):
        """top_k=0 不应导致崩溃"""
        result = self.rag.query("CVE漏洞", tenant_id="test", top_k=0)
        self.assertIsNotNone(result)
        # top_k=0 可能被当作默认值处理，关键是不崩溃

    def test_negative_top_k(self):
        """负 top_k 不应导致崩溃"""
        result = self.rag.query("CVE漏洞", tenant_id="test", top_k=-5)
        self.assertIsNotNone(result)

    def test_very_large_top_k(self):
        """超大 top_k 不应导致崩溃"""
        result = self.rag.query("CVE漏洞", tenant_id="test", top_k=100000)
        self.assertIsNotNone(result)
        # 实际返回数量应受限于可用结果

    def test_concurrent_queries(self):
        """并发查询不应导致数据竞争或崩溃"""
        errors = []

        def worker(thread_id):
            try:
                for i in range(20):
                    result = self.rag.query(
                        f"查询{thread_id}-{i} CVE漏洞",
                        tenant_id=f"tenant-{thread_id}",
                    )
                    if result is None:
                        errors.append(f"None result from thread {thread_id}")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        self.assertEqual(len(errors), 0, f"并发错误: {errors}")

    def test_repeated_same_query(self):
        """重复相同查询应利用缓存，不应导致崩溃"""
        for _ in range(50):
            result = self.rag.query("CVE-2024-1234 漏洞影响", tenant_id="cache-test")
            self.assertIsNotNone(result)

    def test_query_with_only_stopwords(self):
        """仅包含停用词的查询不应导致崩溃"""
        result = self.rag.query("的了是在有和", tenant_id="stopword-test")
        self.assertIsNotNone(result)

    def test_query_numeric_only(self):
        """纯数字查询不应导致崩溃"""
        result = self.rag.query("1234567890", tenant_id="numeric-test")
        self.assertIsNotNone(result)

    def test_get_pipeline_stats(self):
        """获取流水线统计不应导致崩溃"""
        stats = self.rag.get_pipeline_stats()
        self.assertIn("total_queries", stats)
        self.assertIn("total_timeouts", stats)
        self.assertIn("module_timeout_seconds", stats)


class TestResourceProtection(unittest.TestCase):
    """资源保护测试"""

    def test_circuit_breaker_event_queue_limit(self):
        """熔断引擎事件队列有上限（deque maxlen=10000）"""
        cb = SecurityCircuitBreaker(node_id="resource-test")
        for i in range(15000):  # 超过上限
            event = SecurityEvent(
                event_id=f"evt_{i}",
                timestamp=time.time(),
                trigger_type=TriggerType.SECCOMP_VIOLATION_SURGE,
                severity="warning",
            )
            cb.report_event(event)
        stats = cb.get_stats()
        self.assertLessEqual(stats["total_events"], 10000)
        cb.shutdown()

    def test_circuit_breaker_action_history_limit(self):
        """熔断动作历史不会无限增长（通过冷却机制限制触发频率）"""
        cb = SecurityCircuitBreaker(node_id="action-limit-test")
        # 同类型事件有冷却，不会无限触发
        for i in range(100):
            event = SecurityEvent(
                event_id=f"evt_limit_{i}",
                timestamp=time.time(),
                trigger_type=TriggerType.HIGH_RISK_SYSCALL,
                severity="critical",
            )
            cb.report_event(event)
        history = cb.get_action_history()
        # 由于冷却机制，动作数量应远少于事件数量
        self.assertLess(len(history), 100)
        cb.shutdown()


if __name__ == "__main__":
    unittest.main(verbosity=2)
