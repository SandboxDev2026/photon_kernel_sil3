"""
evolution.tests.test_m2_gateway — M2 检测网关测试

覆盖：
- 语义特征提取
- 风险分数计算
- 语义动量计算
- 过滤决策
- 混淆检测
- 审计日志
- 统计信息
"""
import unittest
from evolution.m2_gateway import (
    M2DetectionGateway, M2FilterResult, SemanticMomentum,
    SemanticFeature, RiskLevel, FilterDecision, SemanticFeatureType,
)


class TestM2DetectionGateway(unittest.TestCase):
    """M2 检测网关测试"""

    def setUp(self):
        self.gateway = M2DetectionGateway()

    def test_safe_code_allowed(self):
        """安全代码应该被允许"""
        code = """
def hello():
    print("Hello, World!")
    return 42
"""
        result = self.gateway.analyze_and_filter(code)
        self.assertEqual(result.decision, FilterDecision.ALLOW)
        self.assertEqual(result.risk_level, RiskLevel.SAFE)
        self.assertLess(result.risk_score, 0.3)

    def test_dangerous_api_detected(self):
        """危险API应该被检测到"""
        code = "import os; os.system('ls -la')"
        result = self.gateway.analyze_and_filter(code)
        self.assertGreater(len(result.features), 0)
        system_calls = [f for f in result.features if f.feature_type == SemanticFeatureType.SYSTEM_CALL]
        self.assertGreater(len(system_calls), 0)

    def test_eval_detected_as_high_risk(self):
        """eval应该被检测为高风险"""
        code = "eval('__import__(\"os\").system(\"rm -rf /\")')"
        result = self.gateway.analyze_and_filter(code)
        eval_features = [f for f in result.features if f.feature_type == SemanticFeatureType.CODE_EXECUTION]
        self.assertGreater(len(eval_features), 0)
        self.assertGreater(result.risk_score, 0.3)

    def test_sandbox_evasion_rejected(self):
        """沙盒逃逸尝试应该被拒绝"""
        code = "import os; os.system('nsenter --target 1 --mount --uts --ipc --net --pid')"
        result = self.gateway.analyze_and_filter(code)
        evasion_features = [f for f in result.features if f.feature_type == SemanticFeatureType.SANDBOX_EVASION]
        self.assertGreater(len(evasion_features), 0)
        self.assertIn(result.decision, [FilterDecision.REJECT, FilterDecision.QUARANTINE])

    def test_privilege_escalation_quarantined(self):
        """提权尝试应该被隔离"""
        code = "import os; os.setuid(0); os.system('whoami')"
        result = self.gateway.analyze_and_filter(code)
        priv_features = [f for f in result.features if f.feature_type == SemanticFeatureType.PRIVILEGE_ESCALATION]
        self.assertGreater(len(priv_features), 0)
        self.assertEqual(result.decision, FilterDecision.QUARANTINE)

    def test_network_operation_detected(self):
        """网络操作应该被检测"""
        code = "import requests; requests.get('http://example.com')"
        result = self.gateway.analyze_and_filter(code)
        net_features = [f for f in result.features if f.feature_type == SemanticFeatureType.NETWORK_OPERATION]
        self.assertGreater(len(net_features), 0)

    def test_file_operation_detected(self):
        """危险文件操作应该被检测"""
        code = "import os; os.remove('/etc/passwd')"
        result = self.gateway.analyze_and_filter(code)
        file_features = [f for f in result.features if f.feature_type == SemanticFeatureType.FILE_OPERATION]
        self.assertGreater(len(file_features), 0)

    def test_obfuscation_detection(self):
        """代码混淆应该被检测"""
        # 构造包含大量十六进制编码的代码
        code = 'x = "\\x48\\x65\\x6c\\x6c\\x6f\\x20\\x57\\x6f\\x72\\x6c\\x64"\n'
        code += 'y = "\\x57\\x6f\\x72\\x6c\\x64\\x20\\x48\\x65\\x6c\\x6c\\x6f"\n'
        code += 'z = "\\x48\\x65\\x6c\\x6c\\x6f\\x20\\x57\\x6f\\x72\\x6c\\x64"\n'
        code += 'print(x + y + z)\n'
        result = self.gateway.analyze_and_filter(code)
        self.assertTrue(result.momentum.obfuscation_detected)

    def test_risk_score_calculation(self):
        """风险分数计算"""
        # 安全代码风险分数低
        safe_code = "x = 1 + 1"
        safe_result = self.gateway.analyze_and_filter(safe_code)
        self.assertLess(safe_result.risk_score, 0.3)

        # 危险代码风险分数高
        dangerous_code = "eval('os.system(\"rm -rf /\")')"
        dangerous_result = self.gateway.analyze_and_filter(dangerous_code)
        self.assertGreater(dangerous_result.risk_score, safe_result.risk_score)

    def test_semantic_momentum_calculation(self):
        """语义动量计算"""
        code = "import os; os.system('rm -rf /'); eval('1+1')"
        result = self.gateway.analyze_and_filter(code)
        self.assertIsInstance(result.momentum, SemanticMomentum)
        self.assertGreater(result.momentum.feature_count, 0)
        self.assertGreater(result.momentum.high_risk_feature_count, 0)
        self.assertGreater(result.momentum.risk_delta, 0)

    def test_filter_result_structure(self):
        """过滤结果结构完整性"""
        code = "print('hello')"
        result = self.gateway.analyze_and_filter(code, tenant_id="tenant_001", sandbox_type="LightPool")

        self.assertIsInstance(result, M2FilterResult)
        self.assertIsNotNone(result.request_id)
        self.assertIsNotNone(result.timestamp)
        self.assertIsNotNone(result.code_hash)
        self.assertEqual(result.code_length, len(code))
        self.assertEqual(result.tenant_id, "tenant_001")
        self.assertEqual(result.sandbox_type, "LightPool")
        self.assertGreaterEqual(result.processing_time_ms, 0)
        self.assertIsInstance(result.reasons, list)
        self.assertGreater(len(result.reasons), 0)

    def test_audit_log_recording(self):
        """审计日志记录"""
        self.gateway.analyze_and_filter("print('hello')")
        self.gateway.analyze_and_filter("eval('1+1')")

        audit_log = self.gateway.get_audit_log()
        self.assertEqual(len(audit_log), 2)

    def test_audit_log_limit(self):
        """审计日志大小限制"""
        gateway = M2DetectionGateway()
        gateway._max_audit_log = 5

        for i in range(10):
            gateway.analyze_and_filter(f"print({i})")

        audit_log = gateway.get_audit_log()
        self.assertLessEqual(len(audit_log), 5)

    def test_stats_tracking(self):
        """统计信息跟踪"""
        self.gateway.analyze_and_filter("print('safe')")  # ALLOW
        self.gateway.analyze_and_filter("eval('1+1')")   # 可能 WARN 或 REJECT

        stats = self.gateway.get_stats()
        self.assertEqual(stats["total_requests"], 2)
        self.assertEqual(stats["allowed"] + stats["warned"] + stats["rejected"] + stats["quarantined"], 2)
        self.assertGreater(stats["allow_rate"], 0)

    def test_custom_thresholds(self):
        """自定义决策阈值"""
        # 设置更严格的阈值
        gateway = M2DetectionGateway(
            decision_thresholds={
                FilterDecision.ALLOW: 0.1,
                FilterDecision.WARN: 0.2,
                FilterDecision.REJECT: 0.4,
            }
        )
        # 包含一个中等风险特征的代码
        code = "import requests; requests.get('http://example.com')"
        result = gateway.analyze_and_filter(code)
        # 更严格的阈值下，可能会被拒绝
        self.assertIn(result.decision, [FilterDecision.WARN, FilterDecision.REJECT, FilterDecision.QUARANTINE])

    def test_disable_obfuscation_detection(self):
        """禁用混淆检测"""
        gateway = M2DetectionGateway(enable_obfuscation_detection=False)
        code = 'x = "\\x48\\x65\\x6c\\x6c\\x6f\\x20\\x57\\x6f\\x72\\x6c\\x64"\n'
        code += 'y = "\\x57\\x6f\\x72\\x6c\\x64\\x20\\x48\\x65\\x6c\\x6c\\x6f"\n'
        code += 'z = "\\x48\\x65\\x6c\\x6c\\x6f\\x20\\x57\\x6f\\x72\\x6c\\x64"\n'
        result = gateway.analyze_and_filter(code)
        self.assertFalse(result.momentum.obfuscation_detected)

    def test_data_exfiltration_detected(self):
        """数据外泄应该被检测"""
        code = "import base64; data = base64.b64encode(b'secret'); print(data)"
        result = self.gateway.analyze_and_filter(code)
        exfil_features = [f for f in result.features if f.feature_type == SemanticFeatureType.DATA_EXFILTRATION]
        self.assertGreater(len(exfil_features), 0)

    def test_process_operation_detected(self):
        """进程操作应该被检测"""
        code = "import os; os.fork(); os.execvp('ls', ['ls'])"
        result = self.gateway.analyze_and_filter(code)
        proc_features = [f for f in result.features if f.feature_type == SemanticFeatureType.PROCESS_OPERATION]
        self.assertGreater(len(proc_features), 0)

    def test_empty_code_safe(self):
        """空代码应该是安全的"""
        result = self.gateway.analyze_and_filter("")
        self.assertEqual(result.decision, FilterDecision.ALLOW)
        self.assertEqual(result.risk_score, 0.0)
        self.assertEqual(len(result.features), 0)

    def test_result_to_dict(self):
        """过滤结果转换为字典"""
        result = self.gateway.analyze_and_filter("print('hello')")
        d = result.to_dict()
        self.assertIsInstance(d, dict)
        self.assertIn("decision", d)
        self.assertIn("risk_level", d)
        self.assertIn("risk_score", d)
        self.assertIn("momentum", d)
        self.assertIn("features", d)
        self.assertIn("reasons", d)

    def test_result_to_json(self):
        """过滤结果转换为JSON"""
        result = self.gateway.analyze_and_filter("print('hello')")
        json_str = result.to_json()
        self.assertIsInstance(json_str, str)
        self.assertIn('"decision"', json_str)
        self.assertIn('"allow"', json_str)

    def test_clear_audit_log(self):
        """清空审计日志"""
        self.gateway.analyze_and_filter("print('hello')")
        self.assertEqual(len(self.gateway.get_audit_log()), 1)

        self.gateway.clear_audit_log()
        self.assertEqual(len(self.gateway.get_audit_log()), 0)

    def test_feature_location_tracking(self):
        """特征位置跟踪"""
        code = "print('safe')\nimport os\nos.system('ls')"
        result = self.gateway.analyze_and_filter(code)
        system_features = [f for f in result.features if f.feature_type == SemanticFeatureType.SYSTEM_CALL]
        if system_features:
            self.assertIn("line", system_features[0].location)

    def test_feature_confidence(self):
        """特征置信度"""
        code = "eval('1+1')"
        result = self.gateway.analyze_and_filter(code)
        eval_features = [f for f in result.features if f.feature_type == SemanticFeatureType.CODE_EXECUTION]
        if eval_features:
            self.assertGreater(eval_features[0].confidence, 0.8)
            self.assertLessEqual(eval_features[0].confidence, 1.0)


if __name__ == "__main__":
    unittest.main()
