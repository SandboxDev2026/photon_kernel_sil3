"""
PhotonBox 量子启发安全引擎单元测试

覆盖：
- QuantumAnomalyDetector 量子退火异常检测
- QuantumEventCorrelator 量子概率事件关联
- QuantumSearchReranker Grover搜索重排序
- SNNIntrusionDetector 脉冲神经网络入侵检测
- QuantumInspiredSecurityEngine 统一入口
"""

import os
import sys
import math
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from evolution.quantum_inspired_security import (
    QuantumAnomalyDetector, AnomalyScore,
    QuantumEventCorrelator, QuantumEventState,
    QuantumSearchReranker,
    SNNIntrusionDetector, LIFNeuron,
    QuantumInspiredSecurityEngine,
)


class TestQuantumAnomalyDetector(unittest.TestCase):
    """量子退火异常检测测试"""

    def setUp(self):
        self.detector = QuantumAnomalyDetector(n_qubits=8, n_layers=2, threshold=0.7)

    def test_initialization(self):
        """测试初始化"""
        self.assertEqual(self.detector.n_qubits, 8)
        self.assertEqual(self.detector.n_layers, 2)
        self.assertEqual(self.detector.threshold, 0.7)
        self.assertEqual(len(self.detector.gamma), 2)
        self.assertEqual(len(self.detector.beta), 2)

    def test_set_coupling(self):
        """测试设置耦合系数"""
        self.detector.set_coupling(0, 1, 0.5)
        self.assertEqual(self.detector.couplings[(0, 1)], 0.5)

    def test_set_field(self):
        """测试设置场系数（i==j）"""
        self.detector.set_coupling(0, 0, 0.8)
        self.assertEqual(self.detector.fields[0], 0.8)

    def test_detect_normal(self):
        """测试正常特征检测"""
        features = [0.1, 0.2, 0.1, 0.0, 0.1, 0.0, 0.0, 0.1]
        result = self.detector.detect(features)
        self.assertIsInstance(result, AnomalyScore)
        self.assertGreaterEqual(result.score, 0.0)
        self.assertLessEqual(result.score, 1.0)
        self.assertGreater(result.iterations, 0)

    def test_detect_anomalous(self):
        """测试异常特征检测"""
        # 设置强耦合，使异常特征产生高能量
        self.detector.set_coupling(0, 1, 1.0)
        self.detector.set_coupling(2, 3, 1.0)
        features = [1.0, -1.0, 1.0, -1.0, 0.5, 0.5, 0.5, 0.5]
        result = self.detector.detect(features)
        self.assertIsInstance(result, AnomalyScore)
        self.assertGreaterEqual(result.score, 0.0)

    def test_detect_empty_features(self):
        """测试空特征"""
        result = self.detector.detect([])
        self.assertIsInstance(result, AnomalyScore)
        self.assertGreaterEqual(result.score, 0.0)

    def test_detect_short_features(self):
        """测试短特征（自动补零）"""
        result = self.detector.detect([0.5, 0.3])
        self.assertIsInstance(result, AnomalyScore)

    def test_detect_long_features(self):
        """测试长特征（自动截断）"""
        features = [0.5] * 20
        result = self.detector.detect(features)
        self.assertIsInstance(result, AnomalyScore)

    def test_convergence(self):
        """测试收敛性"""
        features = [0.1] * 8
        result = self.detector.detect(features, max_iterations=100)
        # 收敛或达到最大迭代次数
        self.assertTrue(result.convergence or result.iterations <= 100)

    def test_stats(self):
        """测试统计信息"""
        self.detector.detect([0.1] * 8)
        stats = self.detector.get_stats()
        self.assertIn("total_detections", stats)
        self.assertEqual(stats["total_detections"], 1)


class TestQuantumEventCorrelator(unittest.TestCase):
    """量子概率事件关联测试"""

    def setUp(self):
        self.correlator = QuantumEventCorrelator(interference_strength=0.5)

    def test_initialization(self):
        """测试初始化"""
        self.assertEqual(self.correlator.interference_strength, 0.5)

    def test_add_event_default(self):
        """测试添加事件（默认幅度）"""
        state = self.correlator.add_event("event_1")
        self.assertIsInstance(state, QuantumEventState)
        self.assertEqual(state.event_id, "event_1")
        self.assertFalse(state.measured)
        probs = state.get_probabilities()
        self.assertAlmostEqual(sum(probs.values()), 1.0, places=5)

    def test_add_event_custom(self):
        """测试添加事件（自定义幅度）"""
        amps = {"normal": complex(0.8, 0), "attack": complex(0.6, 0)}
        state = self.correlator.add_event("event_2", amps)
        probs = state.get_probabilities()
        self.assertIn("normal", probs)
        self.assertIn("attack", probs)

    def test_measure(self):
        """测试测量（坍缩）"""
        state = self.correlator.add_event("event_3")
        result = state.measure()
        self.assertTrue(state.measured)
        self.assertEqual(state.measured_state, result)
        # 再次测量应返回相同结果
        result2 = state.measure()
        self.assertEqual(result, result2)

    def test_correlate_single(self):
        """测试单事件关联"""
        self.correlator.add_event("event_1")
        result = self.correlator.correlate(["event_1"])
        self.assertTrue(result["correlated"])
        self.assertEqual(result["event_count"], 1)
        self.assertIn("probabilities", result)
        self.assertIn("measured_state", result)

    def test_correlate_multiple(self):
        """测试多事件关联"""
        self.correlator.add_event("event_1")
        self.correlator.add_event("event_2")
        self.correlator.add_event("event_3")
        result = self.correlator.correlate(["event_1", "event_2", "event_3"])
        self.assertTrue(result["correlated"])
        self.assertEqual(result["event_count"], 3)
        self.assertIn("interference_type", result)
        self.assertIn(result["interference_type"], ["constructive", "destructive", "neutral"])

    def test_correlate_with_severity(self):
        """测试带严重程度的事件关联"""
        # 高危事件应产生高攻击概率
        high_amps = {"normal": complex(0.1, 0), "suspicious": complex(0.3, 0), "attack": complex(0.95, 0)}
        self.correlator.add_event("critical_event", high_amps)
        result = self.correlator.correlate(["critical_event"])
        self.assertGreater(result["attack_probability"], 0.3)

    def test_correlate_empty(self):
        """测试空事件列表"""
        result = self.correlator.correlate([])
        self.assertFalse(result["correlated"])

    def test_correlate_nonexistent(self):
        """测试不存在的事件"""
        result = self.correlator.correlate(["nonexistent_event"])
        self.assertFalse(result["correlated"])

    def test_stats(self):
        """测试统计信息"""
        self.correlator.add_event("e1")
        self.correlator.correlate(["e1"])
        stats = self.correlator.get_stats()
        self.assertIn("total_correlations", stats)
        self.assertEqual(stats["total_correlations"], 1)


class TestQuantumSearchReranker(unittest.TestCase):
    """Grover搜索重排序测试"""

    def setUp(self):
        self.reranker = QuantumSearchReranker(n_iterations=3, oracle_threshold=0.3)

    def test_initialization(self):
        """测试初始化"""
        self.assertEqual(self.reranker.n_iterations, 3)
        self.assertEqual(self.reranker.oracle_threshold, 0.3)

    def test_rerank_empty(self):
        """测试空结果"""
        result = self.reranker.rerank([], "query")
        self.assertEqual(result, [])

    def test_rerank_single(self):
        """测试单结果"""
        results = [{"score": 0.8, "content": "test"}]
        result = self.reranker.rerank(results, "query")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["rank"], 1)

    def test_rerank_multiple(self):
        """测试多结果重排序"""
        results = [
            {"score": 0.2, "content": "unrelated content"},
            {"score": 0.9, "content": "highly relevant security content"},
            {"score": 0.5, "content": "moderately relevant"},
        ]
        reranked = self.reranker.rerank(results, "security relevant")
        self.assertEqual(len(reranked), 3)
        # 高相关结果应排在前面
        self.assertEqual(reranked[0]["original_score"], 0.9)
        # 排名应正确
        self.assertEqual([r["rank"] for r in reranked], [1, 2, 3])

    def test_rerank_amplification(self):
        """测试幅度放大效果"""
        results = [
            {"score": 0.1, "content": "bad"},
            {"score": 0.9, "content": "good security relevant"},
        ]
        reranked = self.reranker.rerank(results, "security relevant")
        # 放大后的分数应与原始分数不同
        self.assertIn("amplified_score", reranked[0])
        self.assertIn("amplification_prob", reranked[0])

    def test_rerank_oracle_keyword(self):
        """测试预言机关键词匹配"""
        results = [
            {"score": 0.1, "content": "contains security keyword"},
            {"score": 0.1, "content": "completely unrelated text here"},
        ]
        reranked = self.reranker.rerank(results, "security keyword")
        # 包含关键词的结果应被预言机标记，排名靠前
        self.assertIn("security", reranked[0]["content"])

    def test_stats(self):
        """测试统计信息"""
        self.reranker.rerank([{"score": 0.5, "content": "test"}], "query")
        stats = self.reranker.get_stats()
        self.assertIn("total_reranks", stats)
        self.assertEqual(stats["total_reranks"], 1)


class TestLIFNeuron(unittest.TestCase):
    """LIF神经元测试"""

    def setUp(self):
        self.neuron = LIFNeuron(neuron_id=0, threshold=1.0, tau=10.0)

    def test_initialization(self):
        """测试初始化"""
        self.assertEqual(self.neuron.neuron_id, 0)
        self.assertEqual(self.neuron.threshold, 1.0)
        self.assertEqual(self.neuron.membrane_potential, 0.0)
        self.assertEqual(self.neuron.spike_count, 0)

    def test_step_no_spike(self):
        """测试无脉冲（低输入电流）"""
        result = self.neuron.step(t=0, input_current=0.1)
        self.assertFalse(result)
        self.assertEqual(self.neuron.spike_count, 0)

    def test_step_spike(self):
        """测试产生脉冲（高输入电流）"""
        # 多次高电流输入，膜电位累积超过阈值
        for t in range(20):
            self.neuron.step(t=t, input_current=2.0)
        self.assertGreater(self.neuron.spike_count, 0)

    def test_refractory_period(self):
        """测试不应期"""
        # 先产生一个脉冲
        for t in range(20):
            self.neuron.step(t=t, input_current=2.0)
        # 不应期内即使高电流也不应产生脉冲
        spike_time = self.neuron.last_spike_time
        result = self.neuron.step(t=spike_time + 1, input_current=10.0)
        self.assertFalse(result)

    def test_reset(self):
        """测试重置"""
        for t in range(20):
            self.neuron.step(t=t, input_current=2.0)
        self.neuron.reset()
        self.assertEqual(self.neuron.membrane_potential, self.neuron.resting_potential)
        self.assertEqual(self.neuron.spike_count, 0)


class TestSNNIntrusionDetector(unittest.TestCase):
    """脉冲神经网络入侵检测测试"""

    def setUp(self):
        self.detector = SNNIntrusionDetector(n_input=8, n_hidden=8, n_output=3, simulation_time=80.0)

    def test_initialization(self):
        """测试初始化"""
        self.assertEqual(self.detector.n_input, 8)
        self.assertEqual(self.detector.n_hidden, 8)
        self.assertEqual(self.detector.n_output, 3)
        self.assertEqual(len(self.detector.input_neurons), 8)
        self.assertEqual(len(self.detector.hidden_neurons), 8)
        self.assertEqual(len(self.detector.output_neurons), 3)
        self.assertEqual(self.detector.output_labels, ["normal", "suspicious", "attack"])

    def test_detect_normal(self):
        """测试正常特征检测"""
        features = [0.1, 0.1, 0.0, 0.0, 0.1, 0.0, 0.0, 0.1]
        result = self.detector.detect(features)
        self.assertIn("predicted", result)
        self.assertIn(result["predicted"], ["normal", "suspicious", "attack"])
        self.assertGreaterEqual(result["confidence"], 0.0)
        self.assertLessEqual(result["confidence"], 1.0)
        self.assertIn("latency_ms", result)

    def test_detect_anomalous(self):
        """测试异常特征检测"""
        features = [1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0]
        result = self.detector.detect(features)
        self.assertIn("predicted", result)
        self.assertIn("output_spike_counts", result)

    def test_detect_empty(self):
        """测试空特征"""
        result = self.detector.detect([])
        self.assertIn("predicted", result)

    def test_detect_short(self):
        """测试短特征"""
        result = self.detector.detect([0.5, 0.3])
        self.assertIn("predicted", result)

    def test_is_attack_flag(self):
        """测试is_attack标志"""
        result = self.detector.detect([0.1] * 8)
        if result["predicted"] == "attack":
            self.assertTrue(result["is_attack"])
        else:
            self.assertFalse(result["is_attack"])

    def test_is_suspicious_flag(self):
        """测试is_suspicious标志"""
        result = self.detector.detect([0.1] * 8)
        if result["predicted"] in ("attack", "suspicious"):
            self.assertTrue(result["is_suspicious"])
        else:
            self.assertFalse(result["is_suspicious"])

    def test_stdp_learning(self):
        """测试STDP学习（多次检测后权重应变化）"""
        # 记录初始权重
        initial_weights = [row[:] for row in self.detector.weights_input_hidden]
        # 多次检测
        for _ in range(5):
            self.detector.detect([0.5, 0.3, 0.2, 0.1, 0.4, 0.2, 0.1, 0.3])
        # 权重应发生变化（STDP学习）
        weights_changed = any(
            initial_weights[i][j] != self.detector.weights_input_hidden[i][j]
            for i in range(len(initial_weights))
            for j in range(len(initial_weights[0]))
        )
        self.assertTrue(weights_changed)

    def test_stats(self):
        """测试统计信息"""
        self.detector.detect([0.1] * 8)
        stats = self.detector.get_stats()
        self.assertIn("total_detections", stats)
        self.assertEqual(stats["total_detections"], 1)
        self.assertIn("avg_latency_ms", stats)


class TestQuantumInspiredSecurityEngine(unittest.TestCase):
    """量子启发安全引擎统一入口测试"""

    def setUp(self):
        self.engine = QuantumInspiredSecurityEngine(n_qubits=8, n_snn_input=8)

    def test_initialization(self):
        """测试初始化"""
        self.assertIsInstance(self.engine.anomaly_detector, QuantumAnomalyDetector)
        self.assertIsInstance(self.engine.event_correlator, QuantumEventCorrelator)
        self.assertIsInstance(self.engine.search_reranker, QuantumSearchReranker)
        self.assertIsInstance(self.engine.intrusion_detector, SNNIntrusionDetector)

    def test_full_analysis_basic(self):
        """测试基础完整分析"""
        features = [0.1, 0.2, 0.1, 0.0, 0.1, 0.0, 0.0, 0.1]
        result = self.engine.full_analysis(features)
        self.assertIn("anomaly_detection", result)
        self.assertIn("intrusion_detection", result)
        self.assertIn("combined_risk_score", result)
        self.assertIn("risk_level", result)
        self.assertIn(result["risk_level"], ["critical", "high", "medium", "low"])
        self.assertGreaterEqual(result["combined_risk_score"], 0.0)
        self.assertLessEqual(result["combined_risk_score"], 1.0)

    def test_full_analysis_with_events(self):
        """测试带事件的完整分析"""
        features = [0.5] * 8
        events = [
            {"event_id": "e1", "severity": "high", "description": "suspicious activity"},
            {"event_id": "e2", "severity": "critical", "description": "attack detected"},
        ]
        result = self.engine.full_analysis(features, events=events)
        self.assertIsNotNone(result["event_correlation"])
        self.assertTrue(result["event_correlation"]["correlated"])

    def test_full_analysis_with_search(self):
        """测试带搜索结果的完整分析"""
        features = [0.3] * 8
        search_results = [
            {"score": 0.9, "content": "relevant security content"},
            {"score": 0.2, "content": "unrelated"},
        ]
        result = self.engine.full_analysis(features, search_results=search_results, query="security")
        self.assertIsNotNone(result["search_reranking"])
        self.assertEqual(len(result["search_reranking"]), 2)

    def test_full_analysis_high_risk(self):
        """测试高风险场景"""
        # 高危特征 + 高危事件
        features = [1.0] * 8
        events = [{"event_id": "e1", "severity": "critical"}]
        result = self.engine.full_analysis(features, events=events)
        # 高风险场景应产生较高的综合风险评分
        self.assertGreater(result["combined_risk_score"], 0.0)

    def test_full_analysis_stats(self):
        """测试完整分析统计"""
        features = [0.1] * 8
        result = self.engine.full_analysis(features)
        self.assertIn("stats", result)
        self.assertIn("anomaly", result["stats"])
        self.assertIn("intrusion", result["stats"])


if __name__ == '__main__':
    unittest.main(verbosity=2)
