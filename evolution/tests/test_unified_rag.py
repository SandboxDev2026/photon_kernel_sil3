"""
PhotonBox 统一安全知识 RAG 编排引擎 - 单元测试

覆盖：
1. 数据结构（RAGContextChunk/RAGResult/RAGStageTiming）
2. 统一 RAG 编排引擎（端到端查询、5模块整合、RRF融合、会话管理）
3. 流水线阶段计时
4. 多租户隔离
5. 统计信息
"""

import unittest
import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evolution.unified_rag_orchestrator import (
    UnifiedRAGOrchestrator,
    RAGContextChunk,
    RAGResult,
    RAGStageTiming,
    RAGPipelineStage,
    create_unified_rag,
)
from evolution.security_knowledge_graph import build_sample_security_graph


class TestRAGContextChunk(unittest.TestCase):
    """RAG 上下文片段测试"""

    def test_create_chunk(self):
        """创建片段"""
        chunk = RAGContextChunk(
            content="测试内容",
            source="hybrid_retrieval",
            score=0.85,
            metadata={"key": "value"},
        )
        self.assertEqual(chunk.content, "测试内容")
        self.assertEqual(chunk.source, "hybrid_retrieval")
        self.assertEqual(chunk.score, 0.85)
        self.assertEqual(chunk.metadata["key"], "value")

    def test_to_dict(self):
        """转换为字典"""
        chunk = RAGContextChunk(content="test", source="knowledge_graph", score=0.9)
        d = chunk.to_dict()
        self.assertEqual(d["content"], "test")
        self.assertEqual(d["source"], "knowledge_graph")
        self.assertEqual(d["score"], 0.9)

    def test_default_metadata(self):
        """默认元数据为空字典"""
        chunk = RAGContextChunk(content="test", source="test", score=0.5)
        self.assertEqual(chunk.metadata, {})


class TestRAGStageTiming(unittest.TestCase):
    """阶段计时测试"""

    def test_create_timing(self):
        """创建计时"""
        t = RAGStageTiming(stage="retrieval", duration_ms=1.5, success=True)
        self.assertEqual(t.stage, "retrieval")
        self.assertEqual(t.duration_ms, 1.5)
        self.assertTrue(t.success)
        self.assertIsNone(t.error)

    def test_failed_timing(self):
        """失败计时"""
        t = RAGStageTiming(stage="retrieval", duration_ms=0.5, success=False, error="timeout")
        self.assertFalse(t.success)
        self.assertEqual(t.error, "timeout")


class TestRAGPipelineStage(unittest.TestCase):
    """流水线阶段枚举测试"""

    def test_all_stages(self):
        """所有阶段"""
        stages = [s.value for s in RAGPipelineStage]
        self.assertIn("session_restore", stages)
        self.assertIn("query_understanding", stages)
        self.assertIn("routing", stages)
        self.assertIn("retrieval", stages)
        self.assertIn("knowledge_graph", stages)
        self.assertIn("context_injection", stages)
        self.assertIn("aggregation", stages)


class TestUnifiedRAGOrchestrator(unittest.TestCase):
    """统一 RAG 编排引擎测试"""

    def setUp(self):
        self.rag = create_unified_rag(enable_session=False)

    def test_query_vulnerability(self):
        """漏洞查询"""
        result = self.rag.query("CVE-2022-3602 漏洞详情")
        self.assertIsInstance(result, RAGResult)
        self.assertEqual(result.query, "CVE-2022-3602 漏洞详情")
        self.assertEqual(result.intent, "vulnerability_query")
        self.assertGreater(result.intent_confidence, 0)

    def test_query_configuration(self):
        """配置查询"""
        result = self.rag.query("如何配置 seccomp 规则")
        self.assertEqual(result.intent, "configuration_query")

    def test_query_returns_chunks(self):
        """查询返回上下文片段"""
        result = self.rag.query("seccomp 沙箱逃逸 防护")
        self.assertIsInstance(result.retrieved_chunks, list)
        # 应该有检索结果（示例文档中包含 seccomp 相关内容）
        self.assertGreater(len(result.retrieved_chunks), 0)

    def test_query_entities(self):
        """查询实体抽取"""
        result = self.rag.query("CVE-2022-3602 OpenSSL 高危")
        entity_types = [e.entity_type for e in result.entities]
        self.assertIn("cve", entity_types)

    def test_query_stage_timings(self):
        """查询阶段计时"""
        result = self.rag.query("测试查询")
        self.assertGreater(len(result.stage_timings), 0)
        stages = [t.stage for t in result.stage_timings]
        self.assertIn("query_understanding", stages)
        self.assertIn("routing", stages)
        self.assertIn("retrieval", stages)
        self.assertIn("aggregation", stages)

    def test_query_total_duration(self):
        """查询总耗时"""
        result = self.rag.query("测试查询")
        self.assertGreater(result.total_duration_ms, 0)
        # 应该在合理时间内完成（<1000ms）
        self.assertLess(result.total_duration_ms, 1000)

    def test_query_confidence(self):
        """查询综合置信度"""
        result = self.rag.query("CVE-2022-3602 漏洞")
        self.assertGreaterEqual(result.overall_confidence, 0)
        self.assertLessEqual(result.overall_confidence, 1.0)

    def test_query_retrieval_strategy(self):
        """查询推荐检索策略"""
        result = self.rag.query("CVE-2022-3602 漏洞")
        self.assertIsInstance(result.retrieval_strategy, str)
        self.assertGreater(len(result.retrieval_strategy), 0)

    def test_query_pipeline_version(self):
        """查询流水线版本"""
        result = self.rag.query("测试")
        self.assertEqual(result.pipeline_version, "1.0")

    def test_query_type(self):
        """查询类型"""
        result = self.rag.query("CVE-2022-3602 漏洞")
        self.assertIsInstance(result.query_type, str)
        self.assertGreater(len(result.query_type), 0)

    def test_to_dict(self):
        """RAGResult 转换为字典"""
        result = self.rag.query("CVE-2022-3602")
        d = result.to_dict()
        self.assertIsInstance(d, dict)
        self.assertIn("query", d)
        self.assertIn("intent", d)
        self.assertIn("retrieved_chunks", d)
        self.assertIn("overall_confidence", d)
        self.assertIn("stage_timings", d)
        self.assertIn("total_duration_ms", d)

    def test_to_json(self):
        """RAGResult 转换为 JSON"""
        result = self.rag.query("CVE-2022-3602")
        json_str = result.to_json()
        self.assertIsInstance(json_str, str)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["query"], "CVE-2022-3602")

    def test_generate_answer(self):
        """生成答案"""
        result = self.rag.query("seccomp 配置", generate_answer=True)
        self.assertIsNotNone(result.generated_answer)
        self.assertIn("seccomp", result.generated_answer)

    def test_no_generate_answer_by_default(self):
        """默认不生成答案"""
        result = self.rag.query("测试")
        self.assertIsNone(result.generated_answer)

    def test_risk_assessment_trigger(self):
        """风险评估意图触发"""
        result = self.rag.query("OpenSSL 风险评估")
        # risk_assessment 可能为 None（如果实例不匹配），但不应该报错
        self.assertIsInstance(result, RAGResult)

    def test_custom_top_k(self):
        """自定义 top_k"""
        result = self.rag.query("seccomp 沙箱", top_k=3)
        self.assertLessEqual(len(result.retrieved_chunks), 3)


class TestRRFFusion(unittest.TestCase):
    """RRF 融合测试"""

    def setUp(self):
        self.rag = create_unified_rag(enable_session=False)

    def test_rrf_fuse_single_source(self):
        """单来源 RRF 融合"""
        chunks = [
            RAGContextChunk(content="a", source="hybrid", score=0.9),
            RAGContextChunk(content="b", source="hybrid", score=0.8),
            RAGContextChunk(content="c", source="hybrid", score=0.7),
        ]
        fused = self.rag._rrf_fuse(chunks)
        self.assertEqual(len(fused), 3)
        # 最高分应该排第一
        self.assertEqual(fused[0].content, "a")

    def test_rrf_fuse_multi_source(self):
        """多来源 RRF 融合"""
        chunks = [
            RAGContextChunk(content="shared", source="hybrid", score=0.9),
            RAGContextChunk(content="shared", source="kg", score=0.8),
            RAGContextChunk(content="only_hybrid", source="hybrid", score=0.7),
        ]
        fused = self.rag._rrf_fuse(chunks)
        # "shared" 在两个来源都出现，RRF 分数应该更高
        self.assertEqual(fused[0].content, "shared")

    def test_rrf_fuse_empty(self):
        """空列表 RRF 融合"""
        fused = self.rag._rrf_fuse([])
        self.assertEqual(len(fused), 0)

    def test_rrf_fuse_custom_k(self):
        """自定义 RRF k 参数"""
        chunks = [
            RAGContextChunk(content="a", source="hybrid", score=0.9),
            RAGContextChunk(content="b", source="hybrid", score=0.8),
        ]
        fused = self.rag._rrf_fuse(chunks, k=10)
        self.assertEqual(len(fused), 2)


class TestSessionManagement(unittest.TestCase):
    """会话管理测试"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.rag = UnifiedRAGOrchestrator(
            enable_session=True,
            session_manager=None,
            tenant_id="test_tenant",
        )
        # 覆盖会话管理器的 base_path
        if self.rag._session_mgr is not None:
            self.rag._session_mgr.base_path = self.temp_dir

    def test_query_creates_session(self):
        """查询自动创建会话"""
        result = self.rag.query("测试查询", session_id="test_session_001")
        self.assertIsNotNone(result.session_id)
        # 会话ID由 SessionStateManager 自动生成

    def test_query_without_session_id(self):
        """无会话ID自动生成"""
        result = self.rag.query("测试查询")
        self.assertIsNotNone(result.session_id)
        # 会话ID由 SessionStateManager 自动生成（sess_ 前缀）
        self.assertTrue(result.session_id.startswith("sess_"))

    def test_previous_session_id(self):
        """上一轮会话ID记录"""
        result = self.rag.query("第二轮查询", previous_session_id="prev_001")
        self.assertEqual(result.previous_session_id, "prev_001")

    def test_session_context_hits(self):
        """会话上下文命中统计"""
        result = self.rag.query("测试", session_id="session_ctx_test")
        self.assertIsInstance(result.session_context_hits, int)
        self.assertGreaterEqual(result.session_context_hits, 0)


class TestMultiTenant(unittest.TestCase):
    """多租户隔离测试"""

    def test_different_tenant_ids(self):
        """不同租户ID"""
        rag1 = create_unified_rag(enable_session=False, tenant_id="tenant_a")
        rag2 = create_unified_rag(enable_session=False, tenant_id="tenant_b")
        self.assertEqual(rag1.tenant_id, "tenant_a")
        self.assertEqual(rag2.tenant_id, "tenant_b")

    def test_query_with_tenant_override(self):
        """查询时覆盖租户"""
        rag = create_unified_rag(enable_session=False, tenant_id="default")
        result = rag.query("测试", tenant_id="override_tenant")
        # 租户覆盖不影响 RAGResult 结构
        self.assertIsInstance(result, RAGResult)


class TestPipelineStats(unittest.TestCase):
    """流水线统计测试"""

    def setUp(self):
        self.rag = create_unified_rag(enable_session=False)

    def test_initial_stats(self):
        """初始统计"""
        stats = self.rag.get_pipeline_stats()
        self.assertEqual(stats["total_queries"], 0)
        self.assertEqual(stats["modules_integrated"], 5)
        self.assertEqual(len(stats["module_names"]), 5)

    def test_stats_after_queries(self):
        """查询后统计"""
        self.rag.query("查询1")
        self.rag.query("查询2")
        stats = self.rag.get_pipeline_stats()
        self.assertEqual(stats["total_queries"], 2)

    def test_module_names(self):
        """模块名称"""
        stats = self.rag.get_pipeline_stats()
        names = stats["module_names"]
        self.assertIn("SLM查询意图理解", names)
        self.assertIn("智能查询路由", names)
        self.assertIn("RRF混合检索", names)
        self.assertIn("三元组安全知识图谱", names)
        self.assertIn("服务器端会话状态管理", names)


class TestConvenienceFunction(unittest.TestCase):
    """便捷函数测试"""

    def test_create_unified_rag(self):
        """创建统一 RAG"""
        rag = create_unified_rag()
        self.assertIsInstance(rag, UnifiedRAGOrchestrator)

    def test_create_with_kg(self):
        """带知识图谱创建"""
        kg = build_sample_security_graph()
        rag = create_unified_rag(knowledge_graph=kg)
        self.assertIsInstance(rag, UnifiedRAGOrchestrator)
        self.assertIsNotNone(rag._kg)

    def test_create_without_session(self):
        """无会话创建"""
        rag = create_unified_rag(enable_session=False)
        self.assertFalse(rag.enable_session)


class TestSourceHitStats(unittest.TestCase):
    """来源命中统计测试"""

    def setUp(self):
        self.rag = create_unified_rag(enable_session=False)

    def test_hybrid_hits_counted(self):
        """混合检索命中统计"""
        result = self.rag.query("seccomp 沙箱逃逸 防护规则")
        self.assertIsInstance(result.hybrid_retrieval_hits, int)
        self.assertGreaterEqual(result.hybrid_retrieval_hits, 0)

    def test_kg_hits_counted(self):
        """知识图谱命中统计"""
        result = self.rag.query("CVE-2022-3602 OpenSSL")
        self.assertIsInstance(result.knowledge_graph_hits, int)
        self.assertGreaterEqual(result.knowledge_graph_hits, 0)

    def test_total_hits_equals_chunks(self):
        """总命中数等于片段数"""
        result = self.rag.query("seccomp 配置 规则")
        total = (
            result.hybrid_retrieval_hits
            + result.knowledge_graph_hits
            + result.session_context_hits
        )
        self.assertEqual(total, len(result.retrieved_chunks))


if __name__ == "__main__":
    unittest.main(verbosity=2)
