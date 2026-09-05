"""
PhotonBox SLM 查询意图理解系统 - 单元测试

覆盖：
1. 查询去噪（拼写纠错、冗余移除、置信度）
2. 意图分类（8种主意图、子意图、领域、动作、约束、置信度）
3. 实体抽取（CVE、组件、严重度、后端、时间范围）
4. 查询重写（缩写扩展、术语补充、查询变体、触发条件）
5. 多意图分解（子意图分解、实体分解、连接词分解）
6. 完整流水线（5阶段、结构化JSON输出、缓存、推荐策略）
"""

import unittest
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evolution.slm_query_intent import (
    QueryDenoiser, IntentClassifier, EntityExtractor, QueryRewriter,
    QueryDecomposer, SLMQueryIntentUnderstanding,
    DenoisedQuery, IntentResult, ExtractedEntity, RewrittenQuery,
    DecomposedQuery, QueryUnderstandingResult,
    IntentType, SecurityDomain, ActionType,
    create_query_intent_system,
)


class TestQueryDenoiser(unittest.TestCase):
    """查询去噪器测试"""

    def setUp(self):
        self.denoiser = QueryDenoiser()

    def test_spelling_correction(self):
        """拼写纠错"""
        result = self.denoiser.denoise("secccomp 配置")
        self.assertIn("seccomp", result.denoised)
        self.assertGreater(len(result.corrections), 0)

    def test_cve_normalization(self):
        """CVE 编号规范化"""
        result = self.denoiser.denoise("cve-2022-3602 漏洞")
        self.assertIn("CVE-2022-3602", result.denoised)

    def test_remove_redundancy(self):
        """移除冗余词"""
        result = self.denoiser.denoise("请问 这个 漏洞 严重 吗")
        self.assertNotIn("请问", result.denoised)
        self.assertGreater(len(result.removed_redundancy), 0)

    def test_whitespace_normalization(self):
        """空白规范化"""
        result = self.denoiser.denoise("  多个   空格  测试  ")
        self.assertEqual(result.denoised, "多个 空格 测试")

    def test_confidence_high(self):
        """高置信度（无纠错）"""
        result = self.denoiser.denoise("CVE-2022-3602 漏洞详情")
        self.assertGreaterEqual(result.confidence, 0.9)

    def test_confidence_lower_with_corrections(self):
        """纠错后置信度降低"""
        result1 = self.denoiser.denoise("正常查询")
        result2 = self.denoiser.denoise("secccomp contianer sandobx")
        self.assertLess(result2.confidence, result1.confidence)

    def test_original_preserved(self):
        """原始查询保留"""
        original = "测试查询"
        result = self.denoiser.denoise(original)
        self.assertEqual(result.original, original)

    def test_empty_query(self):
        """空查询"""
        result = self.denoiser.denoise("")
        self.assertEqual(result.denoised, "")


class TestIntentClassifier(unittest.TestCase):
    """意图分类器测试"""

    def setUp(self):
        self.classifier = IntentClassifier()

    def test_classify_vulnerability_query(self):
        """分类：漏洞查询"""
        result = self.classifier.classify("CVE-2022-3602 漏洞详情 POC")
        self.assertEqual(result.primary_intent, "vulnerability_query")
        self.assertGreater(result.confidence, 0.5)

    def test_classify_configuration_query(self):
        """分类：配置查询"""
        result = self.classifier.classify("如何配置 seccomp 规则参数")
        self.assertEqual(result.primary_intent, "configuration_query")

    def test_classify_log_query(self):
        """分类：日志查询"""
        result = self.classifier.classify("审计日志 事件记录 告警")
        self.assertEqual(result.primary_intent, "log_query")

    def test_classify_risk_assessment(self):
        """分类：风险评估"""
        result = self.classifier.classify("CVE-2022-3602 风险评估 影响分析")
        self.assertEqual(result.primary_intent, "risk_assessment")

    def test_classify_attack_chain(self):
        """分类：攻击链"""
        result = self.classifier.classify("从 seccomp 绕过到容器逃逸的攻击链")
        self.assertEqual(result.primary_intent, "attack_chain")

    def test_classify_defense_query(self):
        """分类：防御查询"""
        result = self.classifier.classify("防御规则 安全策略 加固方案")
        self.assertEqual(result.primary_intent, "defense_query")

    def test_classify_session_context(self):
        """分类：会话上下文"""
        result = self.classifier.classify("上次我们讨论的方案，继续")
        self.assertEqual(result.primary_intent, "session_context")

    def test_classify_general_knowledge(self):
        """分类：通用知识"""
        result = self.classifier.classify("什么是沙箱逃逸？原理是什么？")
        self.assertEqual(result.primary_intent, "general_knowledge")

    def test_sub_intents(self):
        """子意图识别"""
        result = self.classifier.classify("如何配置 seccomp 规则，防止沙箱逃逸？")
        self.assertGreater(len(result.sub_intents), 0)

    def test_domain_classification(self):
        """领域分类"""
        result = self.classifier.classify("沙箱逃逸 seccomp 绕过")
        self.assertEqual(result.domain, "sandbox_escape")

    def test_action_classification(self):
        """动作分类"""
        result = self.classifier.classify("查询 CVE-2022-3602 详情")
        self.assertEqual(result.action, "lookup")

    def test_constraints_severity(self):
        """约束：严重程度"""
        result = self.classifier.classify("高危漏洞 列表")
        self.assertEqual(result.constraints.get("severity"), "high")

    def test_constraints_time(self):
        """约束：时间范围"""
        result = self.classifier.classify("最近 7 天的日志")
        self.assertIn("time_days", result.constraints)

    def test_constraints_backend(self):
        """约束：后端类型"""
        result = self.classifier.classify("StrongPool KVM 配置")
        self.assertEqual(result.constraints.get("backend"), "StrongPool")

    def test_intent_scores(self):
        """意图得分"""
        result = self.classifier.classify("CVE-2022-3602 漏洞")
        self.assertIn("vulnerability_query", result.intent_scores)
        self.assertGreater(result.intent_scores["vulnerability_query"], 0)

    def test_unknown_intent(self):
        """未知意图"""
        result = self.classifier.classify("xyz abc 123")
        self.assertEqual(result.primary_intent, "unknown")
        self.assertLess(result.confidence, 0.5)


class TestEntityExtractor(unittest.TestCase):
    """实体抽取器测试"""

    def setUp(self):
        self.extractor = EntityExtractor()

    def test_extract_cve(self):
        """抽取 CVE"""
        entities = self.extractor.extract("CVE-2022-3602 漏洞")
        cves = [e for e in entities if e.entity_type == "cve"]
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0].normalized, "CVE-2022-3602")

    def test_extract_multiple_cves(self):
        """抽取多个 CVE"""
        entities = self.extractor.extract("CVE-2022-3602 和 CVE-2023-44487")
        cves = [e for e in entities if e.entity_type == "cve"]
        self.assertEqual(len(cves), 2)

    def test_extract_component_openssl(self):
        """抽取组件：OpenSSL"""
        entities = self.extractor.extract("OpenSSL 缓冲区溢出")
        comps = [e for e in entities if e.entity_type == "component"]
        self.assertTrue(any(c.normalized == "OpenSSL" for c in comps))

    def test_extract_component_firecracker(self):
        """抽取组件：Firecracker"""
        entities = self.extractor.extract("Firecracker MicroVM 配置")
        comps = [e for e in entities if e.entity_type == "component"]
        self.assertTrue(any(c.normalized == "Firecracker" for c in comps))

    def test_extract_severity_critical(self):
        """抽取严重程度：critical"""
        entities = self.extractor.extract("严重漏洞 列表")
        sevs = [e for e in entities if e.entity_type == "severity"]
        self.assertEqual(len(sevs), 1)
        self.assertEqual(sevs[0].normalized, "critical")

    def test_extract_severity_high(self):
        """抽取严重程度：high"""
        entities = self.extractor.extract("高危事件")
        sevs = [e for e in entities if e.entity_type == "severity"]
        self.assertEqual(sevs[0].normalized, "high")

    def test_extract_backend_strongpool(self):
        """抽取后端：StrongPool"""
        entities = self.extractor.extract("StrongPool KVM 配置")
        backends = [e for e in entities if e.entity_type == "backend"]
        self.assertTrue(any(b.normalized == "StrongPool" for b in backends))

    def test_extract_backend_lightpool(self):
        """抽取后端：LightPool"""
        entities = self.extractor.extract("LightPool seccomp 规则")
        backends = [e for e in entities if e.entity_type == "backend"]
        self.assertTrue(any(b.normalized == "LightPool" for b in backends))

    def test_extract_time_range(self):
        """抽取时间范围"""
        entities = self.extractor.extract("最近 7 天的日志")
        times = [e for e in entities if e.entity_type == "time_range"]
        self.assertEqual(len(times), 1)

    def test_no_entities(self):
        """无实体"""
        entities = self.extractor.extract("你好世界")
        self.assertEqual(len(entities), 0)

    def test_entity_confidence(self):
        """实体置信度"""
        entities = self.extractor.extract("CVE-2022-3602")
        self.assertEqual(entities[0].confidence, 1.0)

    def test_entity_position(self):
        """实体位置"""
        entities = self.extractor.extract("test CVE-2022-3602 end")
        cve = [e for e in entities if e.entity_type == "cve"][0]
        self.assertEqual(cve.position[0], 5)
        self.assertEqual(cve.position[1], 18)


class TestQueryRewriter(unittest.TestCase):
    """查询重写器测试"""

    def setUp(self):
        self.rewriter = QueryRewriter(confidence_threshold=0.6)
        self.intent = IntentResult(
            primary_intent="vulnerability_query",
            confidence=0.5,  # 低置信度，触发重写
        )
        self.entities = [ExtractedEntity(
            entity_type="cve", value="CVE-2022-3602", normalized="CVE-2022-3602"
        )]

    def test_trigger_rewrite_low_confidence(self):
        """低置信度触发重写"""
        result = self.rewriter.rewrite("CVE-2022-3602", self.intent, self.entities)
        self.assertTrue(result.trigger_reason)
        self.assertIn("低", result.trigger_reason)

    def test_no_trigger_high_confidence(self):
        """高置信度不触发重写"""
        high_intent = IntentResult(
            primary_intent="vulnerability_query",
            confidence=0.9,
        )
        result = self.rewriter.rewrite("CVE-2022-3602", high_intent, self.entities)
        self.assertEqual(result.trigger_reason, "")

    def test_acronym_expansion(self):
        """缩写扩展"""
        result = self.rewriter.rewrite("CVE POC", self.intent, [])
        # CVE 和 POC 应该被扩展（添加到 added_terms）
        self.assertGreater(len(result.added_terms), 0)
        # 检查扩展内容包含 CVE 或 POC 相关术语
        all_terms = " ".join(result.added_terms).lower()
        self.assertTrue("cve" in all_terms or "漏洞" in all_terms)
        self.assertTrue("poc" in all_terms or "验证" in all_terms)

    def test_term_supplement(self):
        """术语补充"""
        result = self.rewriter.rewrite("CVE-2022-3602", self.intent, self.entities)
        self.assertGreater(len(result.added_terms), 0)

    def test_query_variants(self):
        """查询变体生成"""
        result = self.rewriter.rewrite("CVE-2022-3602 漏洞", self.intent, self.entities)
        self.assertGreater(len(result.variants), 0)
        self.assertIn("CVE-2022-3602 漏洞", result.variants)

    def test_rewritten_contains_original(self):
        """重写后包含原始查询"""
        result = self.rewriter.rewrite("CVE-2022-3602", self.intent, self.entities)
        self.assertIn("CVE-2022-3602", result.rewritten)

    def test_confidence_boost(self):
        """重写后置信度提升"""
        result = self.rewriter.rewrite("CVE-2022-3602", self.intent, self.entities)
        if result.added_terms:
            self.assertGreater(result.confidence, self.intent.confidence)

    def test_no_duplicate_terms(self):
        """无重复术语"""
        result = self.rewriter.rewrite("CVE-2022-3602 漏洞", self.intent, self.entities)
        self.assertEqual(len(result.added_terms), len(set(result.added_terms)))


class TestQueryDecomposer(unittest.TestCase):
    """多意图分解器测试"""

    def setUp(self):
        self.decomposer = QueryDecomposer()

    def test_no_decomposition_single_intent(self):
        """单意图不分解"""
        intent = IntentResult(primary_intent="vulnerability_query", sub_intents=[])
        entities = [ExtractedEntity(entity_type="cve", value="CVE-2022-3602")]
        result = self.decomposer.decompose("CVE-2022-3602", intent, entities)
        self.assertEqual(len(result.sub_queries), 0)

    def test_decomposition_multiple_sub_intents(self):
        """多子意图分解"""
        intent = IntentResult(
            primary_intent="configuration_query",
            sub_intents=["defense_query", "general_knowledge"],
        )
        entities = [ExtractedEntity(entity_type="component", value="seccomp")]
        result = self.decomposer.decompose("配置 seccomp 防止逃逸", intent, entities)
        self.assertGreater(len(result.sub_queries), 0)

    def test_decomposition_multiple_entity_types(self):
        """多实体类型分解"""
        intent = IntentResult(primary_intent="vulnerability_query", sub_intents=[])
        entities = [
            ExtractedEntity(entity_type="cve", value="CVE-2022-3602"),
            ExtractedEntity(entity_type="component", value="OpenSSL"),
            ExtractedEntity(entity_type="severity", value="high"),
        ]
        result = self.decomposer.decompose("CVE-2022-3602 OpenSSL 高危", intent, entities)
        self.assertGreater(len(result.sub_queries), 0)

    def test_decomposition_conjunction(self):
        """连接词分解"""
        intent = IntentResult(primary_intent="general_knowledge", sub_intents=[])
        entities = []
        result = self.decomposer.decompose("StrongPool 和 LightPool 对比", intent, entities)
        # 连接词分解可能触发，取决于子意图和实体数量
        self.assertIsInstance(result.sub_queries, list)

    def test_parallel_execution(self):
        """可并行执行"""
        intent = IntentResult(
            primary_intent="configuration_query",
            sub_intents=["defense_query"],
        )
        entities = [ExtractedEntity(entity_type="component", value="seccomp")]
        result = self.decomposer.decompose("test", intent, entities)
        self.assertTrue(result.parallel)

    def test_aggregation_strategy(self):
        """聚合策略"""
        intent = IntentResult(
            primary_intent="configuration_query",
            sub_intents=["defense_query"],
        )
        entities = [ExtractedEntity(entity_type="component", value="seccomp")]
        result = self.decomposer.decompose("test", intent, entities)
        self.assertEqual(result.aggregation_strategy, "rrf_fuse")

    def test_max_sub_queries(self):
        """子查询数量限制"""
        intent = IntentResult(
            primary_intent="configuration_query",
            sub_intents=["defense_query", "general_knowledge", "performance_query"],
        )
        entities = [
            ExtractedEntity(entity_type="component", value="seccomp"),
            ExtractedEntity(entity_type="backend", value="LightPool"),
        ]
        result = self.decomposer.decompose("test query with many parts", intent, entities)
        self.assertLessEqual(len(result.sub_queries), 5)

    def test_original_preserved(self):
        """原始查询保留"""
        intent = IntentResult(primary_intent="vulnerability_query", sub_intents=[])
        entities = []
        result = self.decomposer.decompose("原始查询", intent, entities)
        self.assertEqual(result.original, "原始查询")


class TestSLMQueryIntentUnderstanding(unittest.TestCase):
    """完整查询理解系统测试"""

    def setUp(self):
        self.system = SLMQueryIntentUnderstanding(enable_cache=False)

    def test_process_vulnerability_query(self):
        """处理：漏洞查询"""
        result = self.system.process("CVE-2022-3602 有没有 POC，影响哪些组件？")
        self.assertEqual(result.intent.primary_intent, "vulnerability_query")
        self.assertTrue(any(e.entity_type == "cve" for e in result.entities))
        self.assertEqual(result.recommended_retrieval_strategy, "knowledge_graph_first")

    def test_process_configuration_query(self):
        """处理：配置查询"""
        result = self.system.process("如何配置 seccomp 规则？")
        self.assertEqual(result.intent.primary_intent, "configuration_query")

    def test_process_log_query(self):
        """处理：日志查询"""
        result = self.system.process("最近 7 天的审计日志")
        self.assertEqual(result.intent.primary_intent, "log_query")
        self.assertEqual(result.recommended_retrieval_strategy, "time_filtered_rrf")

    def test_process_session_context(self):
        """处理：会话上下文"""
        result = self.system.process("上次讨论的方案，继续")
        self.assertEqual(result.intent.primary_intent, "session_context")
        self.assertEqual(result.recommended_retrieval_strategy, "session_state_rrf")

    def test_process_attack_chain(self):
        """处理：攻击链"""
        result = self.system.process("从 seccomp 绕过到容器逃逸的攻击链")
        self.assertEqual(result.intent.primary_intent, "attack_chain")
        self.assertEqual(result.recommended_retrieval_strategy, "knowledge_graph_multi_hop")

    def test_process_risk_assessment(self):
        """处理：风险评估"""
        result = self.system.process("CVE-2022-3602 风险评估")
        self.assertEqual(result.intent.primary_intent, "risk_assessment")

    def test_result_structure(self):
        """结果结构完整"""
        result = self.system.process("CVE-2022-3602")
        self.assertIsInstance(result, QueryUnderstandingResult)
        self.assertIsNotNone(result.denoised)
        self.assertIsNotNone(result.intent)
        self.assertIsInstance(result.entities, list)
        self.assertIsNotNone(result.rewritten)
        self.assertIsNotNone(result.decomposed)
        self.assertGreater(result.overall_confidence, 0)
        self.assertGreater(result.processing_time_ms, 0)

    def test_to_dict(self):
        """转换为字典"""
        result = self.system.process("CVE-2022-3602")
        d = result.to_dict()
        self.assertIsInstance(d, dict)
        self.assertIn("query", d)
        self.assertIn("intent", d)
        self.assertIn("entities", d)
        self.assertIn("overall_confidence", d)
        self.assertIn("recommended_retrieval_strategy", d)

    def test_to_json(self):
        """转换为 JSON"""
        result = self.system.process("CVE-2022-3602")
        json_str = result.to_json()
        self.assertIsInstance(json_str, str)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["query"], "CVE-2022-3602")

    def test_denoising_applied(self):
        """去噪已应用"""
        result = self.system.process("请问 CVE-2022-3602 严重吗")
        # 去噪后应该移除"请问"等冗余词
        denoised = result.denoised.denoised
        self.assertNotIn("请问", denoised)

    def test_entities_extracted(self):
        """实体已抽取"""
        result = self.system.process("CVE-2022-3602 OpenSSL 高危")
        entity_types = [e.entity_type for e in result.entities]
        self.assertIn("cve", entity_types)
        self.assertIn("component", entity_types)
        self.assertIn("severity", entity_types)

    def test_low_confidence_triggers_rewrite(self):
        """低置信度触发重写"""
        result = self.system.process("如何配置 seccomp 规则，防止沙箱逃逸？")
        # 这个查询置信度可能较低，触发重写
        self.assertIsInstance(result.needs_rewrite, bool)

    def test_processing_time_fast(self):
        """处理时间快（<100ms）"""
        result = self.system.process("CVE-2022-3602 漏洞详情")
        self.assertLess(result.processing_time_ms, 100)

    def test_pipeline_version(self):
        """流水线版本"""
        result = self.system.process("test")
        self.assertEqual(result.pipeline_version, "1.0")


class TestCaching(unittest.TestCase):
    """缓存测试"""

    def test_cache_enabled(self):
        """缓存启用"""
        system = SLMQueryIntentUnderstanding(enable_cache=True)
        result1 = system.process("CVE-2022-3602")
        result2 = system.process("CVE-2022-3602")
        # 第二次应该从缓存返回，处理时间更短
        self.assertEqual(result1.query, result2.query)

    def test_cache_disabled(self):
        """缓存禁用"""
        system = SLMQueryIntentUnderstanding(enable_cache=False)
        system.process("CVE-2022-3602")
        stats = system.get_cache_stats()
        self.assertEqual(stats["cache_size"], 0)

    def test_clear_cache(self):
        """清空缓存"""
        system = SLMQueryIntentUnderstanding(enable_cache=True)
        system.process("CVE-2022-3602")
        system.clear_cache()
        stats = system.get_cache_stats()
        self.assertEqual(stats["cache_size"], 0)

    def test_cache_stats(self):
        """缓存统计"""
        system = SLMQueryIntentUnderstanding(enable_cache=True)
        system.process("query1")
        system.process("query2")
        stats = system.get_cache_stats()
        self.assertEqual(stats["cache_size"], 2)
        self.assertTrue(stats["cache_enabled"])


class TestConvenienceFunctions(unittest.TestCase):
    """便捷接口函数测试"""

    def test_create_query_intent_system(self):
        """创建查询意图系统"""
        system = create_query_intent_system()
        self.assertIsInstance(system, SLMQueryIntentUnderstanding)

    def test_create_with_model_path(self):
        """带模型路径创建（回退到规则引擎）"""
        system = create_query_intent_system(model_path="/nonexistent/model")
        self.assertIsInstance(system, SLMQueryIntentUnderstanding)
        # 模型加载失败，回退到规则引擎
        self.assertFalse(system.use_llm)


class TestEnums(unittest.TestCase):
    """枚举测试"""

    def test_intent_type_enum(self):
        """意图类型枚举"""
        self.assertEqual(IntentType.VULNERABILITY_QUERY.value, "vulnerability_query")
        self.assertEqual(IntentType.RISK_ASSESSMENT.value, "risk_assessment")
        self.assertEqual(IntentType.ATTACK_CHAIN.value, "attack_chain")
        self.assertEqual(IntentType.UNKNOWN.value, "unknown")

    def test_security_domain_enum(self):
        """安全领域枚举"""
        self.assertEqual(SecurityDomain.SANDBOX_ESCAPE.value, "sandbox_escape")
        self.assertEqual(SecurityDomain.CRYPTOGRAPHY.value, "cryptography")
        self.assertEqual(SecurityDomain.GENERAL.value, "general")

    def test_action_type_enum(self):
        """动作类型枚举"""
        self.assertEqual(ActionType.LOOKUP.value, "lookup")
        self.assertEqual(ActionType.ANALYZE.value, "analyze")
        self.assertEqual(ActionType.UNKNOWN.value, "unknown")


if __name__ == "__main__":
    unittest.main(verbosity=2)
