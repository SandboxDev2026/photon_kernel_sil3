"""
PhotonBox 智能查询路由与统一检索编排器 - 单元测试

覆盖：
1. 查询特征分析（NER、CVE检测、组件检测、类型分类、意图识别）
2. 路由规则引擎（默认规则、自定义规则、优先级、启用/禁用、命中统计）
3. 智能查询路由器（各查询类型路由、决策解释、置信度、路由统计）
4. 统一检索编排器（多后端检索、RRF融合、结果结构）
5. 数据结构（QueryFeatures/RoutingDecision/UnifiedSearchResult/RoutingRule）
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evolution.intelligent_query_router import (
    QueryFeatureAnalyzer, RoutingRuleEngine, IntelligentQueryRouter,
    UnifiedRetrievalOrchestrator, QueryFeatures, RoutingDecision,
    UnifiedSearchResult, RoutingRule, QueryType, RetrievalBackend,
    create_intelligent_router, create_unified_orchestrator,
)


class TestQueryFeatureAnalyzer(unittest.TestCase):
    """查询特征分析器测试"""

    def setUp(self):
        self.analyzer = QueryFeatureAnalyzer()

    def test_detect_cve(self):
        """检测 CVE 编号"""
        features = self.analyzer.analyze("CVE-2022-3602 漏洞")
        self.assertIn("CVE-2022-3602", features.detected_cves)
        self.assertIn("CVE-2022-3602", features.detected_entities)

    def test_detect_multiple_cves(self):
        """检测多个 CVE"""
        features = self.analyzer.analyze("CVE-2022-3602 和 CVE-2023-44487")
        self.assertEqual(len(features.detected_cves), 2)

    def test_detect_security_component(self):
        """检测安全组件"""
        features = self.analyzer.analyze("OpenSSL 缓冲区溢出")
        self.assertIn("openssl", features.detected_components)

    def test_detect_multiple_components(self):
        """检测多个组件"""
        features = self.analyzer.analyze("OpenSSL 和 gRPC 和 Firecracker")
        self.assertIn("openssl", features.detected_components)
        self.assertIn("grpc", features.detected_components)
        self.assertIn("firecracker", features.detected_components)

    def test_classify_entity_lookup(self):
        """分类：实体查询"""
        features = self.analyzer.analyze("CVE-2022-3602")
        self.assertEqual(features.query_type, "entity_lookup")
        self.assertGreater(features.confidence, 0.5)

    def test_classify_risk_assessment(self):
        """分类：风险评估"""
        features = self.analyzer.analyze("CVE-2022-3602 风险评估 影响分析")
        self.assertEqual(features.query_type, "risk_assessment")

    def test_classify_semantic_search(self):
        """分类：语义搜索"""
        features = self.analyzer.analyze("如何防止沙箱逃逸？有哪些最佳实践和防御策略可以参考？")
        self.assertEqual(features.query_type, "semantic_search")

    def test_classify_session_context(self):
        """分类：会话上下文"""
        features = self.analyzer.analyze("上次我们讨论的那个方案，继续")
        self.assertEqual(features.query_type, "session_context")

    def test_classify_attack_chain(self):
        """分类：攻击链"""
        features = self.analyzer.analyze("从 seccomp 绕过到容器逃逸的完整攻击链")
        self.assertEqual(features.query_type, "attack_chain")

    def test_classify_relation_query(self):
        """分类：关系查询"""
        features = self.analyzer.analyze("OpenSSL 和 gRPC 有什么关系？")
        self.assertEqual(features.query_type, "relation_query")

    def test_classify_keyword_search(self):
        """分类：关键词搜索（不含已知实体的短查询）"""
        features = self.analyzer.analyze("configuration settings")
        self.assertEqual(features.query_type, "keyword_search")

    def test_detect_question(self):
        """检测问题"""
        features = self.analyzer.analyze("什么是沙箱逃逸？")
        self.assertTrue(features.is_question)

    def test_detect_not_question(self):
        """检测非问题"""
        features = self.analyzer.analyze("沙箱逃逸的防御方法")
        self.assertFalse(features.is_question)

    def test_keyword_extraction(self):
        """关键词提取"""
        features = self.analyzer.analyze("how to prevent sandbox escape?")
        self.assertIsInstance(features.keywords, list)
        self.assertGreater(len(features.keywords), 0)
        # 停用词不应出现在关键词中
        self.assertNotIn("the", features.keywords)
        self.assertNotIn("how", features.keywords)

    def test_query_length(self):
        """查询长度"""
        features = self.analyzer.analyze("test")
        self.assertEqual(features.query_length, 4)

    def test_features_dict(self):
        """特征字典"""
        features = self.analyzer.analyze("CVE-2022-3602 OpenSSL")
        self.assertIn("cve_count", features.features)
        self.assertIn("component_count", features.features)
        self.assertEqual(features.features["cve_count"], 1)
        self.assertEqual(features.features["component_count"], 1)

    def test_no_cve_no_component(self):
        """无 CVE 无组件的查询"""
        features = self.analyzer.analyze("安全测试")
        self.assertEqual(len(features.detected_cves), 0)
        self.assertEqual(len(features.detected_components), 0)


class TestRoutingRuleEngine(unittest.TestCase):
    """路由规则引擎测试"""

    def setUp(self):
        self.engine = RoutingRuleEngine()

    def test_default_rules_exist(self):
        """默认规则存在"""
        self.assertGreater(len(self.engine.rules), 5)

    def test_default_rules_sorted_by_priority(self):
        """默认规则按优先级排序"""
        for i in range(len(self.engine.rules) - 1):
            self.assertGreaterEqual(
                self.engine.rules[i].priority,
                self.engine.rules[i + 1].priority,
            )

    def test_match_entity_lookup_rule(self):
        """匹配实体查询规则"""
        features = QueryFeatures(
            query="CVE-2022-3602",
            query_type="entity_lookup",
            confidence=0.75,
            detected_entities=["CVE-2022-3602"],
        )
        rule = self.engine.match_rule(features)
        self.assertIsNotNone(rule)
        self.assertEqual(rule.rule_id, "rule_entity_lookup")

    def test_match_risk_assessment_rule(self):
        """匹配风险评估规则"""
        features = QueryFeatures(
            query="风险评估",
            query_type="risk_assessment",
            confidence=0.8,
        )
        rule = self.engine.match_rule(features)
        self.assertIsNotNone(rule)
        self.assertEqual(rule.rule_id, "rule_risk_assessment")

    def test_match_general_rule(self):
        """匹配通用规则（回退）"""
        features = QueryFeatures(
            query="test",
            query_type="general",
            confidence=0.4,
        )
        rule = self.engine.match_rule(features)
        self.assertIsNotNone(rule)
        self.assertEqual(rule.rule_id, "rule_general")

    def test_add_custom_rule(self):
        """添加自定义规则"""
        custom_rule = RoutingRule(
            rule_id="custom_test",
            name="测试规则",
            description="测试",
            condition={"query_type": "semantic_search"},
            action={"backends": ["rrf_hybrid"]},
            priority=200,
        )
        self.engine.add_rule(custom_rule)
        # 新规则应该在最前面（优先级最高）
        self.assertEqual(self.engine.rules[0].rule_id, "custom_test")

    def test_remove_rule(self):
        """移除规则"""
        result = self.engine.remove_rule("rule_general")
        self.assertTrue(result)
        rule_ids = [r.rule_id for r in self.engine.rules]
        self.assertNotIn("rule_general", rule_ids)

    def test_remove_nonexistent_rule(self):
        """移除不存在的规则"""
        result = self.engine.remove_rule("nonexistent")
        self.assertFalse(result)

    def test_enable_disable_rule(self):
        """启用/禁用规则"""
        self.engine.disable_rule("rule_general")
        general_rule = [r for r in self.engine.rules if r.rule_id == "rule_general"][0]
        self.assertFalse(general_rule.enabled)

        self.engine.enable_rule("rule_general")
        self.assertTrue(general_rule.enabled)

    def test_disabled_rule_not_matched(self):
        """禁用的规则不被匹配"""
        self.engine.disable_rule("rule_entity_lookup")
        features = QueryFeatures(
            query="CVE-2022-3602",
            query_type="entity_lookup",
            confidence=0.75,
            detected_entities=["CVE-2022-3602"],
        )
        rule = self.engine.match_rule(features)
        # 禁用后要么匹配到其他规则，要么为 None（无匹配）
        if rule is not None:
            self.assertNotEqual(rule.rule_id, "rule_entity_lookup")

    def test_rule_hit_count(self):
        """规则命中计数"""
        features = QueryFeatures(
            query="CVE-2022-3602",
            query_type="entity_lookup",
            confidence=0.75,
            detected_entities=["CVE-2022-3602"],
        )
        before = [r for r in self.engine.rules if r.rule_id == "rule_entity_lookup"][0].hit_count
        self.engine.match_rule(features)
        after = [r for r in self.engine.rules if r.rule_id == "rule_entity_lookup"][0].hit_count
        self.assertEqual(after, before + 1)

    def test_get_rule_statistics(self):
        """获取规则统计"""
        stats = self.engine.get_rule_statistics()
        self.assertIsInstance(stats, list)
        self.assertGreater(len(stats), 0)
        self.assertIn("rule_id", stats[0])
        self.assertIn("hit_count", stats[0])


class TestIntelligentQueryRouter(unittest.TestCase):
    """智能查询路由器测试"""

    def setUp(self):
        self.router = IntelligentQueryRouter()

    def test_route_entity_lookup(self):
        """路由：实体查询"""
        decision = self.router.route("CVE-2022-3602")
        self.assertEqual(decision.query_type, "entity_lookup")
        self.assertIn("knowledge_graph", decision.selected_backends)
        self.assertGreater(decision.confidence, 0)

    def test_route_risk_assessment(self):
        """路由：风险评估"""
        decision = self.router.route("CVE-2022-3602 风险评估")
        self.assertEqual(decision.query_type, "risk_assessment")
        self.assertIn("knowledge_graph", decision.selected_backends)
        # 风险评估应该给知识图谱更高权重
        self.assertGreater(decision.backend_weights["knowledge_graph"], 1.0)

    def test_route_semantic_search(self):
        """路由：语义搜索"""
        decision = self.router.route("如何防止沙箱逃逸？有哪些最佳实践？")
        self.assertEqual(decision.query_type, "semantic_search")
        self.assertIn("rrf_hybrid", decision.selected_backends)

    def test_route_session_context(self):
        """路由：会话上下文"""
        decision = self.router.route("上次讨论的方案，继续")
        self.assertEqual(decision.query_type, "session_context")
        self.assertIn("session_state", decision.selected_backends)

    def test_route_attack_chain(self):
        """路由：攻击链"""
        decision = self.router.route("从绕过到逃逸的攻击链")
        self.assertEqual(decision.query_type, "attack_chain")
        self.assertIn("knowledge_graph", decision.selected_backends)

    def test_route_relation_query(self):
        """路由：关系查询"""
        decision = self.router.route("OpenSSL 和 gRPC 有什么关系？")
        self.assertEqual(decision.query_type, "relation_query")
        self.assertIn("knowledge_graph", decision.selected_backends)

    def test_route_decision_has_reasoning(self):
        """路由决策包含解释"""
        decision = self.router.route("CVE-2022-3602")
        self.assertTrue(decision.reasoning)
        self.assertIn("entity_lookup", decision.reasoning)

    def test_route_decision_has_metadata(self):
        """路由决策包含元数据"""
        decision = self.router.route("CVE-2022-3602")
        self.assertIn("matched_rule", decision.metadata)
        self.assertIn("detected_entities", decision.metadata)
        self.assertIn("detected_cves", decision.metadata)

    def test_route_rrf_enabled(self):
        """路由决策启用 RRF"""
        decision = self.router.route("CVE-2022-3602")
        self.assertTrue(decision.rrf_enabled)

    def test_route_top_k(self):
        """路由决策 Top-K"""
        decision = self.router.route("test", top_k=20)
        self.assertEqual(decision.top_k, 20)

    def test_analyze_query_public(self):
        """公开查询分析接口"""
        features = self.router.analyze_query("CVE-2022-3602")
        self.assertIsInstance(features, QueryFeatures)
        self.assertEqual(features.query_type, "entity_lookup")

    def test_routing_history(self):
        """路由历史记录"""
        before = len(self.router.routing_history)
        self.router.route("test1")
        self.router.route("test2")
        after = len(self.router.routing_history)
        self.assertEqual(after, before + 2)

    def test_get_routing_statistics(self):
        """获取路由统计"""
        self.router.route("CVE-2022-3602")
        self.router.route("如何防止沙箱逃逸？")
        stats = self.router.get_routing_statistics()
        self.assertEqual(stats["total_routes"], 2)
        self.assertIn("routes_by_type", stats)
        self.assertIn("backend_usage", stats)
        self.assertIn("rule_statistics", stats)


class TestUnifiedRetrievalOrchestrator(unittest.TestCase):
    """统一检索编排器测试"""

    def setUp(self):
        self.orchestrator = UnifiedRetrievalOrchestrator()

    def test_search_returns_structure(self):
        """检索返回结构完整"""
        result = self.orchestrator.search("CVE-2022-3602", top_k=5)
        self.assertIn("query", result)
        self.assertIn("routing_decision", result)
        self.assertIn("fused_results", result)
        self.assertIn("backend_results", result)
        self.assertIn("statistics", result)

    def test_search_statistics(self):
        """检索统计信息"""
        result = self.orchestrator.search("CVE-2022-3602", top_k=5)
        stats = result["statistics"]
        self.assertIn("total_results", stats)
        self.assertIn("backends_used", stats)
        self.assertIn("rrf_enabled", stats)
        self.assertIn("query_type", stats)
        self.assertIn("confidence", stats)

    def test_search_routing_decision(self):
        """检索包含路由决策"""
        result = self.orchestrator.search("CVE-2022-3602")
        decision = result["routing_decision"]
        self.assertIsInstance(decision, RoutingDecision)
        self.assertEqual(decision.query_type, "entity_lookup")

    def test_search_fused_results(self):
        """检索融合结果"""
        result = self.orchestrator.search("CVE-2022-3602", top_k=3)
        fused = result["fused_results"]
        self.assertIsInstance(fused, list)
        self.assertLessEqual(len(fused), 3)

    def test_search_with_session_id(self):
        """带会话 ID 检索"""
        result = self.orchestrator.search(
            "上次的方案", session_id="test-session", tenant_id="tenant-a"
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["routing_decision"].query_type, "session_context")

    def test_search_different_query_types(self):
        """不同查询类型都能检索"""
        queries = [
            "CVE-2022-3602",
            "风险评估",
            "如何防止沙箱逃逸？",
            "上次的方案",
            "攻击链分析",
        ]
        for query in queries:
            result = self.orchestrator.search(query, top_k=3)
            self.assertIsNotNone(result)
            self.assertIn("fused_results", result)

    def test_backend_results_structure(self):
        """各后端原始结果结构"""
        result = self.orchestrator.search("CVE-2022-3602")
        backend_results = result["backend_results"]
        self.assertIsInstance(backend_results, dict)
        for backend, results in backend_results.items():
            self.assertIsInstance(results, list)

    def test_create_orchestrator_with_backends(self):
        """创建带后端的编排器"""
        orchestrator = create_unified_orchestrator(
            rrf_retriever=None,
            knowledge_graph=None,
            session_manager=None,
        )
        self.assertIsInstance(orchestrator, UnifiedRetrievalOrchestrator)


class TestDataStructures(unittest.TestCase):
    """数据结构测试"""

    def test_query_features_defaults(self):
        """QueryFeatures 默认值"""
        features = QueryFeatures(query="test", query_type="general", confidence=0.5)
        self.assertEqual(features.detected_entities, [])
        self.assertEqual(features.detected_cves, [])
        self.assertEqual(features.detected_components, [])
        self.assertEqual(features.keywords, [])
        self.assertFalse(features.has_relation_pattern)
        self.assertFalse(features.has_risk_pattern)
        self.assertFalse(features.has_session_pattern)
        self.assertFalse(features.has_attack_chain_pattern)
        self.assertEqual(features.query_length, 0)
        self.assertFalse(features.is_question)

    def test_routing_decision_defaults(self):
        """RoutingDecision 默认值"""
        decision = RoutingDecision(
            query="test",
            query_type="general",
            selected_backends=["rrf_hybrid"],
            backend_weights={"rrf_hybrid": 1.0},
        )
        self.assertTrue(decision.rrf_enabled)
        self.assertEqual(decision.top_k, 10)
        self.assertEqual(decision.reasoning, "")
        self.assertEqual(decision.confidence, 0.0)
        self.assertEqual(decision.fallback_strategy, "rrf_hybrid")

    def test_unified_search_result_defaults(self):
        """UnifiedSearchResult 默认值"""
        result = UnifiedSearchResult(
            doc_id="test", score=0.5, rank=1, source="test"
        )
        self.assertEqual(result.content, "")
        self.assertIsNone(result.document)
        self.assertEqual(result.matched_backends, [])
        self.assertEqual(result.details, {})

    def test_routing_rule_defaults(self):
        """RoutingRule 默认值"""
        rule = RoutingRule(
            rule_id="test",
            name="test",
            description="test",
            condition={},
            action={},
        )
        self.assertEqual(rule.priority, 0)
        self.assertTrue(rule.enabled)
        self.assertEqual(rule.hit_count, 0)

    def test_query_type_enum(self):
        """查询类型枚举"""
        self.assertEqual(QueryType.ENTITY_LOOKUP.value, "entity_lookup")
        self.assertEqual(QueryType.SEMANTIC_SEARCH.value, "semantic_search")
        self.assertEqual(QueryType.KEYWORD_SEARCH.value, "keyword_search")
        self.assertEqual(QueryType.RELATION_QUERY.value, "relation_query")
        self.assertEqual(QueryType.SESSION_CONTEXT.value, "session_context")
        self.assertEqual(QueryType.RISK_ASSESSMENT.value, "risk_assessment")
        self.assertEqual(QueryType.ATTACK_CHAIN.value, "attack_chain")
        self.assertEqual(QueryType.GENERAL.value, "general")

    def test_retrieval_backend_enum(self):
        """检索后端枚举"""
        self.assertEqual(RetrievalBackend.RRF_HYBRID.value, "rrf_hybrid")
        self.assertEqual(RetrievalBackend.KNOWLEDGE_GRAPH.value, "knowledge_graph")
        self.assertEqual(RetrievalBackend.SESSION_STATE.value, "session_state")


class TestConvenienceFunctions(unittest.TestCase):
    """便捷接口函数测试"""

    def test_create_intelligent_router(self):
        """创建智能路由器"""
        router = create_intelligent_router()
        self.assertIsInstance(router, IntelligentQueryRouter)

    def test_create_unified_orchestrator(self):
        """创建统一编排器"""
        orchestrator = create_unified_orchestrator()
        self.assertIsInstance(orchestrator, UnifiedRetrievalOrchestrator)


if __name__ == "__main__":
    unittest.main(verbosity=2)
