"""
PhotonBox 三元组安全知识图谱 - 单元测试

覆盖：
1. 实体管理（添加、查询、别名、类型索引）
2. 三元组存储（添加、去重、置信度更新、索引）
3. 图遍历（BFS、多跳推理、双向遍历）
4. 安全风险推理（实例风险评估、漏洞-组件-实例关联）
5. 社区检测（简化版 Leiden）
6. 实体优先融合检索
7. 统计与导出
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evolution.security_knowledge_graph import (
    SecurityKnowledgeGraph, Triple, Entity, GraphSearchResult,
    SECURITY_PREDICATES, create_security_knowledge_graph,
    build_sample_security_graph,
)


class TestEntityManagement(unittest.TestCase):
    """实体管理测试"""

    def setUp(self):
        self.graph = SecurityKnowledgeGraph()

    def test_add_entity(self):
        """添加实体"""
        entity = self.graph.add_entity(
            "CVE-2022-3602", "vulnerability", "OpenSSL 缓冲区溢出",
            properties={"severity": "high", "cvss": 7.5},
        )
        self.assertEqual(entity.entity_id, "CVE-2022-3602")
        self.assertEqual(entity.entity_type, "vulnerability")
        self.assertEqual(entity.name, "OpenSSL 缓冲区溢出")
        self.assertEqual(entity.properties["severity"], "high")

    def test_get_entity(self):
        """获取实体"""
        self.graph.add_entity("test-1", "component", "Test Component")
        entity = self.graph.get_entity("test-1")
        self.assertIsNotNone(entity)
        self.assertEqual(entity.name, "Test Component")

    def test_get_nonexistent_entity(self):
        """获取不存在的实体"""
        entity = self.graph.get_entity("nonexistent")
        self.assertIsNone(entity)

    def test_find_entity_by_name(self):
        """通过名称查找实体"""
        self.graph.add_entity("CVE-2022-3602", "vulnerability", "OpenSSL X.509 漏洞")
        entity = self.graph.find_entity_by_name("OpenSSL")
        self.assertIsNotNone(entity)
        self.assertEqual(entity.entity_id, "CVE-2022-3602")

    def test_find_entity_by_alias(self):
        """通过别名查找实体"""
        self.graph.add_entity(
            "CVE-2022-3602", "vulnerability", "OpenSSL 漏洞",
            aliases=["openssl-buffer-overflow", "CVE20223602"],
        )
        entity = self.graph.find_entity_by_name("CVE20223602")
        self.assertIsNotNone(entity)
        self.assertEqual(entity.entity_id, "CVE-2022-3602")

    def test_get_entities_by_type(self):
        """按类型获取实体"""
        self.graph.add_entity("vuln-1", "vulnerability", "漏洞1")
        self.graph.add_entity("vuln-2", "vulnerability", "漏洞2")
        self.graph.add_entity("comp-1", "component", "组件1")
        vulns = self.graph.get_entities_by_type("vulnerability")
        self.assertEqual(len(vulns), 2)
        comps = self.graph.get_entities_by_type("component")
        self.assertEqual(len(comps), 1)


class TestTripleStorage(unittest.TestCase):
    """三元组存储测试"""

    def setUp(self):
        self.graph = SecurityKnowledgeGraph()

    def test_add_triple(self):
        """添加三元组"""
        triple = self.graph.add_triple(
            "CVE-2022-3602", "affects", "openssl-3.0.2",
            confidence=0.9, source="cve_database",
        )
        self.assertEqual(triple.subject, "CVE-2022-3602")
        self.assertEqual(triple.predicate, "affects")
        self.assertEqual(triple.object, "openssl-3.0.2")
        self.assertEqual(triple.confidence, 0.9)
        self.assertEqual(self.graph.triple_count, 1)

    def test_duplicate_triple(self):
        """重复三元组去重并更新置信度"""
        self.graph.add_triple("A", "rel", "B", confidence=0.5)
        self.graph.add_triple("A", "rel", "B", confidence=0.9)
        self.assertEqual(self.graph.triple_count, 1)
        # 置信度应取最大值
        triples = self.graph.get_triples_by_subject("A")
        self.assertEqual(triples[0].confidence, 0.9)

    def test_get_triples_by_subject(self):
        """按主体获取三元组"""
        self.graph.add_triple("A", "rel1", "B")
        self.graph.add_triple("A", "rel2", "C")
        self.graph.add_triple("D", "rel3", "E")
        triples = self.graph.get_triples_by_subject("A")
        self.assertEqual(len(triples), 2)

    def test_get_triples_by_object(self):
        """按客体获取三元组"""
        self.graph.add_triple("A", "rel1", "B")
        self.graph.add_triple("C", "rel2", "B")
        triples = self.graph.get_triples_by_object("B")
        self.assertEqual(len(triples), 2)

    def test_get_triples_by_predicate(self):
        """按谓词获取三元组"""
        self.graph.add_triple("A", "affects", "B")
        self.graph.add_triple("C", "affects", "D")
        self.graph.add_triple("E", "runs_on", "F")
        triples = self.graph.get_triples_by_predicate("affects")
        self.assertEqual(len(triples), 2)

    def test_get_related_entities(self):
        """获取相关实体"""
        self.graph.add_triple("A", "rel", "B")
        self.graph.add_triple("C", "rel", "A")
        related = self.graph.get_related_entities("A", direction="both")
        self.assertIn("B", related)
        self.assertIn("C", related)

    def test_get_related_entities_out_only(self):
        """只获取出边相关实体"""
        self.graph.add_triple("A", "rel", "B")
        self.graph.add_triple("C", "rel", "A")
        related = self.graph.get_related_entities("A", direction="out")
        self.assertIn("B", related)
        self.assertNotIn("C", related)


class TestGraphTraversal(unittest.TestCase):
    """图遍历测试"""

    def setUp(self):
        self.graph = SecurityKnowledgeGraph()
        # 构建链：A -> B -> C -> D
        self.graph.add_triple("A", "rel", "B")
        self.graph.add_triple("B", "rel", "C")
        self.graph.add_triple("C", "rel", "D")

    def test_bfs_basic(self):
        """基本 BFS 遍历"""
        paths = self.graph.bfs_traverse("A", max_depth=3, direction="out")
        self.assertIn("A", paths)
        self.assertIn("B", paths)
        self.assertIn("C", paths)
        self.assertIn("D", paths)
        self.assertEqual(paths["D"], ["A", "B", "C", "D"])

    def test_bfs_max_depth(self):
        """BFS 最大深度限制"""
        paths = self.graph.bfs_traverse("A", max_depth=2, direction="out")
        self.assertIn("A", paths)
        self.assertIn("B", paths)
        self.assertIn("C", paths)
        self.assertNotIn("D", paths)  # 深度3，超出限制

    def test_bfs_bidirectional(self):
        """双向 BFS 遍历"""
        # 添加入边：E -> A
        self.graph.add_triple("E", "rel", "A")
        paths = self.graph.bfs_traverse("A", max_depth=2, direction="both")
        self.assertIn("B", paths)  # 出边
        self.assertIn("E", paths)  # 入边

    def test_bfs_predicate_filter(self):
        """BFS 谓词过滤"""
        self.graph.add_triple("A", "other", "X")
        paths = self.graph.bfs_traverse(
            "A", max_depth=3, predicate_filter={"rel"}, direction="out"
        )
        self.assertIn("B", paths)
        self.assertNotIn("X", paths)

    def test_multi_hop_reasoning(self):
        """多跳推理"""
        self.graph.add_entity("A", "vulnerability", "漏洞A")
        self.graph.add_entity("B", "component", "组件B")
        self.graph.add_entity("C", "sandbox_instance", "实例C")
        results = self.graph.multi_hop_reasoning("A", "sandbox_instance", max_depth=3)
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0].entity_id, "C")
        self.assertEqual(results[0].path, ["A", "B", "C"])

    def test_multi_hop_reasoning_no_target(self):
        """多跳推理无目标类型"""
        results = self.graph.multi_hop_reasoning("A", "nonexistent_type", max_depth=3)
        self.assertEqual(len(results), 0)


class TestSecurityRiskAssessment(unittest.TestCase):
    """安全风险推理测试"""

    def setUp(self):
        self.graph = build_sample_security_graph()

    def test_assess_instance_risk(self):
        """沙箱实例风险评估"""
        risk = self.graph.assess_instance_risk("sandbox-instance-001")
        self.assertEqual(risk["instance_id"], "sandbox-instance-001")
        self.assertIn("risk_score", risk)
        self.assertIn("risk_level", risk)
        self.assertGreaterEqual(risk["risk_score"], 0)
        self.assertLessEqual(risk["risk_score"], 100)
        self.assertGreater(len(risk["vulnerabilities"]), 0)
        self.assertGreater(len(risk["components"]), 0)

    def test_risk_level_classification(self):
        """风险等级分类"""
        # 高风险实例（有多个高危漏洞）
        risk = self.graph.assess_instance_risk("sandbox-instance-001")
        self.assertIn(risk["risk_level"], ["high", "critical"])

    def test_risk_breakdown(self):
        """风险分解"""
        risk = self.graph.assess_instance_risk("sandbox-instance-001")
        self.assertIn("base_risk_from_vulnerabilities", risk["risk_breakdown"])
        self.assertIn("attack_pattern_bonus", risk["risk_breakdown"])
        self.assertIn("defense_mitigation", risk["risk_breakdown"])

    def test_attack_patterns_detected(self):
        """攻击模式检测"""
        risk = self.graph.assess_instance_risk("sandbox-instance-001")
        self.assertGreater(len(risk["attack_patterns"]), 0)

    def test_defense_rules_detected(self):
        """防御规则检测"""
        risk = self.graph.assess_instance_risk("sandbox-instance-001")
        self.assertGreater(len(risk["defense_rules"]), 0)

    def test_instance_with_no_vulnerabilities(self):
        """无漏洞实例风险评估"""
        # 创建一个没有漏洞的实例
        self.graph.add_entity("safe-instance", "sandbox_instance", "安全实例")
        self.graph.add_entity("safe-component", "component", "安全组件")
        self.graph.add_triple("safe-instance", "runs_on", "safe-component")
        risk = self.graph.assess_instance_risk("safe-instance")
        self.assertEqual(risk["risk_score"], 0)
        self.assertEqual(risk["risk_level"], "low")
        self.assertEqual(len(risk["vulnerabilities"]), 0)


class TestCommunityDetection(unittest.TestCase):
    """社区检测测试"""

    def setUp(self):
        self.graph = SecurityKnowledgeGraph()

    def test_detect_communities_basic(self):
        """基本社区检测"""
        # 创建两个独立的社区
        for i in range(3):
            self.graph.add_entity(f"vuln-a-{i}", "vulnerability", f"漏洞A{i}")
            self.graph.add_entity(f"vuln-b-{i}", "vulnerability", f"漏洞B{i}")
        # 社区 A 内部连接
        self.graph.add_triple("vuln-a-0", "related_to", "vuln-a-1")
        self.graph.add_triple("vuln-a-1", "related_to", "vuln-a-2")
        # 社区 B 内部连接
        self.graph.add_triple("vuln-b-0", "related_to", "vuln-b-1")
        self.graph.add_triple("vuln-b-1", "related_to", "vuln-b-2")

        communities = self.graph.detect_communities(entity_type="vulnerability")
        self.assertGreaterEqual(len(communities), 1)
        # 所有实体都应被分配到社区
        all_entities = set()
        for comm in communities:
            all_entities.update(comm)
        self.assertEqual(len(all_entities), 6)

    def test_detect_communities_single_node(self):
        """单节点社区检测"""
        self.graph.add_entity("single", "vulnerability", "单节点")
        communities = self.graph.detect_communities(entity_type="vulnerability")
        self.assertEqual(len(communities), 1)
        self.assertEqual(communities[0], {"single"})

    def test_detect_communities_empty(self):
        """空图谱社区检测"""
        communities = self.graph.detect_communities()
        self.assertEqual(len(communities), 0)

    def test_detect_communities_resolution(self):
        """分辨率参数影响社区大小"""
        # 创建一个完全连接的图
        for i in range(5):
            self.graph.add_entity(f"n{i}", "vulnerability", f"节点{i}")
        for i in range(5):
            for j in range(i + 1, 5):
                self.graph.add_triple(f"n{i}", "related_to", f"n{j}")

        # 低分辨率 → 大社区
        communities_low = self.graph.detect_communities(
            entity_type="vulnerability", resolution=0.1
        )
        # 高分辨率 → 小社区
        communities_high = self.graph.detect_communities(
            entity_type="vulnerability", resolution=2.0
        )
        # 高分辨率不应产生更少社区（通常更多或相等）
        self.assertGreaterEqual(len(communities_high), len(communities_low))


class TestEntityFirstSearch(unittest.TestCase):
    """实体优先融合检索测试"""

    def setUp(self):
        self.graph = build_sample_security_graph()

    def test_entity_first_search_match(self):
        """匹配到标准实体的检索"""
        result = self.graph.entity_first_search("CVE-2022-3602 OpenSSL 漏洞")
        self.assertEqual(result["search_mode"], "entity_first")
        self.assertGreater(len(result["matched_entities"]), 0)
        self.assertGreater(len(result["results"]), 0)

    def test_entity_first_search_by_alias(self):
        """通过别名匹配实体"""
        result = self.graph.entity_first_search("openssl-buffer-overflow 漏洞")
        self.assertEqual(result["search_mode"], "entity_first")
        self.assertIn("CVE-2022-3602", result["matched_entities"])

    def test_entity_first_search_fallback(self):
        """未匹配实体的退化检索"""
        result = self.graph.entity_first_search("完全不相关的查询内容")
        self.assertEqual(result["search_mode"], "fallback")
        self.assertEqual(len(result["matched_entities"]), 0)

    def test_entity_first_search_result_structure(self):
        """检索结果结构完整"""
        result = self.graph.entity_first_search("CVE-2022-3602")
        self.assertIn("search_mode", result)
        self.assertIn("matched_entities", result)
        self.assertIn("results", result)
        self.assertIn("message", result)
        if result["results"]:
            self.assertIn("entity", result["results"][0])
            self.assertIn("related_triples", result["results"][0])
            self.assertIn("related_entities", result["results"][0])

    def test_entity_first_search_top_k(self):
        """Top-K 限制"""
        result = self.graph.entity_first_search("OpenSSL", top_k=1)
        self.assertLessEqual(len(result["results"]), 1)


class TestStatisticsAndExport(unittest.TestCase):
    """统计与导出测试"""

    def setUp(self):
        self.graph = build_sample_security_graph()

    def test_get_statistics(self):
        """获取统计信息"""
        stats = self.graph.get_statistics()
        self.assertEqual(stats["total_entities"], 12)
        self.assertEqual(stats["total_triples"], 14)
        self.assertIn("entities_by_type", stats)
        self.assertIn("triples_by_predicate", stats)
        self.assertIn("average_connections_per_entity", stats)
        self.assertGreater(stats["average_connections_per_entity"], 0)

    def test_export_triples(self):
        """导出三元组"""
        exported = self.graph.export_triples()
        self.assertEqual(len(exported), 14)
        for triple in exported:
            self.assertIn("subject", triple)
            self.assertIn("predicate", triple)
            self.assertIn("object", triple)
            self.assertIn("confidence", triple)
            self.assertIn("source", triple)

    def test_security_predicates_defined(self):
        """安全领域谓词已定义"""
        self.assertIn("affects", SECURITY_PREDICATES)
        self.assertIn("runs_on", SECURITY_PREDICATES)
        self.assertIn("exploited_by", SECURITY_PREDICATES)
        self.assertIn("protected_by", SECURITY_PREDICATES)
        self.assertIn("has_severity", SECURITY_PREDICATES)
        self.assertGreater(len(SECURITY_PREDICATES), 20)


class TestConvenienceFunctions(unittest.TestCase):
    """便捷接口函数测试"""

    def test_create_security_knowledge_graph(self):
        """创建安全知识图谱"""
        graph = create_security_knowledge_graph()
        self.assertIsInstance(graph, SecurityKnowledgeGraph)
        self.assertEqual(graph.triple_count, 0)

    def test_build_sample_security_graph(self):
        """构建示例安全知识图谱"""
        graph = build_sample_security_graph()
        self.assertIsInstance(graph, SecurityKnowledgeGraph)
        self.assertGreater(graph.triple_count, 0)
        self.assertGreater(len(graph.entities), 0)
        # 验证包含关键实体
        self.assertIsNotNone(graph.get_entity("CVE-2022-3602"))
        self.assertIsNotNone(graph.get_entity("sandbox-instance-001"))
        self.assertIsNotNone(graph.get_entity("rule-seccomp-strict"))


class TestTripleDataclass(unittest.TestCase):
    """三元组数据类测试"""

    def test_triple_equality(self):
        """三元组相等性（主体+谓词+客体）"""
        t1 = Triple("A", "rel", "B", confidence=0.5)
        t2 = Triple("A", "rel", "B", confidence=0.9)
        self.assertEqual(t1, t2)  # 置信度不同但三元组相同

    def test_triple_inequality(self):
        """三元组不等性"""
        t1 = Triple("A", "rel", "B")
        t2 = Triple("A", "rel", "C")
        self.assertNotEqual(t1, t2)

    def test_triple_hash(self):
        """三元组哈希（用于集合去重）"""
        t1 = Triple("A", "rel", "B", confidence=0.5)
        t2 = Triple("A", "rel", "B", confidence=0.9)
        self.assertEqual(hash(t1), hash(t2))
        # 集合去重
        s = {t1, t2}
        self.assertEqual(len(s), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
