"""
PhotonBox RRF 混合检索模块 - 单元测试

覆盖：
1. 文本预处理（分词、停用词、小写化）
2. 关键词检索（BM25、文档频率、IDF）
3. 向量检索（TF-IDF、余弦相似度）
4. 图谱检索（实体提取、共现、关联）
5. RRF 混合检索（融合算法、权重、Top-K）
6. 安全事件检索（事件添加、严重程度过滤、攻击链重建）
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evolution.hybrid_retrieval import (
    RetrievalConfig, SearchDocument, SearchResult,
    tokenize, KeywordRetriever, VectorRetriever, GraphRetriever,
    HybridRetriever, SecurityEventRetriever,
    create_hybrid_retriever, create_security_event_retriever,
)


class TestTextPreprocessing(unittest.TestCase):
    """文本预处理测试"""

    def setUp(self):
        self.config = RetrievalConfig()

    def test_tokenize_basic(self):
        """基本分词"""
        tokens = tokenize("hello world test", self.config)
        self.assertIn("hello", tokens)
        self.assertIn("world", tokens)
        self.assertIn("test", tokens)

    def test_tokenize_lowercase(self):
        """小写化"""
        config = RetrievalConfig(lowercase=True)
        tokens = tokenize("Hello WORLD Test", config)
        self.assertIn("hello", tokens)
        self.assertIn("world", tokens)

    def test_tokenize_no_lowercase(self):
        """不使用小写化"""
        config = RetrievalConfig(lowercase=False)
        tokens = tokenize("Hello WORLD", config)
        self.assertIn("Hello", tokens)
        self.assertIn("WORLD", tokens)

    def test_tokenize_remove_stopwords(self):
        """移除停用词"""
        tokens = tokenize("the quick brown fox", self.config)
        self.assertNotIn("the", tokens)
        self.assertIn("quick", tokens)
        self.assertIn("brown", tokens)
        self.assertIn("fox", tokens)

    def test_tokenize_keep_stopwords(self):
        """保留停用词"""
        config = RetrievalConfig(remove_stopwords=False)
        tokens = tokenize("the quick brown fox", config)
        self.assertIn("the", tokens)

    def test_tokenize_min_length(self):
        """最小词长过滤"""
        config = RetrievalConfig(min_token_length=5)
        tokens = tokenize("hello world test", config)
        self.assertIn("hello", tokens)
        self.assertIn("world", tokens)
        self.assertNotIn("test", tokens)  # test 只有4个字符

    def test_tokenize_special_chars(self):
        """特殊字符处理"""
        tokens = tokenize("hello-world test_case 123", self.config)
        self.assertIn("hello", tokens)
        self.assertIn("world", tokens)
        self.assertIn("test_case", tokens)
        self.assertIn("123", tokens)


class TestKeywordRetriever(unittest.TestCase):
    """关键词检索器测试"""

    def setUp(self):
        self.config = RetrievalConfig()
        self.retriever = KeywordRetriever(self.config)
        self.docs = [
            SearchDocument("doc1", "Python security sandbox seccomp isolation"),
            SearchDocument("doc2", "KVM Firecracker MicroVM hardware virtualization"),
            SearchDocument("doc3", "Python machine learning neural network"),
        ]
        for doc in self.docs:
            self.retriever.add_document(doc)

    def test_add_document(self):
        """添加文档"""
        self.assertEqual(self.retriever.total_docs, 3)
        self.assertIn("doc1", self.retriever.documents)

    def test_search_basic(self):
        """基本检索"""
        results = self.retriever.search("Python security", top_k=2)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].doc_id, "doc1")  # doc1 同时包含 Python 和 security
        self.assertEqual(results[0].source, "keyword")

    def test_search_no_match(self):
        """无匹配结果"""
        results = self.retriever.search("nonexistent_xyz", top_k=5)
        self.assertEqual(len(results), 0)

    def test_search_empty_query(self):
        """空查询"""
        results = self.retriever.search("", top_k=5)
        self.assertEqual(len(results), 0)

    def test_search_ranking(self):
        """结果排序"""
        results = self.retriever.search("Python", top_k=3)
        self.assertEqual(len(results), 2)  # doc1 和 doc3 包含 Python
        self.assertTrue(results[0].score >= results[1].score)

    def test_search_score_positive(self):
        """分数为正"""
        results = self.retriever.search("KVM", top_k=1)
        self.assertEqual(len(results), 1)
        self.assertGreater(results[0].score, 0)

    def test_idf_calculation(self):
        """IDF 计算"""
        # Python 出现在 2 个文档中，IDF 应该较低
        idf_python = self.retriever._idf("python")
        # KVM 只出现在 1 个文档中，IDF 应该较高
        idf_kvm = self.retriever._idf("kvm")
        self.assertGreater(idf_kvm, idf_python)

    def test_empty_index(self):
        """空索引"""
        empty_retriever = KeywordRetriever()
        results = empty_retriever.search("test", top_k=5)
        self.assertEqual(len(results), 0)


class TestVectorRetriever(unittest.TestCase):
    """向量检索器测试"""

    def setUp(self):
        self.config = RetrievalConfig()
        self.retriever = VectorRetriever(self.config)
        self.docs = [
            SearchDocument("doc1", "Python security sandbox seccomp isolation"),
            SearchDocument("doc2", "KVM Firecracker MicroVM hardware virtualization"),
            SearchDocument("doc3", "Python machine learning neural network"),
        ]
        for doc in self.docs:
            self.retriever.add_document(doc)

    def test_add_document(self):
        """添加文档"""
        self.assertEqual(self.retriever.total_docs, 3)
        self.assertIn("doc1", self.retriever.documents)

    def test_search_basic(self):
        """基本检索"""
        results = self.retriever.search("Python security", top_k=2)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].source, "vector")

    def test_search_no_match(self):
        """无匹配结果"""
        results = self.retriever.search("nonexistent_xyz", top_k=5)
        self.assertEqual(len(results), 0)

    def test_cosine_similarity(self):
        """余弦相似度计算"""
        v1 = {"a": 1.0, "b": 2.0}
        v2 = {"a": 1.0, "b": 2.0}
        sim = VectorRetriever._cosine_similarity(v1, v2)
        self.assertAlmostEqual(sim, 1.0, places=5)

    def test_cosine_similarity_orthogonal(self):
        """正交向量余弦相似度为 0"""
        v1 = {"a": 1.0}
        v2 = {"b": 1.0}
        sim = VectorRetriever._cosine_similarity(v1, v2)
        self.assertAlmostEqual(sim, 0.0, places=5)

    def test_cosine_similarity_empty(self):
        """空向量余弦相似度"""
        sim = VectorRetriever._cosine_similarity({}, {"a": 1.0})
        self.assertEqual(sim, 0.0)

    def test_empty_index(self):
        """空索引"""
        empty_retriever = VectorRetriever()
        results = empty_retriever.search("test", top_k=5)
        self.assertEqual(len(results), 0)


class TestGraphRetriever(unittest.TestCase):
    """图谱检索器测试"""

    def setUp(self):
        self.config = RetrievalConfig()
        self.retriever = GraphRetriever(self.config)
        self.docs = [
            SearchDocument("doc1", "Python security sandbox", entities=["python", "security", "sandbox"]),
            SearchDocument("doc2", "KVM Firecracker virtualization", entities=["kvm", "firecracker", "virtualization"]),
            SearchDocument("doc3", "Python machine learning", entities=["python", "machine_learning"]),
        ]
        for doc in self.docs:
            self.retriever.add_document(doc)

    def test_add_document(self):
        """添加文档"""
        self.assertEqual(self.retriever.total_docs, 3)

    def test_entity_indexing(self):
        """实体索引"""
        self.assertIn("python", self.retriever.entity_to_docs)
        self.assertEqual(len(self.retriever.entity_to_docs["python"]), 2)  # doc1 和 doc3

    def test_search_by_entity(self):
        """按实体检索"""
        # 使用包含技术术语的查询（seccomp/kvm 等在技术术语列表中）
        results = self.retriever.search("seccomp kvm security sandbox", top_k=5)
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0].source, "graph")

    def test_entity_cooccurrence(self):
        """实体共现"""
        # python 和 security 在 doc1 中共现
        self.assertIn("security", self.retriever.entity_cooccurrence["python"])
        self.assertGreater(self.retriever.entity_cooccurrence["python"]["security"], 0)

    def test_extract_entities_cve(self):
        """提取 CVE 编号"""
        entities = self.retriever._extract_entities("CVE-2022-3602 OpenSSL vulnerability")
        self.assertTrue(any("cve-2022-3602" in e.lower() for e in entities))

    def test_extract_entities_tech_terms(self):
        """提取技术术语"""
        entities = self.retriever._extract_entities("seccomp kvm firecracker sandbox")
        entity_lower = {e.lower() for e in entities}
        self.assertIn("seccomp", entity_lower)
        self.assertIn("kvm", entity_lower)

    def test_empty_index(self):
        """空索引"""
        empty_retriever = GraphRetriever()
        results = empty_retriever.search("test", top_k=5)
        self.assertEqual(len(results), 0)


class TestHybridRetriever(unittest.TestCase):
    """RRF 混合检索器测试"""

    def setUp(self):
        self.config = RetrievalConfig()
        self.retriever = HybridRetriever(self.config)
        self.docs = [
            SearchDocument("doc1", "Python security sandbox seccomp isolation",
                          entities=["python", "security", "sandbox", "seccomp"]),
            SearchDocument("doc2", "KVM Firecracker MicroVM hardware virtualization",
                          entities=["kvm", "firecracker", "microvm", "virtualization"]),
            SearchDocument("doc3", "Python machine learning neural network",
                          entities=["python", "machine_learning", "neural_network"]),
        ]
        for doc in self.docs:
            self.retriever.add_document(doc)

    def test_add_document(self):
        """添加文档"""
        self.assertEqual(len(self.retriever.all_documents), 3)

    def test_search_basic(self):
        """基本混合检索"""
        results = self.retriever.search("Python security", top_k=2)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].source, "hybrid")

    def test_search_rrf_fusion(self):
        """RRF 融合"""
        results = self.retriever.search("Python", top_k=3)
        self.assertGreater(len(results), 0)
        # 检查 RRF 分数
        for r in results:
            self.assertGreater(r.score, 0)
            self.assertIn("rrf_score", r.details)

    def test_search_with_explanation(self):
        """带解释的检索"""
        explanation = self.retriever.search_with_explanation("Python security", top_k=2)
        self.assertIn("query", explanation)
        self.assertIn("hybrid_results", explanation)
        self.assertIn("keyword_results", explanation)
        self.assertIn("vector_results", explanation)
        self.assertIn("graph_results", explanation)
        self.assertIn("config", explanation)

    def test_source_contributions(self):
        """来源贡献"""
        explanation = self.retriever.search_with_explanation("Python security sandbox", top_k=3)
        for r in explanation["hybrid_results"]:
            self.assertIn("source_contributions", r.details)
            contributions = r.details["source_contributions"]
            self.assertIsInstance(contributions, dict)

    def test_disable_retrievers(self):
        """禁用部分检索器"""
        config = RetrievalConfig(enable_keyword=True, enable_vector=False, enable_graph=False)
        retriever = HybridRetriever(config)
        for doc in self.docs:
            retriever.add_document(doc)
        results = retriever.search("Python", top_k=3)
        self.assertGreater(len(results), 0)
        # 只有关键词检索，来源贡献应该只有 keyword
        if results:
            contributions = results[0].details.get("source_contributions", {})
            self.assertIn("keyword", contributions)

    def test_custom_weights(self):
        """自定义权重"""
        config = RetrievalConfig(keyword_weight=2.0, vector_weight=1.0, graph_weight=0.5)
        retriever = HybridRetriever(config)
        for doc in self.docs:
            retriever.add_document(doc)
        results = retriever.search("Python", top_k=3)
        self.assertGreater(len(results), 0)

    def test_empty_index(self):
        """空索引"""
        empty_retriever = HybridRetriever()
        results = empty_retriever.search("test", top_k=5)
        self.assertEqual(len(results), 0)


class TestSecurityEventRetriever(unittest.TestCase):
    """安全事件检索器测试"""

    def setUp(self):
        self.config = RetrievalConfig()
        self.retriever = SecurityEventRetriever(self.config)
        # 添加测试事件
        self.retriever.add_security_event(
            "seccomp_violation", "ptrace syscall blocked by seccomp",
            "high", ["ptrace", "seccomp", "syscall"]
        )
        self.retriever.add_security_event(
            "vm_exit", "VMCALL VM-Exit in Firecracker MicroVM",
            "medium", ["vmcall", "vm-exit", "firecracker"]
        )
        self.retriever.add_security_event(
            "audit_anomaly", "HMAC audit chain tampering detected",
            "critical", ["hmac", "audit", "tampering"]
        )
        self.retriever.add_security_event(
            "escape_attempt", "container escape via cgroup vulnerability",
            "critical", ["cgroup", "container_escape", "cve"]
        )

    def test_add_event(self):
        """添加事件"""
        self.assertEqual(self.retriever.event_count, 4)

    def test_event_id_generation(self):
        """事件 ID 生成"""
        event_id = self.retriever.add_security_event("test", "test event", "low")
        self.assertTrue(event_id.startswith("event-"))
        self.assertEqual(self.retriever.event_count, 5)

    def test_search_related_events(self):
        """检索相关事件"""
        results = self.retriever.search_related_events("ptrace seccomp syscall", top_k=3)
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0].document.metadata["event_type"], "seccomp_violation")

    def test_search_by_severity(self):
        """按严重程度过滤"""
        results = self.retriever.search_related_events(
            "escape tampering", top_k=5, min_severity="critical"
        )
        # 所有结果都应该是 critical 或 high
        for r in results:
            severity = r.document.metadata.get("severity", "low")
            self.assertIn(severity, ["critical", "high"])

    def test_get_attack_chain(self):
        """攻击链重建"""
        chain = self.retriever.get_attack_chain("ptrace seccomp blocked", max_depth=2)
        self.assertGreater(len(chain), 0)
        self.assertLessEqual(len(chain), 2)
        # 链中每个事件都应该是 SearchResult
        for event in chain:
            self.assertIsInstance(event, SearchResult)

    def test_attack_chain_no_duplicates(self):
        """攻击链无重复"""
        chain = self.retriever.get_attack_chain("ptrace seccomp", max_depth=3)
        doc_ids = [e.doc_id for e in chain]
        self.assertEqual(len(doc_ids), len(set(doc_ids)))  # 无重复

    def test_event_metadata(self):
        """事件元数据"""
        results = self.retriever.search_related_events("ptrace", top_k=1)
        self.assertEqual(len(results), 1)
        metadata = results[0].document.metadata
        self.assertIn("event_type", metadata)
        self.assertIn("severity", metadata)
        self.assertIn("timestamp", metadata)
        self.assertEqual(metadata["event_type"], "seccomp_violation")
        self.assertEqual(metadata["severity"], "high")


class TestRetrievalConfig(unittest.TestCase):
    """检索配置测试"""

    def test_default_config(self):
        """默认配置"""
        config = RetrievalConfig()
        self.assertEqual(config.rrf_k, 60)
        self.assertEqual(config.keyword_weight, 1.0)
        self.assertEqual(config.vector_weight, 1.0)
        self.assertEqual(config.graph_weight, 0.8)
        self.assertEqual(config.top_k, 10)
        self.assertTrue(config.enable_keyword)
        self.assertTrue(config.enable_vector)
        self.assertTrue(config.enable_graph)
        self.assertTrue(config.lowercase)
        self.assertTrue(config.remove_stopwords)
        self.assertEqual(config.min_token_length, 2)

    def test_custom_config(self):
        """自定义配置"""
        config = RetrievalConfig(
            rrf_k=100,
            keyword_weight=2.0,
            top_k=20,
            enable_graph=False,
        )
        self.assertEqual(config.rrf_k, 100)
        self.assertEqual(config.keyword_weight, 2.0)
        self.assertEqual(config.top_k, 20)
        self.assertFalse(config.enable_graph)


class TestConvenienceFunctions(unittest.TestCase):
    """便捷接口函数测试"""

    def test_create_hybrid_retriever(self):
        """创建混合检索器"""
        retriever = create_hybrid_retriever()
        self.assertIsInstance(retriever, HybridRetriever)

    def test_create_security_event_retriever(self):
        """创建安全事件检索器"""
        retriever = create_security_event_retriever()
        self.assertIsInstance(retriever, SecurityEventRetriever)

    def test_create_with_config(self):
        """带配置创建"""
        config = RetrievalConfig(top_k=5)
        retriever = create_hybrid_retriever(config)
        self.assertEqual(retriever.config.top_k, 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
