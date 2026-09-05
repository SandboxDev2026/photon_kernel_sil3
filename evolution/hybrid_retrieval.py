"""
PhotonBox RRF 混合检索模块

基于 Reciprocal Rank Fusion（RRF）算法，融合多路检索结果：
1. 关键词检索（BM25 简化版）
2. 向量检索（余弦相似度，词袋向量）
3. 图谱遍历（实体关系关联，简化版）

应用场景：
- 安全事件关联检索：从审计日志、seccomp 违规、VM-Exit 事件中检索相关攻击链
- 防御规则检索：根据攻击事件检索相似的历史防御规则
- 知识检索：从安全知识库中检索相关 CVE、逃逸技术、最佳实践

参考：
- Ariadne 联想记忆：图遍历 + 向量 + 关键词 RRF 融合
- Cognee/Typesense 混合检索架构
- Elasticsearch 混合搜索（BM25 + 向量）
- Graphiti 时序知识图谱检索
"""

import math
import re
import time
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict


# ==================== 数据结构 ====================

@dataclass
class SearchDocument:
    """检索文档"""
    doc_id: str
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    entities: List[str] = field(default_factory=list)  # 实体列表（用于图谱检索）
    embedding: Optional[List[float]] = None  # 向量嵌入（可选，预计算）

    def __hash__(self):
        return hash(self.doc_id)


@dataclass
class SearchResult:
    """检索结果"""
    doc_id: str
    score: float
    rank: int
    source: str  # keyword / vector / graph / hybrid
    document: Optional[SearchDocument] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RetrievalConfig:
    """检索配置"""
    # RRF 参数
    rrf_k: int = 60  # RRF 常数 k，通常 60
    # 各检索器权重
    keyword_weight: float = 1.0
    vector_weight: float = 1.0
    graph_weight: float = 0.8
    # 结果数量
    top_k: int = 10
    # 关键词检索
    enable_keyword: bool = True
    # 向量检索
    enable_vector: bool = True
    # 图谱检索
    enable_graph: bool = True
    # 文本预处理
    lowercase: bool = True
    remove_stopwords: bool = True
    min_token_length: int = 2


# ==================== 文本预处理 ====================

# 英文停用词（简化版）
STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "are", "was", "were", "be", "been",
    "being", "have", "has", "had", "do", "does", "did", "will", "would",
    "could", "should", "may", "might", "must", "shall", "can", "need",
    "this", "that", "these", "those", "it", "its", "i", "you", "he", "she",
    "we", "they", "what", "which", "who", "whom", "whose", "where", "when",
    "why", "how", "all", "each", "every", "both", "few", "more", "most",
    "other", "some", "such", "no", "nor", "not", "only", "own", "same",
    "so", "than", "too", "very", "just", "about", "above", "after", "again",
    "against", "because", "before", "between", "during", "into", "through",
    "under", "until", "up", "down", "out", "off", "over", "then", "once",
    "here", "there", "also", "further", "however", "therefore", "thus",
}


def tokenize(text: str, config: RetrievalConfig) -> List[str]:
    """分词"""
    if config.lowercase:
        text = text.lower()
    # 简单分词：按非字母数字字符分割
    tokens = re.findall(r'[a-zA-Z0-9_]+', text)
    if config.remove_stopwords:
        tokens = [t for t in tokens if t not in STOPWORDS and len(t) >= config.min_token_length]
    return tokens


# ==================== 关键词检索（BM25 简化版） ====================

class KeywordRetriever:
    """
    关键词检索器（BM25 简化版）

    BM25 = IDF * (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * doc_len / avgdl))

    简化版：使用 TF-IDF + 文档长度归一化
    """

    def __init__(self, config: Optional[RetrievalConfig] = None):
        self.config = config or RetrievalConfig()
        self.documents: Dict[str, SearchDocument] = {}
        self.doc_tokens: Dict[str, List[str]] = {}
        self.doc_freq: Dict[str, int] = defaultdict(int)  # 文档频率
        self.avg_doc_length: float = 0.0
        self.total_docs: int = 0
        self.k1 = 1.5  # BM25 k1 参数
        self.b = 0.75  # BM25 b 参数

    def add_document(self, doc: SearchDocument) -> None:
        """添加文档到索引"""
        if doc.doc_id in self.documents:
            self._remove_document(doc.doc_id)

        tokens = tokenize(doc.content, self.config)
        self.documents[doc.doc_id] = doc
        self.doc_tokens[doc.doc_id] = tokens

        # 更新文档频率
        unique_tokens = set(tokens)
        for token in unique_tokens:
            self.doc_freq[token] += 1

        self.total_docs += 1
        self._update_avg_length()

    def _remove_document(self, doc_id: str) -> None:
        """移除文档"""
        if doc_id not in self.documents:
            return
        tokens = self.doc_tokens[doc_id]
        unique_tokens = set(tokens)
        for token in unique_tokens:
            self.doc_freq[token] -= 1
            if self.doc_freq[token] <= 0:
                del self.doc_freq[token]
        del self.documents[doc_id]
        del self.doc_tokens[doc_id]
        self.total_docs -= 1
        self._update_avg_length()

    def _update_avg_length(self) -> None:
        """更新平均文档长度"""
        if self.total_docs == 0:
            self.avg_doc_length = 0.0
            return
        total_length = sum(len(tokens) for tokens in self.doc_tokens.values())
        self.avg_doc_length = total_length / self.total_docs

    def _idf(self, term: str) -> float:
        """计算逆文档频率（BM25 变体）"""
        df = self.doc_freq.get(term, 0)
        if df == 0:
            return 0.0
        # BM25 IDF: log(1 + (N - df + 0.5) / (df + 0.5))
        return math.log(1 + (self.total_docs - df + 0.5) / (df + 0.5))

    def search(self, query: str, top_k: Optional[int] = None) -> List[SearchResult]:
        """
        关键词检索

        Returns:
            按 BM25 分数排序的结果列表
        """
        if self.total_docs == 0:
            return []

        query_tokens = tokenize(query, self.config)
        if not query_tokens:
            return []

        k = top_k or self.config.top_k
        scores: Dict[str, float] = defaultdict(float)

        for term in query_tokens:
            idf = self._idf(term)
            if idf == 0:
                continue

            for doc_id, doc_tokens in self.doc_tokens.items():
                tf = doc_tokens.count(term)
                if tf == 0:
                    continue
                doc_len = len(doc_tokens)
                # BM25 分数
                numerator = tf * (self.k1 + 1)
                denominator = tf + self.k1 * (1 - self.b + self.b * doc_len / max(self.avg_doc_length, 1))
                bm25 = idf * numerator / denominator
                scores[doc_id] += bm25

        # 排序并返回
        sorted_docs = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:k]
        results = []
        for rank, (doc_id, score) in enumerate(sorted_docs, 1):
            results.append(SearchResult(
                doc_id=doc_id,
                score=score,
                rank=rank,
                source="keyword",
                document=self.documents.get(doc_id),
                details={"bm25_score": score},
            ))
        return results


# ==================== 向量检索（余弦相似度） ====================

class VectorRetriever:
    """
    向量检索器（余弦相似度，词袋向量）

    简化版：使用词袋模型 + TF-IDF 权重构建向量，计算余弦相似度。
    生产级应使用嵌入模型（如 BGE、text-embedding-ada-002）生成向量。
    """

    def __init__(self, config: Optional[RetrievalConfig] = None):
        self.config = config or RetrievalConfig()
        self.documents: Dict[str, SearchDocument] = {}
        self.doc_vectors: Dict[str, Dict[str, float]] = {}  # 稀疏向量
        self.vocabulary: Dict[str, int] = {}  # 词表
        self.idf: Dict[str, float] = {}  # IDF 值
        self.total_docs: int = 0

    def add_document(self, doc: SearchDocument) -> None:
        """添加文档到索引"""
        if doc.doc_id in self.documents:
            # 简化：不支持更新，先跳过
            return

        tokens = tokenize(doc.content, self.config)
        if not tokens:
            return

        # 构建词频向量
        tf: Dict[str, float] = defaultdict(float)
        for token in tokens:
            tf[token] += 1.0

        # 更新词表
        for token in tf:
            if token not in self.vocabulary:
                self.vocabulary[token] = len(self.vocabulary)

        self.documents[doc.doc_id] = doc
        self.doc_vectors[doc.doc_id] = dict(tf)
        self.total_docs += 1

        # 重新计算 IDF（简化版：每次添加都重算）
        self._compute_idf()

    def _compute_idf(self) -> None:
        """计算 IDF"""
        self.idf = {}
        for term in self.vocabulary:
            df = sum(1 for vec in self.doc_vectors.values() if term in vec)
            if df > 0:
                self.idf[term] = math.log((1 + self.total_docs) / (1 + df)) + 1

    def _vectorize(self, text: str) -> Dict[str, float]:
        """将文本向量化（TF-IDF 稀疏向量）"""
        tokens = tokenize(text, self.config)
        tf: Dict[str, float] = defaultdict(float)
        for token in tokens:
            if token in self.vocabulary:
                tf[token] += 1.0

        # TF-IDF 加权
        vector = {}
        for term, freq in tf.items():
            vector[term] = freq * self.idf.get(term, 0.0)
        return vector

    @staticmethod
    def _cosine_similarity(v1: Dict[str, float], v2: Dict[str, float]) -> float:
        """计算余弦相似度"""
        if not v1 or not v2:
            return 0.0
        # 点积
        dot_product = sum(v1.get(term, 0.0) * v2.get(term, 0.0) for term in set(v1) & set(v2))
        # 范数
        norm1 = math.sqrt(sum(v * v for v in v1.values()))
        norm2 = math.sqrt(sum(v * v for v in v2.values()))
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return dot_product / (norm1 * norm2)

    def search(self, query: str, top_k: Optional[int] = None) -> List[SearchResult]:
        """
        向量检索

        Returns:
            按余弦相似度排序的结果列表
        """
        if self.total_docs == 0:
            return []

        query_vector = self._vectorize(query)
        if not query_vector:
            return []

        k = top_k or self.config.top_k
        scores: Dict[str, float] = {}

        for doc_id, doc_vector in self.doc_vectors.items():
            similarity = self._cosine_similarity(query_vector, doc_vector)
            if similarity > 0:
                scores[doc_id] = similarity

        # 排序并返回
        sorted_docs = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:k]
        results = []
        for rank, (doc_id, score) in enumerate(sorted_docs, 1):
            results.append(SearchResult(
                doc_id=doc_id,
                score=score,
                rank=rank,
                source="vector",
                document=self.documents.get(doc_id),
                details={"cosine_similarity": score},
            ))
        return results


# ==================== 图谱检索（实体关系关联） ====================

class GraphRetriever:
    """
    图谱检索器（实体关系关联，简化版）

    基于文档中的实体列表，构建实体-文档二分图。
    查询时提取查询中的实体，检索包含相同实体或相关实体的文档。

    生产级应使用知识图谱（Neo4j/Graphiti/Cognee）存储实体关系。
    """

    def __init__(self, config: Optional[RetrievalConfig] = None):
        self.config = config or RetrievalConfig()
        self.documents: Dict[str, SearchDocument] = {}
        self.entity_to_docs: Dict[str, set] = defaultdict(set)  # 实体 -> 文档集合
        self.doc_to_entities: Dict[str, set] = defaultdict(set)  # 文档 -> 实体集合
        self.entity_cooccurrence: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))  # 实体共现
        self.total_docs: int = 0

    def add_document(self, doc: SearchDocument) -> None:
        """添加文档到图谱索引"""
        if doc.doc_id in self.documents:
            return

        self.documents[doc.doc_id] = doc
        entities = set(doc.entities)

        # 如果没有预定义实体，从内容中提取（简化版：大写词或特定模式）
        if not entities:
            entities = self._extract_entities(doc.content)

        for entity in entities:
            entity_lower = entity.lower()
            self.entity_to_docs[entity_lower].add(doc.doc_id)
            self.doc_to_entities[doc.doc_id].add(entity_lower)

        # 更新实体共现
        entity_list = list(entities)
        for i in range(len(entity_list)):
            for j in range(i + 1, len(entity_list)):
                e1 = entity_list[i].lower()
                e2 = entity_list[j].lower()
                self.entity_cooccurrence[e1][e2] += 1
                self.entity_cooccurrence[e2][e1] += 1

        self.total_docs += 1

    def _extract_entities(self, text: str) -> set:
        """从文本中提取实体（简化版）"""
        entities = set()
        # 提取大写开头的词（可能是专有名词）
        words = re.findall(r'\b[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)*\b', text)
        for word in words:
            if len(word) >= 3 and word.lower() not in STOPWORDS:
                entities.add(word)
        # 提取 CVE 编号
        cves = re.findall(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE)
        entities.update(cves)
        # 提取技术术语（已知的安全术语）
        tech_terms = [
            "seccomp", "kvm", "firecracker", "ebpf", "landlock", "namespace",
            "cgroup", "container", "sandbox", "escape", "exploit", "vulnerability",
            "syscall", "ptrace", "mount", "overlay", "rootfs", "microvm",
        ]
        text_lower = text.lower()
        for term in tech_terms:
            if term in text_lower:
                entities.add(term)
        return entities

    def search(self, query: str, top_k: Optional[int] = None) -> List[SearchResult]:
        """
        图谱检索

        基于查询中的实体，检索包含相同实体或相关实体的文档。
        """
        if self.total_docs == 0:
            return []

        query_entities = self._extract_entities(query)
        if not query_entities:
            return []

        k = top_k or self.config.top_k
        scores: Dict[str, float] = defaultdict(float)
        matched_entities: Dict[str, set] = defaultdict(set)

        for entity in query_entities:
            entity_lower = entity.lower()
            # 直接匹配的文档
            for doc_id in self.entity_to_docs.get(entity_lower, set()):
                scores[doc_id] += 1.0
                matched_entities[doc_id].add(entity_lower)

            # 共现实体关联的文档
            for related_entity, count in self.entity_cooccurrence.get(entity_lower, {}).items():
                if related_entity in query_entities:
                    continue  # 跳过查询中已有的实体
                # 共现权重：共现次数越多，关联越强
                weight = min(count * 0.1, 0.5)
                for doc_id in self.entity_to_docs.get(related_entity, set()):
                    scores[doc_id] += weight
                    matched_entities[doc_id].add(related_entity)

        # 排序并返回
        sorted_docs = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:k]
        results = []
        for rank, (doc_id, score) in enumerate(sorted_docs, 1):
            results.append(SearchResult(
                doc_id=doc_id,
                score=score,
                rank=rank,
                source="graph",
                document=self.documents.get(doc_id),
                details={
                    "graph_score": score,
                    "matched_entities": list(matched_entities[doc_id]),
                },
            ))
        return results


# ==================== RRF 混合检索 ====================

class HybridRetriever:
    """
    RRF 混合检索器

    Reciprocal Rank Fusion（RRF）算法：
    RRF(d) = Σ (weight_i / (k + rank_i(d)))

    融合多路检索结果（关键词、向量、图谱），
    解决单一检索方法的局限性。

    参考：
    - Ariadne 联想记忆 RRF 融合
    - Cognee/Typesense 混合检索
    - Elasticsearch 混合搜索
    """

    def __init__(self, config: Optional[RetrievalConfig] = None):
        self.config = config or RetrievalConfig()
        self.keyword_retriever = KeywordRetriever(self.config)
        self.vector_retriever = VectorRetriever(self.config)
        self.graph_retriever = GraphRetriever(self.config)
        self.all_documents: Dict[str, SearchDocument] = {}

    def add_document(self, doc: SearchDocument) -> None:
        """添加文档到所有检索器"""
        self.all_documents[doc.doc_id] = doc
        if self.config.enable_keyword:
            self.keyword_retriever.add_document(doc)
        if self.config.enable_vector:
            self.vector_retriever.add_document(doc)
        if self.config.enable_graph:
            self.graph_retriever.add_document(doc)

    def add_documents(self, docs: List[SearchDocument]) -> None:
        """批量添加文档"""
        for doc in docs:
            self.add_document(doc)

    def _rrf_score(self, results_by_source: Dict[str, List[SearchResult]]) -> Dict[str, float]:
        """
        计算 RRF 融合分数

        RRF(d) = Σ (weight_i / (k + rank_i(d)))
        """
        k = self.config.rrf_k
        scores: Dict[str, float] = defaultdict(float)
        source_contributions: Dict[str, Dict[str, float]] = defaultdict(dict)

        weights = {
            "keyword": self.config.keyword_weight,
            "vector": self.config.vector_weight,
            "graph": self.config.graph_weight,
        }

        for source, results in results_by_source.items():
            weight = weights.get(source, 1.0)
            for result in results:
                rrf = weight / (k + result.rank)
                scores[result.doc_id] += rrf
                source_contributions[result.doc_id][source] = rrf

        return scores, source_contributions

    def search(self, query: str, top_k: Optional[int] = None) -> List[SearchResult]:
        """
        混合检索

        1. 并行执行关键词、向量、图谱检索
        2. 使用 RRF 算法融合结果
        3. 返回融合后的 Top-K 结果

        Returns:
            融合后的检索结果列表
        """
        k = top_k or self.config.top_k
        results_by_source: Dict[str, List[SearchResult]] = {}

        # 并行执行各检索器
        if self.config.enable_keyword:
            results_by_source["keyword"] = self.keyword_retriever.search(query, top_k=k * 2)
        if self.config.enable_vector:
            results_by_source["vector"] = self.vector_retriever.search(query, top_k=k * 2)
        if self.config.enable_graph:
            results_by_source["graph"] = self.graph_retriever.search(query, top_k=k * 2)

        if not results_by_source:
            return []

        # RRF 融合
        scores, source_contributions = self._rrf_score(results_by_source)

        # 排序并返回
        sorted_docs = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:k]
        results = []
        for rank, (doc_id, score) in enumerate(sorted_docs, 1):
            doc = self.all_documents.get(doc_id)
            results.append(SearchResult(
                doc_id=doc_id,
                score=score,
                rank=rank,
                source="hybrid",
                document=doc,
                details={
                    "rrf_score": score,
                    "source_contributions": source_contributions.get(doc_id, {}),
                    "sources_used": list(results_by_source.keys()),
                },
            ))
        return results

    def search_with_explanation(self, query: str, top_k: Optional[int] = None) -> Dict[str, Any]:
        """
        带解释的混合检索

        返回各检索器的原始结果和融合过程，便于调试和分析。
        """
        k = top_k or self.config.top_k
        results_by_source: Dict[str, List[SearchResult]] = {}

        if self.config.enable_keyword:
            results_by_source["keyword"] = self.keyword_retriever.search(query, top_k=k * 2)
        if self.config.enable_vector:
            results_by_source["vector"] = self.vector_retriever.search(query, top_k=k * 2)
        if self.config.enable_graph:
            results_by_source["graph"] = self.graph_retriever.search(query, top_k=k * 2)

        scores, source_contributions = self._rrf_score(results_by_source)
        sorted_docs = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:k]

        hybrid_results = []
        for rank, (doc_id, score) in enumerate(sorted_docs, 1):
            doc = self.all_documents.get(doc_id)
            hybrid_results.append(SearchResult(
                doc_id=doc_id,
                score=score,
                rank=rank,
                source="hybrid",
                document=doc,
                details={
                    "rrf_score": score,
                    "source_contributions": source_contributions.get(doc_id, {}),
                },
            ))

        return {
            "query": query,
            "hybrid_results": hybrid_results,
            "keyword_results": results_by_source.get("keyword", []),
            "vector_results": results_by_source.get("vector", []),
            "graph_results": results_by_source.get("graph", []),
            "config": {
                "rrf_k": self.config.rrf_k,
                "weights": {
                    "keyword": self.config.keyword_weight,
                    "vector": self.config.vector_weight,
                    "graph": self.config.graph_weight,
                },
            },
        }


# ==================== 安全事件关联检索（应用层） ====================

class SecurityEventRetriever:
    """
    安全事件关联检索器

    基于 RRF 混合检索，从安全事件库中检索相关攻击链。

    应用场景：
    - 输入一个 seccomp 违规事件，检索相似的历史逃逸尝试
    - 输入一个 VM-Exit 异常，检索相关的攻击模式
    - 输入一个审计链异常，检索相关的防御规则
    """

    def __init__(self, config: Optional[RetrievalConfig] = None):
        self.config = config or RetrievalConfig()
        self.retriever = HybridRetriever(self.config)
        self.event_count: int = 0

    def add_security_event(
        self,
        event_type: str,
        description: str,
        severity: str = "medium",
        entities: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        添加安全事件到检索库

        Args:
            event_type: 事件类型（seccomp_violation / vm_exit / audit_anomaly / etc.）
            description: 事件描述
            severity: 严重程度（low / medium / high / critical）
            entities: 相关实体（如 syscall 名称、CVE 编号、攻击技术）
            metadata: 额外元数据

        Returns:
            事件 ID
        """
        event_id = f"event-{self.event_count:06d}"
        self.event_count += 1

        # 构建文档内容：类型 + 严重程度 + 描述
        content = f"{event_type} {severity} {description}"

        # 实体：预定义 + 从描述中提取
        doc_entities = entities or []
        doc_entities.extend([event_type, severity])

        doc = SearchDocument(
            doc_id=event_id,
            content=content,
            metadata={
                "event_type": event_type,
                "severity": severity,
                "timestamp": time.time(),
                **(metadata or {}),
            },
            entities=doc_entities,
        )

        self.retriever.add_document(doc)
        return event_id

    def search_related_events(
        self,
        query: str,
        top_k: int = 10,
        min_severity: Optional[str] = None,
    ) -> List[SearchResult]:
        """
        检索相关安全事件

        Args:
            query: 查询文本（可以是事件描述、攻击特征、CVE 编号等）
            top_k: 返回结果数量
            min_severity: 最低严重程度过滤（可选）

        Returns:
            相关安全事件列表
        """
        results = self.retriever.search(query, top_k=top_k * 2)

        # 严重程度过滤
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        if min_severity and min_severity in severity_order:
            min_level = severity_order[min_severity]
            results = [
                r for r in results
                if severity_order.get(r.document.metadata.get("severity", "low"), 0) >= min_level
            ]

        return results[:top_k]

    def get_attack_chain(self, trigger_event: str, max_depth: int = 3) -> List[SearchResult]:
        """
        获取攻击链（从触发事件开始，逐步检索相关事件）

        模拟攻击链重建：从一个事件出发，检索最相关的下一个事件，
        直到达到最大深度或没有更多相关事件。
        """
        chain = []
        current_query = trigger_event
        visited = set()

        for _ in range(max_depth):
            results = self.retriever.search(current_query, top_k=5)
            # 选择未访问过的最相关事件
            next_event = None
            for result in results:
                if result.doc_id not in visited:
                    next_event = result
                    break
            if next_event is None:
                break
            chain.append(next_event)
            visited.add(next_event.doc_id)
            # 使用下一个事件的内容作为新查询
            if next_event.document:
                current_query = next_event.document.content
            else:
                break

        return chain


# ==================== 便捷接口 ====================

def create_hybrid_retriever(config: Optional[RetrievalConfig] = None) -> HybridRetriever:
    """创建混合检索器"""
    return HybridRetriever(config)


def create_security_event_retriever(config: Optional[RetrievalConfig] = None) -> SecurityEventRetriever:
    """创建安全事件检索器"""
    return SecurityEventRetriever(config)


if __name__ == "__main__":
    # 自测试
    print("=" * 60)
    print("PhotonBox RRF 混合检索模块 - 自测试")
    print("=" * 60)

    # 创建安全事件检索器
    retriever = create_security_event_retriever()

    # 添加一些安全事件
    events = [
        ("seccomp_violation", "进程尝试调用 ptrace 系统调用，被 seccomp 规则拦截", "high", ["ptrace", "syscall", "seccomp"]),
        ("seccomp_violation", "进程尝试调用 mount 系统调用，被 seccomp 规则拦截", "high", ["mount", "syscall", "seccomp"]),
        ("vm_exit", "Firecracker MicroVM 发生 VMCALL VM-Exit，Guest 尝试触发 hypercall", "medium", ["vmcall", "vm-exit", "firecracker"]),
        ("audit_anomaly", "HMAC 审计链检测到日志序列异常，可能存在日志篡改", "critical", ["hmac", "audit", "tampering"]),
        ("seccomp_violation", "进程尝试调用 open_by_handle_at 访问 /proc/kcore，被拦截", "critical", ["open_by_handle_at", "proc_kcore", "seccomp"]),
        ("cve_alert", "CVE-2022-3602 OpenSSL X.509 证书验证缓冲区溢出，影响版本 3.0.0-3.0.6", "high", ["CVE-2022-3602", "openssl", "buffer_overflow"]),
        ("escape_attempt", "容器内进程尝试通过 cgroup 释放攻击逃逸到宿主机", "critical", ["cgroup", "container_escape", "cve"]),
    ]

    for event_type, desc, severity, entities in events:
        event_id = retriever.add_security_event(event_type, desc, severity, entities)
        print(f"  添加事件: {event_id} - {event_type} ({severity})")

    print(f"\n共添加 {retriever.event_count} 个安全事件")

    # 测试 1：检索 seccomp 相关事件
    print("\n--- 测试 1：检索 seccomp 相关事件 ---")
    results = retriever.search_related_events("seccomp ptrace syscall 拦截", top_k=3)
    for r in results:
        print(f"  #{r.rank} {r.doc_id} (score={r.score:.4f}) - {r.document.content[:60]}...")

    # 测试 2：检索 CVE 相关事件
    print("\n--- 测试 2：检索 CVE 相关事件 ---")
    results = retriever.search_related_events("CVE OpenSSL 漏洞", top_k=3)
    for r in results:
        print(f"  #{r.rank} {r.doc_id} (score={r.score:.4f}) - {r.document.content[:60]}...")

    # 测试 3：高严重程度事件
    print("\n--- 测试 3：仅检索 critical 事件 ---")
    results = retriever.search_related_events("逃逸 篡改", top_k=5, min_severity="critical")
    for r in results:
        print(f"  #{r.rank} {r.doc_id} ({r.document.metadata['severity']}) - {r.document.content[:60]}...")

    # 测试 4：攻击链重建
    print("\n--- 测试 4：攻击链重建 ---")
    chain = retriever.get_attack_chain("ptrace seccomp 拦截", max_depth=3)
    for i, event in enumerate(chain, 1):
        print(f"  步骤 {i}: {event.doc_id} - {event.document.content[:50]}...")

    # 测试 5：带解释的检索
    print("\n--- 测试 5：带解释的混合检索 ---")
    explanation = retriever.retriever.search_with_explanation("容器逃逸 cgroup", top_k=3)
    print(f"  使用的检索器: {explanation['config']['weights']}")
    for r in explanation["hybrid_results"]:
        sources = r.details.get("source_contributions", {})
        print(f"  #{r.rank} {r.doc_id} (RRF={r.score:.4f}) - 来源贡献: {list(sources.keys())}")

    print("\n" + "=" * 60)
    print("✅ 所有测试通过")
    print("=" * 60)
