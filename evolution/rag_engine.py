"""
PhotonBox RAG 检索增强生成核心引擎

四方向 RAG 集成：
- 方向1：红方攻击用例 RAG 增强（基于 CVE 知识库生成攻击用例）
- 方向2：蓝方防御规则 RAG 增强（基于防御规则知识库生成防御规则）
- 方向3：事件关联 RAG（基于攻击模式知识库关联审计事件）
- 方向4：Agent 策略 RAG（基于安全策略知识库校验 Agent 工具调用）

核心能力：
1. 知识库管理：多知识库加载、添加、删除
2. 检索增强：query 重写、混合检索（关键词+语义）、重排序
3. 上下文构建：将检索结果组装成结构化上下文
4. 生成增强：基于检索结果的提示词模板构建
"""

from __future__ import annotations

import json
import os
import re
import time
import hashlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from .security_knowledge_base import KnowledgeBase


# ============================================================
# 检索结果与上下文
# ============================================================

class RetrievalStrategy(Enum):
    """检索策略"""
    KEYWORD = "keyword"           # 纯关键词检索
    SEMANTIC = "semantic"         # 纯语义检索（TF-IDF）
    HYBRID = "hybrid"             # 混合检索（关键词+语义加权）
    RERANK = "rerank"             # 混合检索+重排序


@dataclass
class RetrievalResult:
    """单条检索结果"""
    doc_id: str
    content: str
    score: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    source_kb: str = ""
    rank: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "content": self.content,
            "score": self.score,
            "metadata": self.metadata,
            "source_kb": self.source_kb,
            "rank": self.rank,
        }


@dataclass
class RAGContext:
    """RAG 上下文（检索结果组装后的结构化上下文）"""
    query: str
    rewritten_query: str
    results: List[RetrievalResult]
    context_text: str
    sources: List[str]
    total_docs: int
    retrieval_time_ms: float
    strategy: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "rewritten_query": self.rewritten_query,
            "results": [r.to_dict() for r in self.results],
            "context_text": self.context_text,
            "sources": self.sources,
            "total_docs": self.total_docs,
            "retrieval_time_ms": self.retrieval_time_ms,
            "strategy": self.strategy,
        }


# ============================================================
# Query 重写器
# ============================================================

class QueryRewriter:
    """
    Query 重写器

    提升检索召回率：
    1. 同义词扩展
    2. 术语规范化
    3. 查询分解（复杂查询拆成多个子查询）
    4. 领域术语映射（安全领域专有名词）
    """

    # 安全领域同义词映射
    SYNONYM_MAP = {
        "逃逸": ["escape", "evasion", "bypass", "breakout"],
        "escape": ["逃逸", "evasion", "bypass", "breakout"],
        "容器": ["container", "docker", "namespace"],
        "container": ["容器", "docker", "namespace"],
        "虚拟机": ["vm", "virtual machine", "microvm", "firecracker"],
        "vm": ["虚拟机", "virtual machine", "microvm", "firecracker"],
        "提权": ["privilege escalation", "privesc", "root"],
        "privilege": ["提权", "privesc", "root", "escalation"],
        "漏洞": ["vulnerability", "cve", "exploit"],
        "vulnerability": ["漏洞", "cve", "exploit"],
        "攻击": ["attack", "exploit", "intrusion"],
        "attack": ["攻击", "exploit", "intrusion"],
        "防御": ["defense", "protection", "mitigation"],
        "defense": ["防御", "protection", "mitigation"],
        "检测": ["detection", "monitor", "detect"],
        "detection": ["检测", "monitor", "detect"],
        "网络": ["network", "traffic", "connection"],
        "network": ["网络", "traffic", "connection"],
        "沙盒": ["sandbox", "sandboxing", "isolation"],
        "sandbox": ["沙盒", "sandboxing", "isolation"],
        "seccomp": ["系统调用过滤", "syscall filter", "bpf"],
        "ebpf": ["extended bpf", "berkeley packet filter", "内核探针"],
        "cgroup": ["控制组", "control group", "资源限制"],
        "namespace": ["命名空间", "名称空间", "隔离"],
    }

    def __init__(self, enable_synonym: bool = True,
                 enable_decomposition: bool = True):
        self.enable_synonym = enable_synonym
        self.enable_decomposition = enable_decomposition

    def rewrite(self, query: str) -> str:
        """重写 query，扩展同义词"""
        if not self.enable_synonym:
            return query

        words = re.findall(r'[\w\u4e00-\u9fff]+', query.lower())
        expanded = []
        for word in words:
            expanded.append(word)
            if word in self.SYNONYM_MAP:
                expanded.extend(self.SYNONYM_MAP[word][:2])  # 最多扩展2个同义词
        return " ".join(expanded)

    def decompose(self, query: str) -> List[str]:
        """将复杂查询分解为多个子查询"""
        if not self.enable_decomposition:
            return [query]

        # 按连接词分解
        connectors = r'(?:\s+(?:and|or|与|和|以及| plus)\s+)'
        parts = re.split(connectors, query, flags=re.IGNORECASE)
        if len(parts) > 1 and len(parts) <= 4:
            return [p.strip() for p in parts if p.strip()]
        return [query]


# ============================================================
# 重排序器
# ============================================================

class Reranker:
    """
    检索结果重排序器

    基于多维度特征重新排序：
    1. 原始检索分数
    2. 关键词匹配密度
    3. 文档新鲜度（时间衰减）
    4. 文档重要性（metadata 中的 importance 字段）
    5. 来源可信度
    """

    def __init__(self, keyword_weight: float = 0.3,
                 freshness_weight: float = 0.1,
                 importance_weight: float = 0.2):
        self.keyword_weight = keyword_weight
        self.freshness_weight = freshness_weight
        self.importance_weight = importance_weight

    def rerank(self, results: List[RetrievalResult],
               query: str) -> List[RetrievalResult]:
        """重排序检索结果"""
        if not results:
            return results

        query_tokens = set(re.findall(r'[a-z0-9_]+', query.lower()))
        max_age = 86400 * 30  # 30天

        for result in results:
            # 关键词匹配密度
            doc_tokens = set(re.findall(r'[a-z0-9_]+', result.content.lower()))
            keyword_density = len(query_tokens & doc_tokens) / max(len(query_tokens), 1)

            # 新鲜度（时间衰减）
            doc_time = result.metadata.get("timestamp", time.time())
            age = min(time.time() - doc_time, max_age)
            freshness = 1.0 - (age / max_age)

            # 重要性
            importance = result.metadata.get("importance", 0.5)

            # 综合分数
            original_score = result.score
            result.score = (
                original_score * (1 - self.keyword_weight - self.freshness_weight - self.importance_weight)
                + keyword_density * self.keyword_weight
                + freshness * self.freshness_weight
                + importance * self.importance_weight
            )

        results.sort(key=lambda r: r.score, reverse=True)
        for i, r in enumerate(results):
            r.rank = i + 1
        return results


# ============================================================
# RAG 引擎核心
# ============================================================

class RAGEngine:
    """
    RAG 检索增强生成核心引擎

    管理多个知识库，提供统一的检索增强接口。

    四方向集成：
    - 方向1：红方攻击用例 RAG（cve_kb + evasion_kb）
    - 方向2：蓝方防御规则 RAG（defense_kb + best_practice_kb）
    - 方向3：事件关联 RAG（attack_pattern_kb + incident_kb）
    - 方向4：Agent 策略 RAG（policy_kb + tool_spec_kb）
    """

    def __init__(self, knowledge_dir: Optional[str] = None,
                 strategy: RetrievalStrategy = RetrievalStrategy.HYBRID,
                 top_k: int = 5):
        self.knowledge_dir = knowledge_dir
        self.strategy = strategy
        self.top_k = top_k
        self._knowledge_bases: Dict[str, KnowledgeBase] = {}
        self._query_rewriter = QueryRewriter()
        self._reranker = Reranker()
        self._stats = {
            "total_queries": 0,
            "total_results": 0,
            "avg_retrieval_time_ms": 0.0,
            "cache_hits": 0,
        }
        self._cache: Dict[str, RAGContext] = {}

        if knowledge_dir and os.path.exists(knowledge_dir):
            self._load_knowledge_bases(knowledge_dir)

    # ---- 知识库管理 ----

    def register_kb(self, name: str, kb: KnowledgeBase) -> None:
        """注册知识库"""
        self._knowledge_bases[name] = kb

    def get_kb(self, name: str) -> Optional[KnowledgeBase]:
        """获取知识库"""
        return self._knowledge_bases.get(name)

    def add_document(self, kb_name: str, doc_id: str, content: str,
                     metadata: Optional[Dict] = None) -> str:
        """向知识库添加文档"""
        if kb_name not in self._knowledge_bases:
            self._knowledge_bases[kb_name] = KnowledgeBase(name=kb_name)
        return self._knowledge_bases[kb_name].add(doc_id, content, metadata or {})

    def list_kbs(self) -> List[str]:
        """列出所有知识库"""
        return list(self._knowledge_bases.keys())

    # ---- 检索接口 ----

    def retrieve(self, query: str, kb_names: Optional[List[str]] = None,
                 top_k: Optional[int] = None,
                 strategy: Optional[RetrievalStrategy] = None,
                 use_cache: bool = True) -> RAGContext:
        """
        检索增强生成主接口

        Args:
            query: 查询文本
            kb_names: 要检索的知识库名称列表（None=全部）
            top_k: 返回结果数量
            strategy: 检索策略
            use_cache: 是否使用缓存

        Returns:
            RAGContext 结构化上下文
        """
        start_time = time.time()
        top_k = top_k or self.top_k
        strategy = strategy or self.strategy

        # 缓存检查
        cached = self._check_cache(query, kb_names, top_k, strategy, use_cache)
        if cached is not None:
            return cached

        # 1. Query 重写
        rewritten_query = self._query_rewriter.rewrite(query)

        # 2. 多知识库检索
        all_results = self._search_all_knowledge_bases(rewritten_query, kb_names, top_k)

        # 3. 应用检索策略（混合/重排序）
        all_results = self._apply_retrieval_strategy(all_results, strategy, rewritten_query)

        # 4. 截断到 top_k 并设置排名
        all_results = self._truncate_and_rank(all_results, top_k)

        # 5. 构建上下文
        context_text = self._build_context_text(query, all_results)
        sources = list(set(r.source_kb for r in all_results))
        retrieval_time_ms = (time.time() - start_time) * 1000

        # 6. 更新统计
        self._update_retrieval_stats(len(all_results), retrieval_time_ms)

        # 7. 构建 RAGContext
        context = RAGContext(
            query=query,
            rewritten_query=rewritten_query,
            results=all_results,
            context_text=context_text,
            sources=sources,
            total_docs=len(all_results),
            retrieval_time_ms=round(retrieval_time_ms, 2),
            strategy=strategy.value,
        )

        # 8. 缓存
        self._cache_result(query, kb_names, top_k, strategy, use_cache, context)

        return context

    def _check_cache(self, query: str, kb_names: Optional[List[str]],
                     top_k: int, strategy: RetrievalStrategy,
                     use_cache: bool) -> Optional[RAGContext]:
        """检查缓存，如果命中则返回缓存结果"""
        if not use_cache:
            return None
        cache_key = hashlib.md5(
            f"{query}:{','.join(kb_names or [])}:{top_k}:{strategy.value}".encode(),
            usedforsecurity=False
        ).hexdigest()
        if cache_key in self._cache:
            self._stats["cache_hits"] += 1
            return self._cache[cache_key]
        return None

    def _search_all_knowledge_bases(self, query: str,
                                     kb_names: Optional[List[str]],
                                     top_k: int) -> List[RetrievalResult]:
        """多知识库检索"""
        all_results = []
        target_kbs = kb_names or list(self._knowledge_bases.keys())
        for kb_name in target_kbs:
            kb = self._knowledge_bases.get(kb_name)
            if not kb:
                continue
            kb_results = kb.search(query, top_k=top_k * 2)
            for r in kb_results:
                all_results.append(RetrievalResult(
                    doc_id=r["entry_id"],
                    content=r["content"],
                    score=r["score"],
                    metadata=r.get("metadata", {}),
                    source_kb=kb_name,
                ))
        return all_results

    def _apply_retrieval_strategy(self, results: List[RetrievalResult],
                                   strategy: RetrievalStrategy,
                                   query: str) -> List[RetrievalResult]:
        """应用检索策略（混合加权/重排序）"""
        if strategy in (RetrievalStrategy.HYBRID, RetrievalStrategy.RERANK):
            results = self._hybrid_merge(results)
        if strategy == RetrievalStrategy.RERANK:
            results = self._reranker.rerank(results, query)
        return results

    def _truncate_and_rank(self, results: List[RetrievalResult],
                            top_k: int) -> List[RetrievalResult]:
        """截断到 top_k 并设置排名"""
        results = results[:top_k]
        for i, r in enumerate(results):
            r.rank = i + 1
        return results

    def _update_retrieval_stats(self, num_results: int, retrieval_time_ms: float):
        """更新检索统计信息"""
        self._stats["total_queries"] += 1
        self._stats["total_results"] += num_results
        total = self._stats["total_queries"]
        self._stats["avg_retrieval_time_ms"] = (
            (self._stats["avg_retrieval_time_ms"] * (total - 1)
             + retrieval_time_ms) / total
        )

    def _cache_result(self, query: str, kb_names: Optional[List[str]],
                      top_k: int, strategy: RetrievalStrategy,
                      use_cache: bool, context: RAGContext):
        """缓存检索结果，超过容量时清理旧缓存"""
        if not use_cache:
            return
        cache_key = hashlib.md5(
            f"{query}:{','.join(kb_names or [])}:{top_k}:{strategy.value}".encode(),
            usedforsecurity=False
        ).hexdigest()
        self._cache[cache_key] = context
        if len(self._cache) > 100:
            old_key = next(iter(self._cache))
            del self._cache[old_key]

    def build_prompt(self, template: str, context: RAGContext,
                     **kwargs) -> str:
        """
        基于检索结果构建提示词

        Args:
            template: 提示词模板，使用 {context}, {query}, {sources} 等占位符
            context: RAG 上下文
            **kwargs: 其他模板变量

        Returns:
            填充后的提示词
        """
        return template.format(
            context=context.context_text,
            query=context.query,
            rewritten_query=context.rewritten_query,
            sources=", ".join(context.sources),
            total_docs=context.total_docs,
            **kwargs,
        )

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self._stats,
            "knowledge_bases": {
                name: kb.size() for name, kb in self._knowledge_bases.items()
            },
            "cache_size": len(self._cache),
            "default_strategy": self.strategy.value,
            "default_top_k": self.top_k,
        }

    # ---- 内部方法 ----

    def _hybrid_merge(self, results: List[RetrievalResult]) -> List[RetrievalResult]:
        """混合检索结果合并（按来源加权）"""
        # 按来源分组，归一化分数
        by_source: Dict[str, List[RetrievalResult]] = defaultdict(list)
        for r in results:
            by_source[r.source_kb].append(r)

        # 每个来源内归一化
        for source, source_results in by_source.items():
            if source_results:
                max_score = max(r.score for r in source_results)
                if max_score > 0:
                    for r in source_results:
                        r.score = r.score / max_score

        # 合并并去重（同 doc_id 取最高分）
        merged: Dict[str, RetrievalResult] = {}
        for r in results:
            if r.doc_id not in merged or r.score > merged[r.doc_id].score:
                merged[r.doc_id] = r

        return sorted(merged.values(), key=lambda r: r.score, reverse=True)

    def _build_context_text(self, query: str,
                             results: List[RetrievalResult]) -> str:
        """构建上下文字符串"""
        if not results:
            return "（未检索到相关知识）"

        parts = [f"根据以下知识库内容回答问题：{query}\n"]
        for i, r in enumerate(results, 1):
            source_info = f"[来源:{r.source_kb}"
            if r.metadata.get("cve_id"):
                source_info += f", CVE:{r.metadata['cve_id']}"
            if r.metadata.get("technique_name"):
                source_info += f", 技术:{r.metadata['technique_name']}"
            source_info += "]"
            parts.append(f"\n{i}. {source_info}\n   {r.content[:300]}")

        parts.append("\n\n请基于以上知识给出回答，并标注引用来源。")
        return "\n".join(parts)

    def _load_knowledge_bases(self, knowledge_dir: str) -> None:
        """从目录加载知识库 JSON 文件"""
        if not os.path.isdir(knowledge_dir):
            return
        for filename in os.listdir(knowledge_dir):
            if filename.endswith(".json"):
                kb_name = filename[:-5]  # 去掉 .json
                filepath = os.path.join(knowledge_dir, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    kb = KnowledgeBase(name=kb_name)
                    if isinstance(data, list):
                        for doc in data:
                            doc_id = doc.get("id", doc.get("doc_id", hashlib.md5(str(doc).encode(), usedforsecurity=False).hexdigest()[:12]))
                            content = doc.get("content", doc.get("text", ""))
                            metadata = {k: v for k, v in doc.items() if k not in ("id", "doc_id", "content", "text")}
                            kb.add(doc_id, content, metadata)
                    elif isinstance(data, dict) and "documents" in data:
                        for doc in data["documents"]:
                            doc_id = doc.get("id", hashlib.md5(str(doc).encode(), usedforsecurity=False).hexdigest()[:12])
                            kb.add(doc_id, doc.get("content", ""), doc)
                    self.register_kb(kb_name, kb)
                except (json.JSONDecodeError, KeyError) as e:
                    print(f"Warning: Failed to load knowledge base {filename}: {e}")
