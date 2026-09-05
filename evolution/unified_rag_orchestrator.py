"""
PhotonBox 统一安全知识 RAG 编排引擎

整合5个智能模块的端到端 RAG 流水线：
1. SLM 查询意图理解（slm_query_intent）- 查询去噪/意图分类/实体抽取/重写/分解
2. 智能查询路由（intelligent_query_router）- 8种查询类型自动路由到检索后端
3. RRF 混合检索（hybrid_retrieval）- BM25关键词 + TF-IDF向量 + 实体图谱 + RRF融合
4. 三元组安全知识图谱（security_knowledge_graph）- 漏洞-组件-实例关联 + 多跳推理 + 风险评估
5. 服务器端会话状态管理（session_state_manager）- 跨会话上下文恢复 + 多租户隔离

流水线：
用户查询 → 会话恢复 → SLM意图理解 → 智能路由 → 并行检索(混合+图谱) → 会话上下文注入 → RAG结果聚合

参考技术：
- 微软 GraphRAG：全局/局部双模式搜索，社区报告
- AWS 统一知识图谱 RAG：双检索系统 + RRF融合 + 查询策略选择
- 百度文心一言：实体优先融合
- 腾讯云：API层→计算层→存储层分层解耦架构
- Google Gemini：服务器端状态管理 previous_interaction_id
"""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import time
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# 5个智能模块
from evolution.slm_query_intent import (
    SLMQueryIntentUnderstanding,
    QueryUnderstandingResult,
    IntentType,
)
from evolution.intelligent_query_router import (
    IntelligentQueryRouter,
    UnifiedRetrievalOrchestrator,
    RoutingDecision,
    QueryType,
    RetrievalBackend,
)
from evolution.hybrid_retrieval import (
    HybridRetriever,
    SearchResult,
    SearchDocument,
    RetrievalConfig,
)
from evolution.security_knowledge_graph import (
    SecurityKnowledgeGraph,
    GraphSearchResult,
    build_sample_security_graph,
)
from evolution.session_state_manager import (
    SessionStateManager,
    SessionState,
    SessionStatus,
)


class RAGPipelineStage(Enum):
    """RAG 流水线阶段"""
    SESSION_RESTORE = "session_restore"
    QUERY_UNDERSTANDING = "query_understanding"
    ROUTING = "routing"
    RETRIEVAL = "retrieval"
    KNOWLEDGE_GRAPH = "knowledge_graph"
    CONTEXT_INJECTION = "context_injection"
    AGGREGATION = "aggregation"


@dataclass
class RAGStageTiming:
    """单阶段耗时统计"""
    stage: str
    duration_ms: float
    success: bool = True
    error: Optional[str] = None


@dataclass
class RAGContextChunk:
    """RAG 上下文片段"""
    content: str
    source: str  # hybrid_retrieval / knowledge_graph / session_context
    score: float
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "content": self.content,
            "source": self.source,
            "score": round(self.score, 4),
            "metadata": self.metadata,
        }


@dataclass
class RAGResult:
    """统一 RAG 结果"""
    query: str
    denoised_query: str
    intent: str
    intent_confidence: float
    query_type: str
    entities: list
    retrieved_chunks: list  # list[RAGContextChunk]
    session_id: Optional[str] = None
    previous_session_id: Optional[str] = None
    overall_confidence: float = 0.0
    retrieval_strategy: str = ""
    stage_timings: list = field(default_factory=list)  # list[RAGStageTiming]
    total_duration_ms: float = 0.0
    knowledge_graph_hits: int = 0
    hybrid_retrieval_hits: int = 0
    session_context_hits: int = 0
    risk_assessment: Optional[dict] = None
    generated_answer: Optional[str] = None
    pipeline_version: str = "1.0"

    def to_dict(self) -> dict:
        return {
            "query": self.query,
            "denoised_query": self.denoised_query,
            "intent": self.intent,
            "intent_confidence": round(self.intent_confidence, 4),
            "query_type": self.query_type,
            "entities": [e.to_dict() if hasattr(e, 'to_dict') else str(e) for e in self.entities],
            "retrieved_chunks": [c.to_dict() for c in self.retrieved_chunks],
            "session_id": self.session_id,
            "previous_session_id": self.previous_session_id,
            "overall_confidence": round(self.overall_confidence, 4),
            "retrieval_strategy": self.retrieval_strategy,
            "stage_timings": [
                {"stage": t.stage, "duration_ms": round(t.duration_ms, 2), "success": t.success}
                for t in self.stage_timings
            ],
            "total_duration_ms": round(self.total_duration_ms, 2),
            "knowledge_graph_hits": self.knowledge_graph_hits,
            "hybrid_retrieval_hits": self.hybrid_retrieval_hits,
            "session_context_hits": self.session_context_hits,
            "risk_assessment": self.risk_assessment,
            "generated_answer": self.generated_answer,
            "pipeline_version": self.pipeline_version,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


class UnifiedRAGOrchestrator:
    """
    统一安全知识 RAG 编排引擎

    整合5个智能模块的端到端 RAG 流水线。
    支持会话上下文、多租户隔离、查询意图理解、智能路由、混合检索、知识图谱推理。
    """

    def __init__(
        self,
        knowledge_graph: Optional[SecurityKnowledgeGraph] = None,
        hybrid_retriever: Optional[HybridRetriever] = None,
        session_manager: Optional[SessionStateManager] = None,
        enable_session: bool = True,
        enable_knowledge_graph: bool = True,
        max_context_chunks: int = 10,
        rrf_k: int = 60,
        tenant_id: str = "default",
    ):
        self.enable_session = enable_session
        self.enable_knowledge_graph = enable_knowledge_graph
        self.max_context_chunks = max_context_chunks
        self.rrf_k = rrf_k
        self.tenant_id = tenant_id

        # 初始化5个模块
        self._query_understanding = SLMQueryIntentUnderstanding(enable_cache=True)
        self._router = IntelligentQueryRouter()
        self._orchestrator = UnifiedRetrievalOrchestrator()

        # 知识图谱
        if knowledge_graph is not None:
            self._kg = knowledge_graph
        elif enable_knowledge_graph:
            self._kg = build_sample_security_graph()
        else:
            self._kg = None

        # 混合检索
        if hybrid_retriever is not None:
            self._hybrid = hybrid_retriever
        else:
            config = RetrievalConfig(top_k=5, rrf_k=rrf_k)
            self._hybrid = HybridRetriever(config=config)
            # 预加载安全领域示例文档
            self._load_sample_documents()

        # 会话管理
        if session_manager is not None:
            self._session_mgr = session_manager
        elif enable_session:
            self._session_mgr = SessionStateManager(
                storage_dir="./.rag_sessions",
            )
        else:
            self._session_mgr = None

        # 统计
        self._total_queries = 0
        self._cache_hits = 0
        self._query_cache = {}

    def query(
        self,
        query: str,
        session_id: Optional[str] = None,
        previous_session_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        top_k: Optional[int] = None,
        generate_answer: bool = False,
    ) -> RAGResult:
        """
        执行端到端 RAG 查询

        Args:
            query: 用户查询
            session_id: 当前会话ID（None则自动创建）
            previous_session_id: 上一轮会话ID（用于跨会话恢复）
            tenant_id: 租户ID（覆盖默认）
            top_k: 返回上下文片段数（覆盖默认）
            generate_answer: 是否生成答案（当前为模板生成，后续可接LLM）

        Returns:
            RAGResult 统一 RAG 结果
        """
        pipeline_start = time.time()
        timings = []
        effective_tenant = tenant_id or self.tenant_id
        effective_top_k = top_k or self.max_context_chunks

        # ========== 阶段1：会话恢复 ==========
        stage_start = time.time()
        current_session = None
        try:
            if self.enable_session and self._session_mgr is not None:
                if previous_session_id:
                    # 跨会话恢复（Google Gemini previous_interaction_id 模式）
                    current_session = self._session_mgr.resume_from_previous(
                        previous_session_id=previous_session_id,
                        tenant_id=effective_tenant,
                    )
                    if current_session is not None:
                        session_id = current_session.session_id
                elif session_id:
                    current_session = self._session_mgr.get_session(
                        session_id, tenant_id=effective_tenant
                    )
                    if current_session is None:
                        current_session = self._session_mgr.create_session(
                            tenant_id=effective_tenant,
                            initial_state={"query": query, "query_history": []},
                        )
                        session_id = current_session.session_id
                else:
                    current_session = self._session_mgr.create_session(
                        tenant_id=effective_tenant,
                        initial_state={"query": query, "query_history": []},
                    )
                    session_id = current_session.session_id
            timings.append(RAGStageTiming(
                stage=RAGPipelineStage.SESSION_RESTORE.value,
                duration_ms=(time.time() - stage_start) * 1000,
            ))
        except Exception as e:
            timings.append(RAGStageTiming(
                stage=RAGPipelineStage.SESSION_RESTORE.value,
                duration_ms=(time.time() - stage_start) * 1000,
                success=False,
                error=str(e),
            ))

        # ========== 阶段2：SLM 查询意图理解 ==========
        stage_start = time.time()
        understanding = self._query_understanding.process(query)
        timings.append(RAGStageTiming(
            stage=RAGPipelineStage.QUERY_UNDERSTANDING.value,
            duration_ms=(time.time() - stage_start) * 1000,
        ))

        # 使用重写后的查询（如果触发了重写）
        search_query = understanding.rewritten.rewritten if understanding.needs_rewrite else understanding.denoised.denoised

        # ========== 阶段3：智能路由 ==========
        stage_start = time.time()
        routing = self._router.route(search_query)
        timings.append(RAGStageTiming(
            stage=RAGPipelineStage.ROUTING.value,
            duration_ms=(time.time() - stage_start) * 1000,
        ))

        # ========== 阶段4：混合检索 ==========
        stage_start = time.time()
        hybrid_results = []
        try:
            hybrid_results = self._hybrid.search(search_query, top_k=effective_top_k)
            timings.append(RAGStageTiming(
                stage=RAGPipelineStage.RETRIEVAL.value,
                duration_ms=(time.time() - stage_start) * 1000,
            ))
        except Exception as e:
            timings.append(RAGStageTiming(
                stage=RAGPipelineStage.RETRIEVAL.value,
                duration_ms=(time.time() - stage_start) * 1000,
                success=False,
                error=str(e),
            ))

        # ========== 阶段5：知识图谱检索 + 风险评估 ==========
        stage_start = time.time()
        kg_results = []
        risk_assessment = None
        try:
            if self.enable_knowledge_graph and self._kg is not None:
                # 实体优先融合检索（百度文心一言模式）
                kg_result = self._kg.entity_first_search(
                    query=search_query,
                    top_k=effective_top_k,
                )
                # 处理返回的 dict 格式
                if isinstance(kg_result, dict):
                    matched = kg_result.get("matched_entities", [])
                    related_triples = kg_result.get("related_triples", [])
                    for ent in matched:
                        if isinstance(ent, dict):
                            kg_results.append({
                                "content": f"实体: {ent.get('name', ent.get('id', ''))} - {ent.get('description', '')}",
                                "score": 0.8,
                                "metadata": {"entity_id": ent.get("id", ""), "entity_type": ent.get("entity_type", "")},
                            })
                    for triple in related_triples:
                        if isinstance(triple, dict):
                            kg_results.append({
                                "content": f"{triple.get('subject', '')} --{triple.get('predicate', '')}--> {triple.get('object', '')}",
                                "score": 0.7,
                                "metadata": {"triple_id": triple.get("id", "")},
                            })
                        elif hasattr(triple, 'subject'):
                            kg_results.append({
                                "content": f"{triple.subject} --{triple.predicate}--> {triple.object}",
                                "score": 0.7,
                                "metadata": {},
                            })
                elif hasattr(kg_result, 'results'):
                    kg_results = kg_result.results

                # 风险评估（如果查询涉及实例或风险评估意图）
                if understanding.intent.primary_intent == IntentType.RISK_ASSESSMENT.value:
                    instance_entities = [e for e in understanding.entities if e.entity_type == "component"]
                    if instance_entities:
                        risk_assessment = self._kg.assess_instance_risk(
                            instance_entities[0].normalized
                        )

            timings.append(RAGStageTiming(
                stage=RAGPipelineStage.KNOWLEDGE_GRAPH.value,
                duration_ms=(time.time() - stage_start) * 1000,
            ))
        except Exception as e:
            timings.append(RAGStageTiming(
                stage=RAGPipelineStage.KNOWLEDGE_GRAPH.value,
                duration_ms=(time.time() - stage_start) * 1000,
                success=False,
                error=str(e),
            ))

        # ========== 阶段6：会话上下文注入 ==========
        stage_start = time.time()
        session_chunks = []
        try:
            if current_session is not None and current_session.state:
                # 从会话历史中提取相关上下文
                session_history = current_session.state.get("query_history", [])
                if session_history:
                    # 简单的会话上下文：取最近2轮查询作为上下文
                    recent = session_history[-2:] if len(session_history) >= 2 else session_history
                    for item in recent:
                        if isinstance(item, dict) and "query" in item:
                            session_chunks.append(RAGContextChunk(
                                content=f"历史查询: {item['query']}",
                                source="session_context",
                                score=0.3,
                                metadata={"session_id": session_id},
                            ))
            timings.append(RAGStageTiming(
                stage=RAGPipelineStage.CONTEXT_INJECTION.value,
                duration_ms=(time.time() - stage_start) * 1000,
            ))
        except Exception as e:
            timings.append(RAGStageTiming(
                stage=RAGPipelineStage.CONTEXT_INJECTION.value,
                duration_ms=(time.time() - stage_start) * 1000,
                success=False,
                error=str(e),
            ))

        # ========== 阶段7：RAG 结果聚合（RRF 融合） ==========
        stage_start = time.time()
        all_chunks = []

        # 混合检索结果
        for r in hybrid_results:
            content = r.content if hasattr(r, 'content') else str(r)
            score = r.score if hasattr(r, 'score') else 0.5
            all_chunks.append(RAGContextChunk(
                content=content,
                source="hybrid_retrieval",
                score=score,
                metadata={"doc_id": getattr(r, 'doc_id', ''), "retrieval_method": getattr(r, 'retrieval_method', '')},
            ))

        # 知识图谱结果
        for r in kg_results:
            if isinstance(r, dict):
                content = r.get("content", r.get("triple", str(r)))
                score = r.get("score", 0.6)
                all_chunks.append(RAGContextChunk(
                    content=content,
                    source="knowledge_graph",
                    score=score,
                    metadata=r.get("metadata", {}),
                ))
            else:
                all_chunks.append(RAGContextChunk(
                    content=str(r),
                    source="knowledge_graph",
                    score=0.5,
                ))

        # 会话上下文
        all_chunks.extend(session_chunks)

        # RRF 融合排序
        fused_chunks = self._rrf_fuse(all_chunks)
        final_chunks = fused_chunks[:effective_top_k]

        # 统计各来源命中数
        hybrid_hits = sum(1 for c in final_chunks if c.source == "hybrid_retrieval")
        kg_hits = sum(1 for c in final_chunks if c.source == "knowledge_graph")
        session_hits = sum(1 for c in final_chunks if c.source == "session_context")

        timings.append(RAGStageTiming(
            stage=RAGPipelineStage.AGGREGATION.value,
            duration_ms=(time.time() - stage_start) * 1000,
        ))

        # ========== 生成答案（模板式，后续可接LLM） ==========
        generated_answer = None
        if generate_answer and final_chunks:
            generated_answer = self._generate_template_answer(
                query=query,
                intent=understanding.intent.primary_intent,
                chunks=final_chunks,
                risk_assessment=risk_assessment,
            )

        # ========== 更新会话状态 ==========
        if current_session is not None and self._session_mgr is not None:
            try:
                query_history = current_session.state.get("query_history", [])
                query_history.append({
                    "query": query,
                    "intent": understanding.intent.primary_intent,
                    "timestamp": time.time(),
                })
                self._session_mgr.update_state(
                    session_id=session_id,
                    updates={"query_history": query_history[-20:]},  # 保留最近20轮
                    tenant_id=effective_tenant,
                )
            except Exception:
                pass  # 会话更新失败不影响主流程

        # ========== 综合置信度 ==========
        retrieval_confidence = 0.0
        if final_chunks:
            retrieval_confidence = min(1.0, sum(c.score for c in final_chunks[:3]) / 3)
        overall_confidence = (
            understanding.overall_confidence * 0.4
            + retrieval_confidence * 0.4
            + (routing.confidence if hasattr(routing, 'confidence') else 0.5) * 0.2
        )

        total_duration = (time.time() - pipeline_start) * 1000
        self._total_queries += 1

        return RAGResult(
            query=query,
            denoised_query=understanding.denoised.denoised,
            intent=understanding.intent.primary_intent,
            intent_confidence=understanding.intent.confidence,
            query_type=routing.query_type.value if hasattr(routing.query_type, 'value') else str(routing.query_type),
            entities=understanding.entities,
            retrieved_chunks=final_chunks,
            session_id=session_id,
            previous_session_id=previous_session_id,
            overall_confidence=overall_confidence,
            retrieval_strategy=understanding.recommended_retrieval_strategy,
            stage_timings=timings,
            total_duration_ms=total_duration,
            knowledge_graph_hits=kg_hits,
            hybrid_retrieval_hits=hybrid_hits,
            session_context_hits=session_hits,
            risk_assessment=risk_assessment,
            generated_answer=generated_answer,
        )

    def _load_sample_documents(self):
        """预加载安全领域示例文档到混合检索器"""
        sample_docs = [
            SearchDocument(doc_id="doc_seccomp_001", content="seccomp-BPF 系统调用过滤，限制进程可调用的系统调用，支持参数级过滤，是 LightPool 进程沙箱的核心安全机制", metadata={"module": "LightPool", "topic": "seccomp"}),
            SearchDocument(doc_id="doc_escape_001", content="沙箱逃逸技术包括：ptrace注入父进程、fd泄露继承特权文件描述符、TOCTOU竞争条件、seccomp-bpf绕过、32位兼容模式系统调用", metadata={"module": "security", "topic": "escape"}),
            SearchDocument(doc_id="doc_openssl_001", content="OpenSSL 3.0.2 存在 CVE-2022-3602 高危缓冲区溢出漏洞，影响 X.509 证书验证，建议升级到 3.0.7 或更高版本", metadata={"module": "dependency", "topic": "CVE"}),
            SearchDocument(doc_id="doc_grpc_001", content="gRPC C++ 存在 CVE-2023-44487 HTTP/2 快速重置拒绝服务漏洞，攻击者可通过大量 RST_STREAM 帧耗尽服务器资源", metadata={"module": "dependency", "topic": "CVE"}),
            SearchDocument(doc_id="doc_strongpool_001", content="StrongPool 基于 Firecracker MicroVM 的 KVM 强隔离沙箱，提供硬件级虚拟化隔离，启动延迟<125ms，内存开销5-15MB/实例", metadata={"module": "StrongPool", "topic": "architecture"}),
            SearchDocument(doc_id="doc_lightpool_001", content="LightPool 进程级沙箱，基于 namespace+seccomp-BPF+Landlock+cgroupv2，无需硬件虚拟化，已在 CI 中通过 690+ 测试，生产就绪", metadata={"module": "LightPool", "topic": "architecture"}),
            SearchDocument(doc_id="doc_audit_001", content="审计日志包含：seccomp违规事件、VM-Exit统计、HMAC审计链异常、资源使用超限、进程生命周期事件，支持 SIEM 集成", metadata={"module": "audit", "topic": "logging"}),
            SearchDocument(doc_id="doc_pqc_001", content="后量子密码迁移：Kyber KEM 密钥封装机制+混合密钥交换，PQC Readiness 评分 81.7/100，Dilithium 签名框架级待完善", metadata={"module": "cryptography", "topic": "PQC"}),
            SearchDocument(doc_id="doc_redblue_001", content="红蓝对抗自进化：红方生成攻击用例尝试逃逸，蓝方监控检测防御，裁判判定结果，在线自博弈强化学习持续进化防御规则", metadata={"module": "evolution", "topic": "adversary"}),
            SearchDocument(doc_id="doc_rag_001", content="统一 RAG 编排引擎整合5个智能模块：SLM查询意图理解、智能查询路由、RRF混合检索、三元组安全知识图谱、服务器端会话状态管理", metadata={"module": "RAG", "topic": "architecture"}),
        ]
        try:
            self._hybrid.add_documents(sample_docs)
        except Exception:
            pass  # 检索器接口可能不同，忽略预加载失败

    def _rrf_fuse(self, chunks: list, k: Optional[int] = None) -> list:
        """
        Reciprocal Rank Fusion (RRF) 融合排序

        对多个来源的检索结果按排名倒数融合，消除不同来源评分尺度差异。
        """
        effective_k = k or self.rrf_k
        # 按来源分组
        source_groups = {}
        for chunk in chunks:
            source_groups.setdefault(chunk.source, []).append(chunk)

        # 每组内按 score 排序，计算 RRF 分数
        rrf_scores = {}
        for source, group in source_groups.items():
            sorted_group = sorted(group, key=lambda c: c.score, reverse=True)
            for rank, chunk in enumerate(sorted_group):
                key = chunk.content[:100]  # 用内容前100字符作为去重键
                if key not in rrf_scores:
                    rrf_scores[key] = {"chunk": chunk, "score": 0.0}
                rrf_scores[key]["score"] += 1.0 / (effective_k + rank + 1)

        # 按 RRF 分数排序
        fused = sorted(rrf_scores.values(), key=lambda x: x["score"], reverse=True)
        result = []
        for item in fused:
            chunk = item["chunk"]
            chunk.score = item["score"]  # 更新为 RRF 融合分数
            result.append(chunk)
        return result

    def _generate_template_answer(
        self,
        query: str,
        intent: str,
        chunks: list,
        risk_assessment: Optional[dict] = None,
    ) -> str:
        """生成模板式答案（后续可替换为 LLM 生成）"""
        parts = [f"针对查询「{query}」的检索结果：\n"]

        if risk_assessment:
            parts.append(f"【风险评估】{risk_assessment.get('risk_level', '未知')}级风险")
            if 'affected_components' in risk_assessment:
                parts.append(f"影响组件: {', '.join(risk_assessment['affected_components'])}")
            parts.append("")

        for i, chunk in enumerate(chunks[:5], 1):
            source_label = {
                "hybrid_retrieval": "混合检索",
                "knowledge_graph": "知识图谱",
                "session_context": "会话上下文",
            }.get(chunk.source, chunk.source)
            parts.append(f"{i}. [{source_label}] (置信度 {chunk.score:.2f}) {chunk.content[:200]}")

        return "\n".join(parts)

    def get_pipeline_stats(self) -> dict:
        """获取流水线统计"""
        return {
            "total_queries": self._total_queries,
            "modules_integrated": 5,
            "module_names": [
                "SLM查询意图理解",
                "智能查询路由",
                "RRF混合检索",
                "三元组安全知识图谱",
                "服务器端会话状态管理",
            ],
            "max_context_chunks": self.max_context_chunks,
            "rrf_k": self.rrf_k,
            "session_enabled": self.enable_session,
            "knowledge_graph_enabled": self.enable_knowledge_graph,
            "tenant_id": self.tenant_id,
        }

    def clear_cache(self):
        """清空查询缓存"""
        self._query_cache.clear()
        self._query_understanding.clear_cache()


def create_unified_rag(
    knowledge_graph: Optional[SecurityKnowledgeGraph] = None,
    enable_session: bool = True,
    tenant_id: str = "default",
) -> UnifiedRAGOrchestrator:
    """便捷创建统一 RAG 编排引擎"""
    return UnifiedRAGOrchestrator(
        knowledge_graph=knowledge_graph,
        enable_session=enable_session,
        tenant_id=tenant_id,
    )


# ========== 自测试 ==========
if __name__ == "__main__":
    print("=" * 60)
    print("PhotonBox 统一安全知识 RAG 编排引擎 - 自测试")
    print("=" * 60)

    rag = create_unified_rag(enable_session=False)

    test_queries = [
        "CVE-2022-3602 有没有 POC，影响哪些组件？",
        "如何配置 seccomp 规则，防止沙箱逃逸？",
        "最近 7 天的审计日志中有哪些高危事件？",
        "StrongPool 和 LightPool 有什么区别？",
        "OpenSSL 漏洞的风险评估",
    ]

    for i, q in enumerate(test_queries, 1):
        print(f"\n--- 测试 {i}: {q[:50]}... ---")
        result = rag.query(q, generate_answer=True)
        print(f"  意图: {result.intent} (置信度 {result.intent_confidence:.0%})")
        print(f"  查询类型: {result.query_type}")
        print(f"  实体数: {len(result.entities)}")
        print(f"  检索片段: {len(result.retrieved_chunks)}")
        print(f"  混合检索命中: {result.hybrid_retrieval_hits}")
        print(f"  知识图谱命中: {result.knowledge_graph_hits}")
        print(f"  综合置信度: {result.overall_confidence:.0%}")
        print(f"  总耗时: {result.total_duration_ms:.1f}ms")
        if result.risk_assessment:
            print(f"  风险评估: {result.risk_assessment.get('risk_level', 'N/A')}")

    print("\n" + "=" * 60)
    print(f"流水线统计: {json.dumps(rag.get_pipeline_stats(), indent=2, ensure_ascii=False)}")
    print("=" * 60)
    print("✅ 统一 RAG 编排引擎自测试完成")
