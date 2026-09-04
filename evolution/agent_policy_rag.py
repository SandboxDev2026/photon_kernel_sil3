"""
PhotonBox Agent 策略 RAG（方向 4）

将 RAG 检索增强生成与 PolicyGuard 策略校验框架集成：
1. Agent 工具调用前，先检索相关安全策略
2. 基于检索结果增强 PolicyGuard 的校验
3. 提供策略推荐功能（根据工具类型推荐相关策略）
4. 策略知识库持续更新（从安全事件中学习新策略）

设计参考：
- PolicyGuard 合规校验框架
- Mem0 自动记忆提取
- RAG 检索增强生成
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .rag_engine import RAGEngine, RAGContext, RetrievalStrategy
from .policy_guard import (
    PolicyGuard, PolicyRule, PolicyAction, PolicyType,
    ValidationResult, ValidationResultCode,
)


@dataclass
class PolicyRecommendation:
    """策略推荐结果"""
    tool_name: str
    recommended_policies: List[Dict[str, Any]]
    risk_assessment: str
    required_approvals: List[str]
    confidence: float
    rag_context: Optional[RAGContext] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "recommended_policies": self.recommended_policies,
            "risk_assessment": self.risk_assessment,
            "required_approvals": self.required_approvals,
            "confidence": self.confidence,
            "rag_sources": self.rag_context.sources if self.rag_context else [],
        }


class AgentPolicyRAG:
    """
    Agent 策略 RAG 集成器

    核心能力：
    1. 策略检索：根据工具名和参数检索相关安全策略
    2. 增强校验：将 RAG 检索结果注入 PolicyGuard 校验流程
    3. 策略推荐：为新工具自动推荐安全策略
    4. 策略学习：从安全事件中提取新策略并加入知识库
    """

    def __init__(self, policy_guard: Optional[PolicyGuard] = None,
                 rag_engine: Optional[RAGEngine] = None,
                 knowledge_dir: Optional[str] = None):
        self.policy_guard = policy_guard or PolicyGuard()
        self.rag_engine = rag_engine or RAGEngine(
            knowledge_dir=knowledge_dir,
            strategy=RetrievalStrategy.HYBRID,
            top_k=5,
        )
        self._stats = {
            "total_checks": 0,
            "rag_enhanced_checks": 0,
            "policy_recommendations": 0,
            "new_policies_learned": 0,
        }

    def check_with_rag(self, agent_id: str, tool_name: str,
                        params: Dict[str, Any],
                        conversation_history: Optional[List[Dict]] = None,
                        agent_role: Optional[str] = None,
                        use_rag: bool = True) -> ValidationResult:
        """
        带 RAG 增强的工具调用校验

        流程：检索相关策略→临时注入 PolicyGuard→执行校验→清理临时策略→返回结果

        Args:
            agent_id: Agent ID
            tool_name: 工具名
            params: 工具参数
            conversation_history: 对话历史
            agent_role: Agent 角色
            use_rag: 是否使用 RAG 增强

        Returns:
            校验结果
        """
        self._stats["total_checks"] += 1
        if not use_rag:
            return self.policy_guard.check_tool_call(
                agent_id, tool_name, params, conversation_history, agent_role,
            )
        return self._perform_rag_enhanced_check(
            agent_id, tool_name, params, conversation_history, agent_role
        )

    def _perform_rag_enhanced_check(self, agent_id: str, tool_name: str,
                                      params: Dict[str, Any],
                                      conversation_history: Optional[List[Dict]],
                                      agent_role: Optional[str]) -> ValidationResult:
        """执行 RAG 增强的校验：检索策略→注入→校验→清理"""
        # 1. 检索相关策略
        query = self._build_policy_query(tool_name, params, agent_role)
        rag_context = self.rag_engine.retrieve(
            query, kb_names=["policy_knowledge"], top_k=5,
        )

        # 2. 将检索到的策略临时注入 PolicyGuard
        temp_rule_ids = self._inject_rag_policies(rag_context, tool_name)
        self._stats["rag_enhanced_checks"] += 1

        try:
            # 3. 执行校验
            result = self.policy_guard.check_tool_call(
                agent_id, tool_name, params, conversation_history, agent_role,
            )
            # 附加 RAG 信息
            self._attach_rag_metadata(result, rag_context)
            return result
        finally:
            # 4. 清理临时策略
            self._remove_temp_policies(temp_rule_ids)

    def _attach_rag_metadata(self, result: ValidationResult, rag_context) -> None:
        """附加 RAG 元数据到校验结果"""
        result.metadata = getattr(result, 'metadata', {})
        result.metadata["rag_sources"] = rag_context.sources
        result.metadata["rag_docs"] = rag_context.total_docs
        result.metadata["rag_retrieval_time_ms"] = rag_context.retrieval_time_ms

    def recommend_policy(self, tool_name: str,
                          tool_description: str = "") -> PolicyRecommendation:
        """
        为新工具推荐安全策略

        Args:
            tool_name: 工具名
            tool_description: 工具描述

        Returns:
            策略推荐结果
        """
        self._stats["policy_recommendations"] += 1

        query = f"安全策略 for {tool_name} {tool_description}"
        rag_context = self.rag_engine.retrieve(
            query, kb_names=["policy_knowledge"], top_k=5,
        )

        recommended = []
        required_approvals = []
        risk_level = "low"

        for result in rag_context.results:
            policy = {
                "policy_id": result.doc_id,
                "content": result.content[:200],
                "severity": result.metadata.get("severity", "medium"),
                "policy_type": result.metadata.get("policy_type", "general"),
                "relevance_score": result.score,
            }
            recommended.append(policy)

            severity = result.metadata.get("severity", "medium")
            if severity in ("critical", "high"):
                risk_level = "high"
                if result.metadata.get("policy_type") in ("permission", "isolation", "secret_management"):
                    required_approvals.append(result.doc_id)

        confidence = min(0.5 + len(recommended) * 0.1, 0.95)

        return PolicyRecommendation(
            tool_name=tool_name,
            recommended_policies=recommended,
            risk_assessment=risk_level,
            required_approvals=required_approvals,
            confidence=confidence,
            rag_context=rag_context,
        )

    def learn_policy_from_event(self, event: Dict[str, Any],
                                  event_type: str = "security_event") -> Optional[str]:
        """
        从安全事件中学习新策略

        Args:
            event: 安全事件
            event_type: 事件类型

        Returns:
            新策略 ID（如果学习成功）
        """
        # 提取事件关键信息
        attack_type = event.get("attack_type", event_type)
        description = event.get("description", "")
        severity = event.get("severity", "medium")

        if not description:
            return None

        # 检查是否已有相似策略
        existing = self.rag_engine.retrieve(
            description, kb_names=["policy_knowledge"], top_k=3,
        )
        if existing.results and existing.results[0].score > 0.7:
            return None  # 已有相似策略，不重复学习

        # 创建新策略
        policy_id = f"pol_learned_{int(time.time())}"
        policy_content = f"从安全事件学习的策略：{description}。攻击类型：{attack_type}。建议措施：根据事件类型采取相应防护措施。"

        # 添加到 RAG 知识库
        self.rag_engine.add_document(
            "policy_knowledge", policy_id, policy_content,
            metadata={"policy_type": "learned", "severity": severity,
                      "learned_from": event_type, "timestamp": time.time()},
        )

        # 添加到 PolicyGuard
        rule = PolicyRule(
            rule_id=policy_id,
            policy_type=PolicyType.SECURITY,
            action=PolicyAction.LOG_ONLY,  # 新学习的策略先只记录，不拦截
            description=policy_content[:200],
            tool_pattern=f".*{attack_type}.*",
            priority=200,
            metadata={"learned": True, "event_type": event_type},
        )
        self.policy_guard.add_rule(rule)

        self._stats["new_policies_learned"] += 1
        return policy_id

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self._stats,
            "policy_guard": self.policy_guard.get_stats(),
            "rag_engine": self.rag_engine.get_stats(),
        }

    # ---- 内部方法 ----

    def _build_policy_query(self, tool_name: str, params: Dict[str, Any],
                             agent_role: Optional[str]) -> str:
        """构建策略检索 query"""
        parts = [tool_name]
        if agent_role:
            parts.append(f"role:{agent_role}")
        for key, value in list(params.items())[:3]:
            parts.append(f"{key}:{value}")
        return " ".join(str(p) for p in parts)

    def _inject_rag_policies(self, rag_context: RAGContext,
                               tool_name: str) -> List[str]:
        """将 RAG 检索到的策略临时注入 PolicyGuard"""
        temp_ids = []
        for result in rag_context.results:
            if result.score < 0.3:  # 只注入相关性较高的策略
                continue
            rule_id = f"rag_temp_{result.doc_id}"
            # 检查是否已存在
            if rule_id in [r.rule_id for r in self.policy_guard.get_rules()]:
                continue
            severity = result.metadata.get("severity", "medium")
            action = PolicyAction.LOG_ONLY  # RAG 策略默认只记录，不拦截
            if severity == "critical":
                action = PolicyAction.REQUIRE_APPROVAL

            rule = PolicyRule(
                rule_id=rule_id,
                policy_type=PolicyType.SECURITY,
                action=action,
                description=f"[RAG] {result.content[:150]}",
                tool_pattern=f".*{tool_name}.*",
                priority=150,
                metadata={"rag_source": result.source_kb, "rag_score": result.score},
            )
            self.policy_guard.add_rule(rule)
            temp_ids.append(rule_id)
        return temp_ids

    def _remove_temp_policies(self, rule_ids: List[str]) -> None:
        """移除临时注入的策略"""
        for rule_id in rule_ids:
            self.policy_guard.remove_rule(rule_id)
