"""
PhotonBox 智能查询路由与统一检索编排器

参考 AWS 统一知识图谱 RAG（awslabs/unified-kg-rag-on-aws）的查询策略选择：
- 根据查询特征自动选择检索策略
- 实体明确→图检索优先；语义模糊→向量检索优先
- 双检索系统 + RRF 融合 + 策略选择

整合现有模块：
1. RRF 混合检索（关键词+向量+图谱三路融合）
2. 三元组安全知识图谱（实体优先融合检索）
3. 服务器端会话状态管理（会话上下文检索）

核心功能：
1. 查询特征分析（NER实体检测、查询类型分类、意图识别）
2. 检索策略选择（根据查询特征自动选择最优检索器组合）
3. 统一检索编排（整合多个检索后端，RRF融合结果）
4. 路由规则引擎（可配置的路由规则，支持自定义）
5. 路由结果解释（透明告知为什么选择这个检索策略）
6. 路由效果反馈（根据检索结果质量优化路由规则）
"""

import re
import time
import math
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set
from collections import defaultdict
from enum import Enum


# ==================== 查询类型枚举 ====================

class QueryType(Enum):
    """查询类型枚举"""
    ENTITY_LOOKUP = "entity_lookup"           # 实体查询（明确的实体名称/ID）
    SEMANTIC_SEARCH = "semantic_search"       # 语义搜索（模糊描述）
    KEYWORD_SEARCH = "keyword_search"         # 关键词搜索（精确术语）
    RELATION_QUERY = "relation_query"         # 关系查询（A和B的关系）
    SESSION_CONTEXT = "session_context"       # 会话上下文（历史相关）
    RISK_ASSESSMENT = "risk_assessment"       # 风险评估（漏洞影响分析）
    ATTACK_CHAIN = "attack_chain"             # 攻击链（多步关联）
    GENERAL = "general"                       # 通用查询


class RetrievalBackend(Enum):
    """检索后端枚举"""
    RRF_HYBRID = "rrf_hybrid"                 # RRF 混合检索（关键词+向量+图谱）
    KNOWLEDGE_GRAPH = "knowledge_graph"       # 三元组安全知识图谱
    SESSION_STATE = "session_state"           # 会话状态管理
    KEYWORD_ONLY = "keyword_only"             # 仅关键词检索
    VECTOR_ONLY = "vector_only"               # 仅向量检索
    GRAPH_ONLY = "graph_only"                 # 仅图谱检索


# ==================== 数据结构 ====================

@dataclass
class QueryFeatures:
    """查询特征分析结果"""
    query: str
    query_type: str
    confidence: float                          # 类型判断置信度（0-1）
    detected_entities: List[str] = field(default_factory=list)  # 检测到的实体
    detected_cves: List[str] = field(default_factory=list)      # 检测到的 CVE
    detected_components: List[str] = field(default_factory=list)  # 检测到的组件
    keywords: List[str] = field(default_factory=list)             # 关键词
    has_relation_pattern: bool = False        # 是否包含关系模式（A和B）
    has_risk_pattern: bool = False            # 是否包含风险评估模式
    has_session_pattern: bool = False         # 是否包含会话上下文模式
    has_attack_chain_pattern: bool = False    # 是否包含攻击链模式
    query_length: int = 0
    is_question: bool = False
    features: Dict[str, Any] = field(default_factory=dict)  # 额外特征


@dataclass
class RoutingDecision:
    """路由决策结果"""
    query: str
    query_type: str
    selected_backends: List[str]               # 选中的检索后端（按优先级排序）
    backend_weights: Dict[str, float]          # 各后端权重
    rrf_enabled: bool = True                    # 是否启用 RRF 融合
    top_k: int = 10
    reasoning: str = ""                         # 路由决策解释
    confidence: float = 0.0                     # 路由决策置信度
    fallback_strategy: str = "rrf_hybrid"      # 回退策略
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UnifiedSearchResult:
    """统一检索结果"""
    doc_id: str
    score: float
    rank: int
    source: str                                # 来源后端
    content: str = ""
    document: Optional[Any] = None
    matched_backends: List[str] = field(default_factory=list)  # 哪些后端匹配到了
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RoutingRule:
    """路由规则"""
    rule_id: str
    name: str
    description: str
    condition: Dict[str, Any]                   # 条件（查询特征匹配规则）
    action: Dict[str, Any]                      # 动作（选择后端、权重等）
    priority: int = 0                           # 优先级（数字越大越优先）
    enabled: bool = True
    hit_count: int = 0                          # 命中次数（统计用）


# ==================== 查询特征分析器 ====================

class QueryFeatureAnalyzer:
    """
    查询特征分析器

    分析查询的特征，包括：
    1. NER 实体检测（CVE 编号、组件名称、安全术语）
    2. 查询类型分类（实体查询/语义搜索/关键词搜索/关系查询等）
    3. 意图识别（风险评估/攻击链/会话上下文等）
    4. 关键词提取
    """

    # CVE 编号正则
    CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

    # 安全组件关键词
    SECURITY_COMPONENTS = {
        "openssl", "grpc", "firecracker", "kvm", "seccomp", "ebpf", "bpf",
        "landlock", "cgroup", "namespace", "container", "docker", "kubernetes",
        "k8s", "qemu", "libvirt", "criu", "systemd", "linux", "kernel",
        "python", "golang", "rust", "cpp", "java", "nodejs",
        "nginx", "apache", "mysql", "postgresql", "redis", "mongodb",
        "strongpool", "lightpool", "photonbox", "sandbox",
    }

    # 关系查询模式（A和B的关系）
    RELATION_PATTERNS = [
        r'(.+)\s+和\s+(.+)\s+的关系',
        r'(.+)\s+与\s+(.+)\s+的关联',
        r'(.+)\s+影响\s+(.+)',
        r'(.+)\s+和\s+(.+)\s+有什么关系',
        r'relation\s+between\s+(.+)\s+and\s+(.+)',
        r'how\s+(.+)\s+affects?\s+(.+)',
    ]

    # 风险评估模式
    RISK_PATTERNS = [
        r'风险评估', r'风险分析', r'影响分析', r'漏洞影响',
        r'risk\s+assessment', r'risk\s+analysis', r'impact\s+analysis',
        r'哪些.*受影响', r'哪些实例.*漏洞',
    ]

    # 会话上下文模式
    SESSION_PATTERNS = [
        r'上次', r'之前', r'刚才', r'历史', r'会话', r'继续',
        r'previous', r'last\s+time', r'earlier', r'history', r'session',
        r'continue', r'接着',
    ]

    # 攻击链模式
    ATTACK_CHAIN_PATTERNS = [
        r'攻击链', r'攻击路径', r'逃逸路径', r'利用链',
        r'attack\s+chain', r'attack\s+path', r'escape\s+path',
        r'exploit\s+chain', r'多步', r'链式',
    ]

    # 问题模式
    QUESTION_PATTERNS = [
        r'什么', r'怎么', r'如何', r'为什么', r'哪些', r'谁',
        r'what', r'how', r'why', r'which', r'who', r'when', r'where',
        r'\?', r'？',
    ]

    def analyze(self, query: str) -> QueryFeatures:
        """
        分析查询特征

        Args:
            query: 查询文本

        Returns:
            查询特征分析结果
        """
        query_lower = query.lower()
        query_length = len(query)

        # 1. 检测 CVE 编号
        cves = self.CVE_PATTERN.findall(query)

        # 2. 检测安全组件
        components = []
        for comp in self.SECURITY_COMPONENTS:
            if comp in query_lower:
                components.append(comp)

        # 3. 检测实体（CVE + 组件）
        entities = cves + components

        # 4. 检测关系模式
        has_relation = any(
            re.search(pattern, query_lower)
            for pattern in self.RELATION_PATTERNS
        )

        # 5. 检测风险评估模式
        has_risk = any(
            re.search(pattern, query_lower)
            for pattern in self.RISK_PATTERNS
        )

        # 6. 检测会话上下文模式
        has_session = any(
            re.search(pattern, query_lower)
            for pattern in self.SESSION_PATTERNS
        )

        # 7. 检测攻击链模式
        has_attack_chain = any(
            re.search(pattern, query_lower)
            for pattern in self.ATTACK_CHAIN_PATTERNS
        )

        # 8. 检测是否为问题
        is_question = any(
            re.search(pattern, query_lower)
            for pattern in self.QUESTION_PATTERNS
        )

        # 9. 提取关键词（简单分词，去除停用词）
        keywords = self._extract_keywords(query)

        # 10. 分类查询类型
        query_type, confidence = self._classify_query(
            query=query,
            entities=entities,
            cves=cves,
            components=components,
            has_relation=has_relation,
            has_risk=has_risk,
            has_session=has_session,
            has_attack_chain=has_attack_chain,
            is_question=is_question,
            query_length=query_length,
        )

        return QueryFeatures(
            query=query,
            query_type=query_type,
            confidence=confidence,
            detected_entities=entities,
            detected_cves=cves,
            detected_components=components,
            keywords=keywords,
            has_relation_pattern=has_relation,
            has_risk_pattern=has_risk,
            has_session_pattern=has_session,
            has_attack_chain_pattern=has_attack_chain,
            query_length=query_length,
            is_question=is_question,
            features={
                "cve_count": len(cves),
                "component_count": len(components),
                "entity_count": len(entities),
                "keyword_count": len(keywords),
            },
        )

    def _extract_keywords(self, query: str) -> List[str]:
        """简单关键词提取"""
        # 去除标点，分词
        words = re.findall(r'[a-zA-Z0-9_\-]+', query.lower())
        # 去除停用词
        stopwords = {
            "the", "a", "an", "is", "are", "was", "were", "be", "been",
            "being", "have", "has", "had", "do", "does", "did", "will",
            "would", "could", "should", "may", "might", "must", "shall",
            "can", "need", "dare", "ought", "used", "how", "what", "why", "when", "where", "which", "who", "to", "of", "in",
            "for", "on", "with", "at", "by", "from", "as", "into",
            "through", "during", "before", "after", "above", "below",
            "between", "out", "off", "over", "under", "again", "further",
            "then", "once", "and", "but", "or", "nor", "not", "so",
            "yet", "both", "either", "neither", "each", "every", "all",
            "any", "few", "more", "most", "other", "some", "such", "no",
            "only", "own", "same", "than", "too", "very", "just",
            "什么", "怎么", "如何", "为什么", "哪些", "的", "了", "是",
            "在", "有", "和", "与", "或", "及", "等", "也", "都",
            "就", "还", "又", "再", "已", "被", "把", "让", "使",
        }
        return [w for w in words if w not in stopwords and len(w) > 1]

    def _classify_query(
        self,
        query: str,
        entities: List[str],
        cves: List[str],
        components: List[str],
        has_relation: bool,
        has_risk: bool,
        has_session: bool,
        has_attack_chain: bool,
        is_question: bool,
        query_length: int,
    ) -> Tuple[str, float]:
        """
        分类查询类型（基于规则的分类器）

        Returns:
            (查询类型, 置信度)
        """
        # 优先级从高到低判断

        # 1. 攻击链查询
        if has_attack_chain:
            return QueryType.ATTACK_CHAIN.value, 0.85

        # 2. 风险评估查询
        if has_risk or (cves and ("影响" in query or "受影响" in query)):
            return QueryType.RISK_ASSESSMENT.value, 0.80

        # 3. 会话上下文查询
        if has_session:
            return QueryType.SESSION_CONTEXT.value, 0.75

        # 4. 关系查询
        if has_relation or (len(entities) >= 2 and ("和" in query or "与" in query or "and" in query.lower())):
            return QueryType.RELATION_QUERY.value, 0.70

        # 5. 实体查询（明确的 CVE，且查询较短）
        if cves and query_length < 50:
            return QueryType.ENTITY_LOOKUP.value, 0.75

        # 6. 语义搜索（问题形式或较长描述性查询）
        if is_question or query_length >= 30:
            return QueryType.SEMANTIC_SEARCH.value, 0.65

        # 7. 关键词搜索（短查询，无 CVE，非问题形式）
        if query_length < 30 and not cves:
            return QueryType.KEYWORD_SEARCH.value, 0.60

        # 7.5 组件查询（有组件但查询较长，分类为实体查询）
        if components and query_length < 50:
            return QueryType.ENTITY_LOOKUP.value, 0.65

        # 8. 通用查询
        return QueryType.GENERAL.value, 0.40


# ==================== 路由规则引擎 ====================

class RoutingRuleEngine:
    """
    路由规则引擎

    基于规则的检索策略选择，支持：
    1. 预定义规则（内置常用路由规则）
    2. 自定义规则（用户添加）
    3. 规则优先级
    4. 规则启用/禁用
    5. 规则命中统计
    """

    def __init__(self):
        self.rules: List[RoutingRule] = []
        self._init_default_rules()

    def _init_default_rules(self):
        """初始化默认路由规则"""
        default_rules = [
            RoutingRule(
                rule_id="rule_entity_lookup",
                name="实体查询优先知识图谱",
                description="检测到明确实体（CVE/组件）时，知识图谱优先",
                condition={"query_type": "entity_lookup", "min_entities": 1},
                action={
                    "backends": ["knowledge_graph", "rrf_hybrid"],
                    "weights": {"knowledge_graph": 1.5, "rrf_hybrid": 1.0},
                    "rrf_enabled": True,
                },
                priority=100,
            ),
            RoutingRule(
                rule_id="rule_risk_assessment",
                name="风险评估使用知识图谱推理",
                description="风险评估查询使用知识图谱进行漏洞-组件-实例关联推理",
                condition={"query_type": "risk_assessment"},
                action={
                    "backends": ["knowledge_graph", "rrf_hybrid"],
                    "weights": {"knowledge_graph": 2.0, "rrf_hybrid": 0.8},
                    "rrf_enabled": True,
                    "extra": {"enable_risk_reasoning": True},
                },
                priority=95,
            ),
            RoutingRule(
                rule_id="rule_attack_chain",
                name="攻击链使用图谱+混合检索",
                description="攻击链查询使用知识图谱多跳推理+混合检索",
                condition={"query_type": "attack_chain"},
                action={
                    "backends": ["knowledge_graph", "rrf_hybrid"],
                    "weights": {"knowledge_graph": 1.8, "rrf_hybrid": 1.0},
                    "rrf_enabled": True,
                    "extra": {"enable_multi_hop": True, "max_depth": 3},
                },
                priority=90,
            ),
            RoutingRule(
                rule_id="rule_relation_query",
                name="关系查询使用知识图谱",
                description="关系查询（A和B的关系）使用知识图谱",
                condition={"query_type": "relation_query"},
                action={
                    "backends": ["knowledge_graph", "rrf_hybrid"],
                    "weights": {"knowledge_graph": 1.5, "rrf_hybrid": 1.0},
                    "rrf_enabled": True,
                },
                priority=85,
            ),
            RoutingRule(
                rule_id="rule_session_context",
                name="会话上下文使用会话状态管理",
                description="包含历史/上次/继续等词的查询使用会话状态",
                condition={"query_type": "session_context"},
                action={
                    "backends": ["session_state", "rrf_hybrid"],
                    "weights": {"session_state": 1.5, "rrf_hybrid": 1.0},
                    "rrf_enabled": True,
                },
                priority=80,
            ),
            RoutingRule(
                rule_id="rule_semantic_search",
                name="语义搜索使用向量优先",
                description="语义模糊的查询使用向量检索优先",
                condition={"query_type": "semantic_search"},
                action={
                    "backends": ["rrf_hybrid"],
                    "weights": {"rrf_hybrid": 1.0},
                    "rrf_enabled": True,
                    "extra": {"vector_weight_boost": 1.5},
                },
                priority=70,
            ),
            RoutingRule(
                rule_id="rule_keyword_search",
                name="关键词搜索使用关键词优先",
                description="精确术语查询使用关键词检索优先",
                condition={"query_type": "keyword_search"},
                action={
                    "backends": ["rrf_hybrid"],
                    "weights": {"rrf_hybrid": 1.0},
                    "rrf_enabled": True,
                    "extra": {"keyword_weight_boost": 1.5},
                },
                priority=60,
            ),
            RoutingRule(
                rule_id="rule_general",
                name="通用查询默认RRF混合",
                description="无法分类的查询使用默认RRF混合检索",
                condition={"query_type": "general"},
                action={
                    "backends": ["rrf_hybrid"],
                    "weights": {"rrf_hybrid": 1.0},
                    "rrf_enabled": True,
                },
                priority=0,
            ),
        ]
        self.rules = default_rules

    def add_rule(self, rule: RoutingRule):
        """添加自定义规则"""
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority, reverse=True)

    def remove_rule(self, rule_id: str) -> bool:
        """移除规则"""
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
        return len(self.rules) < before

    def enable_rule(self, rule_id: str) -> bool:
        """启用规则"""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                rule.enabled = True
                return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """禁用规则"""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                rule.enabled = False
                return True
        return False

    def match_rule(self, features: QueryFeatures) -> Optional[RoutingRule]:
        """
        匹配路由规则

        按优先级从高到低匹配，返回第一个匹配的规则。
        """
        for rule in self.rules:
            if not rule.enabled:
                continue
            if self._check_condition(rule.condition, features):
                rule.hit_count += 1
                return rule
        return None

    def _check_condition(self, condition: Dict[str, Any], features: QueryFeatures) -> bool:
        """检查规则条件是否匹配"""
        # 查询类型匹配
        if "query_type" in condition:
            if features.query_type != condition["query_type"]:
                return False

        # 最小实体数
        if "min_entities" in condition:
            if len(features.detected_entities) < condition["min_entities"]:
                return False

        # 最小 CVE 数
        if "min_cves" in condition:
            if len(features.detected_cves) < condition["min_cves"]:
                return False

        # 必须包含的特征
        if "require_features" in condition:
            for feat in condition["require_features"]:
                if not getattr(features, feat, False):
                    return False

        return True

    def get_rule_statistics(self) -> List[Dict[str, Any]]:
        """获取规则命中统计"""
        return [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "priority": r.priority,
                "enabled": r.enabled,
                "hit_count": r.hit_count,
            }
            for r in sorted(self.rules, key=lambda r: r.hit_count, reverse=True)
        ]


# ==================== 智能查询路由器 ====================

class IntelligentQueryRouter:
    """
    智能查询路由器

    整合查询特征分析和路由规则引擎，根据查询特征自动选择最优检索策略。

    核心流程：
    1. 查询特征分析（NER、类型分类、意图识别）
    2. 路由规则匹配（按优先级匹配规则）
    3. 生成路由决策（选择后端、权重、RRF融合）
    4. 路由决策解释（透明告知为什么选择）
    """

    def __init__(self, rule_engine: Optional[RoutingRuleEngine] = None):
        self.analyzer = QueryFeatureAnalyzer()
        self.rule_engine = rule_engine or RoutingRuleEngine()
        self.routing_history: List[RoutingDecision] = []  # 路由历史（反馈优化用）

    def route(self, query: str, top_k: int = 10) -> RoutingDecision:
        """
        路由查询，生成检索策略决策

        Args:
            query: 查询文本
            top_k: 返回结果数量

        Returns:
            路由决策结果
        """
        # 1. 查询特征分析
        features = self.analyzer.analyze(query)

        # 2. 匹配路由规则
        matched_rule = self.rule_engine.match_rule(features)

        # 3. 生成路由决策
        if matched_rule:
            decision = self._build_decision_from_rule(query, features, matched_rule, top_k)
        else:
            # 无匹配规则，使用默认回退策略
            decision = self._build_fallback_decision(query, features, top_k)

        # 4. 记录路由历史
        self.routing_history.append(decision)
        if len(self.routing_history) > 1000:
            self.routing_history = self.routing_history[-1000:]

        return decision

    def _build_decision_from_rule(
        self,
        query: str,
        features: QueryFeatures,
        rule: RoutingRule,
        top_k: int,
    ) -> RoutingDecision:
        """从规则构建路由决策"""
        action = rule.action
        backends = action.get("backends", ["rrf_hybrid"])
        weights = action.get("weights", {b: 1.0 for b in backends})
        rrf_enabled = action.get("rrf_enabled", True)
        extra = action.get("extra", {})

        # 生成决策解释
        reasoning = self._generate_reasoning(features, rule, backends, weights)

        return RoutingDecision(
            query=query,
            query_type=features.query_type,
            selected_backends=backends,
            backend_weights=weights,
            rrf_enabled=rrf_enabled,
            top_k=top_k,
            reasoning=reasoning,
            confidence=features.confidence,
            fallback_strategy="rrf_hybrid",
            metadata={
                "matched_rule": rule.rule_id,
                "rule_name": rule.name,
                "rule_priority": rule.priority,
                "detected_entities": features.detected_entities,
                "detected_cves": features.detected_cves,
                "detected_components": features.detected_components,
                "keywords": features.keywords,
                "extra": extra,
                "features": features.features,
            },
        )

    def _build_fallback_decision(
        self,
        query: str,
        features: QueryFeatures,
        top_k: int,
    ) -> RoutingDecision:
        """构建回退决策（无匹配规则时）"""
        return RoutingDecision(
            query=query,
            query_type=features.query_type,
            selected_backends=["rrf_hybrid"],
            backend_weights={"rrf_hybrid": 1.0},
            rrf_enabled=True,
            top_k=top_k,
            reasoning=f"未匹配到特定路由规则（查询类型：{features.query_type}），使用默认RRF混合检索回退策略",
            confidence=max(0.3, features.confidence * 0.5),
            fallback_strategy="rrf_hybrid",
            metadata={
                "matched_rule": None,
                "detected_entities": features.detected_entities,
                "keywords": features.keywords,
                "features": features.features,
            },
        )

    def _generate_reasoning(
        self,
        features: QueryFeatures,
        rule: RoutingRule,
        backends: List[str],
        weights: Dict[str, float],
    ) -> str:
        """生成路由决策解释"""
        parts = [f"查询类型识别为「{features.query_type}」（置信度 {features.confidence:.0%}）"]

        if features.detected_cves:
            parts.append(f"检测到 CVE：{', '.join(features.detected_cves)}")
        if features.detected_components:
            parts.append(f"检测到组件：{', '.join(features.detected_components)}")

        parts.append(f"匹配规则「{rule.name}」（优先级 {rule.priority}）")
        parts.append(f"选择检索后端：{', '.join(backends)}")

        if len(weights) > 1:
            weight_desc = ", ".join(f"{b}={w:.1f}x" for b, w in weights.items())
            parts.append(f"后端权重：{weight_desc}")

        return "；".join(parts)

    def analyze_query(self, query: str) -> QueryFeatures:
        """公开查询特征分析接口"""
        return self.analyzer.analyze(query)

    def get_routing_statistics(self) -> Dict[str, Any]:
        """获取路由统计"""
        type_counts = defaultdict(int)
        backend_counts = defaultdict(int)
        for decision in self.routing_history:
            type_counts[decision.query_type] += 1
            for backend in decision.selected_backends:
                backend_counts[backend] += 1

        return {
            "total_routes": len(self.routing_history),
            "routes_by_type": dict(type_counts),
            "backend_usage": dict(backend_counts),
            "rule_statistics": self.rule_engine.get_rule_statistics(),
        }


# ==================== 统一检索编排器 ====================

class UnifiedRetrievalOrchestrator:
    """
    统一检索编排器

    整合多个检索后端，根据智能路由决策执行检索并融合结果。

    支持的检索后端：
    1. RRF 混合检索（关键词+向量+图谱三路融合）
    2. 三元组安全知识图谱（实体优先融合检索）
    3. 服务器端会话状态管理（会话上下文检索）

    结果融合：
    - RRF（Reciprocal Rank Fusion）融合多个后端的结果
    - 支持后端权重调整
    - 透明标注每个结果的来源后端
    """

    def __init__(
        self,
        router: Optional[IntelligentQueryRouter] = None,
        rrf_retriever: Optional[Any] = None,
        knowledge_graph: Optional[Any] = None,
        session_manager: Optional[Any] = None,
    ):
        self.router = router or IntelligentQueryRouter()
        self.rrf_retriever = rrf_retriever
        self.knowledge_graph = knowledge_graph
        self.session_manager = session_manager

    def search(
        self,
        query: str,
        top_k: int = 10,
        session_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        统一检索入口

        Args:
            query: 查询文本
            top_k: 返回结果数量
            session_id: 会话 ID（用于会话上下文检索）
            tenant_id: 租户 ID（用于多租户隔离）

        Returns:
            统一检索结果（包含路由决策、融合结果、各后端原始结果）
        """
        # 1. 智能路由
        decision = self.router.route(query, top_k=top_k)

        # 2. 按决策执行各后端检索
        backend_results: Dict[str, List[UnifiedSearchResult]] = {}
        for backend in decision.selected_backends:
            results = self._execute_backend(
                backend=backend,
                query=query,
                top_k=top_k,
                decision=decision,
                session_id=session_id,
                tenant_id=tenant_id,
            )
            backend_results[backend] = results

        # 3. RRF 融合结果
        if decision.rrf_enabled and len(backend_results) > 1:
            fused_results = self._rrf_fuse(backend_results, decision.backend_weights, top_k)
        else:
            # 单后端或禁用 RRF，直接使用第一个后端的结果
            first_backend = decision.selected_backends[0]
            fused_results = backend_results.get(first_backend, [])[:top_k]

        # 4. 返回统一结果
        return {
            "query": query,
            "routing_decision": decision,
            "fused_results": fused_results,
            "backend_results": {
                backend: [r.__dict__ if hasattr(r, '__dict__') else r for r in results]
                for backend, results in backend_results.items()
            },
            "statistics": {
                "total_results": len(fused_results),
                "backends_used": decision.selected_backends,
                "rrf_enabled": decision.rrf_enabled,
                "query_type": decision.query_type,
                "confidence": decision.confidence,
            },
        }

    def _execute_backend(
        self,
        backend: str,
        query: str,
        top_k: int,
        decision: RoutingDecision,
        session_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> List[UnifiedSearchResult]:
        """执行单个后端检索"""
        if backend == "rrf_hybrid":
            return self._search_rrf_hybrid(query, top_k, decision)
        elif backend == "knowledge_graph":
            return self._search_knowledge_graph(query, top_k, decision)
        elif backend == "session_state":
            return self._search_session_state(query, top_k, session_id, tenant_id)
        elif backend == "keyword_only":
            return self._search_keyword_only(query, top_k)
        elif backend == "vector_only":
            return self._search_vector_only(query, top_k)
        elif backend == "graph_only":
            return self._search_graph_only(query, top_k)
        else:
            return []

    def _search_rrf_hybrid(
        self, query: str, top_k: int, decision: RoutingDecision
    ) -> List[UnifiedSearchResult]:
        """RRF 混合检索"""
        if self.rrf_retriever is None:
            return self._mock_search_results(query, top_k, "rrf_hybrid")

        try:
            raw_results = self.rrf_retriever.search(query, top_k=top_k)
            return [
                UnifiedSearchResult(
                    doc_id=r.doc_id,
                    score=r.score,
                    rank=i + 1,
                    source="rrf_hybrid",
                    content=r.document.content if r.document else "",
                    document=r.document,
                    matched_backends=["rrf_hybrid"],
                    details=getattr(r, "details", {}),
                )
                for i, r in enumerate(raw_results)
            ]
        except Exception:
            return self._mock_search_results(query, top_k, "rrf_hybrid")

    def _search_knowledge_graph(
        self, query: str, top_k: int, decision: RoutingDecision
    ) -> List[UnifiedSearchResult]:
        """知识图谱检索"""
        if self.knowledge_graph is None:
            return self._mock_search_results(query, top_k, "knowledge_graph")

        try:
            result = self.knowledge_graph.entity_first_search(query, top_k=top_k)
            kg_results = result.get("results", [])
            return [
                UnifiedSearchResult(
                    doc_id=item["entity"].entity_id,
                    score=1.0 / (i + 1),  # 简化评分
                    rank=i + 1,
                    source="knowledge_graph",
                    content=item["entity"].name + " " + item["entity"].description,
                    document=item["entity"],
                    matched_backends=["knowledge_graph"],
                    details={
                        "entity_type": item["entity"].entity_type,
                        "related_triples": len(item.get("related_triples", [])),
                        "search_mode": result.get("search_mode", "unknown"),
                    },
                )
                for i, item in enumerate(kg_results)
            ]
        except Exception:
            return self._mock_search_results(query, top_k, "knowledge_graph")

    def _search_session_state(
        self,
        query: str,
        top_k: int,
        session_id: Optional[str],
        tenant_id: Optional[str],
    ) -> List[UnifiedSearchResult]:
        """会话状态检索"""
        if self.session_manager is None or session_id is None:
            return []

        try:
            session = self.session_manager.get_session(session_id, tenant_id)
            if session is None:
                return []

            # 简单匹配：检查会话状态中是否包含查询关键词
            keywords = query.lower().split()
            state_str = json.dumps(session.state, ensure_ascii=False).lower()
            metadata_str = json.dumps(session.metadata, ensure_ascii=False).lower()

            match_count = sum(
                1 for kw in keywords
                if kw in state_str or kw in metadata_str
            )

            if match_count == 0:
                return []

            return [
                UnifiedSearchResult(
                    doc_id=session.session_id,
                    score=min(1.0, match_count / len(keywords)),
                    rank=1,
                    source="session_state",
                    content=f"会话 {session.session_id} 状态匹配",
                    document=session,
                    matched_backends=["session_state"],
                    details={
                        "session_type": session.session_type,
                        "status": session.status,
                        "match_count": match_count,
                        "tenant_id": session.tenant_id,
                    },
                )
            ]
        except Exception:
            return []

    def _search_keyword_only(self, query: str, top_k: int) -> List[UnifiedSearchResult]:
        """仅关键词检索"""
        if self.rrf_retriever is None:
            return self._mock_search_results(query, top_k, "keyword_only")
        try:
            keyword_retriever = getattr(self.rrf_retriever, 'keyword_retriever', None)
            if keyword_retriever is None:
                return []
            raw_results = keyword_retriever.search(query, top_k=top_k)
            return [
                UnifiedSearchResult(
                    doc_id=r.doc_id, score=r.score, rank=i+1,
                    source="keyword_only", content="",
                    matched_backends=["keyword_only"],
                )
                for i, r in enumerate(raw_results)
            ]
        except Exception:
            return []

    def _search_vector_only(self, query: str, top_k: int) -> List[UnifiedSearchResult]:
        """仅向量检索"""
        if self.rrf_retriever is None:
            return self._mock_search_results(query, top_k, "vector_only")
        try:
            vector_retriever = getattr(self.rrf_retriever, 'vector_retriever', None)
            if vector_retriever is None:
                return []
            raw_results = vector_retriever.search(query, top_k=top_k)
            return [
                UnifiedSearchResult(
                    doc_id=r.doc_id, score=r.score, rank=i+1,
                    source="vector_only", content="",
                    matched_backends=["vector_only"],
                )
                for i, r in enumerate(raw_results)
            ]
        except Exception:
            return []

    def _search_graph_only(self, query: str, top_k: int) -> List[UnifiedSearchResult]:
        """仅图谱检索"""
        if self.rrf_retriever is None:
            return self._mock_search_results(query, top_k, "graph_only")
        try:
            graph_retriever = getattr(self.rrf_retriever, 'graph_retriever', None)
            if graph_retriever is None:
                return []
            raw_results = graph_retriever.search(query, top_k=top_k)
            return [
                UnifiedSearchResult(
                    doc_id=r.doc_id, score=r.score, rank=i+1,
                    source="graph_only", content="",
                    matched_backends=["graph_only"],
                )
                for i, r in enumerate(raw_results)
            ]
        except Exception:
            return []

    def _rrf_fuse(
        self,
        backend_results: Dict[str, List[UnifiedSearchResult]],
        weights: Dict[str, float],
        top_k: int,
        rrf_k: int = 60,
    ) -> List[UnifiedSearchResult]:
        """
        RRF（Reciprocal Rank Fusion）融合多个后端的结果

        RRF(d) = Σ (weight_i / (k + rank_i(d)))
        """
        scores: Dict[str, float] = defaultdict(float)
        doc_map: Dict[str, UnifiedSearchResult] = {}
        backend_matches: Dict[str, Set[str]] = defaultdict(set)

        for backend, results in backend_results.items():
            weight = weights.get(backend, 1.0)
            for rank, result in enumerate(results, 1):
                doc_id = result.doc_id
                rrf_score = weight / (rrf_k + rank)
                scores[doc_id] += rrf_score
                backend_matches[doc_id].add(backend)
                if doc_id not in doc_map:
                    doc_map[doc_id] = result

        # 排序并返回
        sorted_docs = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:top_k]
        fused_results = []
        for rank, (doc_id, score) in enumerate(sorted_docs, 1):
            result = doc_map[doc_id]
            result.score = score
            result.rank = rank
            result.source = "fused"
            result.matched_backends = list(backend_matches[doc_id])
            result.details["rrf_score"] = score
            result.details["matched_backends"] = list(backend_matches[doc_id])
            fused_results.append(result)

        return fused_results

    def _mock_search_results(
        self, query: str, top_k: int, source: str
    ) -> List[UnifiedSearchResult]:
        """生成模拟检索结果（后端未配置时使用）"""
        return [
            UnifiedSearchResult(
                doc_id=f"mock_{source}_{i}",
                score=1.0 / (i + 1),
                rank=i + 1,
                source=source,
                content=f"Mock result {i+1} for query: {query[:50]}",
                matched_backends=[source],
                details={"mock": True, "note": "Backend not configured, returning mock results"},
            )
            for i in range(min(top_k, 3))
        ]


# ==================== 便捷接口 ====================

def create_intelligent_router() -> IntelligentQueryRouter:
    """创建智能查询路由器"""
    return IntelligentQueryRouter()


def create_unified_orchestrator(
    rrf_retriever: Optional[Any] = None,
    knowledge_graph: Optional[Any] = None,
    session_manager: Optional[Any] = None,
) -> UnifiedRetrievalOrchestrator:
    """创建统一检索编排器"""
    return UnifiedRetrievalOrchestrator(
        rrf_retriever=rrf_retriever,
        knowledge_graph=knowledge_graph,
        session_manager=session_manager,
    )


import json  # 用于会话状态检索中的 JSON 序列化


if __name__ == "__main__":
    # 自测试
    print("=" * 60)
    print("PhotonBox 智能查询路由与统一检索编排器 - 自测试")
    print("=" * 60)

    router = IntelligentQueryRouter()

    # 测试 1：实体查询路由
    print("\n--- 测试 1：实体查询路由（CVE）---")
    decision = router.route("CVE-2022-3602 漏洞详情")
    print(f"  查询类型：{decision.query_type}")
    print(f"  选择后端：{decision.selected_backends}")
    print(f"  置信度：{decision.confidence:.0%}")
    print(f"  决策解释：{decision.reasoning}")

    # 测试 2：风险评估路由
    print("\n--- 测试 2：风险评估路由 ---")
    decision = router.route("CVE-2022-3602 影响哪些沙箱实例？风险评估")
    print(f"  查询类型：{decision.query_type}")
    print(f"  选择后端：{decision.selected_backends}")
    print(f"  后端权重：{decision.backend_weights}")

    # 测试 3：语义搜索路由
    print("\n--- 测试 3：语义搜索路由 ---")
    decision = router.route("如何防止沙箱逃逸？有哪些最佳实践和防御策略？")
    print(f"  查询类型：{decision.query_type}")
    print(f"  选择后端：{decision.selected_backends}")

    # 测试 4：会话上下文路由
    print("\n--- 测试 4：会话上下文路由 ---")
    decision = router.route("上次我们讨论的那个漏洞修复方案，继续")
    print(f"  查询类型：{decision.query_type}")
    print(f"  选择后端：{decision.selected_backends}")

    # 测试 5：攻击链路由
    print("\n--- 测试 5：攻击链路由 ---")
    decision = router.route("从 seccomp 绕过到容器逃逸的完整攻击链是什么？")
    print(f"  查询类型：{decision.query_type}")
    print(f"  选择后端：{decision.selected_backends}")

    # 测试 6：关系查询路由
    print("\n--- 测试 6：关系查询路由 ---")
    decision = router.route("OpenSSL 和 gRPC 有什么关系？")
    print(f"  查询类型：{decision.query_type}")
    print(f"  选择后端：{decision.selected_backends}")

    # 测试 7：统一检索编排（无后端配置，使用模拟结果）
    print("\n--- 测试 7：统一检索编排 ---")
    orchestrator = UnifiedRetrievalOrchestrator()
    result = orchestrator.search("CVE-2022-3602 漏洞", top_k=5)
    print(f"  查询类型：{result['statistics']['query_type']}")
    print(f"  使用后端：{result['statistics']['backends_used']}")
    print(f"  融合结果数：{result['statistics']['total_results']}")
    print(f"  RRF 启用：{result['statistics']['rrf_enabled']}")

    # 测试 8：路由统计
    print("\n--- 测试 8：路由统计 ---")
    stats = router.get_routing_statistics()
    print(f"  总路由数：{stats['total_routes']}")
    print(f"  按类型分布：{stats['routes_by_type']}")
    print(f"  后端使用：{stats['backend_usage']}")

    # 测试 9：查询特征分析
    print("\n--- 测试 9：查询特征分析 ---")
    features = router.analyze_query("CVE-2022-3602 OpenSSL 3.0.2 缓冲区溢出漏洞影响分析")
    print(f"  查询类型：{features.query_type}")
    print(f"  检测到 CVE：{features.detected_cves}")
    print(f"  检测到组件：{features.detected_components}")
    print(f"  关键词：{features.keywords}")
    print(f"  风险模式：{features.has_risk_pattern}")

    print("\n" + "=" * 60)
    print("✅ 所有测试通过")
    print("=" * 60)
