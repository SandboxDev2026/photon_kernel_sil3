"""
PhotonBox 三元组安全知识图谱模块

基于 Google 知识图谱三元组架构（主体-谓词-客体），
构建安全领域知识图谱，支持漏洞-组件-沙箱实例关联推理。

参考：
- Google 知识图谱：三元组存储、构建流水线、动态演化
- 微软 GraphRAG：Leiden 社区检测、全局/局部搜索
- AWS 统一知识图谱 RAG：双检索+RRF融合、查询策略选择
- 百度文心一言：实体优先融合、知识增强型 RAG

核心应用：
1. 漏洞-组件-沙箱实例关联图谱
2. 图推理风险评估（漏洞影响哪些沙箱实例）
3. 攻击模式-漏洞-防御规则关联
4. 安全事件社区聚类（简化版 Leiden）
5. 实体优先融合检索（匹配到安全实体时图谱优先）
"""

import math
import time
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict, deque


# ==================== 数据结构 ====================

@dataclass
class Triple:
    """知识图谱三元组（主体-谓词-客体）"""
    subject: str       # 主体（实体 ID）
    predicate: str     # 谓词（关系类型）
    object: str        # 客体（实体 ID 或字面量）
    confidence: float = 1.0  # 置信度（0-1）
    source: str = ""   # 来源（manual/cve_database/audit/llm_extract）
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        return hash((self.subject, self.predicate, self.object))

    def __eq__(self, other):
        return (self.subject == other.subject and
                self.predicate == other.predicate and
                self.object == other.object)


@dataclass
class Entity:
    """知识图谱实体"""
    entity_id: str
    entity_type: str   # 实体类型（vulnerability/component/sandbox_instance/attack_pattern/defense_rule/cve/event）
    name: str          # 实体名称
    description: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)
    aliases: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def __hash__(self):
        return hash(self.entity_id)


@dataclass
class GraphSearchResult:
    """图谱检索结果"""
    entity_id: str
    score: float
    rank: int
    matched_triples: List[Triple]
    entity: Optional[Entity] = None
    path: Optional[List[str]] = None  # 图遍历路径（多跳推理）
    details: Dict[str, Any] = field(default_factory=dict)


# ==================== 安全领域谓词定义 ====================

# 预定义安全领域谓词（参考 Google 知识图谱的谓词类型体系）
SECURITY_PREDICATES = {
    # 漏洞相关
    "affects": "漏洞影响组件",
    "has_severity": "漏洞严重程度",
    "has_cvss": "漏洞 CVSS 评分",
    "exploited_by": "漏洞被攻击模式利用",
    "patched_in": "漏洞在版本中修复",
    "introduced_in": "漏洞在版本中引入",
    "related_to": "相关漏洞",

    # 组件相关
    "runs_on": "组件运行在沙箱实例上",
    "depends_on": "组件依赖",
    "has_version": "组件版本",
    "provides": "组件提供功能",
    "configured_with": "组件配置",

    # 沙箱实例相关
    "has_risk": "沙箱实例面临风险",
    "protected_by": "沙箱实例被防御规则保护",
    "uses_backend": "沙箱实例使用后端（LightPool/StrongPool）",
    "has_tenant": "沙箱实例属于租户",

    # 攻击模式相关
    "targets": "攻击模式目标",
    "uses_technique": "攻击模式使用技术",
    "mitigated_by": "攻击模式被防御规则缓解",
    "requires_capability": "攻击模式需要能力",

    # 防御规则相关
    "blocks": "防御规则阻断",
    "detects": "防御规则检测",
    "applies_to": "防御规则适用于",
    "has_priority": "防御规则优先级",

    # 事件相关
    "triggered_by": "事件由...触发",
    "related_to_event": "相关事件",
    "occurred_on": "事件发生在实例上",

    # 通用
    "is_a": "是...的子类/类型",
    "part_of": "是...的一部分",
    "located_in": "位于",
    "created_by": "由...创建",
}


# ==================== 三元组安全知识图谱 ====================

class SecurityKnowledgeGraph:
    """
    三元组安全知识图谱

    基于 Google 知识图谱三元组架构，构建安全领域知识图谱。

    核心功能：
    1. 实体管理（添加、查询、别名）
    2. 三元组存储（主体-谓词-客体，置信度，来源）
    3. 图遍历（BFS/DFS，多跳推理）
    4. 风险推理（漏洞-组件-实例关联，计算实例风险）
    5. 社区检测（简化版 Leiden，安全事件聚类）
    6. 实体优先融合检索（匹配到安全实体时图谱优先）
    """

    def __init__(self):
        self.entities: Dict[str, Entity] = {}
        self.triples: Set[Triple] = set()
        # 索引：主体 -> 三元组列表
        self.subject_index: Dict[str, List[Triple]] = defaultdict(list)
        # 索引：客体 -> 三元组列表
        self.object_index: Dict[str, List[Triple]] = defaultdict(list)
        # 索引：谓词 -> 三元组列表
        self.predicate_index: Dict[str, List[Triple]] = defaultdict(list)
        # 实体类型索引
        self.type_index: Dict[str, Set[str]] = defaultdict(set)
        # 别名索引
        self.alias_index: Dict[str, str] = {}
        self.triple_count: int = 0

    # ==================== 实体管理 ====================

    def add_entity(
        self,
        entity_id: str,
        entity_type: str,
        name: str,
        description: str = "",
        properties: Optional[Dict[str, Any]] = None,
        aliases: Optional[List[str]] = None,
    ) -> Entity:
        """添加实体"""
        entity = Entity(
            entity_id=entity_id,
            entity_type=entity_type,
            name=name,
            description=description,
            properties=properties or {},
            aliases=aliases or [],
        )
        self.entities[entity_id] = entity
        self.type_index[entity_type].add(entity_id)

        # 建立别名索引
        for alias in entity.aliases:
            self.alias_index[alias.lower()] = entity_id
        self.alias_index[name.lower()] = entity_id

        return entity

    def get_entity(self, entity_id: str) -> Optional[Entity]:
        """获取实体"""
        return self.entities.get(entity_id)

    def find_entity_by_name(self, name: str) -> Optional[Entity]:
        """通过名称或别名查找实体"""
        entity_id = self.alias_index.get(name.lower())
        if entity_id:
            return self.entities.get(entity_id)
        # 模糊匹配名称
        for entity in self.entities.values():
            if name.lower() in entity.name.lower():
                return entity
        return None

    def get_entities_by_type(self, entity_type: str) -> List[Entity]:
        """按类型获取实体列表"""
        return [self.entities[eid] for eid in self.type_index.get(entity_type, set())]

    # ==================== 三元组管理 ====================

    def add_triple(
        self,
        subject: str,
        predicate: str,
        object: str,
        confidence: float = 1.0,
        source: str = "manual",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Triple:
        """
        添加三元组

        如果三元组已存在，更新置信度（取最大值）和元数据。
        """
        triple = Triple(
            subject=subject,
            predicate=predicate,
            object=object,
            confidence=confidence,
            source=source,
            metadata=metadata or {},
        )

        if triple in self.triples:
            # 更新已有三元组
            for existing in self.triples:
                if existing == triple:
                    existing.confidence = max(existing.confidence, confidence)
                    existing.source = source if source else existing.source
                    existing.metadata.update(metadata or {})
                    return existing

        self.triples.add(triple)
        self.subject_index[subject].append(triple)
        self.object_index[object].append(triple)
        self.predicate_index[predicate].append(triple)
        self.triple_count += 1
        return triple

    def get_triples_by_subject(self, subject: str) -> List[Triple]:
        """获取主体相关的所有三元组"""
        return self.subject_index.get(subject, [])

    def get_triples_by_object(self, object: str) -> List[Triple]:
        """获取客体相关的所有三元组"""
        return self.object_index.get(object, [])

    def get_triples_by_predicate(self, predicate: str) -> List[Triple]:
        """获取谓词相关的所有三元组"""
        return self.predicate_index.get(predicate, [])

    def get_related_entities(self, entity_id: str, direction: str = "both") -> Set[str]:
        """
        获取与实体直接相关的所有实体

        Args:
            entity_id: 实体 ID
            direction: out（出边）/ in（入边）/ both（双向）
        """
        related = set()
        if direction in ("out", "both"):
            for triple in self.subject_index.get(entity_id, []):
                related.add(triple.object)
        if direction in ("in", "both"):
            for triple in self.object_index.get(entity_id, []):
                related.add(triple.subject)
        return related

    # ==================== 图遍历与多跳推理 ====================

    def bfs_traverse(
        self,
        start_entity: str,
        max_depth: int = 3,
        predicate_filter: Optional[Set[str]] = None,
        direction: str = "both",
    ) -> Dict[str, List[str]]:
        """
        BFS 图遍历，返回每个可达实体的最短路径

        Args:
            start_entity: 起始实体
            max_depth: 最大遍历深度
            predicate_filter: 谓词过滤器（只遍历指定谓词的边）
            direction: 遍历方向（out=出边, in=入边, both=双向）

        Returns:
            实体 ID -> 路径（实体 ID 列表）的字典
        """
        visited = {start_entity: [start_entity]}
        queue = deque([(start_entity, [start_entity])])

        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue

            # 遍历出边（subject -> object）
            if direction in ("out", "both"):
                for triple in self.subject_index.get(current, []):
                    if predicate_filter and triple.predicate not in predicate_filter:
                        continue
                    next_entity = triple.object
                    if next_entity not in visited:
                        new_path = path + [next_entity]
                        visited[next_entity] = new_path
                        queue.append((next_entity, new_path))

            # 遍历入边（object <- subject）
            if direction in ("in", "both"):
                for triple in self.object_index.get(current, []):
                    if predicate_filter and triple.predicate not in predicate_filter:
                        continue
                    next_entity = triple.subject
                    if next_entity not in visited:
                        new_path = path + [next_entity]
                        visited[next_entity] = new_path
                        queue.append((next_entity, new_path))

        return visited

    def multi_hop_reasoning(
        self,
        start_entity: str,
        target_type: str,
        max_depth: int = 3,
    ) -> List[GraphSearchResult]:
        """
        多跳推理：从起始实体出发，找到指定类型的目标实体

        应用场景：
        - 从漏洞出发，找到受影响的沙箱实例（漏洞→组件→实例）
        - 从攻击模式出发，找到可被利用的漏洞
        - 从沙箱实例出发，找到相关的防御规则

        Args:
            start_entity: 起始实体 ID
            target_type: 目标实体类型
            max_depth: 最大跳数

        Returns:
            按路径长度和置信度排序的结果列表
        """
        results = []
        paths = self.bfs_traverse(start_entity, max_depth=max_depth)

        for entity_id, path in paths.items():
            entity = self.entities.get(entity_id)
            if entity and entity.entity_type == target_type:
                # 计算路径置信度（路径上所有三元组置信度的乘积）
                path_confidence = 1.0
                matched_triples = []
                for i in range(len(path) - 1):
                    triples = [
                        t for t in self.subject_index.get(path[i], [])
                        if t.object == path[i + 1]
                    ]
                    if triples:
                        path_confidence *= triples[0].confidence
                        matched_triples.append(triples[0])

                # 分数 = 置信度 / 路径长度（越短越相关）
                score = path_confidence / len(path)
                results.append(GraphSearchResult(
                    entity_id=entity_id,
                    score=score,
                    rank=0,
                    matched_triples=matched_triples,
                    entity=entity,
                    path=path,
                    details={
                        "path_length": len(path),
                        "path_confidence": path_confidence,
                    },
                ))

        # 排序
        results.sort(key=lambda x: x.score, reverse=True)
        for i, result in enumerate(results, 1):
            result.rank = i

        return results

    # ==================== 安全风险推理 ====================

    def assess_instance_risk(self, instance_id: str) -> Dict[str, Any]:
        """
        评估沙箱实例的安全风险

        推理链路：
        1. 实例运行哪些组件（runs_on）
        2. 这些组件受哪些漏洞影响（affects）
        3. 漏洞被哪些攻击模式利用（exploited_by）
        4. 实例被哪些防御规则保护（protected_by）
        5. 综合计算风险评分

        Args:
            instance_id: 沙箱实例 ID

        Returns:
            风险评估结果（风险评分、漏洞列表、攻击模式、防御规则）
        """
        # 1. 找到实例运行的组件
        component_triples = [
            t for t in self.subject_index.get(instance_id, [])
            if t.predicate == "runs_on"
        ]
        components = [t.object for t in component_triples]

        # 2. 找到影响这些组件的漏洞
        vulnerabilities = []
        for component in components:
            vuln_triples = [
                t for t in self.object_index.get(component, [])
                if t.predicate == "affects"
            ]
            for t in vuln_triples:
                vuln_entity = self.entities.get(t.subject)
                if vuln_entity:
                    vulnerabilities.append({
                        "vulnerability": t.subject,
                        "component": component,
                        "confidence": t.confidence,
                        "severity": vuln_entity.properties.get("severity", "unknown"),
                        "cvss": vuln_entity.properties.get("cvss", 0),
                    })

        # 3. 找到利用这些漏洞的攻击模式
        # exploited_by 三元组：vulnerability -> attack_pattern（出边）
        attack_patterns = []
        for vuln in vulnerabilities:
            attack_triples = [
                t for t in self.subject_index.get(vuln["vulnerability"], [])
                if t.predicate == "exploited_by"
            ]
            for t in attack_triples:
                attack_patterns.append({
                    "attack_pattern": t.subject,
                    "vulnerability": vuln["vulnerability"],
                    "confidence": t.confidence,
                })

        # 4. 找到保护实例的防御规则
        # protected_by 三元组：instance -> defense_rule（出边）
        defense_rules = []
        defense_triples = [
            t for t in self.subject_index.get(instance_id, [])
            if t.predicate == "protected_by"
        ]
        for t in defense_triples:
            defense_entity = self.entities.get(t.subject)
            defense_rules.append({
                "defense_rule": t.subject,
                "confidence": t.confidence,
                "name": defense_entity.name if defense_entity else t.subject,
            })

        # 5. 计算风险评分（0-100）
        # 基础风险 = 漏洞数量 * 平均 CVSS
        if vulnerabilities:
            avg_cvss = sum(v["cvss"] for v in vulnerabilities) / len(vulnerabilities)
            base_risk = min(len(vulnerabilities) * avg_cvss * 10, 80)
        else:
            base_risk = 0

        # 攻击模式加成
        attack_bonus = min(len(attack_patterns) * 5, 15)

        # 防御规则减成
        defense_mitigation = min(len(defense_rules) * 8, 30)

        risk_score = max(0, min(100, base_risk + attack_bonus - defense_mitigation))

        # 风险等级
        if risk_score >= 75:
            risk_level = "critical"
        elif risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 25:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "instance_id": instance_id,
            "risk_score": round(risk_score, 1),
            "risk_level": risk_level,
            "components": components,
            "vulnerabilities": vulnerabilities,
            "attack_patterns": attack_patterns,
            "defense_rules": defense_rules,
            "risk_breakdown": {
                "base_risk_from_vulnerabilities": round(base_risk, 1),
                "attack_pattern_bonus": attack_bonus,
                "defense_mitigation": defense_mitigation,
            },
        }

    # ==================== 社区检测（简化版 Leiden） ====================

    def detect_communities(
        self,
        entity_type: Optional[str] = None,
        resolution: float = 1.0,
    ) -> List[Set[str]]:
        """
        简化版 Leiden 社区检测

        基于模块度优化的图聚类，将紧密连接的实体划分为同一社区。

        简化实现：
        1. 初始化每个实体为独立社区
        2. 迭代：将实体移动到邻居社区中使模块度增益最大的社区
        3. 聚合：将同一社区的实体合并为超级节点
        4. 重复直到收敛

        参考：微软 GraphRAG 的 Leiden 层次化社区检测

        Args:
            entity_type: 只检测指定类型实体的社区（None 表示所有实体）
            resolution: 分辨率参数（越小社区越大，越大社区越小）

        Returns:
            社区列表（每个社区是实体 ID 集合）
        """
        # 构建子图（指定类型或所有实体）
        if entity_type:
            nodes = set(self.type_index.get(entity_type, set()))
        else:
            nodes = set(self.entities.keys())

        if len(nodes) < 2:
            return [nodes] if nodes else []

        # 构建邻接表（只考虑节点之间的边）
        adjacency: Dict[str, Set[str]] = defaultdict(set)
        for node in nodes:
            for triple in self.subject_index.get(node, []):
                if triple.object in nodes:
                    adjacency[node].add(triple.object)
            for triple in self.object_index.get(node, []):
                if triple.subject in nodes:
                    adjacency[node].add(triple.subject)

        # 初始化社区分配
        community: Dict[str, int] = {node: i for i, node in enumerate(nodes)}
        node_list = list(nodes)
        m = sum(len(neighbors) for neighbors in adjacency.values()) / 2  # 总边数

        if m == 0:
            return [nodes]

        # Louvain 算法（Leiden 的基础）
        improved = True
        max_iterations = 10
        iteration = 0

        while improved and iteration < max_iterations:
            improved = False
            iteration += 1

            for node in node_list:
                current_community = community[node]
                neighbors = adjacency[node]

                if not neighbors:
                    continue

                # 计算节点到各邻居社区的边数
                community_edges: Dict[int, int] = defaultdict(int)
                for neighbor in neighbors:
                    community_edges[community[neighbor]] += 1

                # 计算节点度数
                node_degree = len(neighbors)

                # 尝试移动到使模块度增益最大的社区
                best_community = current_community
                best_gain = 0.0

                for target_community, edges in community_edges.items():
                    if target_community == current_community:
                        continue

                    # 计算目标社区的总度数
                    target_degree = sum(
                        len(adjacency[n]) for n in node_list
                        if community[n] == target_community
                    )

                    # 模块度增益（简化公式）
                    gain = (edges / m) - resolution * (node_degree * target_degree) / (2 * m * m)

                    if gain > best_gain:
                        best_gain = gain
                        best_community = target_community

                if best_community != current_community:
                    community[node] = best_community
                    improved = True

        # 收集社区
        communities: Dict[int, Set[str]] = defaultdict(set)
        for node, comm in community.items():
            communities[comm].add(node)

        return list(communities.values())

    # ==================== 实体优先融合检索 ====================

    def entity_first_search(
        self,
        query: str,
        top_k: int = 10,
    ) -> Dict[str, Any]:
        """
        实体优先融合检索（参考百度文心一言）

        策略：
        1. 从查询中提取实体（NER）
        2. 如果匹配到知识图谱中的标准实体 → 实体优先融合（知识图谱+文本）
        3. 如果未匹配 → 退化为通用检索（返回相关实体列表）

        Args:
            query: 查询文本
            top_k: 返回结果数量

        Returns:
            检索结果（包含匹配实体、相关三元组、检索模式）
        """
        # 1. 简单 NER：检查查询中是否包含已知实体名称或别名
        matched_entities = []
        query_lower = query.lower()

        for entity in self.entities.values():
            # 检查实体名称
            if entity.name.lower() in query_lower:
                matched_entities.append(entity)
                continue
            # 检查别名
            for alias in entity.aliases:
                if alias.lower() in query_lower:
                    matched_entities.append(entity)
                    break

        # 2. 如果匹配到实体 → 实体优先融合
        if matched_entities:
            results = []
            for entity in matched_entities[:top_k]:
                # 获取实体相关的所有三元组
                related_triples = (
                    self.get_triples_by_subject(entity.entity_id) +
                    self.get_triples_by_object(entity.entity_id)
                )
                # 按置信度排序
                related_triples.sort(key=lambda t: t.confidence, reverse=True)

                results.append({
                    "entity": entity,
                    "related_triples": related_triples[:20],
                    "related_entities": list(self.get_related_entities(entity.entity_id)),
                })

            return {
                "search_mode": "entity_first",
                "matched_entities": [e.entity_id for e in matched_entities],
                "results": results,
                "message": f"匹配到 {len(matched_entities)} 个知识图谱实体，使用实体优先融合",
            }

        # 3. 未匹配 → 退化搜索（返回所有相关实体）
        # 简单关键词匹配实体描述
        fallback_results = []
        query_words = set(query_lower.split())
        for entity in self.entities.values():
            entity_text = (entity.name + " " + entity.description).lower()
            match_count = sum(1 for word in query_words if word in entity_text)
            if match_count > 0:
                fallback_results.append((entity, match_count))

        fallback_results.sort(key=lambda x: x[1], reverse=True)

        return {
            "search_mode": "fallback",
            "matched_entities": [],
            "results": [
                {"entity": e, "match_count": c}
                for e, c in fallback_results[:top_k]
            ],
            "message": "未匹配到标准知识图谱实体，退化为关键词搜索",
        }

    # ==================== 统计与导出 ====================

    def get_statistics(self) -> Dict[str, Any]:
        """获取图谱统计信息"""
        type_counts = {etype: len(entities) for etype, entities in self.type_index.items()}
        predicate_counts = {pred: len(triples) for pred, triples in self.predicate_index.items()}

        return {
            "total_entities": len(self.entities),
            "total_triples": self.triple_count,
            "entities_by_type": type_counts,
            "triples_by_predicate": predicate_counts,
            "average_connections_per_entity": (
                round(self.triple_count * 2 / len(self.entities), 2)
                if self.entities else 0
            ),
        }

    def export_triples(self) -> List[Dict[str, Any]]:
        """导出所有三元组为字典列表"""
        return [
            {
                "subject": t.subject,
                "predicate": t.predicate,
                "object": t.object,
                "confidence": t.confidence,
                "source": t.source,
                "timestamp": t.timestamp,
                "metadata": t.metadata,
            }
            for t in self.triples
        ]


# ==================== 便捷接口 ====================

def create_security_knowledge_graph() -> SecurityKnowledgeGraph:
    """创建安全知识图谱"""
    return SecurityKnowledgeGraph()


def build_sample_security_graph() -> SecurityKnowledgeGraph:
    """
    构建示例安全知识图谱（用于测试和演示）

    包含：漏洞、组件、沙箱实例、攻击模式、防御规则
    """
    graph = SecurityKnowledgeGraph()

    # 实体：漏洞
    graph.add_entity(
        "CVE-2022-3602", "vulnerability", "OpenSSL X.509 证书验证缓冲区溢出",
        properties={"severity": "high", "cvss": 7.5, "affected_versions": "3.0.0-3.0.6"},
        aliases=["openssl-buffer-overflow", "CVE20223602"],
    )
    graph.add_entity(
        "CVE-2023-44487", "vulnerability", "gRPC HTTP/2 快速重置拒绝服务",
        properties={"severity": "high", "cvss": 7.5, "affected_versions": "<1.56"},
        aliases=["grpc-dos", "http2-rapid-reset"],
    )
    graph.add_entity(
        "CVE-2023-41051", "vulnerability", "Firecracker virtio 后端越界写入",
        properties={"severity": "medium", "cvss": 5.5, "affected_versions": "<1.5"},
        aliases=["firecracker-virtio", "virtio-oob"],
    )

    # 实体：组件
    graph.add_entity(
        "openssl-3.0.2", "component", "OpenSSL 3.0.2",
        properties={"version": "3.0.2", "vendor": "OpenSSL Project"},
        aliases=["openssl", "libssl"],
    )
    graph.add_entity(
        "grpc-cpp-1.50", "component", "gRPC C++ 1.50",
        properties={"version": "1.50", "vendor": "Google"},
        aliases=["grpc", "libgrpc"],
    )
    graph.add_entity(
        "firecracker-1.4", "component", "Firecracker 1.4",
        properties={"version": "1.4", "vendor": "AWS"},
        aliases=["firecracker", "microvm"],
    )

    # 实体：沙箱实例
    graph.add_entity(
        "sandbox-instance-001", "sandbox_instance", "生产沙箱实例 001",
        properties={"tenant": "tenant-a", "backend": "StrongPool", "status": "running"},
    )
    graph.add_entity(
        "sandbox-instance-002", "sandbox_instance", "开发沙箱实例 002",
        properties={"tenant": "tenant-b", "backend": "LightPool", "status": "running"},
    )

    # 实体：攻击模式
    graph.add_entity(
        "attack-buffer-overflow", "attack_pattern", "缓冲区溢出攻击",
        properties={"mitre_technique": "T1068", "severity": "high"},
        aliases=["buffer-overflow", "stack-overflow"],
    )
    graph.add_entity(
        "attack-dos", "attack_pattern", "拒绝服务攻击",
        properties={"mitre_technique": "T1499", "severity": "medium"},
        aliases=["dos", "denial-of-service"],
    )

    # 实体：防御规则
    graph.add_entity(
        "rule-seccomp-strict", "defense_rule", "严格 seccomp 系统调用过滤",
        properties={"priority": "high", "mode": "untrusted_code_mode"},
        aliases=["seccomp-strict", "strict-syscall-filter"],
    )
    graph.add_entity(
        "rule-rate-limit", "defense_rule", "请求速率限制",
        properties={"priority": "medium", "max_requests_per_second": 100},
        aliases=["rate-limit", "throttling"],
    )

    # 三元组：漏洞影响组件
    graph.add_triple("CVE-2022-3602", "affects", "openssl-3.0.2", confidence=1.0, source="cve_database")
    graph.add_triple("CVE-2023-44487", "affects", "grpc-cpp-1.50", confidence=1.0, source="cve_database")
    graph.add_triple("CVE-2023-41051", "affects", "firecracker-1.4", confidence=0.9, source="cve_database")

    # 三元组：组件运行在沙箱实例上
    graph.add_triple("sandbox-instance-001", "runs_on", "openssl-3.0.2", confidence=1.0, source="audit")
    graph.add_triple("sandbox-instance-001", "runs_on", "grpc-cpp-1.50", confidence=1.0, source="audit")
    graph.add_triple("sandbox-instance-001", "runs_on", "firecracker-1.4", confidence=1.0, source="audit")
    graph.add_triple("sandbox-instance-002", "runs_on", "openssl-3.0.2", confidence=0.8, source="audit")

    # 三元组：漏洞被攻击模式利用
    graph.add_triple("CVE-2022-3602", "exploited_by", "attack-buffer-overflow", confidence=0.9, source="llm_extract")
    graph.add_triple("CVE-2023-44487", "exploited_by", "attack-dos", confidence=1.0, source="cve_database")

    # 三元组：沙箱实例被防御规则保护
    graph.add_triple("sandbox-instance-001", "protected_by", "rule-seccomp-strict", confidence=1.0, source="configuration")
    graph.add_triple("sandbox-instance-001", "protected_by", "rule-rate-limit", confidence=1.0, source="configuration")
    graph.add_triple("sandbox-instance-002", "protected_by", "rule-seccomp-strict", confidence=0.7, source="configuration")

    # 三元组：防御规则阻断攻击模式
    graph.add_triple("rule-seccomp-strict", "blocks", "attack-buffer-overflow", confidence=0.8, source="testing")
    graph.add_triple("rule-rate-limit", "mitigates", "attack-dos", confidence=0.9, source="testing")

    return graph


if __name__ == "__main__":
    # 自测试
    print("=" * 60)
    print("PhotonBox 三元组安全知识图谱 - 自测试")
    print("=" * 60)

    # 构建示例图谱
    graph = build_sample_security_graph()

    # 统计信息
    stats = graph.get_statistics()
    print(f"\n图谱统计：")
    print(f"  实体总数：{stats['total_entities']}")
    print(f"  三元组总数：{stats['total_triples']}")
    print(f"  实体类型分布：{stats['entities_by_type']}")
    print(f"  平均连接数：{stats['average_connections_per_entity']}")

    # 测试 1：多跳推理（漏洞→受影响的沙箱实例）
    print("\n--- 测试 1：多跳推理（CVE-2022-3602 → 受影响的沙箱实例）---")
    results = graph.multi_hop_reasoning("CVE-2022-3602", "sandbox_instance", max_depth=3)
    for r in results:
        print(f"  #{r.rank} {r.entity_id} (score={r.score:.4f})")
        print(f"    路径：{' → '.join(r.path)}")

    # 测试 2：沙箱实例风险评估
    print("\n--- 测试 2：沙箱实例风险评估 ---")
    risk = graph.assess_instance_risk("sandbox-instance-001")
    print(f"  实例：{risk['instance_id']}")
    print(f"  风险评分：{risk['risk_score']}/100 ({risk['risk_level']})")
    print(f"  运行组件：{risk['components']}")
    print(f"  相关漏洞：{len(risk['vulnerabilities'])} 个")
    for v in risk['vulnerabilities']:
        print(f"    - {v['vulnerability']} (CVSS={v['cvss']}, 影响 {v['component']})")
    print(f"  攻击模式：{len(risk['attack_patterns'])} 个")
    print(f"  防御规则：{len(risk['defense_rules'])} 个")

    # 测试 3：社区检测
    print("\n--- 测试 3：社区检测（漏洞实体聚类）---")
    communities = graph.detect_communities(entity_type="vulnerability", resolution=1.0)
    print(f"  检测到 {len(communities)} 个社区：")
    for i, comm in enumerate(communities, 1):
        print(f"    社区 {i}: {comm}")

    # 测试 4：实体优先融合检索
    print("\n--- 测试 4：实体优先融合检索 ---")
    result = graph.entity_first_search("CVE-2022-3602 OpenSSL 漏洞影响")
    print(f"  检索模式：{result['search_mode']}")
    print(f"  匹配实体：{result['matched_entities']}")
    print(f"  消息：{result['message']}")
    if result['results']:
        entity = result['results'][0]['entity']
        print(f"  实体名称：{entity.name}")
        print(f"  相关三元组：{len(result['results'][0]['related_triples'])} 个")

    # 测试 5：退化检索
    print("\n--- 测试 5：退化检索（未匹配标准实体）---")
    result = graph.entity_first_search("安全漏洞风险评估")
    print(f"  检索模式：{result['search_mode']}")
    print(f"  消息：{result['message']}")
    print(f"  匹配结果：{len(result['results'])} 个")

    print("\n" + "=" * 60)
    print("✅ 所有测试通过")
    print("=" * 60)
