"""
PhotonBox 记忆系统增强模块

借鉴 Mem0（25k+ stars 生产级长期记忆层）和 MemGPT/Letta（OS 风格内存管理）：

1. VirtualContextManager - 虚拟上下文管理（MemGPT 分页机制）
   - 主上下文（Main Context）：当前活跃记忆，token 预算内
   - 归档（Archive）：不活跃记忆，持久化存储
   - 回忆（Recall）：从归档检索相关记忆放回主上下文
   - 分页（Paging）：主上下文满时自动移动不相关记忆到归档

2. AutoMemoryExtractor - 自动记忆提取（Mem0 风格）
   - 从对话/任务中自动提取重要信息
   - 实体提取（人物、地点、时间、事件）
   - 偏好提取（用户习惯、配置选择）
   - 事实提取（可验证的陈述）
   - 重要性评分（自动判断是否值得记忆）

3. SemanticMemoryStore - 语义记忆存储+CRUD API
   - Mem0 风格 add/get/update/delete/search API
   - TF-IDF 语义检索（可替换为向量数据库）
   - 多租户隔离（user_id/session_id/agent_id）
   - 记忆版本管理
   - 记忆关联（记忆之间的关系图谱）

设计参考：
- Mem0: 用户/会话/Agent 三级记忆，自动提取检索
- MemGPT/Letta: OS 风格虚拟内存管理，主上下文/归档/回忆三层
- 记忆压缩: LLM 摘要提炼（此处用规则+统计的轻量实现）
"""

from __future__ import annotations

import json
import math
import re
import time
import hashlib
from collections import Counter, OrderedDict, defaultdict
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


# ============================================================
# 记忆类型与重要性
# ============================================================

class MemoryCategory(Enum):
    """记忆类别"""
    FACT = "fact"              # 事实（可验证的陈述）
    PREFERENCE = "preference"  # 偏好（用户习惯、选择）
    ENTITY = "entity"          # 实体（人物、地点、组织）
    EVENT = "event"            # 事件（发生的事情）
    TASK = "task"              # 任务（待办、目标）
    SKILL = "skill"            # 技能（可复用的能力）
    CONVERSATION = "conversation"  # 对话摘要


@dataclass
class EnhancedMemory:
    """增强记忆条目"""
    memory_id: str
    content: str
    category: MemoryCategory = MemoryCategory.FACT
    importance: float = 0.5          # 重要性 0-1
    confidence: float = 0.8          # 置信度 0-1
    access_count: int = 0
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    expires_at: float = 0.0          # 0 = 永不过期
    tags: List[str] = field(default_factory=list)
    entities: List[str] = field(default_factory=list)  # 关联实体
    related_memories: List[str] = field(default_factory=list)  # 关联记忆ID
    source: str = ""                  # 来源（对话/任务/自动提取）
    user_id: str = ""                 # 多租户：用户ID
    session_id: str = ""              # 多租户：会话ID
    agent_id: str = ""                # 多租户：Agent ID
    version: int = 1                  # 版本号
    is_archived: bool = False         # 是否在归档中
    compressed_from: str = ""         # 压缩来源

    def touch(self) -> None:
        self.access_count += 1
        self.last_accessed = time.time()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EnhancedMemory":
        data = data.copy()
        data["category"] = MemoryCategory(data.get("category", "fact"))
        return cls(**data)


# ============================================================
# 1. 虚拟上下文管理器（MemGPT 风格分页机制）
# ============================================================

class VirtualContextManager:
    """
    虚拟上下文管理器（MemGPT/Letta 风格）

    OS 风格虚拟内存管理：
    - 主上下文（Main Context）：当前活跃记忆，受 token 预算限制
    - 归档（Archive）：不活跃记忆，持久化存储，容量大
    - 回忆（Recall）：从归档检索相关记忆放回主上下文
    - 分页（Paging）：主上下文满时自动移动不相关记忆到归档

    核心机制：
    1. 添加记忆时检查 token 预算
    2. 超出预算时，按"最近最少使用+低重要性"淘汰到归档
    3. 检索时同时搜索主上下文和归档
    4. 归档中命中的记忆自动召回（page-in）到主上下文
    """

    def __init__(self, main_context_tokens: int = 4000,
                 archive_max_items: int = 10000,
                 recall_threshold: float = 0.3):
        """
        Args:
            main_context_tokens: 主上下文 token 预算
            archive_max_items: 归档最大条目数
            recall_threshold: 召回阈值（相关性高于此值才召回）
        """
        self.main_context_tokens = main_context_tokens
        self.archive_max_items = archive_max_items
        self.recall_threshold = recall_threshold
        self._main_context: OrderedDict[str, EnhancedMemory] = OrderedDict()
        self._archive: OrderedDict[str, EnhancedMemory] = OrderedDict()
        self._stats = {
            "page_outs": 0,      # 淘汰到归档的次数
            "page_ins": 0,       # 召回的次数
            "recall_hits": 0,    # 归档命中次数
            "total_searches": 0,
        }

    def add(self, memory: EnhancedMemory) -> str:
        """
        添加记忆到主上下文

        如果主上下文超出 token 预算，自动淘汰不相关记忆到归档。
        """
        # 检查是否已存在（更新）
        if memory.memory_id in self._main_context:
            self._main_context[memory.memory_id] = memory
            self._main_context.move_to_end(memory.memory_id)
            return memory.memory_id
        if memory.memory_id in self._archive:
            # 从归档召回
            del self._archive[memory.memory_id]
            memory.is_archived = False
            self._stats["page_ins"] += 1

        self._main_context[memory.memory_id] = memory
        self._main_context.move_to_end(memory.memory_id)

        # 检查 token 预算，必要时淘汰
        self._enforce_budget()
        return memory.memory_id

    def get(self, memory_id: str) -> Optional[EnhancedMemory]:
        """获取记忆（主上下文优先，归档次之）"""
        if memory_id in self._main_context:
            mem = self._main_context[memory_id]
            mem.touch()
            self._main_context.move_to_end(memory_id)
            return mem
        if memory_id in self._archive:
            # 归档命中，自动召回
            mem = self._archive[memory_id]
            self._recall(memory_id)
            return mem
        return None

    def search(self, query: str, limit: int = 5,
               user_id: str = "", session_id: str = "") -> List[EnhancedMemory]:
        """
        搜索记忆（主上下文+归档）

        归档中命中的高相关性记忆自动召回。
        """
        self._stats["total_searches"] += 1
        query_tokens = self._tokenize(query)
        results = []

        # 搜索主上下文
        for mem in self._main_context.values():
            if not self._match_tenant(mem, user_id, session_id):
                continue
            score = self._relevance_score(query_tokens, mem)
            if score > 0:
                results.append((mem, score, "main"))

        # 搜索归档
        for mem in self._archive.values():
            if not self._match_tenant(mem, user_id, session_id):
                continue
            score = self._relevance_score(query_tokens, mem)
            if score > 0:
                results.append((mem, score, "archive"))

        # 排序
        results.sort(key=lambda x: x[1], reverse=True)

        # 归档中高相关性记忆自动召回
        final_results = []
        for mem, score, source in results[:limit]:
            if source == "archive" and score >= self.recall_threshold:
                self._recall(mem.memory_id)
                self._stats["recall_hits"] += 1
            mem.touch()
            final_results.append(mem)

        return final_results

    def get_context_string(self, max_tokens: int = 3000) -> str:
        """获取主上下文的字符串表示（用于 LLM 输入）"""
        parts = []
        total_tokens = 0
        for mem in reversed(self._main_context.values()):
            content = f"[{mem.category.value}] {mem.content}"
            tokens = self._estimate_tokens(content)
            if total_tokens + tokens > max_tokens:
                break
            parts.append(content)
            total_tokens += tokens
        return "\n".join(parts)

    def archive_oldest(self, n: int = 5) -> int:
        """手动将最旧的 n 条记忆淘汰到归档"""
        count = 0
        for _ in range(min(n, len(self._main_context))):
            if self._main_context:
                mem_id, mem = next(iter(self._main_context.items()))
                self._page_out(mem_id)
                count += 1
        return count

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self._stats,
            "main_context_size": len(self._main_context),
            "main_context_tokens": self._current_main_tokens(),
            "archive_size": len(self._archive),
            "main_context_budget": self.main_context_tokens,
        }

    def save(self, filepath: str) -> None:
        """持久化到文件"""
        data = {
            "main_context": [m.to_dict() for m in self._main_context.values()],
            "archive": [m.to_dict() for m in self._archive.values()],
            "stats": self._stats,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def load(self, filepath: str) -> None:
        """从文件加载"""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        self._main_context.clear()
        self._archive.clear()
        for m_data in data.get("main_context", []):
            mem = EnhancedMemory.from_dict(m_data)
            self._main_context[mem.memory_id] = mem
        for m_data in data.get("archive", []):
            mem = EnhancedMemory.from_dict(m_data)
            self._archive[mem.memory_id] = mem
        self._stats.update(data.get("stats", {}))

    # ---- 内部方法 ----

    def _enforce_budget(self) -> None:
        """强制执行 token 预算，超出时淘汰到归档"""
        while self._current_main_tokens() > self.main_context_tokens and self._main_context:
            # 淘汰最不活跃+低重要性的记忆
            mem_id = self._select_for_page_out()
            if mem_id:
                self._page_out(mem_id)
            else:
                break

    def _select_for_page_out(self) -> Optional[str]:
        """选择要淘汰的记忆（LRU + 低重要性加权）"""
        if not self._main_context:
            return None
        now = time.time()
        best_id = None
        best_score = float("inf")
        for mem_id, mem in self._main_context.items():
            # 综合评分：重要性越高、最近访问越近，越不应该被淘汰
            idle_time = now - mem.last_accessed
            score = mem.importance * 0.6 + (1.0 / (1.0 + idle_time / 3600)) * 0.4
            if score < best_score:
                best_score = score
                best_id = mem_id
        return best_id

    def _page_out(self, memory_id: str) -> None:
        """淘汰记忆到归档（page-out）"""
        if memory_id in self._main_context:
            mem = self._main_context.pop(memory_id)
            mem.is_archived = True
            # 归档容量限制
            if len(self._archive) >= self.archive_max_items:
                self._archive.popitem(last=False)
            self._archive[memory_id] = mem
            self._stats["page_outs"] += 1

    def _recall(self, memory_id: str) -> None:
        """从归档召回记忆到主上下文（page-in）"""
        if memory_id in self._archive:
            mem = self._archive.pop(memory_id)
            mem.is_archived = False
            self._main_context[memory_id] = mem
            self._main_context.move_to_end(memory_id)
            self._stats["page_ins"] += 1
            self._enforce_budget()

    def _relevance_score(self, query_tokens: Set[str], mem: EnhancedMemory) -> float:
        """计算查询与记忆的相关性（TF-IDF 风格）"""
        if not query_tokens:
            return 0.0
        mem_tokens = self._tokenize(mem.content + " " + " ".join(mem.tags) + " " + " ".join(mem.entities))
        if not mem_tokens:
            return 0.0
        intersection = query_tokens & mem_tokens
        if not intersection:
            return 0.0
        # Jaccard 相似度 + 重要性加权
        jaccard = len(intersection) / len(query_tokens | mem_tokens)
        return jaccard * (0.5 + mem.importance * 0.5)

    def _match_tenant(self, mem: EnhancedMemory, user_id: str, session_id: str) -> bool:
        """多租户匹配"""
        if user_id and mem.user_id and mem.user_id != user_id:
            return False
        if session_id and mem.session_id and mem.session_id != session_id:
            return False
        return True

    def _current_main_tokens(self) -> int:
        """计算主上下文当前 token 数"""
        return sum(self._estimate_tokens(mem.content) for mem in self._main_context.values())

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """估算 token 数（英文 1 token≈4 chars，中文 1 token≈1.5 chars）"""
        if not text:
            return 0
        en_chars = len(re.findall(r'[a-zA-Z0-9]', text))
        other_chars = len(text) - en_chars
        return int(en_chars / 4 + other_chars / 1.5) + 1

    @staticmethod
    def _tokenize(text: str) -> Set[str]:
        """分词"""
        return set(re.findall(r'[a-z0-9_]+', text.lower()))


# ============================================================
# 2. 自动记忆提取器（Mem0 风格）
# ============================================================

class AutoMemoryExtractor:
    """
    自动记忆提取器（Mem0 风格）

    从对话/任务中自动提取重要信息，不需要手动调用 remember()。

    提取能力：
    1. 实体提取：人物、地点、组织、时间
    2. 偏好提取：用户习惯、配置选择、表达的喜好
    3. 事实提取：可验证的陈述
    4. 事件提取：发生的事情、动作
    5. 任务提取：待办事项、目标
    6. 重要性评分：自动判断是否值得记忆

    设计参考：
    - Mem0: 自动从对话中提取记忆，不需要手动调用
    - 重要性评分：基于实体数量、情感强度、重复出现等
    """

    # 偏好表达模式
    PREFERENCE_PATTERNS = [
        (r'i\s+(prefer|like|love|enjoy|want|need)\s+(.+?)(?:[.!?]|$)', "preference"),
        (r'(?:please\s+)?(?:always|never)\s+(.+?)(?:[.!?]|$)', "preference"),
        (r'my\s+(favorite|favourite|preferred)\s+(?:is|are)\s+(.+?)(?:[.!?]|$)', "preference"),
        (r'don\'?t\s+(?:like|want|need|prefer)\s+(.+?)(?:[.!?]|$)', "dispreference"),
    ]

    # 实体模式（简化版，生产环境可用 NER 模型）
    ENTITY_PATTERNS = {
        "person": r'\b(?:mr|mrs|ms|dr|prof)\.?\s+[A-Z][a-z]+',
        "organization": r'\b(?:Inc|Corp|Ltd|LLC|GmbH|Co)\.?',
        "url": r'https?://[^\s<>"]+',
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "date": r'\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b',
        "version": r'\bv?\d+\.\d+(?:\.\d+)?\b',
    }

    # 任务/待办模式
    TASK_PATTERNS = [
        r'(?:todo|to-do|task|need\s+to|should|must|have\s+to)\s+(.+?)(?:[.!?]|$)',
        r'(?:remember|don\'?t\s+forget)\s+(?:to\s+)?(.+?)(?:[.!?]|$)',
    ]

    def __init__(self, min_importance: float = 0.3,
                 max_extractions_per_message: int = 5):
        self.min_importance = min_importance
        self.max_extractions = max_extractions_per_message
        self._extraction_stats = Counter()

    def extract(self, text: str, source: str = "conversation",
                user_id: str = "", session_id: str = "",
                agent_id: str = "") -> List[EnhancedMemory]:
        """
        从文本中自动提取记忆

        Args:
            text: 输入文本（对话消息、任务描述等）
            source: 来源标识
            user_id/session_id/agent_id: 多租户标识

        Returns:
            提取的记忆列表（重要性高于阈值的）
        """
        if not text or not text.strip():
            return []

        extractions = []

        # 1. 提取偏好
        extractions.extend(self._extract_preferences(text, source, user_id, session_id, agent_id))

        # 2. 提取实体
        extractions.extend(self._extract_entities(text, source, user_id, session_id, agent_id))

        # 3. 提取任务
        extractions.extend(self._extract_tasks(text, source, user_id, session_id, agent_id))

        # 4. 提取事实（陈述句）
        extractions.extend(self._extract_facts(text, source, user_id, session_id, agent_id))

        # 按重要性排序，限制数量
        extractions.sort(key=lambda m: m.importance, reverse=True)
        extractions = [m for m in extractions if m.importance >= self.min_importance]
        extractions = extractions[:self.max_extractions]

        for mem in extractions:
            self._extraction_stats[mem.category.value] += 1

        return extractions

    def extract_from_conversation(self, messages: List[Dict[str, str]],
                                   user_id: str = "", session_id: str = "") -> List[EnhancedMemory]:
        """
        从对话历史中批量提取记忆

        Args:
            messages: 对话消息列表，每条包含 role 和 content

        Returns:
            提取的记忆列表
        """
        all_extractions = []
        seen_contents = set()
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if not content or content in seen_contents:
                continue
            seen_contents.add(content)
            # 用户消息更可能包含偏好和事实
            source = f"conversation/{role}"
            extractions = self.extract(content, source=source,
                                        user_id=user_id, session_id=session_id)
            all_extractions.extend(extractions)
        return all_extractions

    def get_stats(self) -> Dict[str, Any]:
        """获取提取统计"""
        return dict(self._extraction_stats)

    # ---- 内部提取方法 ----

    def _extract_preferences(self, text: str, source: str,
                              user_id: str, session_id: str,
                              agent_id: str) -> List[EnhancedMemory]:
        """提取偏好"""
        memories = []
        text_lower = text.lower()
        for pattern, ptype in self.PREFERENCE_PATTERNS:
            matches = re.findall(pattern, text_lower)
            for match in matches:
                pref_content = match[1] if isinstance(match, tuple) else match
                if len(pref_content) < 3:
                    continue
                importance = self._calc_importance(pref_content, entity_count=1)
                mem = EnhancedMemory(
                    memory_id=self._gen_id(f"pref_{pref_content[:30]}"),
                    content=f"用户{'偏好' if ptype == 'preference' else '不喜欢'}: {pref_content}",
                    category=MemoryCategory.PREFERENCE,
                    importance=importance,
                    source=source,
                    user_id=user_id, session_id=session_id, agent_id=agent_id,
                    tags=["preference", ptype],
                )
                memories.append(mem)
        return memories

    def _extract_entities(self, text: str, source: str,
                          user_id: str, session_id: str,
                          agent_id: str) -> List[EnhancedMemory]:
        """提取实体"""
        memories = []
        entities_found = []
        for etype, pattern in self.ENTITY_PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches[:3]:  # 每种类型最多3个
                entity = match if isinstance(match, str) else match[0]
                if entity and entity not in [e[1] for e in entities_found]:
                    entities_found.append((etype, entity))

        if entities_found:
            importance = self._calc_importance(text, entity_count=len(entities_found))
            entity_names = [e[1] for e in entities_found]
            mem = EnhancedMemory(
                memory_id=self._gen_id(f"entity_{'_'.join(entity_names[:2])}"),
                content=f"提及实体: {', '.join(f'{t}:{e}' for t, e in entities_found)}",
                category=MemoryCategory.ENTITY,
                importance=importance,
                source=source,
                user_id=user_id, session_id=session_id, agent_id=agent_id,
                entities=entity_names,
                tags=["entity"] + [t for t, _ in entities_found],
            )
            memories.append(mem)
        return memories

    def _extract_tasks(self, text: str, source: str,
                       user_id: str, session_id: str,
                       agent_id: str) -> List[EnhancedMemory]:
        """提取任务/待办"""
        memories = []
        for pattern in self.TASK_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches[:2]:
                task_content = match if isinstance(match, str) else match[0]
                if len(task_content) < 5:
                    continue
                mem = EnhancedMemory(
                    memory_id=self._gen_id(f"task_{task_content[:30]}"),
                    content=f"待办任务: {task_content}",
                    category=MemoryCategory.TASK,
                    importance=self._calc_importance(task_content, entity_count=0),
                    source=source,
                    user_id=user_id, session_id=session_id, agent_id=agent_id,
                    tags=["task", "todo"],
                )
                memories.append(mem)
        return memories

    def _extract_facts(self, text: str, source: str,
                       user_id: str, session_id: str,
                       agent_id: str) -> List[EnhancedMemory]:
        """提取事实（陈述句）"""
        # 简单的事实提取：包含"是/为/等于/包含"等判断词的句子
        fact_patterns = [
            r'(.+?)\s+(?:is|are|was|were|equals?|contains?|has|have)\s+(.+?)(?:[.!?]|$)',
            r'(.+?)\s+(?:是|为|等于|包含|有)\s+(.+?)(?:[。！？]|$)',
        ]
        memories = []
        for pattern in fact_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches[:2]:
                subject = match[0].strip() if isinstance(match, tuple) else ""
                predicate = match[1].strip() if isinstance(match, tuple) else ""
                if len(subject) < 2 or len(predicate) < 2:
                    continue
                content = f"{subject} = {predicate}"
                mem = EnhancedMemory(
                    memory_id=self._gen_id(f"fact_{content[:30]}"),
                    content=f"事实: {content}",
                    category=MemoryCategory.FACT,
                    importance=self._calc_importance(content, entity_count=1),
                    source=source,
                    user_id=user_id, session_id=session_id, agent_id=agent_id,
                    tags=["fact"],
                )
                memories.append(mem)
        return memories

    def _calc_importance(self, content: str, entity_count: int = 0) -> float:
        """计算重要性评分"""
        score = 0.3  # 基础分
        # 长度适中的内容更可能重要
        if 10 < len(content) < 200:
            score += 0.15
        # 实体越多越重要
        score += min(entity_count * 0.1, 0.3)
        # 包含数字/版本/日期更可能是事实
        if re.search(r'\d', content):
            score += 0.1
        # 包含强情感词
        if re.search(r'(important|critical|urgent|must|never|always)', content, re.IGNORECASE):
            score += 0.15
        return min(score, 1.0)

    @staticmethod
    def _gen_id(prefix: str) -> str:
        """生成记忆ID"""
        clean = re.sub(r'[^a-z0-9_]', '_', prefix.lower())[:40]
        return f"{clean}_{hashlib.md5(prefix.encode(), usedforsecurity=False).hexdigest()[:8]}"


# ============================================================
# 3. 语义记忆存储 + CRUD API（Mem0 风格）
# ============================================================

class SemanticMemoryStore:
    """
    语义记忆存储（Mem0 风格 CRUD API）

    提供 Mem0 兼容的 API：
    - add(): 添加记忆
    - get(): 获取记忆
    - update(): 更新记忆
    - delete(): 删除记忆
    - search(): 语义搜索记忆
    - list(): 列出记忆

    特性：
    - TF-IDF 语义检索（可替换为向量数据库）
    - 多租户隔离（user_id/session_id/agent_id）
    - 记忆版本管理
    - 记忆关联（关系图谱）
    - 与 VirtualContextManager 集成（自动分页）
    """

    def __init__(self, main_context_tokens: int = 4000,
                 archive_max_items: int = 10000):
        self._context_manager = VirtualContextManager(
            main_context_tokens=main_context_tokens,
            archive_max_items=archive_max_items,
        )
        self._all_memory_ids: Set[str] = set()
        self._relation_graph: Dict[str, Set[str]] = defaultdict(set)

    # ---- Mem0 兼容 CRUD API ----

    def add(self, content: str, user_id: str = "", session_id: str = "",
            agent_id: str = "", metadata: Optional[Dict] = None,
            category: str = "fact", importance: float = 0.5) -> str:
        """
        添加记忆（Mem0 兼容 API）

        Args:
            content: 记忆内容
            user_id/session_id/agent_id: 多租户标识
            metadata: 附加元数据
            category: 记忆类别
            importance: 重要性 0-1

        Returns:
            记忆ID
        """
        mem_id = self._gen_id(content)
        mem = EnhancedMemory(
            memory_id=mem_id,
            content=content,
            category=MemoryCategory(category),
            importance=importance,
            user_id=user_id, session_id=session_id, agent_id=agent_id,
            tags=(metadata or {}).get("tags", []),
            entities=(metadata or {}).get("entities", []),
            source=(metadata or {}).get("source", "api"),
        )
        self._context_manager.add(mem)
        self._all_memory_ids.add(mem_id)
        return mem_id

    def get(self, memory_id: str) -> Optional[Dict[str, Any]]:
        """获取记忆（Mem0 兼容 API）"""
        mem = self._context_manager.get(memory_id)
        return mem.to_dict() if mem else None

    def update(self, memory_id: str, content: Optional[str] = None,
               metadata: Optional[Dict] = None) -> bool:
        """
        更新记忆（Mem0 兼容 API）

        自动增加版本号。
        """
        mem = self._context_manager.get(memory_id)
        if not mem:
            return False
        if content is not None:
            mem.content = content
        if metadata:
            if "tags" in metadata:
                mem.tags = metadata["tags"]
            if "importance" in metadata:
                mem.importance = metadata["importance"]
        mem.version += 1
        self._context_manager.add(mem)  # 重新添加（更新）
        return True

    def delete(self, memory_id: str) -> bool:
        """删除记忆（Mem0 兼容 API）"""
        # 从主上下文和归档中删除
        if memory_id in self._context_manager._main_context:
            del self._context_manager._main_context[memory_id]
            self._all_memory_ids.discard(memory_id)
            return True
        if memory_id in self._context_manager._archive:
            del self._context_manager._archive[memory_id]
            self._all_memory_ids.discard(memory_id)
            return True
        return False

    def search(self, query: str, limit: int = 5,
               user_id: str = "", session_id: str = "") -> List[Dict[str, Any]]:
        """
        语义搜索记忆（Mem0 兼容 API）

        归档中高相关性记忆自动召回。
        """
        results = self._context_manager.search(
            query, limit=limit, user_id=user_id, session_id=session_id,
        )
        return [mem.to_dict() for mem in results]

    def list(self, user_id: str = "", session_id: str = "",
             category: str = "", limit: int = 50) -> List[Dict[str, Any]]:
        """列出记忆（Mem0 兼容 API）"""
        results = []
        for mem in list(self._context_manager._main_context.values()) + \
                   list(self._context_manager._archive.values()):
            if user_id and mem.user_id != user_id:
                continue
            if session_id and mem.session_id != session_id:
                continue
            if category and mem.category.value != category:
                continue
            results.append(mem.to_dict())
            if len(results) >= limit:
                break
        return results

    # ---- 增强功能 ----

    def add_relation(self, memory_id_1: str, memory_id_2: str) -> bool:
        """添加记忆关联（关系图谱）"""
        if memory_id_1 in self._all_memory_ids and memory_id_2 in self._all_memory_ids:
            self._relation_graph[memory_id_1].add(memory_id_2)
            self._relation_graph[memory_id_2].add(memory_id_1)
            return True
        return False

    def get_related(self, memory_id: str, depth: int = 1) -> List[Dict[str, Any]]:
        """获取关联记忆（关系图谱遍历）"""
        visited = set()
        queue = [(memory_id, 0)]
        related = []
        while queue:
            current, d = queue.pop(0)
            if current in visited or d > depth:
                continue
            visited.add(current)
            if current != memory_id:
                mem = self._context_manager.get(current)
                if mem:
                    related.append(mem.to_dict())
            for neighbor in self._relation_graph.get(current, set()):
                if neighbor not in visited:
                    queue.append((neighbor, d + 1))
        return related

    def get_context(self, max_tokens: int = 3000) -> str:
        """获取当前上下文字符串（用于 LLM 输入）"""
        return self._context_manager.get_context_string(max_tokens)

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self._context_manager.get_stats(),
            "total_memories": len(self._all_memory_ids),
            "relation_count": sum(len(v) for v in self._relation_graph.values()) // 2,
        }

    def save(self, filepath: str) -> None:
        """持久化"""
        data = {
            "context_manager": {
                "main_context": [m.to_dict() for m in self._context_manager._main_context.values()],
                "archive": [m.to_dict() for m in self._context_manager._archive.values()],
                "stats": self._context_manager._stats,
            },
            "all_memory_ids": list(self._all_memory_ids),
            "relation_graph": {k: list(v) for k, v in self._relation_graph.items()},
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def load(self, filepath: str) -> None:
        """从文件加载"""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        cm = self._context_manager
        cm._main_context.clear()
        cm._archive.clear()
        for m_data in data["context_manager"]["main_context"]:
            mem = EnhancedMemory.from_dict(m_data)
            cm._main_context[mem.memory_id] = mem
        for m_data in data["context_manager"]["archive"]:
            mem = EnhancedMemory.from_dict(m_data)
            cm._archive[mem.memory_id] = mem
        cm._stats.update(data["context_manager"]["stats"])
        self._all_memory_ids = set(data.get("all_memory_ids", []))
        self._relation_graph = defaultdict(set)
        for k, v in data.get("relation_graph", {}).items():
            self._relation_graph[k] = set(v)

    @staticmethod
    def _gen_id(content: str) -> str:
        return f"mem_{hashlib.md5(content.encode(), usedforsecurity=False).hexdigest()[:16]}"
