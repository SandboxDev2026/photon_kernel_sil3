"""
evolution.memory_engine — AutoGeneticMemory 自主生长记忆引擎

分层记忆架构：
- 短期记忆（Short-term）：当前上下文窗口，LRU 淘汰
- 中期记忆（Mid-term）：任务执行记录，按时间衰减
- 长期记忆（Long-term）：沉淀的 Skill/知识，持久化存储

核心能力：
- 自动记忆压缩：短期→中期→长期，逐层提炼
- 自动淘汰：LRU + 时间衰减 + 重要性评分
- 提炼成 Skill：高频成功模式自动沉淀为 Skill
- Token 预算控制：避免 token 无限膨胀

设计参考：
- 短期记忆：Transformer 上下文窗口 + LRU
- 中期记忆：向量数据库 + 时间衰减
- 长期记忆：Skill 库 + 知识图谱
- 记忆压缩：LLM 摘要提炼
"""
from __future__ import annotations
import json
import time
import hashlib
from typing import List, Optional, Dict, Any, Callable
from dataclasses import dataclass, field, asdict
from collections import OrderedDict
from .skill_library import Skill, SkillLibrary


@dataclass
class MemoryItem:
    """记忆条目"""
    content: str
    memory_type: str = "short"      # short / mid / long
    importance: float = 0.5          # 重要性评分 0-1
    access_count: int = 0
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    expires_at: float = 0.0          # 0 = 永不过期
    tags: List[str] = field(default_factory=list)
    source_task: str = ""
    compressed_from: str = ""         # 压缩来源（短期→中期时记录）

    @property
    def is_expired(self) -> bool:
        if self.expires_at == 0:
            return False
        return time.time() > self.expires_at

    @property
    def age_seconds(self) -> float:
        return time.time() - self.created_at

    def touch(self) -> None:
        self.access_count += 1
        self.last_accessed = time.time()

    def to_dict(self) -> dict:
        return asdict(self)


class ShortTermMemory:
    """
    短期记忆：当前上下文窗口

    特性：
    - LRU 淘汰（最近最少使用）
    - 固定容量（token 预算）
    - 快速读写
    - 自动压缩到中期记忆
    """
    def __init__(self, max_items: int = 50, max_tokens: int = 8000,
                 ttl_seconds: int = 3600):
        self.max_items = max_items
        self.max_tokens = max_tokens
        self.ttl = ttl_seconds
        self._items: OrderedDict[str, MemoryItem] = OrderedDict()

    def add(self, content: str, importance: float = 0.5,
            tags: List[str] = None, source_task: str = "") -> str:
        """添加记忆，返回记忆 ID"""
        mem_id = hashlib.md5(f"{content}{time.time()}".encode()).hexdigest()[:12]
        item = MemoryItem(
            content=content,
            memory_type="short",
            importance=importance,
            tags=tags or [],
            source_task=source_task,
            expires_at=time.time() + self.ttl,
        )
        self._items[mem_id] = item
        self._items.move_to_end(mem_id)
        self._evict()
        return mem_id

    def get(self, mem_id: str) -> Optional[MemoryItem]:
        """获取记忆（LRU 触碰）"""
        if mem_id in self._items:
            item = self._items[mem_id]
            if item.is_expired:
                del self._items[mem_id]
                return None
            item.touch()
            self._items.move_to_end(mem_id)
            return item
        return None

    def search(self, keyword: str, limit: int = 5) -> List[MemoryItem]:
        """关键词搜索"""
        results = []
        for item in self._items.values():
            if item.is_expired:
                continue
            if keyword.lower() in item.content.lower() or any(keyword.lower() in t.lower() for t in item.tags):
                results.append(item)
        results.sort(key=lambda x: (x.importance, x.last_accessed), reverse=True)
        return results[:limit]

    def get_all(self) -> List[MemoryItem]:
        """获取所有未过期记忆"""
        return [item for item in self._items.values() if not item.is_expired]

    def _evict(self) -> None:
        """LRU 淘汰 + 过期清理"""
        # 先清理过期
        expired = [mid for mid, item in self._items.items() if item.is_expired]
        for mid in expired:
            del self._items[mid]

        # LRU 淘汰（超过容量时，移除最久未使用的）
        while len(self._items) > self.max_items:
            self._items.popitem(last=False)

    def get_oldest_for_compression(self, n: int = 5) -> List[MemoryItem]:
        """获取最老的 n 条记忆用于压缩到中期"""
        items = sorted(self._items.values(), key=lambda x: x.last_accessed)
        return items[:n]

    def remove(self, mem_id: str) -> None:
        if mem_id in self._items:
            del self._items[mem_id]

    def clear(self) -> None:
        self._items.clear()

    @property
    def size(self) -> int:
        return len(self._items)

    @property
    def estimated_tokens(self) -> int:
        return sum(len(item.content) // 4 for item in self._items.values())


class MidTermMemory:
    """
    中期记忆：任务执行记录

    特性：
    - 时间衰减（越老的记忆权重越低）
    - 按任务/标签索引
    - 自动提炼到长期记忆（高频成功模式）
    - 容量控制
    """
    def __init__(self, max_items: int = 500, decay_rate: float = 0.0001):
        self.max_items = max_items
        self.decay_rate = decay_rate  # 每秒衰减率
        self._items: Dict[str, MemoryItem] = {}

    def add(self, content: str, importance: float = 0.5,
            tags: List[str] = None, source_task: str = "",
            compressed_from: str = "") -> str:
        """添加中期记忆"""
        mem_id = hashlib.md5(f"{content}{time.time()}".encode()).hexdigest()[:12]
        item = MemoryItem(
            content=content,
            memory_type="mid",
            importance=importance,
            tags=tags or [],
            source_task=source_task,
            compressed_from=compressed_from,
        )
        self._items[mem_id] = item
        self._evict()
        return mem_id

    def get_effective_importance(self, item: MemoryItem) -> float:
        """计算时间衰减后的有效重要性"""
        decay = max(0, 1 - self.decay_rate * item.age_seconds)
        return item.importance * decay * (1 + item.access_count * 0.1)

    def search(self, keyword: str = "", tag: str = "",
               task: str = "", limit: int = 10) -> List[MemoryItem]:
        """搜索中期记忆"""
        results = []
        for item in self._items.values():
            if keyword and keyword.lower() not in item.content.lower():
                continue
            if tag and tag not in item.tags:
                continue
            if task and task != item.source_task:
                continue
            results.append(item)
        results.sort(key=self.get_effective_importance, reverse=True)
        return results[:limit]

    def get_high_value(self, threshold: float = 0.7, limit: int = 10) -> List[MemoryItem]:
        """获取高价值记忆（用于提炼到长期）"""
        results = [
            item for item in self._items.values()
            if self.get_effective_importance(item) >= threshold
        ]
        results.sort(key=self.get_effective_importance, reverse=True)
        return results[:limit]

    def _evict(self) -> None:
        """淘汰低价值记忆"""
        if len(self._items) <= self.max_items:
            return
        sorted_items = sorted(self._items.items(), key=lambda kv: self.get_effective_importance(kv[1]))
        while len(self._items) > self.max_items and sorted_items:
            lowest_id, _ = sorted_items.pop(0)
            if lowest_id in self._items:
                del self._items[lowest_id]

    def remove(self, mem_id: str) -> None:
        if mem_id in self._items:
            del self._items[mem_id]

    @property
    def size(self) -> int:
        return len(self._items)


class AutoGeneticMemory:
    """
    AutoGeneticMemory 自主生长记忆引擎

    三层记忆架构：
    1. 短期记忆（Short-term）：当前上下文，LRU 淘汰，TTL 过期
    2. 中期记忆（Mid-term）：任务记录，时间衰减，高价值提炼
    3. 长期记忆（Long-term）：沉淀的 Skill，持久化存储

    自主生长机制：
    - 自动压缩：短期→中期（LLM 摘要）
    - 自动提炼：中期→长期（高频成功模式 → Skill）
    - 自动淘汰：LRU + 时间衰减 + 重要性评分
    - Token 预算：三层总 token 不超过预算

    安全约束：
    - 所有记忆内容经过安全过滤
    - 敏感信息不进入长期记忆
    - Skill 提炼经过安全门控
    """

    def __init__(self,
                 skill_library: Optional[SkillLibrary] = None,
                 llm: Optional[Any] = None,
                 short_max_items: int = 50,
                 short_max_tokens: int = 8000,
                 mid_max_items: int = 500,
                 total_token_budget: int = 32000,
                 compression_threshold: int = 40,
                 skill_extraction_threshold: float = 0.8):
        self.short_term = ShortTermMemory(max_items=short_max_items, max_tokens=short_max_tokens)
        self.mid_term = MidTermMemory(max_items=mid_max_items)
        self.long_term = skill_library or SkillLibrary()
        self.llm = llm
        self.total_token_budget = total_token_budget
        self.compression_threshold = compression_threshold
        self.skill_extraction_threshold = skill_extraction_threshold

        # 统计
        self.compressions_done = 0
        self.skills_extracted = 0
        self.items_evicted = 0

    # ==================== 写入接口 ====================

    def remember(self, content: str, importance: float = 0.5,
                 tags: List[str] = None, source_task: str = "") -> str:
        """
        记录一条记忆（自动进入短期记忆）

        Returns:
            记忆 ID
        """
        # 安全过滤
        content = self._sanitize(content)
        mem_id = self.short_term.add(content, importance, tags, source_task)

        # 检查是否需要压缩
        if self.short_term.size >= self.compression_threshold:
            self.compress_short_to_mid()

        # 检查 token 预算
        self._enforce_token_budget()

        return mem_id

    def remember_task_result(self, task: str, result: str, success: bool,
                             importance: float = 0.5) -> str:
        """记录任务执行结果"""
        content = f"Task: {task}\nResult: {result}\nSuccess: {success}"
        tags = ["task_result", "success" if success else "failure"]
        return self.remember(content, importance, tags, source_task=task)

    # ==================== 读取接口 ====================

    def recall(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """
        回忆相关记忆（跨三层搜索）

        Returns:
            记忆列表，按相关度排序
        """
        results = []

        # 短期记忆（最高优先级）
        for item in self.short_term.search(query, limit=limit):
            results.append({
                "content": item.content,
                "layer": "short",
                "importance": item.importance,
                "age": item.age_seconds,
                "tags": item.tags,
            })

        # 中期记忆
        for item in self.mid_term.search(query, limit=limit):
            results.append({
                "content": item.content,
                "layer": "mid",
                "importance": self.mid_term.get_effective_importance(item),
                "age": item.age_seconds,
                "tags": item.tags,
            })

        # 长期记忆（Skill 库）
        for skill in self.long_term.list(min_fitness=0.3)[:limit]:
            if query.lower() in skill.name.lower() or query.lower() in skill.description.lower():
                results.append({
                    "content": f"Skill: {skill.name}\n{skill.description}\n{skill.code[:500]}",
                    "layer": "long",
                    "importance": skill.current_fitness,
                    "age": 0,
                    "tags": skill.tags,
                    "skill_id": skill.id,
                })

        results.sort(key=lambda x: x["importance"], reverse=True)
        return results[:limit]

    def get_context(self, max_tokens: int = 4000) -> str:
        """
        获取当前上下文（用于 LLM prompt）

        按优先级组合：短期记忆 + 高价值中期记忆 + 相关 Skill
        """
        context_parts = []
        current_tokens = 0

        # 短期记忆
        for item in self.short_term.get_all()[-10:]:
            text = f"[Recent] {item.content}"
            if current_tokens + len(text) // 4 > max_tokens:
                break
            context_parts.append(text)
            current_tokens += len(text) // 4

        # 高价值中期记忆
        for item in self.mid_term.get_high_value(threshold=0.6, limit=5):
            text = f"[Memory] {item.content}"
            if current_tokens + len(text) // 4 > max_tokens:
                break
            context_parts.append(text)
            current_tokens += len(text) // 4

        return "\n\n".join(context_parts)

    # ==================== 自主生长：压缩与提炼 ====================

    def compress_short_to_mid(self, n: int = 5) -> int:
        """
        短期→中期压缩

        策略：
        1. 取最老的 n 条短期记忆
        2. 用 LLM 摘要压缩（如果有 LLM）
        3. 存入中期记忆
        4. 从短期记忆删除

        Returns:
            压缩的记忆数量
        """
        oldest = self.short_term.get_oldest_for_compression(n)
        if not oldest:
            return 0

        compressed_count = 0
        for item in oldest:
            # 压缩内容（LLM 摘要或简单截断）
            compressed = self._compress_content(item.content)

            # 存入中期记忆
            self.mid_term.add(
                content=compressed,
                importance=item.importance * 0.8,  # 压缩后重要性略降
                tags=item.tags + ["compressed"],
                source_task=item.source_task,
                compressed_from=item.content[:200],
            )

            # 从短期删除
            self.short_term.remove(
                next((mid for mid, it in self.short_term._items.items() if it == item), "")
            )
            compressed_count += 1

        self.compressions_done += compressed_count
        return compressed_count

    def extract_skills_from_mid(self, min_occurrences: int = 3) -> int:
        """
        中期→长期提炼：高频成功模式 → Skill

        策略：
        1. 扫描中期记忆中的高价值成功记录
        2. 识别重复出现的成功模式
        3. 用 LLM 提炼为 Skill 代码
        4. 存入 Skill 库（长期记忆）

        Returns:
            提炼的 Skill 数量
        """
        high_value = self.mid_term.get_high_value(threshold=self.skill_extraction_threshold, limit=20)
        if len(high_value) < min_occurrences:
            return 0

        # 简单模式识别：按 source_task 分组
        task_groups: Dict[str, List[MemoryItem]] = {}
        for item in high_value:
            if item.source_task:
                task_groups.setdefault(item.source_task, []).append(item)

        extracted = 0
        for task, items in task_groups.items():
            if len(items) >= min_occurrences:
                # 提炼为 Skill
                skill = self._extract_skill(task, items)
                if skill:
                    self.long_term.add(skill)
                    extracted += 1

        self.skills_extracted += extracted
        return extracted

    def _extract_skill(self, task: str, items: List[MemoryItem]) -> Optional[Skill]:
        """从记忆中提炼 Skill"""
        # 汇总成功案例
        success_cases = [item.content for item in items if "success" in item.tags]

        if not success_cases or not self.llm:
            # 无 LLM 时创建简单 Skill
            return Skill(
                name=f"auto_skill_{task[:20]}",
                description=f"Auto-extracted from {len(items)} successful executions of: {task}",
                code=f"# Auto-extracted skill for: {task}\n# Based on {len(items)} successful executions\ndef execute(input_data):\n    pass",
                tags=["auto-extracted", task],
            )

        # 用 LLM 提炼
        prompt = f"基于以下 {len(success_cases)} 个成功案例，提炼一个可复用的 Python Skill：\n\n"
        prompt += "\n---\n".join(success_cases[:5])
        prompt += "\n\n请输出完整的 Python 函数代码，包含 docstring 和错误处理。"

        try:
            code = self.llm.generate(prompt, temperature=0.2)
            return Skill(
                name=f"auto_skill_{task[:20]}",
                description=f"Auto-extracted from {len(items)} successful executions",
                code=code,
                tags=["auto-extracted", task],
            )
        except Exception:
            return None

    # ==================== 内部工具 ====================

    def _compress_content(self, content: str) -> str:
        """压缩内容（LLM 摘要或简单截断）"""
        if self.llm and len(content) > 200:
            try:
                prompt = f"请用不超过100字总结以下内容，保留关键信息：\n\n{content[:1000]}"
                return self.llm.generate(prompt, temperature=0.1)
            except Exception:
                pass
        # 简单截断
        if len(content) > 500:
            return content[:500] + "...[truncated]"
        return content

    def _sanitize(self, content: str) -> str:
        """安全过滤：移除敏感信息"""
        import re
        # 移除 API key 模式
        content = re.sub(r'sk-[a-zA-Z0-9]{20,}', '[REDACTED_API_KEY]', content)
        # 移除密码模式
        content = re.sub(r'password["\s:=]+["\']?[^"\'\s]{6,}', 'password=[REDACTED]', content, flags=re.IGNORECASE)
        # 移除 token 模式
        content = re.sub(r'ghp_[a-zA-Z0-9]{20,}', '[REDACTED_GITHUB_TOKEN]', content)
        return content

    def _enforce_token_budget(self) -> None:
        """强制执行 token 预算"""
        total = self.short_term.estimated_tokens + sum(len(item.content) // 4 for item in self.mid_term._items.values())
        if total > self.total_token_budget:
            # 压缩短期到中期
            self.compress_short_to_mid(n=10)

    # ==================== 统计与持久化 ====================

    def get_stats(self) -> Dict[str, Any]:
        """获取记忆引擎统计"""
        return {
            "short_term": {
                "items": self.short_term.size,
                "estimated_tokens": self.short_term.estimated_tokens,
            },
            "mid_term": {
                "items": self.mid_term.size,
            },
            "long_term": {
                "skills": len(self.long_term),
            },
            "compressions_done": self.compressions_done,
            "skills_extracted": self.skills_extracted,
            "total_token_budget": self.total_token_budget,
        }

    def save(self, filepath: str) -> None:
        """保存记忆状态"""
        data = {
            "short_term": [item.to_dict() for item in self.short_term.get_all()],
            "mid_term": [item.to_dict() for item in self.mid_term._items.values()],
            "stats": self.get_stats(),
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        # 长期记忆（Skill 库）单独保存
        self.long_term.save(filepath + ".skills.json")
