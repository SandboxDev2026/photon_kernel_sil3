"""
evolution.wiki_skill_evolver — WikiSkill 三层架构技能进化器

集成 WikiSkill 三层架构：
- Raw Layer（原始轨迹层）：记录不可变的执行轨迹
- Wiki Layer（维基知识层）：编译结构化知识，永不回滚
- Skill Layer（可执行技能层）：基于 Wiki 知识进化技能，允许回滚

四角色闭环：
1. Executor（执行者）：使用 Skill 执行任务，记录轨迹到 Raw 层
2. Compiler（编译者）：将 Raw 轨迹编译成 Wiki 知识
3. Evolver（进化者）：基于 Wiki 知识进化 Skill
4. Validator（验证者）：验证新 Skill，决定接受或回滚

参考论文：WikiSkill: Compiling Agent Experience into Persistent Knowledge for Skill Evolution
- Google Research, 2026
- 关键发现：持久 Wiki 是关键，接入 Wiki 后效果从 48.7% 提升到 63.7%
- 反直觉发现：给推理 agent 看 Wiki 反而降分（轨迹被污染），Wiki 应该用于技能进化
- 跨模型迁移：9B 模型用 27B 模型进化的 skill 反而更好

核心设计：
- Wiki 永不回滚：Skill 被拒绝时，Wiki 保留所有知识
- 下次进化时，即使之前的 Skill 改动被拒绝，Wiki 中的知识仍然可用
- 避免重复尝试失败的改动
- 跨迭代持续积累
"""
from __future__ import annotations
import json
import time
from typing import List, Optional, Dict, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum

from .skill_library import Skill, SkillLibrary
from .llm_adapter import BaseLLMAdapter, MockLLMAdapter
from .raw_layer import RawLayer, RawTrajectory
from .wiki_layer import (
    WikiLayer, WikiPattern, PatternType, PatternSeverity,
    WikiLogEntry, SkillImpactRecord,
)
from .skill_evolver import SkillEvolver, SkillExecutionRecord, SkillEvolutionEvent


class EvolutionPhase(Enum):
    """进化阶段"""
    IDLE = "idle"                          # 空闲
    RECORDING = "recording"                # 记录轨迹
    COMPILING = "compiling"                # 编译知识
    EVOLVING = "evolving"                  # 进化技能
    VALIDATING = "validating"              # 验证技能
    COMPLETED = "completed"                # 完成


@dataclass
class WikiSkillEvolutionResult:
    """WikiSkill 进化结果"""
    success: bool
    phase: EvolutionPhase
    skill_id: str = ""
    old_version: str = ""
    new_version: str = ""
    validation_result: str = ""            # accepted / rejected
    rejection_reason: str = ""
    patterns_discovered: int = 0
    trajectories_analyzed: int = 0
    success_rate_before: float = 0.0
    success_rate_after: float = 0.0
    duration_ms: int = 0
    wiki_knowledge_used: bool = True       # 是否使用了 Wiki 知识
    notes: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["phase"] = self.phase.value
        return d


class WikiSkillEvolver:
    """
    WikiSkill 三层架构技能进化器

    集成 Raw Layer + Wiki Layer + Skill Layer，实现四角色闭环：
    1. Executor：执行任务，记录轨迹到 Raw 层
    2. Compiler：将 Raw 轨迹编译成 Wiki 知识
    3. Evolver：基于 Wiki 知识进化 Skill
    4. Validator：验证新 Skill，决定接受或回滚

    关键设计（论文核心）：
    - Wiki 永不回滚：Skill 可以回滚，但 Wiki 永远保留
    - 避免重复尝试失败的改动
    - 跨迭代持续积累

    使用示例：
        # 初始化三层架构
        raw = RawLayer()
        wiki = WikiLayer()
        skill_lib = SkillLibrary()
        evolver = WikiSkillEvolver(skill_lib, raw_layer=raw, wiki_layer=wiki)

        # 1. 执行任务并记录轨迹
        evolver.record_execution(
            skill_id="code_gen",
            task="生成排序函数",
            success=False,
            error="IndentationError",
            error_type="logic_error",
        )

        # 2. 编译知识（从轨迹提取模式）
        patterns = evolver.compile_knowledge()

        # 3. 进化技能（基于 Wiki 知识）
        result = evolver.evolve_skill("code_gen")

        # 4. 查看 Wiki 知识（永不回滚）
        knowledge = evolver.get_wiki_knowledge("code_gen")
    """

    def __init__(self,
                 skill_library: SkillLibrary,
                 llm: Optional[BaseLLMAdapter] = None,
                 raw_layer: Optional[RawLayer] = None,
                 wiki_layer: Optional[WikiLayer] = None,
                 failure_threshold: int = 3,
                 success_rate_threshold: float = 0.6,
                 min_executions_before_evolve: int = 5,
                 use_wiki_knowledge: bool = True,
                 wiki_never_rollback: bool = True):
        """
        初始化 WikiSkill 进化器

        Args:
            skill_library: 技能库
            llm: LLM 适配器（用于反思和生成）
            raw_layer: 原始轨迹层（None 则自动创建）
            wiki_layer: 维基知识层（None 则自动创建）
            failure_threshold: 连续失败阈值（触发进化）
            success_rate_threshold: 成功率阈值（低于则触发进化）
            min_executions_before_evolve: 最少执行次数后才进化
            use_wiki_knowledge: 是否使用 Wiki 知识进行进化
            wiki_never_rollback: Wiki 是否永不回滚（核心设计，默认 True）
        """
        self.skill_library = skill_library
        self.llm = llm or MockLLMAdapter()
        self.raw_layer = raw_layer or RawLayer()
        self.wiki_layer = wiki_layer or WikiLayer()
        self.failure_threshold = failure_threshold
        self.success_rate_threshold = success_rate_threshold
        self.min_executions_before_evolve = min_executions_before_evolve
        self.use_wiki_knowledge = use_wiki_knowledge
        self.wiki_never_rollback = wiki_never_rollback

        # 内部状态
        self._current_phase = EvolutionPhase.IDLE
        self._consecutive_failures: Dict[str, int] = {}
        self._evolution_history: List[WikiSkillEvolutionResult] = []

        # 开始第一轮迭代
        self.wiki_layer.start_iteration()

    def record_execution(self,
                         skill_id: str,
                         task: str,
                         success: bool,
                         input_data: Optional[Dict[str, Any]] = None,
                         output_data: Optional[Dict[str, Any]] = None,
                         error: str = "",
                         error_type: str = "",
                         tool_calls: Optional[List[Dict[str, Any]]] = None,
                         duration_ms: int = 0,
                         token_usage: Optional[Dict[str, int]] = None,
                         skill_name: str = "",
                         skill_version: str = "",
                         metadata: Optional[Dict[str, Any]] = None) -> RawTrajectory:
        """
        【Executor 角色】执行任务并记录轨迹到 Raw 层

        Args:
            skill_id: Skill ID
            task: 任务描述
            success: 是否成功
            input_data: 完整输入
            output_data: 完整输出
            error: 错误信息
            error_type: 错误类型
            tool_calls: 工具调用记录
            duration_ms: 耗时
            token_usage: token 使用
            skill_name: Skill 名称
            skill_version: Skill 版本
            metadata: 额外元数据

        Returns:
            创建的 RawTrajectory
        """
        self._current_phase = EvolutionPhase.RECORDING

        # 记录到 Raw 层
        trajectory = self.raw_layer.record(
            skill_id=skill_id,
            task=task,
            input_data=input_data,
            output_data=output_data,
            success=success,
            error=error,
            error_type=error_type,
            tool_calls=tool_calls,
            duration_ms=duration_ms,
            token_usage=token_usage,
            skill_name=skill_name,
            skill_version=skill_version,
            metadata=metadata,
        )

        # 更新连续失败计数
        if success:
            self._consecutive_failures[skill_id] = 0
        else:
            self._consecutive_failures[skill_id] = self._consecutive_failures.get(skill_id, 0) + 1

        return trajectory

    def compile_knowledge(self, skill_id: Optional[str] = None) -> List[WikiPattern]:
        """
        【Compiler 角色】将 Raw 轨迹编译成 Wiki 知识

        分析失败轨迹提取失败模式，分析成功轨迹提取成功策略。
        编译后的知识永久保存在 Wiki 层（永不回滚）。

        Args:
            skill_id: 可选，只编译指定 Skill 的轨迹

        Returns:
            新发现的模式列表
        """
        self._current_phase = EvolutionPhase.COMPILING

        # 获取轨迹
        if skill_id:
            trajectories = self.raw_layer.get_by_skill(skill_id)
        else:
            trajectories = self.raw_layer.get_all()

        # 编译知识
        new_patterns = self.wiki_layer.compile_from_trajectories(trajectories)

        return new_patterns

    def should_evolve(self, skill_id: str) -> bool:
        """
        判断是否应该触发进化

        触发条件（满足任一）：
        1. 连续失败达到阈值
        2. 成功率低于阈值
        3. 手动触发
        """
        # 连续失败
        if self._consecutive_failures.get(skill_id, 0) >= self.failure_threshold:
            return True

        # 成功率
        trajectories = self.raw_layer.get_by_skill(skill_id)
        if len(trajectories) >= self.min_executions_before_evolve:
            success_rate = self.raw_layer.get_success_rate(skill_id)
            if success_rate < self.success_rate_threshold:
                return True

        return False

    def evolve_skill(self,
                     skill_id: str,
                     trigger: str = "auto",
                     force: bool = False) -> WikiSkillEvolutionResult:
        """
        【Evolver + Validator 角色】基于 Wiki 知识进化 Skill

        完整流程：
        1. 编译知识（从轨迹提取模式）
        2. 获取 Wiki 知识包（失败模式、成功策略、被拒绝的改动）
        3. 基于知识生成新 Skill
        4. 验证新 Skill
        5. 接受或回滚（Skill 层可以回滚，Wiki 层永不回滚）

        Args:
            skill_id: 要进化的 Skill ID
            trigger: 触发原因
            force: 是否强制进化（忽略触发条件）

        Returns:
            进化结果
        """
        start_time = time.time()
        self._current_phase = EvolutionPhase.EVOLVING

        # 检查触发条件
        if not force and not self.should_evolve(skill_id):
            return WikiSkillEvolutionResult(
                success=False,
                phase=EvolutionPhase.IDLE,
                skill_id=skill_id,
                validation_result="skipped",
                rejection_reason="未达到进化触发条件",
                notes="连续失败未达阈值或成功率未低于阈值",
            )

        # 获取进化前的成功率
        success_rate_before = self.raw_layer.get_success_rate(skill_id)

        # 1. 编译知识
        patterns = self.compile_knowledge(skill_id)

        # 2. 获取 Wiki 知识包
        wiki_knowledge = self.wiki_layer.get_knowledge_for_skill_evolution(skill_id)

        # 3. 检查被拒绝的改动（避免重复尝试）
        rejected_changes = wiki_knowledge["rejected_changes"]
        avoid_repeating = len(rejected_changes) > 0

        # 4. 生成新 Skill（基于 Wiki 知识）
        # 这里使用简化的模拟实现，实际应调用 LLM 生成
        old_skill = self.skill_library.get(skill_id)
        old_version = old_skill.version if old_skill else "unknown"
        new_version = f"{old_version}-wiki-evolved"

        # 5. 验证新 Skill（简化模拟）
        self._current_phase = EvolutionPhase.VALIDATING

        # 模拟验证：基于 Wiki 知识的进化应该比没有知识的好
        # 实际应执行验证任务集
        validation_passed = self.use_wiki_knowledge and len(patterns) > 0

        # 6. 记录 Skill 影响（即使被拒绝也保留在 Wiki 中）
        impact = self.wiki_layer.record_skill_impact(
            skill_id=skill_id,
            change_type="modify",
            old_version=old_version,
            new_version=new_version,
            description=f"基于 Wiki 知识进化（发现 {len(patterns)} 个新模式）",
            trigger=trigger,
            validation_result="accepted" if validation_passed else "rejected",
            validation_metrics={
                "success_rate_before": success_rate_before,
                "patterns_discovered": len(patterns),
                "rejected_changes_avoided": len(rejected_changes),
            },
            rejection_reason="" if validation_passed else "验证未通过，回滚到上一版本",
            source_patterns=[p.pattern_id for p in patterns],
        )

        # 7. 记录进化日志
        self.wiki_layer.add_log(
            event_type="modification" if validation_passed else "rollback",
            description=f"Skill '{skill_id}' 进化{'成功' if validation_passed else '失败回滚'}，"
                       f"发现 {len(patterns)} 个新模式，"
                       f"避免 {len(rejected_changes)} 个重复失败改动",
            affected_skills=[skill_id],
            patterns_discovered=[p.pattern_id for p in patterns],
            skill_changes=[{"skill_id": skill_id, "old_version": old_version,
                           "new_version": new_version, "result": "accepted" if validation_passed else "rejected"}],
            metrics_before={"success_rate": success_rate_before},
            metrics_after={"success_rate": success_rate_before},  # 实际应更新
            notes=f"Wiki 永不回滚: {self.wiki_never_rollback}, "
                  f"使用 Wiki 知识: {self.use_wiki_knowledge}",
        )

        # 8. 构造结果
        duration_ms = int((time.time() - start_time) * 1000)
        result = WikiSkillEvolutionResult(
            success=validation_passed,
            phase=EvolutionPhase.COMPLETED,
            skill_id=skill_id,
            old_version=old_version,
            new_version=new_version,
            validation_result="accepted" if validation_passed else "rejected",
            rejection_reason="" if validation_passed else "验证未通过，回滚到上一版本",
            patterns_discovered=len(patterns),
            trajectories_analyzed=len(self.raw_layer.get_by_skill(skill_id)),
            success_rate_before=success_rate_before,
            success_rate_after=success_rate_before,  # 实际应更新
            duration_ms=duration_ms,
            wiki_knowledge_used=self.use_wiki_knowledge,
            notes=f"避免重复 {len(rejected_changes)} 个失败改动" if avoid_repeating else "",
        )

        self._evolution_history.append(result)
        self._current_phase = EvolutionPhase.IDLE

        # 重置连续失败计数
        self._consecutive_failures[skill_id] = 0

        return result

    def get_wiki_knowledge(self, skill_id: str) -> Dict[str, Any]:
        """获取指定 Skill 的 Wiki 知识包"""
        return self.wiki_layer.get_knowledge_for_skill_evolution(skill_id)

    def get_evolution_history(self, skill_id: Optional[str] = None) -> List[WikiSkillEvolutionResult]:
        """获取进化历史"""
        if skill_id:
            return [r for r in self._evolution_history if r.skill_id == skill_id]
        return list(self._evolution_history)

    def get_stats(self) -> Dict[str, Any]:
        """获取完整统计信息（三层架构）"""
        raw_stats = self.raw_layer.get_stats()
        wiki_stats = self.wiki_layer.get_stats()

        return {
            "raw_layer": raw_stats,
            "wiki_layer": wiki_stats,
            "skill_layer": {
                "total_skills": len(self.skill_library.list()),
                "evolution_history": len(self._evolution_history),
                "current_phase": self._current_phase.value,
            },
            "wiki_never_rollback": self.wiki_never_rollback,
            "use_wiki_knowledge": self.use_wiki_knowledge,
        }

    def start_new_iteration(self):
        """开始新一轮迭代"""
        self.wiki_layer.start_iteration()

    def export_wiki_markdown(self) -> str:
        """导出 Wiki 知识库为 Markdown"""
        return self.wiki_layer.export_markdown()
