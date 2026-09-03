"""
evolution.wiki_layer — WikiSkill 维基知识层（Wiki Layer）

WikiSkill 三层架构的中间层（核心层）：
- 将原始轨迹（Raw Layer）编译成结构化知识
- 包含 patterns/、logs.md、skill-impact.md
- 关键设计：Wiki 永不回滚（Skill 被拒绝时 Wiki 保留所有知识）

参考论文：WikiSkill: Compiling Agent Experience into Persistent Knowledge for Skill Evolution
- Google Research, 2026
- 三层架构：Raw Layer → Wiki Layer → Skill Layer
- Wiki 层关键设计：永不回滚、跨迭代持续积累、结构化知识

核心组件：
1. WikiPattern（知识模式）：记录失败原因或成功策略，带可操作修复方案
2. WikiLog（进化日志）：按迭代记录发现了什么、改了什么
3. SkillImpact（技能影响）：哪些 Skill 改动被接受、哪些被拒绝，带完整 diff
4. WikiLayer（维基层）：管理所有知识，永不回滚

设计原则：
1. 永不回滚（never rollback）：Skill 可以回滚，但 Wiki 永远保留
2. 持续积累：每次迭代都在已有知识上构建
3. 结构化：patterns 带可操作修复方案，不是简单记录
4. 可追溯：每条知识都有源轨迹引用
"""
from __future__ import annotations
import json
import time
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field, asdict
from enum import Enum


class PatternType(Enum):
    """知识模式类型"""
    FAILURE_PATTERN = "failure_pattern"      # 失败模式
    SUCCESS_PATTERN = "success_pattern"      # 成功策略
    BEST_PRACTICE = "best_practice"          # 最佳实践
    ANTI_PATTERN = "anti_pattern"            # 反模式
    LESSON_LEARNED = "lesson_learned"        # 经验教训


class PatternSeverity(Enum):
    """模式严重程度"""
    CRITICAL = "critical"    # 严重（必须修复）
    HIGH = "high"            # 高（建议修复）
    MEDIUM = "medium"        # 中（可选修复）
    LOW = "low"              # 低（记录即可）


@dataclass
class WikiPattern:
    """
    知识模式（Wiki Pattern）

    记录具体的失败原因或成功策略，带可操作的修复方案。
    每个模式对应一个 markdown 文件（patterns/ 目录）。

    参考论文设计：
    - 每个模式一个 markdown 文件
    - 记录具体的失败原因或成功策略
    - 带可操作的修复方案
    - 有源轨迹引用（可追溯）
    """
    pattern_id: str = field(default_factory=lambda: f"pat_{int(time.time()*1000)}_{__import__('random').randint(1000,9999)}")
    pattern_type: PatternType = PatternType.FAILURE_PATTERN
    severity: PatternSeverity = PatternSeverity.MEDIUM
    title: str = ""                          # 模式标题
    description: str = ""                    # 详细描述
    root_cause: str = ""                     # 根因分析
    fix_strategy: str = ""                   # 修复策略（可操作）
    fix_example: str = ""                    # 修复示例（代码/配置）
    affected_skills: List[str] = field(default_factory=list)  # 受影响的 Skill
    source_trajectories: List[str] = field(default_factory=list)  # 源轨迹 ID（可追溯）
    occurrence_count: int = 1                # 发生次数
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    status: str = "active"                   # active / resolved / deprecated
    resolution: str = ""                     # 解决方案（如果已解决）
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # 类变量：标签映射（避免每次调用都重新创建字典）
    _STATUS_EMOJI = {"active": "🔴", "resolved": "🟢", "deprecated": "⚪"}
    _TYPE_LABELS = {
        "failure_pattern": "失败模式",
        "success_pattern": "成功策略",
        "best_practice": "最佳实践",
        "anti_pattern": "反模式",
        "lesson_learned": "经验教训",
    }
    _SEVERITY_LABELS = {
        "critical": "🔴 严重",
        "high": "🟠 高",
        "medium": "🟡 中",
        "low": "🟢 低",
    }

    def to_dict(self) -> dict:
        d = asdict(self)
        d["pattern_type"] = self.pattern_type.value
        d["severity"] = self.severity.value
        return d

    def to_markdown(self) -> str:
        """转换为 Markdown 格式（优化版：标签映射提取为类变量）"""
        status_emoji = self._STATUS_EMOJI.get(self.status, "⚪")
        type_label = self._TYPE_LABELS.get(self.pattern_type.value, self.pattern_type.value)
        severity_label = self._SEVERITY_LABELS.get(self.severity.value, self.severity.value)

        md = f"""# {self.title}

**模式ID**: {self.pattern_id}
**类型**: {type_label}
**严重程度**: {severity_label}
**状态**: {status_emoji} {self.status}
**发生次数**: {self.occurrence_count}
**首次发现**: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.first_seen))}
**最后发生**: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.last_seen))}

## 描述

{self.description}

## 根因分析

{self.root_cause}

## 修复策略

{self.fix_strategy}

## 修复示例

```
{self.fix_example}
```

## 受影响的 Skill

{', '.join(self.affected_skills) if self.affected_skills else '无'}

## 源轨迹（可追溯）

{', '.join(self.source_trajectories) if self.source_trajectories else '无'}

## 标签

{', '.join(self.tags) if self.tags else '无'}
"""
        if self.status == "resolved":
            md += f"""
## 解决方案

{self.resolution}
"""
        return md


@dataclass
class WikiLogEntry:
    """
    进化日志条目（Wiki Log Entry）

    按迭代记录发现了什么、改了什么。
    对应 logs.md 文件。
    """
    log_id: str = field(default_factory=lambda: f"log_{int(time.time()*1000)}_{__import__('random').randint(1000,9999)}")
    iteration: int = 0                     # 迭代轮次
    timestamp: float = field(default_factory=time.time)
    event_type: str = ""                    # discovery / modification / validation / rollback
    description: str = ""                   # 详细描述
    affected_skills: List[str] = field(default_factory=list)
    patterns_discovered: List[str] = field(default_factory=list)  # 发现的新模式
    skill_changes: List[Dict[str, Any]] = field(default_factory=list)  # Skill 改动
    metrics_before: Dict[str, Any] = field(default_factory=dict)
    metrics_after: Dict[str, Any] = field(default_factory=dict)
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SkillImpactRecord:
    """
    Skill 影响记录（Skill Impact Record）

    记录哪些 Skill 改动被接受、哪些被拒绝，带完整 diff。
    对应 skill-impact.md 文件。

    关键设计：即使 Skill 改动被拒绝（回滚），这条记录仍然保留在 Wiki 中，
    下次进化时可以参考，避免重复尝试失败的改动。
    """
    impact_id: str = field(default_factory=lambda: f"imp_{int(time.time()*1000)}_{__import__('random').randint(1000,9999)}")
    skill_id: str = ""
    skill_name: str = ""
    old_version: str = ""
    new_version: str = ""
    change_type: str = ""                    # modify / create / deprecate
    diff: str = ""                           # 完整 diff
    description: str = ""                    # 改动描述
    trigger: str = ""                        # 触发原因
    validation_result: str = ""              # accepted / rejected / pending
    validation_metrics: Dict[str, Any] = field(default_factory=dict)  # 验证指标
    rejection_reason: str = ""               # 拒绝原因（如果被拒绝）
    source_patterns: List[str] = field(default_factory=list)  # 源模式引用
    timestamp: float = field(default_factory=time.time)
    iteration: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


class WikiLayer:
    """
    维基知识层（Wiki Layer）

    WikiSkill 三层架构的核心层，负责：
    1. 管理知识模式（patterns）：失败原因、成功策略、最佳实践
    2. 记录进化日志（logs）：按迭代记录发现和改动
    3. 跟踪 Skill 影响（skill-impact）：哪些改动被接受/拒绝
    4. 从原始轨迹编译知识（compile）
    5. 为 Skill 进化提供知识支撑

    关键设计（论文核心）：
    - **永不回滚**：Skill 可以回滚，但 Wiki 永远保留所有知识
    - 下次进化时，即使之前的 Skill 改动被拒绝，Wiki 中的知识仍然可用
    - 避免重复尝试失败的改动
    - 跨迭代持续积累

    使用示例：
        wiki = WikiLayer()

        # 从原始轨迹编译知识
        wiki.compile_from_trajectories(raw_trajectories)

        # 添加知识模式
        pattern = wiki.add_pattern(
            title="Python 缩进错误",
            pattern_type=PatternType.FAILURE_PATTERN,
            root_cause="生成的代码使用了空格和制表符混合缩进",
            fix_strategy="统一使用4空格缩进",
            affected_skills=["code_gen"],
        )

        # 记录 Skill 改动影响（即使被拒绝也保留）
        wiki.record_skill_impact(
            skill_id="code_gen",
            change_type="modify",
            validation_result="rejected",
            rejection_reason="成功率从 75% 降到 60%",
        )

        # 查询知识
        patterns = wiki.get_patterns_for_skill("code_gen")
        history = wiki.get_skill_impact_history("code_gen")
    """

    def __init__(self, persist_dir: Optional[str] = None):
        """
        初始化维基知识层

        Args:
            persist_dir: 持久化目录（可选，对应 wiki/ 目录结构）
        """
        self._patterns: Dict[str, WikiPattern] = {}
        self._logs: List[WikiLogEntry] = []
        self._skill_impacts: List[SkillImpactRecord] = []
        self._persist_dir = persist_dir
        self._iteration = 0
        self._total_compilations = 0

    def _find_existing_pattern(self, title: str) -> Optional[WikiPattern]:
        """查找已存在相同标题的模式"""
        for p in self._patterns.values():
            if p.title == title:
                return p
        return None

    def _update_existing_pattern(self,
                                   existing: WikiPattern,
                                   affected_skills: Optional[List[str]],
                                   source_trajectories: Optional[List[str]]) -> WikiPattern:
        """更新已存在的模式（增加发生次数和关联）"""
        existing.occurrence_count += 1
        existing.last_seen = time.time()
        if affected_skills:
            for s in affected_skills:
                if s not in existing.affected_skills:
                    existing.affected_skills.append(s)
        if source_trajectories:
            for t in source_trajectories:
                if t not in existing.source_trajectories:
                    existing.source_trajectories.append(t)
        return existing

    def _create_new_pattern(self,
                              title: str,
                              pattern_type: PatternType,
                              severity: PatternSeverity,
                              description: str,
                              root_cause: str,
                              fix_strategy: str,
                              fix_example: str,
                              affected_skills: Optional[List[str]],
                              source_trajectories: Optional[List[str]],
                              tags: Optional[List[str]],
                              metadata: Optional[Dict[str, Any]]) -> WikiPattern:
        """创建新知识模式"""
        pattern = WikiPattern(
            pattern_type=pattern_type,
            severity=severity,
            title=title,
            description=description,
            root_cause=root_cause,
            fix_strategy=fix_strategy,
            fix_example=fix_example,
            affected_skills=affected_skills or [],
            source_trajectories=source_trajectories or [],
            tags=tags or [],
            metadata=metadata or {},
        )
        self._patterns[pattern.pattern_id] = pattern
        return pattern

    def add_pattern(self,
                    title: str,
                    pattern_type: PatternType = PatternType.FAILURE_PATTERN,
                    severity: PatternSeverity = PatternSeverity.MEDIUM,
                    description: str = "",
                    root_cause: str = "",
                    fix_strategy: str = "",
                    fix_example: str = "",
                    affected_skills: Optional[List[str]] = None,
                    source_trajectories: Optional[List[str]] = None,
                    tags: Optional[List[str]] = None,
                    metadata: Optional[Dict[str, Any]] = None) -> WikiPattern:
        """
        添加知识模式（优化版：拆分为3个子函数）

        如果已存在相同标题的模式，则更新发生次数和最后发生时间。
        """
        # 1. 检查是否已存在相同标题的模式
        existing = self._find_existing_pattern(title)
        if existing:
            return self._update_existing_pattern(existing, affected_skills, source_trajectories)

        # 2. 创建新模式
        return self._create_new_pattern(
            title, pattern_type, severity, description, root_cause,
            fix_strategy, fix_example, affected_skills, source_trajectories, tags, metadata
        )

    def get_pattern(self, pattern_id: str) -> Optional[WikiPattern]:
        """按 ID 获取模式"""
        return self._patterns.get(pattern_id)

    def get_all_patterns(self) -> List[WikiPattern]:
        """获取所有模式"""
        return list(self._patterns.values())

    def get_patterns_for_skill(self, skill_id: str) -> List[WikiPattern]:
        """获取影响指定 Skill 的模式"""
        return [p for p in self._patterns.values() if skill_id in p.affected_skills]

    def get_failure_patterns(self) -> List[WikiPattern]:
        """获取所有失败模式"""
        return [p for p in self._patterns.values()
                if p.pattern_type in [PatternType.FAILURE_PATTERN, PatternType.ANTI_PATTERN]]

    def get_success_patterns(self) -> List[WikiPattern]:
        """获取所有成功策略"""
        return [p for p in self._patterns.values()
                if p.pattern_type in [PatternType.SUCCESS_PATTERN, PatternType.BEST_PRACTICE]]

    def resolve_pattern(self, pattern_id: str, resolution: str) -> bool:
        """标记模式为已解决"""
        pattern = self._patterns.get(pattern_id)
        if pattern:
            pattern.status = "resolved"
            pattern.resolution = resolution
            return True
        return False

    def record_skill_impact(self,
                             skill_id: str,
                             change_type: str,
                             old_version: str = "",
                             new_version: str = "",
                             diff: str = "",
                             description: str = "",
                             trigger: str = "",
                             validation_result: str = "pending",
                             validation_metrics: Optional[Dict[str, Any]] = None,
                             rejection_reason: str = "",
                             source_patterns: Optional[List[str]] = None,
                             skill_name: str = "") -> SkillImpactRecord:
        """
        记录 Skill 改动影响

        关键设计：即使 validation_result = "rejected"，这条记录仍然保留。
        下次进化时可以参考，避免重复尝试失败的改动。
        """
        record = SkillImpactRecord(
            skill_id=skill_id,
            skill_name=skill_name,
            old_version=old_version,
            new_version=new_version,
            change_type=change_type,
            diff=diff,
            description=description,
            trigger=trigger,
            validation_result=validation_result,
            validation_metrics=validation_metrics or {},
            rejection_reason=rejection_reason,
            source_patterns=source_patterns or [],
            iteration=self._iteration,
        )
        self._skill_impacts.append(record)
        return record

    def get_skill_impact_history(self, skill_id: str) -> List[SkillImpactRecord]:
        """获取 Skill 的改动历史（包括被拒绝的）"""
        return [r for r in self._skill_impacts if r.skill_id == skill_id]

    def get_rejected_changes(self, skill_id: Optional[str] = None) -> List[SkillImpactRecord]:
        """获取被拒绝的改动（用于避免重复尝试）"""
        rejected = [r for r in self._skill_impacts if r.validation_result == "rejected"]
        if skill_id:
            rejected = [r for r in rejected if r.skill_id == skill_id]
        return rejected

    def add_log(self,
                event_type: str,
                description: str,
                affected_skills: Optional[List[str]] = None,
                patterns_discovered: Optional[List[str]] = None,
                skill_changes: Optional[List[Dict[str, Any]]] = None,
                metrics_before: Optional[Dict[str, Any]] = None,
                metrics_after: Optional[Dict[str, Any]] = None,
                notes: str = "") -> WikiLogEntry:
        """添加进化日志条目"""
        entry = WikiLogEntry(
            iteration=self._iteration,
            event_type=event_type,
            description=description,
            affected_skills=affected_skills or [],
            patterns_discovered=patterns_discovered or [],
            skill_changes=skill_changes or [],
            metrics_before=metrics_before or {},
            metrics_after=metrics_after or {},
            notes=notes,
        )
        self._logs.append(entry)
        return entry

    def get_logs(self, iteration: Optional[int] = None) -> List[WikiLogEntry]:
        """获取进化日志"""
        if iteration is not None:
            return [l for l in self._logs if l.iteration == iteration]
        return list(self._logs)

    def start_iteration(self):
        """开始新一轮迭代"""
        self._iteration += 1

    def _compile_failure_patterns(self, failures: List[Any]) -> List[WikiPattern]:
        """分析失败轨迹，提取失败模式"""
        new_patterns = []
        for failure in failures:
            if failure.error_type:
                title = f"{failure.error_type} 错误（{failure.skill_id}）"
                pattern = self.add_pattern(
                    title=title,
                    pattern_type=PatternType.FAILURE_PATTERN,
                    severity=PatternSeverity.HIGH if failure.error_type in ["timeout", "exception"] else PatternSeverity.MEDIUM,
                    description=f"Skill '{failure.skill_id}' 执行失败，错误类型: {failure.error_type}",
                    root_cause=failure.error or "未知错误",
                    fix_strategy=f"针对 {failure.error_type} 错误进行修复",
                    affected_skills=[failure.skill_id],
                    source_trajectories=[failure.trajectory_id],
                    tags=[failure.error_type, failure.skill_id],
                )
                if pattern.occurrence_count == 1:
                    new_patterns.append(pattern)
        return new_patterns

    def _compile_success_patterns(self, successes: List[Any]) -> List[WikiPattern]:
        """分析成功轨迹，提取成功策略"""
        new_patterns = []
        if not successes:
            return new_patterns

        # 统计高成功率的 Skill
        skill_success: Dict[str, int] = {}
        for s in successes:
            skill_success[s.skill_id] = skill_success.get(s.skill_id, 0) + 1

        for skill_id, count in skill_success.items():
            if count >= 3:  # 至少成功3次才记录为成功策略
                title = f"{skill_id} 成功策略（{count}次成功）"
                pattern = self.add_pattern(
                    title=title,
                    pattern_type=PatternType.SUCCESS_PATTERN,
                    severity=PatternSeverity.LOW,
                    description=f"Skill '{skill_id}' 已成功执行 {count} 次",
                    root_cause="该 Skill 的当前实现有效",
                    fix_strategy="保持当前实现，可作为其他 Skill 的参考",
                    affected_skills=[skill_id],
                    source_trajectories=[s.trajectory_id for s in successes if s.skill_id == skill_id][:5],
                    tags=["success", skill_id],
                )
                if pattern.occurrence_count == 1:
                    new_patterns.append(pattern)
        return new_patterns

    def compile_from_trajectories(self, trajectories: List[Any]) -> List[WikiPattern]:
        """
        从原始轨迹编译知识（优化版：拆分成子函数）

        分析失败轨迹，提取失败模式；分析成功轨迹，提取成功策略。

        Args:
            trajectories: RawTrajectory 列表

        Returns:
            新发现的模式列表
        """
        self._total_compilations += 1

        # 分析失败轨迹
        failures = [t for t in trajectories if not t.success]
        failure_patterns = self._compile_failure_patterns(failures)

        # 分析成功轨迹
        successes = [t for t in trajectories if t.success]
        success_patterns = self._compile_success_patterns(successes)

        new_patterns = failure_patterns + success_patterns

        # 记录编译日志
        if new_patterns:
            self.add_log(
                event_type="discovery",
                description=f"从 {len(trajectories)} 条轨迹中编译发现 {len(new_patterns)} 个新模式",
                patterns_discovered=[p.pattern_id for p in new_patterns],
            )

        return new_patterns

    def get_knowledge_for_skill_evolution(self, skill_id: str) -> Dict[str, Any]:
        """
        获取用于 Skill 进化的知识包

        整合该 Skill 相关的所有知识：
        - 失败模式（需要修复的）
        - 成功策略（可以参考的）
        - 被拒绝的改动（避免重复尝试）
        - 历史改动记录

        这是 Wiki 层为 Skill 层提供的核心接口。
        """
        return {
            "skill_id": skill_id,
            "failure_patterns": [p.to_dict() for p in self.get_patterns_for_skill(skill_id)
                                  if p.pattern_type in [PatternType.FAILURE_PATTERN, PatternType.ANTI_PATTERN]],
            "success_patterns": [p.to_dict() for p in self.get_patterns_for_skill(skill_id)
                                 if p.pattern_type in [PatternType.SUCCESS_PATTERN, PatternType.BEST_PRACTICE]],
            "rejected_changes": [r.to_dict() for r in self.get_rejected_changes(skill_id)],
            "impact_history": [r.to_dict() for r in self.get_skill_impact_history(skill_id)],
            "all_patterns": [p.to_dict() for p in self.get_patterns_for_skill(skill_id)],
        }

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        failure_count = len(self.get_failure_patterns())
        success_count = len(self.get_success_patterns())
        accepted_count = sum(1 for r in self._skill_impacts if r.validation_result == "accepted")
        rejected_count = sum(1 for r in self._skill_impacts if r.validation_result == "rejected")
        pending_count = sum(1 for r in self._skill_impacts if r.validation_result == "pending")

        return {
            "total_patterns": len(self._patterns),
            "failure_patterns": failure_count,
            "success_patterns": success_count,
            "total_logs": len(self._logs),
            "total_skill_impacts": len(self._skill_impacts),
            "accepted_changes": accepted_count,
            "rejected_changes": rejected_count,
            "pending_changes": pending_count,
            "current_iteration": self._iteration,
            "total_compilations": self._total_compilations,
            "wiki_never_rollback": True,  # 核心设计声明
        }

    def export_markdown(self) -> str:
        """导出为 Markdown 格式（对应 wiki/ 目录的完整内容）"""
        md = "# Wiki 知识库\n\n"
        md += "> WikiSkill 持久知识库 — 永不回滚，跨迭代持续积累\n\n"

        # 统计
        stats = self.get_stats()
        md += "## 统计概览\n\n"
        md += f"- 知识模式总数: {stats['total_patterns']}\n"
        md += f"- 失败模式: {stats['failure_patterns']}\n"
        md += f"- 成功策略: {stats['success_patterns']}\n"
        md += f"- 进化日志: {stats['total_logs']}\n"
        md += f"- Skill 改动记录: {stats['total_skill_impacts']} (接受: {stats['accepted_changes']}, 拒绝: {stats['rejected_changes']}, 待验证: {stats['pending_changes']})\n"
        md += f"- 当前迭代: {stats['current_iteration']}\n\n"

        # 模式列表
        md += "## 知识模式 (patterns/)\n\n"
        for pattern in self._patterns.values():
            status_emoji = {"active": "🔴", "resolved": "🟢", "deprecated": "⚪"}.get(pattern.status, "⚪")
            md += f"### {status_emoji} {pattern.title}\n\n"
            md += f"- **类型**: {pattern.pattern_type.value}\n"
            md += f"- **严重程度**: {pattern.severity.value}\n"
            md += f"- **发生次数**: {pattern.occurrence_count}\n"
            md += f"- **受影响 Skill**: {', '.join(pattern.affected_skills)}\n\n"
            md += f"**根因**: {pattern.root_cause}\n\n"
            md += f"**修复策略**: {pattern.fix_strategy}\n\n"

        # 进化日志
        md += "## 进化日志 (logs.md)\n\n"
        for log in reversed(self._logs[-20:]):  # 最近20条
            time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(log.timestamp))
            md += f"### [{time_str}] 迭代 {log.iteration} - {log.event_type}\n\n"
            md += f"{log.description}\n\n"
            if log.notes:
                md += f"> {log.notes}\n\n"

        # Skill 影响
        md += "## Skill 改动影响 (skill-impact.md)\n\n"
        md += "> 包括被接受和被拒绝的改动，永不删除，避免重复尝试失败的改动\n\n"
        for impact in reversed(self._skill_impacts[-20:]):
            result_emoji = {"accepted": "✅", "rejected": "❌", "pending": "⏳"}.get(impact.validation_result, "❓")
            time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(impact.timestamp))
            md += f"### {result_emoji} {impact.skill_id} {impact.change_type} ({time_str})\n\n"
            md += f"- **版本**: {impact.old_version} → {impact.new_version}\n"
            md += f"- **验证结果**: {impact.validation_result}\n"
            if impact.rejection_reason:
                md += f"- **拒绝原因**: {impact.rejection_reason}\n"
            md += f"- **描述**: {impact.description}\n\n"

        return md
