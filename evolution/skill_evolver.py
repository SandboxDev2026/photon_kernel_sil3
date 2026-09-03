"""
evolution.skill_evolver — 轻量级 Skill 自演进闭环

完整闭环：任务执行 → 识别失败/异常 → 自动反思 → 修改旧Skill / 生成新Skill
→ 存入技能库 → 下次调用。

比 AgentEvolver 更轻量化，专注于 Skill 层面的自演进，
不涉及完整的 Agent 执行轨迹管理。

设计参考：
- 触发式进化（不是每轮都进化，节省算力）
- 失败驱动变异（参考 CodeEvolve 失败用例驱动）
- 最小改动原则（参考 Darwin-Agent GEPA）
- 安全门控（变更过大直接拒绝）
"""
from __future__ import annotations
import json
import time
from typing import List, Optional, Dict, Any, Callable
from dataclasses import dataclass, field, asdict
from .skill_library import Skill, SkillLibrary
from .llm_adapter import BaseLLMAdapter, MockLLMAdapter
from .prompts import ReflectionPrompts


@dataclass
class SkillExecutionRecord:
    """Skill 执行记录"""
    skill_id: str
    skill_name: str
    task: str
    success: bool
    output: str = ""
    error: str = ""
    duration_ms: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SkillEvolutionEvent:
    """Skill 进化事件"""
    event_id: str = field(default_factory=lambda: f"evt_{int(time.time()*1000)}")
    trigger: str = ""              # 触发原因：failure_threshold / low_success / manual
    skill_id: str = ""             # 被进化的 Skill ID
    action: str = ""               # modify / create / deprecate
    reflection: str = ""           # 反思结果
    old_version: str = ""
    new_version: str = ""
    success_before: float = 0.0
    timestamp: float = field(default_factory=time.time)


class SkillEvolver:
    """
    轻量级 Skill 自演进闭环管理器

    闭环流程：
    1. 任务执行（调用 Skill）
    2. 识别失败/异常（连续失败阈值 / 成功率低于阈值）
    3. 自动反思（LLM 分析失败原因）
    4. 修改旧 Skill / 生成新 Skill（最小改动原则）
    5. 存入技能库（版本管理）
    6. 下次调用自动使用新版本

    触发策略（参考 Darwin-Agent Closed-Learning-Loop）：
    - 连续失败 N 次触发（默认 3 次）
    - 成功率低于阈值触发（默认 60%）
    - 手动触发
    - 不是每次执行都进化，节省算力
    """

    def __init__(self,
                 skill_library: SkillLibrary,
                 llm: Optional[BaseLLMAdapter] = None,
                 failure_threshold: int = 3,
                 success_rate_threshold: float = 0.6,
                 min_executions_before_evolve: int = 5,
                 evolution_cooldown_seconds: int = 300,
                 security_gate: Optional[Callable[[str], bool]] = None):
        self.library = skill_library
        self.llm = llm or MockLLMAdapter()
        self.failure_threshold = failure_threshold
        self.success_rate_threshold = success_rate_threshold
        self.min_executions = min_executions_before_evolve
        self.evolution_cooldown_seconds = evolution_cooldown_seconds
        self.security_gate = security_gate or self._default_security_gate

        # 执行记录（按 skill_id 分组）
        self.execution_history: Dict[str, List[SkillExecutionRecord]] = {}
        # 连续失败计数
        self.consecutive_failures: Dict[str, int] = {}
        # 进化事件历史
        self.evolution_events: List[SkillEvolutionEvent] = []
        # 进化冷却时间（防止频繁进化同一个 Skill）
        self.last_evolution_time: Dict[str, float] = {}
        # 错误日志
        self._error_log: List[Dict[str, Any]] = []

    # ==================== 闭环步骤 1：任务执行 ====================

    def execute_skill(self, skill_id: str, task: str,
                      executor: Callable[[Skill, str], tuple]) -> SkillExecutionRecord:
        """
        执行 Skill 并记录结果

        Args:
            skill_id: Skill ID
            task: 任务描述
            executor: 执行函数 (skill, task) -> (success, output, error)

        Returns:
            SkillExecutionRecord: 执行记录
        """
        skill = self.library.get(skill_id)
        if not skill:
            record = SkillExecutionRecord(
                skill_id=skill_id, skill_name="unknown",
                task=task, success=False, error=f"Skill {skill_id} not found"
            )
            self._record_execution(record)
            return record

        start = time.time()
        try:
            success, output, error = executor(skill, task)
        except Exception as e:
            success, output, error = False, "", str(e)

        record = SkillExecutionRecord(
            skill_id=skill_id,
            skill_name=skill.name,
            task=task,
            success=success,
            output=output,
            error=error,
            duration_ms=int((time.time() - start) * 1000),
        )
        self._record_execution(record)
        return record

    def _record_execution(self, record: SkillExecutionRecord) -> None:
        """记录执行结果"""
        sid = record.skill_id
        if sid not in self.execution_history:
            self.execution_history[sid] = []
        self.execution_history[sid].append(record)

        # 更新连续失败计数
        if record.success:
            self.consecutive_failures[sid] = 0
        else:
            self.consecutive_failures[sid] = self.consecutive_failures.get(sid, 0) + 1

    # ==================== 闭环步骤 2：识别失败/异常 ====================

    def should_evolve(self, skill_id: str) -> tuple[bool, str]:
        """
        判断是否应该触发进化

        Returns:
            (should_evolve, reason): 是否进化 + 原因
        """
        # 冷却时间检查
        last_time = self.last_evolution_time.get(skill_id, 0)
        if time.time() - last_time < self.evolution_cooldown_seconds:
            return False, "cooldown"

        history = self.execution_history.get(skill_id, [])
        if len(history) < self.min_executions:
            return False, f"insufficient_executions ({len(history)}/{self.min_executions})"

        # 触发条件 1：连续失败达到阈值
        consecutive = self.consecutive_failures.get(skill_id, 0)
        if consecutive >= self.failure_threshold:
            return True, f"consecutive_failures={consecutive}"

        # 触发条件 2：近期成功率低于阈值
        recent = history[-10:]
        success_rate = sum(1 for r in recent if r.success) / len(recent)
        if success_rate < self.success_rate_threshold:
            return True, f"low_success_rate={success_rate:.2f}"

        return False, "healthy"

    # ==================== 闭环步骤 3：自动反思 ====================

    def reflect(self, skill_id: str) -> str:
        """
        自动反思：分析失败原因

        参考 Darwin-Agent GEPA：最小改动原则，只修复失效点。
        """
        skill = self.library.get(skill_id)
        if not skill:
            return f"Skill {skill_id} not found"

        history = self.execution_history.get(skill_id, [])
        failures = [r for r in history[-10:] if not r.success]

        if not failures:
            return "No failures to reflect on"

        # 构造失败案例摘要
        fail_cases = [f"Task: {r.task[:80]}\nError: {r.error[:100]}" for r in failures[:5]]
        trajectory = "\n---\n".join(fail_cases)

        # 使用 LLM 反思
        prompt = ReflectionPrompts.geppa(trajectory, [r.error for r in failures[:3]])
        try:
            reflection = self.llm.generate(prompt, temperature=0.3)
            return reflection
        except Exception as e:
            return f"Reflection failed: {e}. Failures: {len(failures)}"

    # ==================== 闭环步骤 4：修改/生成 Skill ====================

    def _create_evolution_event(self, skill_id: str, reason: str) -> Optional[SkillEvolutionEvent]:
        """创建进化事件（检查触发条件和Skill是否存在）"""
        skill = self.library.get(skill_id)
        if not skill:
            return None

        return SkillEvolutionEvent(
            trigger=reason,
            skill_id=skill_id,
            old_version=skill.version,
            success_before=skill.success_rate,
        )

    def _apply_skill_evolution(self, skill: Any, improved_code: str, event: SkillEvolutionEvent) -> bool:
        """应用技能进化（修改现有Skill或创建新Skill）"""
        # 步骤 5：存入技能库（版本管理）
        new_skill = self.library.evolve_skill(skill.id, improved_code, mutation_type="auto_evolve")
        if new_skill:
            event.action = "modify"
            event.new_version = new_skill.version
        else:
            event.action = "create_new"
            # 创建新 Skill
            new_skill = Skill(
                name=f"{skill.name}_v2",
                description=f"Auto-evolved from {skill.name}",
                code=improved_code,
                tags=skill.tags + ["auto-evolved"],
            )
            self.library.add(new_skill)
            event.new_version = new_skill.version

        # 记录进化时间（冷却）
        self.last_evolution_time[skill.id] = time.time()
        # 重置失败计数
        self.consecutive_failures[skill.id] = 0

        return True

    def evolve_skill(self, skill_id: str, trigger: str = "auto") -> Optional[SkillEvolutionEvent]:
        """
        执行 Skill 进化（完整闭环）（优化版：拆分为2个子函数）

        Returns:
            SkillEvolutionEvent: 进化事件（如果触发了进化）
        """
        should, reason = self.should_evolve(skill_id)
        if not should:
            return None

        # 1. 创建进化事件
        event = self._create_evolution_event(skill_id, reason)
        if not event:
            return None

        skill = self.library.get(skill_id)

        # 步骤 3：反思
        event.reflection = self.reflect(skill_id)

        # 步骤 4：生成改进后的 Skill 代码
        improved_code = self._generate_improved_skill(skill, event.reflection)

        # 安全门控
        if not self.security_gate(improved_code):
            event.action = "rejected_by_security_gate"
            self.evolution_events.append(event)
            return event

        # 步骤 5：应用技能进化（修改或创建）
        self._apply_skill_evolution(skill, improved_code, event)

        self.evolution_events.append(event)
        return event

    def _generate_improved_skill(self, skill: Skill, reflection: str) -> str:
        """生成改进后的 Skill 代码"""
        prompt = ReflectionPrompts.skill_improvement(skill.code, [reflection])
        try:
            improved = self.llm.generate(prompt, temperature=0.2)
            # 简单验证：代码非空且包含 def 或 class
            if improved and ("def " in improved or "class " in improved or "return" in improved):
                return improved
        except Exception as e:
            # LLM调用失败，记录错误并退化返回原代码
            if hasattr(self, '_error_log'):
                self._error_log.append({
                    "type": "llm_generation_failed",
                    "error": str(e),
                    "skill_id": skill.id,
                    "timestamp": time.time(),
                })
        # 退化：返回原代码
        return skill.code

    # ==================== 闭环步骤 6：下次调用自动使用新版本 ====================

    def get_best_skill(self, name: str) -> Optional[Skill]:
        """
        获取最佳版本的 Skill（下次调用自动使用最新版本）

        策略：
        1. 优先选择成功率最高的版本
        2. 如果成功率相同，选择最新版本
        """
        candidates = [s for s in self.library.skills.values() if s.name == name]
        if not candidates:
            # 模糊匹配
            candidates = [s for s in self.library.skills.values() if name in s.name]
        if not candidates:
            return None

        # 按成功率排序，相同则按版本号
        candidates.sort(key=lambda s: (s.success_rate, s.version), reverse=True)
        return candidates[0]

    # ==================== 批量进化 ====================

    def evolve_all_due(self) -> List[SkillEvolutionEvent]:
        """
        批量进化所有达到触发条件的 Skill

        Returns:
            进化事件列表
        """
        events = []
        for skill_id in list(self.execution_history.keys()):
            event = self.evolve_skill(skill_id)
            if event:
                events.append(event)
        return events

    # ==================== 安全门控 ====================

    @staticmethod
    def _default_security_gate(code: str) -> bool:
        """默认安全门控：检查危险模式"""
        dangerous = [
            "os.system", "subprocess.call", "subprocess.run",
            "eval(", "exec(", "__import__",
            "shutil.rmtree", "os.remove", "os.unlink",
            "socket.socket", "requests.post", "urllib.request",
            "open('/", "open(\"/",
        ]
        for pattern in dangerous:
            if pattern in code:
                return False
        # 代码长度变化过大拒绝
        if len(code) > 50000:
            return False
        return True

    # ==================== 统计与持久化 ====================

    def get_stats(self) -> Dict[str, Any]:
        """获取进化统计"""
        total_executions = sum(len(h) for h in self.execution_history.values())
        total_failures = sum(
            sum(1 for r in h if not r.success)
            for h in self.execution_history.values()
        )
        return {
            "tracked_skills": len(self.execution_history),
            "total_executions": total_executions,
            "total_failures": total_failures,
            "overall_success_rate": (total_executions - total_failures) / max(1, total_executions),
            "evolution_events": len(self.evolution_events),
            "skills_in_library": len(self.library),
        }

    def save_events(self, filepath: str) -> None:
        """保存进化事件历史"""
        data = {
            "events": [asdict(e) for e in self.evolution_events],
            "execution_summary": {
                sid: {
                    "total": len(h),
                    "failures": sum(1 for r in h if not r.success),
                    "consecutive_failures": self.consecutive_failures.get(sid, 0),
                }
                for sid, h in self.execution_history.items()
            },
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
