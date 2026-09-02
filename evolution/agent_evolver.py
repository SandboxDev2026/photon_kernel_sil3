"""
evolution.agent_evolver — 自进化 Agent 闭环

参考 AgentEvolver（阿里魔搭 Apache-2.0）的完整自进化闭环抽象分层：
- 执行层：Agent 跑任务，记录轨迹日志
- 反思层：读取轨迹、失败 case，输出改进点
- 生成层：改写 Prompt / Skill 工具函数
- 评测层：批量测试，打分，区分成功/失败
- 版本快照：每一轮产物做版本保存，支持回滚

参考 Darwin-Agent / Hermes-Agent Closed-Loop：
- Closed-Learning-Loop 闭环范式：触发-review-写回-注入
- 触发：任务多次失败触发进化，不是每轮都进化，节省算力
- GEPA 反思提示词：针对失败样本最小改动原则
"""
from __future__ import annotations
import json
import time
from typing import List, Optional, Dict, Any, Callable
from dataclasses import dataclass, field
from .individual import Individual
from .population import Population
from .evaluator import BaseEvaluator
from .mutator import BaseMutator, NLFeedbackMutator
from .crossover import BaseCrossover
from .skill_library import SkillLibrary, Skill
from .archive import Archive
from .llm_adapter import BaseLLMAdapter
from .prompts import ReflectionPrompts
from .sandbox_client import SandboxClient


@dataclass
class ExecutionTrace:
    """执行轨迹日志（参考 AgentEvolver 轨迹日志结构化存储模板）"""
    task_id: str = ""
    input: str = ""
    output: str = ""
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration_ms: int = 0
    success: bool = False
    skill_used: str = ""
    prompt_used: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "input": self.input,
            "output": self.output,
            "tool_calls": self.tool_calls,
            "errors": self.errors,
            "duration_ms": self.duration_ms,
            "success": self.success,
            "skill_used": self.skill_used,
            "timestamp": self.timestamp,
        }


@dataclass
class EvolutionRound:
    """进化轮次"""
    round_id: int = 0
    trigger: str = ""              # 触发原因
    traces: List[ExecutionTrace] = field(default_factory=list)
    reflection: str = ""           # 反思结果
    improvements: List[str] = field(default_factory=list)
    skills_evolved: List[str] = field(default_factory=list)
    fitness_before: float = 0.0
    fitness_after: float = 0.0
    timestamp: float = field(default_factory=time.time)


class AgentEvolver:
    """
    自进化 Agent 闭环

    五层架构（参考 AgentEvolver）：
    1. 执行层：Agent 跑任务，记录轨迹日志
    2. 反思层：读取轨迹、失败 case，输出改进点
    3. 生成层：改写 Prompt / Skill 工具函数
    4. 评测层：批量测试，打分，区分成功/失败
    5. 版本快照：每一轮产物做版本保存，支持回滚

    闭环范式（参考 Darwin-Agent Closed-Learning-Loop）：
    触发 → review → 写回 → 注入
    - 触发：任务多次失败触发进化，不是每轮都进化
    - review：LLM 复盘执行日志，定位根因
    - 写回：生成改进后的 Skill/Prompt
    - 注入：存入技能库，下次任务使用
    """
    def __init__(self,
                 sandbox: SandboxClient,
                 llm: Optional[BaseLLMAdapter] = None,
                 evaluator: Optional[BaseEvaluator] = None,
                 skill_library: Optional[SkillLibrary] = None,
                 archive: Optional[Archive] = None,
                 failure_threshold: int = 3,       # 连续失败 N 次触发进化
                 max_rounds: int = 10,
                 target_success_rate: float = 0.9):
        self.sandbox = sandbox
        self.llm = llm
        self.evaluator = evaluator
        self.skills = skill_library or SkillLibrary()
        self.archive = archive or Archive()
        self.failure_threshold = failure_threshold
        self.max_rounds = max_rounds
        self.target_success_rate = target_success_rate

        self.traces: List[ExecutionTrace] = []
        self.rounds: List[EvolutionRound] = []
        self.consecutive_failures = 0
        self.current_round = 0

    # ==================== 执行层 ====================
    def execute_task(self, task: str, skill_id: str = "",
                     code: str = "") -> ExecutionTrace:
        """
        执行任务（全部通过沙盒，禁止本地 exec）

        Args:
            task: 任务描述
            skill_id: 使用的技能 ID
            code: 要执行的代码（如果有）

        Returns:
            ExecutionTrace: 执行轨迹
        """
        trace = ExecutionTrace(
            task_id=f"task_{int(time.time())}",
            input=task,
            skill_used=skill_id,
        )
        start = time.time()

        try:
            # 如果有代码，通过沙盒执行
            if code:
                result = self.sandbox.execute(code, task_id=trace.task_id)
                trace.output = result.output
                trace.success = result.success
                if not result.success:
                    trace.errors.append(result.error)
                if result.security_alert:
                    trace.errors.append(f"Security alert: risk_score={result.risk_score}")
            else:
                # 无代码时，记录任务但不执行
                trace.success = True
                trace.output = "Task recorded (no code to execute)"

        except Exception as e:
            trace.success = False
            trace.errors.append(str(e))

        trace.duration_ms = int((time.time() - start) * 1000)
        self.traces.append(trace)

        # 更新连续失败计数
        if trace.success:
            self.consecutive_failures = 0
        else:
            self.consecutive_failures += 1

        return trace

    # ==================== 触发层 ====================
    def should_evolve(self) -> bool:
        """
        是否应该触发进化（参考 Darwin-Agent：任务多次失败触发，不是每轮都进化）

        触发条件：
        1. 连续失败次数达到阈值
        2. 成功率低于目标
        3. 达到最大轮次限制
        """
        if self.current_round >= self.max_rounds:
            return False

        # 连续失败触发
        if self.consecutive_failures >= self.failure_threshold:
            return True

        # 成功率低于目标触发
        if len(self.traces) >= 10:
            recent = self.traces[-10:]
            success_rate = sum(1 for t in recent if t.success) / len(recent)
            if success_rate < self.target_success_rate:
                return True

        return False

    # ==================== 反思层 ====================
    def reflect(self, traces: List[ExecutionTrace]) -> str:
        """
        反思：读取轨迹、失败 case，输出改进点

        参考 AgentEvolver 反思层 + Darwin-Agent GEPA 提示词。
        """
        fail_traces = [t for t in traces if not t.success]
        if not fail_traces:
            return "No failures to reflect on."

        if self.llm is None:
            # 无 LLM 时的简单反思
            errors = set()
            for t in fail_traces:
                errors.update(t.errors)
            return f"Failures detected: {'; '.join(list(errors)[:5])}"

        # 构造轨迹摘要
        trajectory_summary = "\n".join(
            f"Task: {t.input[:100]}\n"
            f"Errors: {', '.join(t.errors[:3])}\n"
            f"Output: {t.output[:200]}\n"
            for t in fail_traces[:5]
        )

        fail_cases = [f"{t.input[:50]}: {', '.join(t.errors[:2])}" for t in fail_traces[:5]]
        prompt = ReflectionPrompts.geppa(trajectory_summary, fail_cases)

        try:
            reflection = self.llm.generate(prompt, temperature=0.3)
            return reflection
        except Exception as e:
            return f"Reflection failed: {e}"

    # ==================== 生成层 ====================
    def generate_improvement(self, reflection: str,
                              skill: Optional[Skill] = None) -> Optional[Skill]:
        """
        生成改进：改写 Prompt / Skill 工具函数

        参考 AgentEvolver 生成层。
        """
        if self.llm is None or skill is None:
            return None

        prompt = ReflectionPrompts.skill_improvement(skill.code, [reflection])

        try:
            improved_code = self.llm.generate(prompt, temperature=0.2)
            new_skill = self.skills.evolve_skill(
                skill.id, improved_code, mutation_type="reflection"
            )
            return new_skill
        except Exception:
            return None

    # ==================== 评测层 ====================
    def evaluate_skill(self, skill: Skill,
                       test_cases: List[Dict[str, Any]]) -> float:
        """
        评测：批量测试，打分

        全部通过沙盒执行，禁止本地 exec。
        """
        if not self.evaluator:
            return 0.0

        ind = Individual(payload={"code": skill.code})
        result = self.evaluator.evaluate(ind)
        skill.record_execution(
            success=result.test_pass == result.test_total,
            fitness=result.fitness
        )
        return result.fitness

    # ==================== 闭环主流程 ====================
    def run_evolution_round(self, trigger: str = "auto") -> Optional[EvolutionRound]:
        """
        运行一轮进化闭环

        流程：触发 → review → 写回 → 注入
        """
        if not self.should_evolve():
            return None

        self.current_round += 1
        round_data = EvolutionRound(
            round_id=self.current_round,
            trigger=trigger,
            traces=list(self.traces[-20:]),  # 最近 20 条轨迹
        )

        # 1. 反思
        round_data.reflection = self.reflect(round_data.traces)

        # 2. 生成改进
        if self.skills and len(self.skills) > 0:
            # 选择成功率最低的技能进行改进
            skills_list = self.skills.list()
            if skills_list:
                worst_skill = min(skills_list, key=lambda s: s.success_rate)
                improved = self.generate_improvement(round_data.reflection, worst_skill)
                if improved:
                    round_data.skills_evolved.append(improved.id)

        # 3. 评测改进效果
        round_data.fitness_before = self._get_current_success_rate()
        # 这里应该重新运行测试集评估改进后的技能
        # 简化：记录改进后的预期
        round_data.fitness_after = round_data.fitness_before  # 占位

        # 4. 注入（技能已经在 generate_improvement 中注入到技能库）

        # 5. 版本快照
        self._save_snapshot(round_data)

        self.rounds.append(round_data)
        self.consecutive_failures = 0  # 重置失败计数

        return round_data

    def _get_current_success_rate(self) -> float:
        if not self.traces:
            return 0.0
        recent = self.traces[-10:]
        return sum(1 for t in recent if t.success) / len(recent)

    def _save_snapshot(self, round_data: EvolutionRound) -> None:
        """保存版本快照（每一轮必须快照，支持回滚）"""
        import os
        snapshot_dir = "./evolution_snapshots/agent_evolver"
        os.makedirs(snapshot_dir, exist_ok=True)
        filepath = f"{snapshot_dir}/round_{round_data.round_id}_{int(time.time())}.json"
        data = {
            "round": round_data.round_id,
            "trigger": round_data.trigger,
            "reflection": round_data.reflection,
            "skills_evolved": round_data.skills_evolved,
            "fitness_before": round_data.fitness_before,
            "fitness_after": round_data.fitness_after,
            "traces": [t.to_dict() for t in round_data.traces],
            "skills": [s.to_dict() for s in self.skills.skills.values()],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    # ==================== 安全门控 ====================
    def security_gate(self, code: str) -> bool:
        """
        安全门控（参考 AgentEvolver 安全门控模块）

        变更幅度校验、敏感词扫描，过大的修改直接拒绝。
        """
        # 敏感词扫描
        dangerous_patterns = [
            "os.system", "subprocess.call", "eval(", "exec(",
            "__import__", "open('/", "shutil.rmtree", "os.remove",
            "socket.socket", "requests.post", "urllib.request",
        ]
        for pattern in dangerous_patterns:
            if pattern in code:
                return False

        # 变更幅度校验（代码长度变化超过 300% 拒绝）
        # 这里简化，实际应对比原始代码
        if len(code) > 10000:
            return False

        return True
