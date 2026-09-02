"""
evolution — 遗传算法 + 自进化 Agent 模块

参考开源项目：
- EvoPrompt（微软）：GA/DE 差分进化外层循环骨架
- Prompt-Darwinism：锦标赛选择、7种变异策略、LLM-as-Judge
- AutoEvolve / OpenEvolve：rewrite/patch/nl_feedback 三种变异模式
- CodeEvolve：岛屿遗传算法（island-GA）
- AgentEvolver（阿里魔搭）：自进化闭环五层架构
- Darwin-Agent / Hermes-Agent：Closed-Learning-Loop 闭环范式

安全约束：
- 所有代码执行必须通过沙盒（photon_kernel_sil3），禁止本地 exec/eval
- 适应度函数必须包含安全惩罚项
- 每一代个体必须快照保存，支持回滚
- LLM 调用通过适配器抽象，不硬编码模型名称
"""

from .individual import Individual
from .population import Population
from .evaluator import (
    BaseEvaluator,
    EvaluationResult,
    CodeGenerationEvaluator,
    PromptEvolutionEvaluator,
)
from .mutator import (
    BaseMutator,
    RewriteMutator,
    PatchMutator,
    NLFeedbackMutator,
    MultiStrategyMutator,
)
from .crossover import BaseCrossover, SemanticCrossover, BlendCrossover
from .selector import (
    BaseSelector,
    TournamentSelector,
    RouletteWheelSelector,
    EliteSelector,
)
from .ga_loop import GALoop
from .island_ga import IslandGA, Island
from .agent_evolver import AgentEvolver, ExecutionTrace, EvolutionRound
from .skill_library import Skill, SkillLibrary
from .archive import Archive
from .llm_adapter import (
    BaseLLMAdapter,
    OpenAIAdapter,
    AnthropicAdapter,
    MockLLMAdapter,
    LLMAdapterFactory,
)
from .sandbox_client import SandboxClient, SandboxResult
from .prompts import MutationPrompts, CrossoverPrompts, ReflectionPrompts, LLMJudgePrompts

__version__ = "1.0.0"
__all__ = [
    "Individual",
    "Population",
    "BaseEvaluator",
    "EvaluationResult",
    "CodeGenerationEvaluator",
    "PromptEvolutionEvaluator",
    "BaseMutator",
    "RewriteMutator",
    "PatchMutator",
    "NLFeedbackMutator",
    "MultiStrategyMutator",
    "BaseCrossover",
    "SemanticCrossover",
    "BlendCrossover",
    "BaseSelector",
    "TournamentSelector",
    "RouletteWheelSelector",
    "EliteSelector",
    "GALoop",
    "IslandGA",
    "Island",
    "AgentEvolver",
    "ExecutionTrace",
    "EvolutionRound",
    "Skill",
    "SkillLibrary",
    "Archive",
    "BaseLLMAdapter",
    "OpenAIAdapter",
    "AnthropicAdapter",
    "MockLLMAdapter",
    "LLMAdapterFactory",
    "SandboxClient",
    "SandboxResult",
    "MutationPrompts",
    "CrossoverPrompts",
    "ReflectionPrompts",
    "LLMJudgePrompts",
]
