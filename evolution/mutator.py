"""
evolution.mutator — 变异算子抽象

三种变异模式（参考 AutoEvolve / OpenEvolve）：
1. rewrite: 完整重写（早期探索用）
2. patch: 局部diff补丁修改（后期迭代用，减少语法崩坏）
3. nl_feedback: 参考历史失败案例变异（失败驱动变异）

所有变异交给 LLM 语义生成，不是字符串随机拼接。
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from .individual import Individual
from .prompts import MutationPrompts


class BaseMutator(ABC):
    """变异算子基类"""
    def __init__(self, llm_adapter=None, mutation_rate: float = 0.3):
        self.llm = llm_adapter
        self.mutation_rate = mutation_rate

    @abstractmethod
    def mutate(self, ind: Individual, fail_cases: List[str] = None) -> Individual:
        """
        变异个体

        Args:
            ind: 原个体
            fail_cases: 失败用例（用于失败驱动变异）

        Returns:
            新个体（已克隆，原个体不变）
        """
        pass


class RewriteMutator(BaseMutator):
    """
    完整重写变异（参考 AutoEvolve rewrite 模式）

    早期探索用：让 LLM 完整重写代码，探索更大的搜索空间。
    缺点：容易语法崩坏，适合早期。
    """
    def mutate(self, ind: Individual, fail_cases: List[str] = None) -> Individual:
        new = ind.clone()
        new.mutation_type = "rewrite"

        if self.llm is None:
            # 无 LLM 时的退化策略：随机扰动（不推荐，仅用于测试）
            return new

        code = ind.payload.get("code", "")
        prompt = MutationPrompts.rewrite(code, fail_cases)

        try:
            mutated_code = self.llm.generate(prompt, temperature=0.7)
            new.payload["code"] = mutated_code
            new.payload["original_code"] = code
        except Exception as e:
            new.payload["code"] = code  # 变异失败，保留原代码
            new.fail_cases.append(f"mutation_error: {e}")

        return new


class PatchMutator(BaseMutator):
    """
    局部补丁变异（参考 AutoEvolve patch 模式）

    后期迭代用：让 LLM 生成 diff 补丁，只修改必要部分，
    减少语法崩坏概率。
    """
    def mutate(self, ind: Individual, fail_cases: List[str] = None) -> Individual:
        new = ind.clone()
        new.mutation_type = "patch"

        if self.llm is None:
            return new

        code = ind.payload.get("code", "")
        prompt = MutationPrompts.patch(code, fail_cases)

        try:
            diff = self.llm.generate(prompt, temperature=0.3)
            patched_code = self._apply_diff(code, diff)
            new.payload["code"] = patched_code
            new.payload["diff"] = diff
        except Exception as e:
            new.payload["code"] = code
            new.fail_cases.append(f"patch_error: {e}")

        return new

    def _apply_diff(self, original: str, diff: str) -> str:
        """应用 diff 补丁（简化实现，实际可用 unified diff 解析）"""
        # 简单策略：如果 LLM 返回了完整代码，直接用
        if "def " in diff and "return" in diff and len(diff) > 50:
            return diff
        # 否则尝试行级替换
        lines = original.split("\n")
        for line in diff.split("\n"):
            if line.startswith("-") and line[1:].strip() in original:
                # 找到要删除的行
                pass
            elif line.startswith("+"):
                pass
        return original  # 简化：无法解析 diff 时返回原代码


class NLFeedbackMutator(BaseMutator):
    """
    自然语言反馈变异（参考 AutoEvolve nl_feedback 模式）

    失败驱动变异：把测试失败案例塞给 LLM，针对性变异修复 bug。
    参考 CodeEvolve 的失败用例驱动变异。
    """
    def mutate(self, ind: Individual, fail_cases: List[str] = None) -> Individual:
        new = ind.clone()
        new.mutation_type = "nl_feedback"

        if self.llm is None or not fail_cases:
            return new

        code = ind.payload.get("code", "")
        prompt = MutationPrompts.nl_feedback(code, fail_cases)

        try:
            fixed_code = self.llm.generate(prompt, temperature=0.2)  # 低温度，精准修复
            new.payload["code"] = fixed_code
            new.payload["fixed_fail_cases"] = fail_cases
        except Exception as e:
            new.payload["code"] = code
            new.fail_cases.append(f"nl_feedback_error: {e}")

        return new


class MultiStrategyMutator(BaseMutator):
    """
    多策略变异器 — 根据进化阶段自动选择变异策略

    早期：rewrite（探索）
    中期：patch（利用）
    后期：nl_feedback（精修）
    """
    def __init__(self, llm_adapter=None, **kwargs):
        super().__init__(llm_adapter, **kwargs)
        self.rewrite = RewriteMutator(llm_adapter)
        self.patch = PatchMutator(llm_adapter)
        self.nl_feedback = NLFeedbackMutator(llm_adapter)

    def mutate(self, ind: Individual, fail_cases: List[str] = None) -> Individual:
        # 根据代数选择策略
        if ind.gen < 5:
            return self.rewrite.mutate(ind, fail_cases)
        elif ind.gen < 15:
            return self.patch.mutate(ind, fail_cases)
        else:
            return self.nl_feedback.mutate(ind, fail_cases)
