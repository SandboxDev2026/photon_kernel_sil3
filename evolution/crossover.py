"""
evolution.crossover — 交叉算子抽象

灵感式交叉（参考 AutoEvolve）：不是字符串剪切拼接，
提示词让 LLM 吸收两份代码优点输出新代码，避免语法碎块。
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional
from .individual import Individual
from .prompts import CrossoverPrompts


class BaseCrossover(ABC):
    """交叉算子基类"""
    def __init__(self, llm_adapter=None, crossover_rate: float = 0.5):
        self.llm = llm_adapter
        self.crossover_rate = crossover_rate

    @abstractmethod
    def cross(self, ind_a: Individual, ind_b: Individual) -> Individual:
        """
        交叉两个个体，产生新个体

        关键点：不是字符串拼接，而是 LLM 语义合并。
        """
        pass


class SemanticCrossover(BaseCrossover):
    """
    语义交叉（参考 AutoEvolve 灵感式交叉）

    提示词让 LLM 吸收两份代码的优点，输出新代码。
    避免传统字符串剪切拼接导致的语法碎块。
    """
    def cross(self, ind_a: Individual, ind_b: Individual) -> Individual:
        new = ind_a.clone()
        new.parent_ids = [ind_a.id, ind_b.id]
        new.mutation_type = "crossover"

        if self.llm is None:
            # 无 LLM 时退化：选择适应度高的父代
            return ind_a if ind_a.fitness >= ind_b.fitness else ind_b

        code_a = ind_a.payload.get("code", "")
        code_b = ind_b.payload.get("code", "")

        prompt = CrossoverPrompts.semantic(code_a, code_b,
                                             ind_a.fitness, ind_b.fitness)

        try:
            crossed_code = self.llm.generate(prompt, temperature=0.5)
            new.payload["code"] = crossed_code
            new.payload["parent_a_code"] = code_a
            new.payload["parent_b_code"] = code_b
        except Exception as e:
            # 交叉失败，选择适应度高的父代
            best = ind_a if ind_a.fitness >= ind_b.fitness else ind_b
            new.payload["code"] = best.payload.get("code", "")
            new.fail_cases.append(f"crossover_error: {e}")

        return new


class BlendCrossover(BaseCrossover):
    """
    混合交叉 — 结合语义交叉和精英保留

    70% 概率用语义交叉，30% 概率直接保留精英父代。
    """
    def __init__(self, llm_adapter=None, **kwargs):
        super().__init__(llm_adapter, **kwargs)
        self.semantic = SemanticCrossover(llm_adapter)

    def cross(self, ind_a: Individual, ind_b: Individual) -> Individual:
        import random
        if random.random() < 0.3:
            # 30% 概率直接保留精英父代（防止退化）
            best = ind_a if ind_a.fitness >= ind_b.fitness else ind_b
            return best.clone()
        return self.semantic.cross(ind_a, ind_b)
