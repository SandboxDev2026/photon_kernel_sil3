"""
evolution.selector — 选择算子

锦标赛选择（参考 Prompt-Darwinism）：比轮盘赌更稳定，工程最常用。
"""
from __future__ import annotations
import random
from abc import ABC, abstractmethod
from typing import List
from .individual import Individual


class BaseSelector(ABC):
    """选择算子基类"""
    @abstractmethod
    def select(self, population: List[Individual], n: int) -> List[Individual]:
        """从种群中选择 n 个个体"""
        pass


class TournamentSelector(BaseSelector):
    """
    锦标赛选择（参考 Prompt-Darwinism）

    随机选 k 个个体，取适应度最高的。
    比轮盘赌更稳定，工程最常用。
    """
    def __init__(self, tournament_size: int = 3):
        self.tournament_size = tournament_size

    def select(self, population: List[Individual], n: int) -> List[Individual]:
        if not population:
            return []
        selected = []
        for _ in range(n):
            # 随机选 k 个
            contenders = random.sample(population, min(self.tournament_size, len(population)))
            # 取适应度最高的
            best = max(contenders, key=lambda ind: ind.fitness)
            selected.append(best)
        return selected


class RouletteWheelSelector(BaseSelector):
    """
    轮盘赌选择

    适应度越高，被选中概率越大。
    缺点：容易被极端值主导，不如锦标赛稳定。
    """
    def select(self, population: List[Individual], n: int) -> List[Individual]:
        if not population:
            return []
        total_fitness = sum(ind.fitness for ind in population)
        if total_fitness == 0:
            # 全零适应度，随机选
            return random.sample(population, min(n, len(population)))

        selected = []
        for _ in range(n):
            r = random.uniform(0, total_fitness)
            cumulative = 0
            for ind in population:
                cumulative += ind.fitness
                if cumulative >= r:
                    selected.append(ind)
                    break
            else:
                selected.append(population[-1])
        return selected


class EliteSelector(BaseSelector):
    """
    精英选择 — 直接选 Top-N

    用于精英保留策略：每一代保留最好的个体不被破坏。
    参考 EvoPrompt 的精英保留策略。
    """
    def select(self, population: List[Individual], n: int) -> List[Individual]:
        sorted_pop = sorted(population, key=lambda ind: ind.fitness, reverse=True)
        return sorted_pop[:n]
