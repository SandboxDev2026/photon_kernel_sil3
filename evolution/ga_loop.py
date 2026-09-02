"""
evolution.ga_loop — 遗传算法主循环

参考 EvoPrompt（微软）的 GA/DE 差分进化外层循环骨架：
种群初始化 → 评估打分 → 选择 → 变异交叉 → 更新种群

参考 Prompt-Darwinism 的锦标赛选择、精英保留策略。
"""
from __future__ import annotations
import random
import time
from typing import List, Optional, Callable, Dict, Any
from .individual import Individual
from .population import Population
from .evaluator import BaseEvaluator
from .mutator import BaseMutator, MultiStrategyMutator
from .crossover import BaseCrossover, BlendCrossover
from .selector import BaseSelector, TournamentSelector, EliteSelector


class GALoop:
    """
    遗传算法主循环

    流程（参考 EvoPrompt / Prompt-Darwinism）：
    1. 种群初始化（随机/种子个体）
    2. 评估打分（全部通过沙盒执行，禁止本地exec）
    3. 选择（锦标赛选择）
    4. 变异交叉（LLM语义生成，不是字符串拼接）
    5. 精英保留（Top-N 不被破坏）
    6. 更新种群 → 回到步骤2
    """
    def __init__(self,
                 evaluator: BaseEvaluator,
                 mutator: Optional[BaseMutator] = None,
                 crossover: Optional[BaseCrossover] = None,
                 selector: Optional[BaseSelector] = None,
                 population_size: int = 20,
                 elite_count: int = 2,
                 max_generations: int = 50,
                 target_fitness: float = 0.95,
                 mutation_rate: float = 0.3,
                 crossover_rate: float = 0.5,
                 callbacks: Optional[Dict[str, Callable]] = None):
        self.evaluator = evaluator
        self.mutator = mutator or MultiStrategyMutator()
        self.crossover = crossover or BlendCrossover()
        self.selector = selector or TournamentSelector(tournament_size=3)
        self.elite_selector = EliteSelector()
        self.population = Population(size=population_size, elite_count=elite_count)
        self.max_generations = max_generations
        self.target_fitness = target_fitness
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        self.callbacks = callbacks or {}
        self.best_individual: Optional[Individual] = None
        self.stats: List[Dict[str, Any]] = []

    def initialize(self, seed_individuals: List[Individual] = None,
                   initial_payloads: List[Dict[str, Any]] = None) -> None:
        """
        种群初始化

        Args:
            seed_individuals: 种子个体（直接加入）
            initial_payloads: 初始 payload 列表（用于创建个体）
        """
        if seed_individuals:
            for ind in seed_individuals:
                self.population.add(ind)

        if initial_payloads:
            for payload in initial_payloads:
                ind = Individual(payload=payload)
                self.population.add(ind)

        # 如果种群不足，随机填充（实际应该由 LLM 生成初始个体）
        while len(self.population) < self.population.size:
            ind = Individual(payload={"code": "# TODO: generate initial code"})
            self.population.add(ind)

        # 初始评估
        self._evaluate_population()
        self.population.sort()
        self._record_stats("init")

    def run(self) -> Individual:
        """
        运行 GA 主循环

        Returns:
            最佳个体
        """
        self._trigger_callback("on_start", self.population)

        for gen in range(self.max_generations):
            start_time = time.time()

            # 1. 选择父代
            parents = self.selector.select(
                self.population.non_elites,
                n=self.population.size - self.population.elite_count
            )

            # 2. 变异 + 交叉产生新个体
            offspring = self._produce_offspring(parents)

            # 3. 评估新个体
            for ind in offspring:
                if not ind.evaluated:
                    self.evaluator.evaluate(ind)

            # 4. 精英保留 + 更新种群
            elites = self.population.elites
            new_population = elites + offspring
            self.population.clear()
            self.population.add_many(new_population)
            self.population.trim()

            # 5. 下一代
            self.population.next_generation()
            self.population.sort()

            # 6. 记录统计
            elapsed = time.time() - start_time
            self._record_stats(f"gen_{gen}", elapsed)

            # 7. 回调
            self._trigger_callback("on_generation", self.population, gen, elapsed)

            # 8. 终止条件
            if self.population.best and self.population.best.fitness >= self.target_fitness:
                self._trigger_callback("on_target_reached", self.population.best)
                break

        self.best_individual = self.population.best
        self._trigger_callback("on_finish", self.best_individual)
        return self.best_individual

    def _produce_offspring(self, parents: List[Individual]) -> List[Individual]:
        """产生后代（变异 + 交叉）"""
        offspring = []
        i = 0
        while len(offspring) < len(parents) and i < len(parents):
            parent = parents[i]

            # 交叉
            if random.random() < self.crossover_rate and i + 1 < len(parents):
                child = self.crossover.cross(parent, parents[i + 1])
                i += 2
            else:
                # 变异
                if random.random() < self.mutation_rate:
                    child = self.mutator.mutate(parent, parent.fail_cases)
                else:
                    child = parent.clone()
                i += 1

            offspring.append(child)

        return offspring

    def _evaluate_population(self) -> None:
        """评估整个种群"""
        for ind in self.population:
            if not ind.evaluated:
                self.evaluator.evaluate(ind)

    def _record_stats(self, phase: str, elapsed: float = 0) -> None:
        """记录统计信息"""
        stat = {
            "phase": phase,
            "generation": self.population.generation,
            "population_size": len(self.population),
            "best_fitness": self.population.best.fitness if self.population.best else 0,
            "avg_fitness": self.population.avg_fitness,
            "best_pass_rate": self.population.best.pass_rate if self.population.best else 0,
            "security_violations": sum(ind.sandbox_violations for ind in self.population),
            "elapsed_seconds": elapsed,
        }
        self.stats.append(stat)

    def _trigger_callback(self, name: str, *args, **kwargs) -> None:
        """触发回调"""
        if name in self.callbacks:
            try:
                self.callbacks[name](*args, **kwargs)
            except Exception:
                pass  # 回调异常不影响主循环
