"""
evolution.island_ga — 岛屿遗传算法

参考 CodeEvolve 的岛屿GA（island-GA）架构：
多子种群独立演化，定期迁移交换个体，提升多样性，防止局部最优。
适合高算力批量并行沙盒评测。
"""
from __future__ import annotations
import random
from typing import List, Optional, Callable, Dict, Any
from .individual import Individual
from .population import Population
from .ga_loop import GALoop
from .evaluator import BaseEvaluator


class Island:
    """岛屿 — 独立子种群"""
    def __init__(self, island_id: int, population: Population,
                 evaluator: BaseEvaluator, ga_loop: GALoop):
        self.island_id = island_id
        self.population = population
        self.evaluator = evaluator
        self.ga_loop = ga_loop
        self.migration_count = 0

    @property
    def best(self) -> Optional[Individual]:
        return self.population.best

    def run_generation(self) -> None:
        """运行一代（简化版，实际应调用 ga_loop 的单步）"""
        # 这里简化处理，实际使用时应调用 GALoop 的单步执行
        pass


class IslandGA:
    """
    岛屿遗传算法

    架构（参考 CodeEvolve）：
    - 多个岛屿（子种群）独立演化
    - 定期迁移：从每个岛屿选 Top-N 个体，交换到其他岛屿
    - 提升多样性，防止局部最优
    - 适合高算力批量并行沙盒评测

    迁移策略：
    - 环状迁移：island 0 → 1 → 2 → ... → 0
    - 随机迁移：随机选择目标岛屿
    - 精英迁移：只迁移各岛屿的精英个体
    """
    def __init__(self,
                 num_islands: int = 4,
                 population_size_per_island: int = 10,
                 migration_interval: int = 5,
                 migration_count: int = 2,
                 migration_strategy: str = "ring",  # ring / random / elite
                 max_generations: int = 50,
                 target_fitness: float = 0.95):
        self.num_islands = num_islands
        self.population_size_per_island = population_size_per_island
        self.migration_interval = migration_interval
        self.migration_count = migration_count
        self.migration_strategy = migration_strategy
        self.max_generations = max_generations
        self.target_fitness = target_fitness
        self.islands: List[Island] = []
        self.global_best: Optional[Individual] = None
        self.migration_history: List[Dict[str, Any]] = []

    def add_island(self, island: Island) -> None:
        """添加岛屿"""
        self.islands.append(island)

    def migrate(self) -> None:
        """
        执行迁移

        从每个岛屿选 Top-N 个体，交换到其他岛屿。
        """
        if len(self.islands) < 2:
            return

        migrants_per_island = []
        for island in self.islands:
            # 选 Top-N 精英
            sorted_inds = sorted(island.population.individuals,
                                 key=lambda ind: ind.fitness, reverse=True)
            migrants = sorted_inds[:self.migration_count]
            migrants_per_island.append(migrants)

        # 根据策略分配
        for i, island in enumerate(self.islands):
            if self.migration_strategy == "ring":
                # 环状：接收前一个岛屿的移民
                source_idx = (i - 1) % len(self.islands)
            elif self.migration_strategy == "random":
                # 随机：随机选一个岛屿
                source_idx = random.randint(0, len(self.islands) - 1)
            else:  # elite
                # 精英：所有岛屿共享全局最佳
                source_idx = i  # 简化

            migrants = migrants_per_island[source_idx]
            for migrant in migrants:
                # 克隆移民（避免共享引用）
                new_migrant = migrant.clone()
                new_migrant.gen = island.population.generation
                island.population.add(new_migrant)
                island.migration_count += 1

            # 裁剪种群大小
            island.population.trim()

        self.migration_history.append({
            "generation": self.islands[0].population.generation if self.islands else 0,
            "strategy": self.migration_strategy,
            "migrants_per_island": self.migration_count,
        })

    def get_global_best(self) -> Optional[Individual]:
        """获取全局最佳个体"""
        best = None
        for island in self.islands:
            if island.best and (best is None or island.best.fitness > best.fitness):
                best = island.best
        self.global_best = best
        return best

    def run(self) -> Optional[Individual]:
        """运行岛屿 GA"""
        for gen in range(self.max_generations):
            # 每个岛屿独立演化一代
            for island in self.islands:
                island.run_generation()

            # 定期迁移
            if gen > 0 and gen % self.migration_interval == 0:
                self.migrate()

            # 检查全局最佳
            global_best = self.get_global_best()
            if global_best and global_best.fitness >= self.target_fitness:
                break

        return self.get_global_best()
