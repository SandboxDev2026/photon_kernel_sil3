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


class AdaptiveMutationController:
    """
    自适应变异算子控制器（借鉴 Grounded Agent Forge）

    核心思想：进化算子本身也会进化，动态调整变异/交叉概率。
    - 种群快速进化时：降低变异率，提高交叉率（利用已有好基因）
    - 种群停滞时：提高变异率，降低交叉率（鼓励探索）
    - 长期停滞时：切换新奇搜索模式（novelty search）

    参考：Grounded Agent Forge 的元进化策略优化器，动态调整变异/交叉算子概率，
    当种群停滞自动切换新奇搜索，解决GA早熟收敛问题。
    """

    def __init__(
        self,
        initial_mutation_rate: float = 0.3,
        initial_crossover_rate: float = 0.7,
        min_mutation_rate: float = 0.05,
        max_mutation_rate: float = 0.8,
        stagnation_threshold: int = 5,
        novelty_search_threshold: int = 10,
        adaptation_rate: float = 0.1,
    ):
        """
        初始化自适应变异控制器

        Args:
            initial_mutation_rate: 初始变异率
            initial_crossover_rate: 初始交叉率
            min_mutation_rate: 最小变异率
            max_mutation_rate: 最大变异率
            stagnation_threshold: 停滞判定阈值（连续N代无提升）
            novelty_search_threshold: 新奇搜索触发阈值（连续N代停滞）
            adaptation_rate: 适应率（每次调整的幅度）
        """
        self.mutation_rate = initial_mutation_rate
        self.crossover_rate = initial_crossover_rate
        self.min_mutation_rate = min_mutation_rate
        self.max_mutation_rate = max_mutation_rate
        self.stagnation_threshold = stagnation_threshold
        self.novelty_search_threshold = novelty_search_threshold
        self.adaptation_rate = adaptation_rate

        # 状态跟踪
        self.best_fitness_history: List[float] = []
        self.stagnation_count = 0
        self.novelty_search_enabled = False
        self.adjustment_history: List[Dict[str, Any]] = []

    def update(self, current_best_fitness: float) -> Dict[str, Any]:
        """
        根据当前种群最佳适应度更新算子参数

        Args:
            current_best_fitness: 当前种群最佳适应度

        Returns:
            调整结果字典，包含新的变异率、交叉率、是否触发新奇搜索
        """
        self.best_fitness_history.append(current_best_fitness)

        # 检测停滞
        is_stagnant = self._detect_stagnation()
        if is_stagnant:
            self.stagnation_count += 1
        else:
            self.stagnation_count = 0
            self.novelty_search_enabled = False

        # 调整算子
        adjustment = self._adjust_operators(is_stagnant)

        # 检测是否触发新奇搜索
        if self.stagnation_count >= self.novelty_search_threshold:
            self.novelty_search_enabled = True
            adjustment["novelty_search_triggered"] = True
            adjustment["action"] = "启用新奇搜索模式，大幅提高变异率"
            self._trigger_novelty_search()
        else:
            adjustment["novelty_search_triggered"] = False

        # 记录调整历史
        adjustment["generation"] = len(self.best_fitness_history)
        adjustment["current_best_fitness"] = current_best_fitness
        adjustment["stagnation_count"] = self.stagnation_count
        self.adjustment_history.append(adjustment)

        return adjustment

    def _detect_stagnation(self) -> bool:
        """
        检测种群是否停滞

        判定标准：最近 stagnation_threshold 代的最佳适应度提升小于 1%
        """
        if len(self.best_fitness_history) < self.stagnation_threshold + 1:
            return False

        recent = self.best_fitness_history[-(self.stagnation_threshold + 1):]
        oldest = recent[0]
        newest = recent[-1]

        if oldest <= 0:
            return newest <= oldest

        improvement = (newest - oldest) / abs(oldest)
        return improvement < 0.01  # 提升小于1%判定为停滞

    def _adjust_operators(self, is_stagnant: bool) -> Dict[str, Any]:
        """
        调整变异/交叉算子概率

        - 停滞时：提高变异率，降低交叉率（鼓励探索）
        - 进化时：降低变异率，提高交叉率（利用已有好基因）
        """
        old_mutation = self.mutation_rate
        old_crossover = self.crossover_rate

        if is_stagnant:
            # 停滞：提高变异率
            self.mutation_rate = min(
                self.max_mutation_rate,
                self.mutation_rate + self.adaptation_rate
            )
            self.crossover_rate = max(
                0.3,
                self.crossover_rate - self.adaptation_rate
            )
            action = "种群停滞，提高变异率鼓励探索"
        else:
            # 进化：降低变异率
            self.mutation_rate = max(
                self.min_mutation_rate,
                self.mutation_rate - self.adaptation_rate * 0.5
            )
            self.crossover_rate = min(
                0.9,
                self.crossover_rate + self.adaptation_rate * 0.5
            )
            action = "种群进化中，降低变异率利用好基因"

        return {
            "old_mutation_rate": old_mutation,
            "new_mutation_rate": self.mutation_rate,
            "old_crossover_rate": old_crossover,
            "new_crossover_rate": self.crossover_rate,
            "action": action,
            "is_stagnant": is_stagnant,
        }

    def _trigger_novelty_search(self) -> None:
        """
        触发新奇搜索模式

        当种群长期停滞时，大幅提高变异率，鼓励探索新的行为模式，
        而不是继续在局部最优附近微调。
        """
        self.mutation_rate = self.max_mutation_rate
        self.crossover_rate = 0.3  # 降低交叉率，鼓励独立探索

    def get_current_params(self) -> Dict[str, Any]:
        """获取当前算子参数"""
        return {
            "mutation_rate": self.mutation_rate,
            "crossover_rate": self.crossover_rate,
            "stagnation_count": self.stagnation_count,
            "novelty_search_enabled": self.novelty_search_enabled,
            "best_fitness_history_length": len(self.best_fitness_history),
            "total_adjustments": len(self.adjustment_history),
        }

    def reset(self) -> None:
        """重置控制器状态"""
        self.best_fitness_history = []
        self.stagnation_count = 0
        self.novelty_search_enabled = False
        self.adjustment_history = []
