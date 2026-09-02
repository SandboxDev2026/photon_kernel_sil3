"""
evolution.population — 种群管理

支持：添加/移除个体、按适应度排序、精英保留、快照保存/恢复。
"""
from __future__ import annotations
import json
import time
import os
from typing import List, Optional, Callable
from .individual import Individual


class Population:
    """
    种群管理

    功能：
    - 添加/移除个体
    - 按适应度排序
    - 精英保留（Top-N 不参与变异）
    - 快照保存/恢复（每一代必须快照，支持回滚）
    """
    def __init__(self, size: int = 20, elite_count: int = 2):
        self.size = size
        self.elite_count = elite_count
        self.individuals: List[Individual] = []
        self.generation: int = 0
        self.best_fitness_history: List[float] = []
        self.avg_fitness_history: List[float] = []
        self.snapshots_dir: str = ""

    def add(self, ind: Individual) -> None:
        """添加个体"""
        ind.gen = self.generation
        self.individuals.append(ind)

    def add_many(self, inds: List[Individual]) -> None:
        """批量添加"""
        for ind in inds:
            self.add(ind)

    def remove(self, ind: Individual) -> None:
        """移除个体"""
        if ind in self.individuals:
            self.individuals.remove(ind)

    def clear(self) -> None:
        """清空种群"""
        self.individuals.clear()

    @property
    def best(self) -> Optional[Individual]:
        """适应度最高的个体"""
        if not self.individuals:
            return None
        return max(self.individuals, key=lambda ind: ind.fitness)

    @property
    def worst(self) -> Optional[Individual]:
        """适应度最低的个体"""
        if not self.individuals:
            return None
        return min(self.individuals, key=lambda ind: ind.fitness)

    @property
    def avg_fitness(self) -> float:
        """平均适应度"""
        if not self.individuals:
            return 0.0
        return sum(ind.fitness for ind in self.individuals) / len(self.individuals)

    @property
    def elites(self) -> List[Individual]:
        """精英个体（Top-N）"""
        sorted_inds = sorted(self.individuals, key=lambda ind: ind.fitness, reverse=True)
        return sorted_inds[:self.elite_count]

    @property
    def non_elites(self) -> List[Individual]:
        """非精英个体（参与变异/交叉）"""
        sorted_inds = sorted(self.individuals, key=lambda ind: ind.fitness, reverse=True)
        return sorted_inds[self.elite_count:]

    def sort(self) -> None:
        """按适应度降序排序"""
        self.individuals.sort(key=lambda ind: ind.fitness, reverse=True)

    def trim(self) -> None:
        """裁剪到种群大小（移除适应度最低的）"""
        self.sort()
        if len(self.individuals) > self.size:
            self.individuals = self.individuals[:self.size]

    def next_generation(self) -> None:
        """进入下一代（记录历史+快照）"""
        self.generation += 1
        if self.best:
            self.best_fitness_history.append(self.best.fitness)
        self.avg_fitness_history.append(self.avg_fitness)
        # 自动快照
        if self.snapshots_dir:
            self.save_snapshot()

    def save_snapshot(self, filepath: str = "") -> str:
        """
        保存种群快照（每一代必须快照，支持回滚）

        参考 AgentEvolver 的版本快照机制。
        """
        if not filepath:
            if not self.snapshots_dir:
                self.snapshots_dir = "./evolution_snapshots"
            os.makedirs(self.snapshots_dir, exist_ok=True)
            filepath = os.path.join(
                self.snapshots_dir,
                f"generation_{self.generation}_{int(time.time())}.json"
            )

        data = {
            "generation": self.generation,
            "size": self.size,
            "elite_count": self.elite_count,
            "best_fitness_history": self.best_fitness_history,
            "avg_fitness_history": self.avg_fitness_history,
            "individuals": [ind.to_dict() for ind in self.individuals],
            "timestamp": time.time(),
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return filepath

    @classmethod
    def load_snapshot(cls, filepath: str) -> "Population":
        """从快照恢复种群（支持回滚）"""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        pop = cls(size=data.get("size", 20), elite_count=data.get("elite_count", 2))
        pop.generation = data.get("generation", 0)
        pop.best_fitness_history = data.get("best_fitness_history", [])
        pop.avg_fitness_history = data.get("avg_fitness_history", [])
        pop.individuals = [Individual.from_dict(d) for d in data.get("individuals", [])]
        return pop

    def __len__(self) -> int:
        return len(self.individuals)

    def __iter__(self):
        return iter(self.individuals)

    def __repr__(self) -> str:
        best_fit = f"{self.best.fitness:.3f}" if self.best else "N/A"
        return (f"Population(gen={self.generation}, size={len(self.individuals)}/{self.size}, "
                f"best={best_fit}, avg={self.avg_fitness:.3f})")
