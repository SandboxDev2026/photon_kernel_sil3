"""
evolution.archive — 档案库

参考 AutoEvolve 的 Archive 机制：保存历史精英个体，防止退化，
下一代可以复用历史优秀样本。
"""
from __future__ import annotations
import json
import uuid
import time
from typing import List, Optional, Dict, Any
from .individual import Individual


class Archive:
    """
    档案库 — 保存历史精英个体

    功能：
    - 保存每一代的精英个体
    - 防止退化（保留历史最佳）
    - 下一代可以复用历史优秀样本
    - 按适应度/代数/来源筛选
    """
    def __init__(self, max_size: int = 100, min_fitness: float = 0.5):
        self.max_size = max_size
        self.min_fitness = min_fitness
        self.individuals: List[Individual] = []
        self.best_ever: Optional[Individual] = None

    def add(self, ind: Individual) -> bool:
        """
        添加个体到档案库

        Returns:
            True 如果添加成功，False 如果被拒绝（适应度太低或重复）
        """
        # 最低适应度过滤
        if ind.fitness < self.min_fitness:
            return False

        # 重复检测（相同 payload 不重复添加）
        for existing in self.individuals:
            if existing.payload.get("code") == ind.payload.get("code"):
                return False

        # 添加
        self.individuals.append(ind)

        # 更新历史最佳（用 deepcopy 保留 fitness，不用 clone 因为 clone 会重置 fitness）
        import copy
        if self.best_ever is None or ind.fitness > self.best_ever.fitness:
            self.best_ever = copy.deepcopy(ind)
            self.best_ever.id = str(uuid.uuid4())[:8]  # 新 id 避免冲突

        # 超过最大大小时，移除适应度最低的
        if len(self.individuals) > self.max_size:
            self.individuals.sort(key=lambda x: x.fitness, reverse=True)
            self.individuals = self.individuals[:self.max_size]

        return True

    def add_generation(self, population, elite_count: int = 3) -> int:
        """添加一代的精英个体"""
        added = 0
        elites = sorted(population.individuals, key=lambda x: x.fitness, reverse=True)[:elite_count]
        for elite in elites:
            if self.add(elite):
                added += 1
        return added

    def get_best(self, n: int = 1) -> List[Individual]:
        """获取最佳的 n 个个体"""
        sorted_inds = sorted(self.individuals, key=lambda x: x.fitness, reverse=True)
        return sorted_inds[:n]

    def get_by_generation(self, gen: int) -> List[Individual]:
        """按代数获取个体"""
        return [ind for ind in self.individuals if ind.gen == gen]

    def get_by_fitness_range(self, min_fit: float, max_fit: float) -> List[Individual]:
        """按适应度范围获取"""
        return [ind for ind in self.individuals if min_fit <= ind.fitness <= max_fit]

    def sample(self, n: int = 5) -> List[Individual]:
        """随机采样（用于注入下一代）"""
        import random
        if len(self.individuals) <= n:
            return list(self.individuals)
        return random.sample(self.individuals, n)

    def get_diversity(self) -> Dict[str, Any]:
        """
        计算种群多样性

        指标：
        - 个体数
        - 适应度分布（均值/方差/最大/最小）
        - 独特代码比例
        """
        if not self.individuals:
            return {"count": 0, "diversity": 0.0}

        fitnesses = [ind.fitness for ind in self.individuals]
        mean_fit = sum(fitnesses) / len(fitnesses)
        variance = sum((f - mean_fit) ** 2 for f in fitnesses) / len(fitnesses)

        unique_codes = set(ind.payload.get("code", "") for ind in self.individuals)

        return {
            "count": len(self.individuals),
            "mean_fitness": mean_fit,
            "fitness_variance": variance,
            "max_fitness": max(fitnesses),
            "min_fitness": min(fitnesses),
            "unique_code_ratio": len(unique_codes) / len(self.individuals),
            "best_ever_fitness": self.best_ever.fitness if self.best_ever else 0,
        }

    def save(self, filepath: str) -> None:
        """保存档案库"""
        data = {
            "max_size": self.max_size,
            "min_fitness": self.min_fitness,
            "individuals": [ind.to_dict() for ind in self.individuals],
            "best_ever": self.best_ever.to_dict() if self.best_ever else None,
            "saved_at": time.time(),
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, filepath: str) -> "Archive":
        """加载档案库"""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        archive = cls(max_size=data.get("max_size", 100),
                       min_fitness=data.get("min_fitness", 0.5))
        archive.individuals = [Individual.from_dict(d) for d in data.get("individuals", [])]
        if data.get("best_ever"):
            archive.best_ever = Individual.from_dict(data["best_ever"])
        return archive

    def __len__(self) -> int:
        return len(self.individuals)
