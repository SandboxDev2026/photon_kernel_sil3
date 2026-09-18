"""
Sandbox Town 实验层 — 时间线分叉 + 可插拔模块 + 对照实验

借鉴：
- OpenStory (浙大)：注入外来变量扰动剧情，生成分支对比
- AgentSims：可插拔记忆/规划模块，跑对照实验
- Agent-Kernel：微内核式大规模仿真实验调度
"""
from __future__ import annotations

import copy
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from evolution.sandbox_town import SandboxTown, TownResident, TownLocation


# ============================================================
# 可插拔接口（AgentSims 范式）
# ============================================================

@runtime_checkable
class MemoryBackend(Protocol):
    """记忆后端协议：可替换 ShortTermMemory / 向量库 / 数据库"""
    def add(self, content: str, importance: float = 0.5,
            tags: Optional[List[str]] = None) -> str: ...
    def recall_recent(self, n: int = 10) -> List[str]: ...
    def __len__(self) -> int: ...


class DefaultMemory:
    """默认记忆：就是 ShortTermMemory 的薄包装"""
    def __init__(self, max_items: int = 30):
        from evolution.memory_engine import ShortTermMemory
        self._mem = ShortTermMemory(max_items=max_items, ttl_seconds=86400 * 7)
        self._ids: List[str] = []

    def add(self, content: str, importance: float = 0.5,
            tags: Optional[List[str]] = None) -> str:
        mid = self._mem.add(content, importance=importance,
                            tags=tags or [], source_task="town")
        self._ids.append(mid)
        return mid

    def recall_recent(self, n: int = 10) -> List[str]:
        items = list(self._mem._items.values())[-n:]
        return [it.content for it in items]

    def __len__(self) -> int:
        return len(self._mem._items)


class NoisyMemory:
    """噪声记忆：按概率丢弃一部分记忆（对照实验用）"""
    def __init__(self, drop_rate: float = 0.3):
        import random as _r
        self._rng = _r.Random(hash(drop_rate) & 0xffff)  # nosec B311
        self.drop_rate = drop_rate
        self._kept: List[str] = []
        self.total_added = 0

    def add(self, content: str, importance: float = 0.5,
            tags: Optional[List[str]] = None) -> str:
        self.total_added += 1
        if self._rng.random() < self.drop_rate:  # nosec B311
            return f"dropped-{self.total_added}"
        self._kept.append(content)
        return f"kept-{self.total_added}"

    def recall_recent(self, n: int = 10) -> List[str]:
        return self._kept[-n:]

    def __len__(self) -> int:
        return len(self._kept)


@runtime_checkable
class Planner(Protocol):
    """规划器协议：决定居民每tick去哪"""
    def plan(self, resident: TownResident, tick: int,
             locations: Dict[str, TownLocation]) -> TownLocation: ...


class DefaultPlanner:
    """默认规划器：居民自己的 plan_day"""
    def plan(self, resident: TownResident, tick: int,
             locations: Dict[str, TownLocation]) -> TownLocation:
        return resident.plan_day(tick, locations)


class RandomPlanner:
    """随机规划器（对照组：无日程）"""
    def __init__(self, seed: int = 0):
        import random as _r
        self._rng = _r.Random(seed)  # nosec B311

    def plan(self, resident: TownResident, tick: int,
             locations: Dict[str, TownLocation]) -> TownLocation:
        return self._rng.choice(list(locations.values()))  # nosec B311  # nosec B311


# ============================================================
# 时间线分叉（OpenStory 范式）
# ============================================================

@dataclass
class TimelineBranch:
    """一条时间线分支"""
    branch_id: str
    seed: int
    num_residents: int
    injected_events: List[Dict[str, Any]] = field(default_factory=list)
    town: Optional[SandboxTown] = None
    result: Optional[Dict[str, Any]] = None

    def build(self) -> SandboxTown:
        self.town = SandboxTown(
            num_residents=self.num_residents, seed=self.seed)
        return self.town


class TimelineManager:
    """
    时间线分叉管理器

    用法：
        mgr = TimelineManager(base_seed=42, num_residents=8)
        mgr.add_branch("baseline", seed=42)
        mgr.add_branch("with_fire", seed=42, injected=[("fire", 3)])  # tick=3 注入火灾
        mgr.add_branch("with_gossip", seed=42, injected=[("gossip", 5)])
        mgr.run(num_ticks=20)
        diff = mgr.compare()
    """

    def __init__(self, base_seed: int = 42, num_residents: int = 8):
        self.base_seed = base_seed
        self.num_residents = num_residents
        self.branches: Dict[str, TimelineBranch] = {}

    def add_branch(self, branch_id: str, seed: Optional[int] = None,
                   injected: Optional[List] = None) -> TimelineBranch:
        b = TimelineBranch(
            branch_id=branch_id,
            seed=seed if seed is not None else self.base_seed,
            num_residents=self.num_residents,
            injected_events=injected or [],
        )
        self.branches[branch_id] = b
        return b

    def run(self, num_ticks: int = 20) -> Dict[str, Any]:
        """跑所有分支"""
        for b in self.branches.values():
            town = b.build()
            # 按 tick 注入事件
            inject_map = {}
            for kind, at_tick in b.injected_events:
                inject_map.setdefault(at_tick, []).append(kind)

            for t in range(num_ticks):
                town.step(t)
                for kind in inject_map.get(t, []):
                    town.inject_incident(kind)
            b.result = town.generate_report()
        return {bid: b.result for bid, b in self.branches.items()}

    def compare(self) -> Dict[str, Any]:
        """对比各分支结果"""
        if not self.branches:
            return {}
        metrics = {}
        for bid, b in self.branches.items():
            if b.result is None:
                continue
            metrics[bid] = {
                "total_events": b.result["total_events"],
                "social_interactions": b.result["social_interactions"],
                "incidents": b.result["incidents"],
                "most_social": b.result["most_social_resident"],
                "richest": b.result["richest_resident"],
            }
        # 找差异最大的分支
        if len(metrics) >= 2:
            baseline = list(metrics.values())[0]
            diffs = {}
            for bid, m in metrics.items():
                if bid == list(metrics.keys())[0]:
                    continue
                diffs[bid] = {
                    "event_delta": m["total_events"] - baseline["total_events"],
                    "social_delta": m["social_interactions"] - baseline["social_interactions"],
                }
            return {"branches": metrics, "diffs_vs_baseline": diffs}
        return {"branches": metrics}


# ============================================================
# 对照实验器（A/B 测试）
# ============================================================

@dataclass
class ExperimentConfig:
    name: str
    seed: int
    num_residents: int = 8
    active_ratio: float = 0.7
    memory_backend: str = "default"   # default / noisy
    planner: str = "default"          # default / random


class ABExperiment:
    """
    A/B 对照实验：跑两个配置，对比指标

    用法：
        exp = ABExperiment(
            A=ExperimentConfig("with_schedule", seed=42, planner="default"),
            B=ExperimentConfig("no_schedule", seed=42, planner="random"),
        )
        result = exp.run(num_ticks=15)
    """

    BACKENDS = {"default": DefaultMemory, "noisy": NoisyMemory}
    PLANNERS = {"default": DefaultPlanner, "random": RandomPlanner}

    def __init__(self, A: ExperimentConfig, B: ExperimentConfig):
        self.A = A
        self.B = B
        self.results: Dict[str, Any] = {}

    def _run_one(self, cfg: ExperimentConfig) -> Dict[str, Any]:
        planner_cls = self.PLANNERS.get(cfg.planner, DefaultPlanner)
        planner = planner_cls() if cfg.planner != "default" else None
        town = SandboxTown(
            num_residents=cfg.num_residents, seed=cfg.seed,
            active_ratio=cfg.active_ratio,
            planner=planner,
        )
        for t in range(self._num_ticks):
            town.step(t)
        report = town.generate_report()
        # 指标：社交总量、事件密度、居民活跃度
        return {
            "total_events": report["total_events"],
            "social": report["social_interactions"],
            "incidents": report["incidents"],
            "residents": report["residents"],
            "avg_energy": sum(r.energy for r in town.residents) / len(town.residents),
            "total_reflections": sum(len(r.reflections) for r in town.residents),
        }

    def run(self, num_ticks: int = 15) -> Dict[str, Any]:
        # 把 num_ticks 传给 _run_one
        self._num_ticks = num_ticks
        self.results["A"] = self._run_one(self.A)
        self.results["B"] = self._run_one(self.B)
        self.results["delta"] = {
            k: self.results["B"][k] - self.results["A"][k]
            for k in self.results["A"] if isinstance(self.results["A"][k], (int, float))
        }
        return self.results
