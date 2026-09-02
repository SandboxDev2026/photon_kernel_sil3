"""
evolution.individual — 遗传算法个体抽象

几乎所有开源GA项目(EvoPrompt/AutoEvolve/DarwinAgent)的标准个体结构。
payload 可以存 prompt / code / skill 配置。
"""
from __future__ import annotations
import uuid
import time
import json
import copy
from typing import Any, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class Individual:
    """遗传算法个体 — 标准抽象，几乎所有开源项目都这么写"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    gen: int = 0                          # 第几代
    payload: dict = field(default_factory=dict)  # 可以存 prompt / code / skill 配置
    fitness: float = 0.0                  # 适应度分数 (0.0 - 1.0)
    test_pass: int = 0                    # 通过的测试数
    test_total: int = 0                   # 总测试数
    fail_cases: list = field(default_factory=list)  # 失败用例记录
    parent_ids: list = field(default_factory=list)  # 父代ID（交叉时记录）
    mutation_type: str = ""               # 变异类型（rewrite/patch/nl_feedback）
    created_at: float = field(default_factory=time.time)
    evaluated: bool = False               # 是否已评估
    # 安全相关
    security_alerts: list = field(default_factory=list)  # 安全告警记录
    sandbox_violations: int = 0           # 沙盒违规次数

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:8]

    @property
    def pass_rate(self) -> float:
        """测试通过率"""
        if self.test_total == 0:
            return 0.0
        return self.test_pass / self.test_total

    @property
    def is_elite(self) -> bool:
        """是否是精英个体（适应度 > 0.8）"""
        return self.fitness >= 0.8

    def clone(self) -> "Individual":
        """深拷贝个体（用于变异/交叉）"""
        new = copy.deepcopy(self)
        new.id = str(uuid.uuid4())[:8]
        new.parent_ids = [self.id]
        new.fitness = 0.0
        new.test_pass = 0
        new.evaluated = False
        new.security_alerts = []
        new.sandbox_violations = 0
        new.created_at = time.time()
        return new

    def to_dict(self) -> dict:
        """序列化（用于快照存储）"""
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Individual":
        """从快照恢复"""
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def to_json(self, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def __repr__(self) -> str:
        return (f"Individual(id={self.id}, gen={self.gen}, "
                f"fitness={self.fitness:.3f}, pass={self.test_pass}/{self.test_total}, "
                f"violations={self.sandbox_violations})")
