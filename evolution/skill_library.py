"""
evolution.skill_library — Skill 技能库

参考 Darwin-Agent / Hermes-Agent Closed-Loop 的 Skill 技能实体抽象：
id、版本号、描述、入参出参、python代码片段、历史评分。
"""
from __future__ import annotations
import json
import time
import uuid
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field, asdict


@dataclass
class Skill:
    """Skill 技能实体"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    description: str = ""
    version: str = "1.0.0"
    code: str = ""                          # python 代码片段
    input_schema: Dict[str, Any] = field(default_factory=dict)
    output_schema: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    # 评分历史
    fitness_history: List[float] = field(default_factory=list)
    current_fitness: float = 0.0
    use_count: int = 0
    success_count: int = 0
    # 安全
    security_level: str = "low"  # low / medium / high
    requires_sandbox: bool = True
    # 元数据
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    parent_skill_id: str = ""     # 父技能 ID（进化时记录）
    mutation_type: str = ""        # 变异类型

    @property
    def success_rate(self) -> float:
        if self.use_count == 0:
            return 0.0
        return self.success_count / self.use_count

    @property
    def is_elite(self) -> bool:
        return self.current_fitness >= 0.8

    def record_execution(self, success: bool, fitness: float = 0.0) -> None:
        """记录执行结果"""
        self.use_count += 1
        if success:
            self.success_count += 1
        if fitness > 0:
            self.fitness_history.append(fitness)
            self.current_fitness = sum(self.fitness_history[-10:]) / min(10, len(self.fitness_history))
        self.updated_at = time.time()

    def clone(self) -> "Skill":
        """克隆技能（用于进化）"""
        new = Skill(
            name=self.name,
            description=self.description,
            code=self.code,
            input_schema=dict(self.input_schema),
            output_schema=dict(self.output_schema),
            tags=list(self.tags),
            security_level=self.security_level,
            requires_sandbox=self.requires_sandbox,
            parent_skill_id=self.id,
        )
        return new

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Skill":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class SkillLibrary:
    """
    Skill 技能库

    功能：
    - 技能的增删改查
    - 按标签/评分/安全等级筛选
    - 技能版本管理和回滚
    - 技能进化（变异/交叉）
    """
    def __init__(self):
        self.skills: Dict[str, Skill] = {}
        self.version_history: Dict[str, List[Skill]] = {}

    def add(self, skill: Skill) -> str:
        """添加技能"""
        self.skills[skill.id] = skill
        if skill.id not in self.version_history:
            self.version_history[skill.id] = []
        self.version_history[skill.id].append(skill)
        return skill.id

    def get(self, skill_id: str) -> Optional[Skill]:
        """获取技能"""
        return self.skills.get(skill_id)

    def get_by_name(self, name: str) -> Optional[Skill]:
        """按名称获取技能"""
        for skill in self.skills.values():
            if skill.name == name:
                return skill
        return None

    def remove(self, skill_id: str) -> bool:
        """删除技能"""
        if skill_id in self.skills:
            del self.skills[skill_id]
            return True
        return False

    def list(self, tag: str = "", min_fitness: float = 0.0,
             security_level: str = "") -> List[Skill]:
        """列出技能（可筛选）"""
        result = list(self.skills.values())
        if tag:
            result = [s for s in result if tag in s.tags]
        if min_fitness > 0:
            result = [s for s in result if s.current_fitness >= min_fitness]
        if security_level:
            result = [s for s in result if s.security_level == security_level]
        return sorted(result, key=lambda s: s.current_fitness, reverse=True)

    def get_elite(self, n: int = 5) -> List[Skill]:
        """获取精英技能"""
        return self.list(min_fitness=0.8)[:n]

    def evolve_skill(self, skill_id: str, new_code: str,
                      mutation_type: str = "manual") -> Optional[Skill]:
        """
        进化技能（创建新版本）

        参考 Darwin-Agent Closed-Learning-Loop：
        触发 → review → 写回 → 注入
        """
        old_skill = self.get(skill_id)
        if not old_skill:
            return None

        new_skill = old_skill.clone()
        new_skill.id = old_skill.id  # 保持相同 id（同一技能的新版本）
        new_skill.code = new_code
        new_skill.mutation_type = mutation_type
        new_skill.version = self._bump_version(old_skill.version)
        new_skill.current_fitness = 0.0  # 新版本需要重新评估

        self.add(new_skill)
        return new_skill

    def rollback(self, skill_id: str, version: str = "") -> Optional[Skill]:
        """回滚到指定版本"""
        history = self.version_history.get(skill_id, [])
        if not history:
            return None

        if version:
            for s in history:
                if s.version == version:
                    self.skills[skill_id] = s
                    return s
        else:
            # 回滚到上一个版本
            if len(history) >= 2:
                prev = history[-2]
                self.skills[skill_id] = prev
                return prev

        return None

    def _bump_version(self, version: str) -> str:
        """版本号 +1"""
        parts = version.split(".")
        if len(parts) == 3:
            try:
                parts[2] = str(int(parts[2]) + 1)
                return ".".join(parts)
            except ValueError:
                pass
        return version + "_1"

    def save(self, filepath: str) -> None:
        """保存技能库到文件"""
        data = {
            "skills": [s.to_dict() for s in self.skills.values()],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, filepath: str) -> "SkillLibrary":
        """从文件加载技能库"""
        lib = cls()
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        for d in data.get("skills", []):
            skill = Skill.from_dict(d)
            lib.skills[skill.id] = skill
        return lib

    def __len__(self) -> int:
        return len(self.skills)
