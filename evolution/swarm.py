"""
evolution.swarm — JiuwenSwarm 蜂群多智能体

多Agent种群协同架构：
- 个体变异：每个 Agent 有独立的 Skill 集合和参数，可变异
- 技能迁移：优秀 Agent 的 Skill 可以迁移到其他 Agent
- 种群协同：多个 Agent 并行处理任务，结果汇总
- 遗传调度：用遗传算法调度 Agent 种群，优胜劣汰

设计参考：
- 蜂群算法（ABC, Artificial Bee Colony）：雇佣蜂、观察蜂、侦察蜂
- 遗传算法种群：选择、变异、交叉
- 多智能体协同：任务分配、结果聚合
- Skill 迁移：优秀个体的 Skill 横向传播

与 PhotonBox 沙盒集成：
- 每个 Agent 的代码执行通过沙盒
- Agent 变异产生的新代码必须经过安全门控
- 种群调度的风险评估对接 RiskScorer
"""
from __future__ import annotations
import json
import time
import random
import hashlib
from typing import List, Optional, Dict, Any, Callable, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from .individual import Individual
from .skill_library import Skill, SkillLibrary
from .selector import TournamentSelector
from .llm_adapter import BaseLLMAdapter, MockLLMAdapter


class AgentRole(Enum):
    """Agent 角色（参考蜂群算法）"""
    EMPLOYED = "employed"      # 雇佣蜂：负责开发已知食物源（执行已知任务）
    ONLOOKER = "onlooker"      # 观察蜂：根据雇佣蜂的信息选择食物源（选择优秀任务）
    SCOUT = "scout"            # 侦察蜂：随机探索新食物源（探索新任务/新 Skill）


@dataclass
class SwarmAgent:
    """
    蜂群智能体

    每个 Agent 有：
    - 独立的 Skill 集合（可变异）
    - 角色（雇佣蜂/观察蜂/侦察蜂）
    - 适应度（任务成功率）
    - 任务历史
    """
    agent_id: str = field(default_factory=lambda: f"agent_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}")
    name: str = ""
    role: AgentRole = AgentRole.EMPLOYED
    skills: List[str] = field(default_factory=list)  # Skill ID 列表
    fitness: float = 0.0
    tasks_completed: int = 0
    tasks_failed: int = 0
    total_reward: float = 0.0
    mutation_rate: float = 0.1
    generation: int = 0
    parent_ids: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)

    @property
    def success_rate(self) -> float:
        total = self.tasks_completed + self.tasks_failed
        if total == 0:
            return 0.0
        return self.tasks_completed / total

    @property
    def is_elite(self) -> bool:
        return self.fitness >= 0.8

    def record_task(self, success: bool, reward: float = 0.0) -> None:
        """记录任务结果"""
        if success:
            self.tasks_completed += 1
        else:
            self.tasks_failed += 1
        self.total_reward += reward
        self.fitness = self.total_reward / max(1, self.tasks_completed + self.tasks_failed)
        self.last_active = time.time()

    def clone(self) -> "SwarmAgent":
        """克隆 Agent（用于繁殖）"""
        new = SwarmAgent(
            name=f"{self.name}_child",
            role=self.role,
            skills=list(self.skills),
            mutation_rate=self.mutation_rate,
            generation=self.generation + 1,
            parent_ids=[self.agent_id],
        )
        return new

    def to_dict(self) -> dict:
        d = asdict(self)
        d["role"] = self.role.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "SwarmAgent":
        d["role"] = AgentRole(d.get("role", "employed"))
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class TaskAssignment:
    """任务分配"""
    task_id: str
    task_content: str
    agent_id: str
    assigned_at: float = field(default_factory=time.time)
    completed: bool = False
    success: bool = False
    result: str = ""
    reward: float = 0.0
    completed_at: float = 0.0


class JiuwenSwarm:
    """
    JiuwenSwarm 蜂群多智能体种群

    核心机制：
    1. 种群协同：多个 Agent 并行处理任务
    2. 个体变异：Agent 的 Skill 集合和参数可变异
    3. 技能迁移：优秀 Agent 的 Skill 迁移到其他 Agent
    4. 遗传调度：优胜劣汰，优秀 Agent 繁殖，差的淘汰
    5. 角色动态切换：雇佣蜂→观察蜂→侦察蜂

    蜂群算法流程（参考 ABC）：
    1. 雇佣蜂阶段：每个雇佣蜂开发已知食物源（执行已知任务）
    2. 观察蜂阶段：观察蜂根据雇佣蜂的信息选择食物源（选择优秀任务）
    3. 侦察蜂阶段：侦察蜂随机探索新食物源（探索新任务/新 Skill）
    4. 种群更新：优胜劣汰，优秀个体繁殖
    """

    def __init__(self,
                 skill_library: SkillLibrary,
                 llm: Optional[BaseLLMAdapter] = None,
                 population_size: int = 20,
                 elite_count: int = 3,
                 mutation_rate: float = 0.1,
                 migration_rate: float = 0.2,
                 scout_ratio: float = 0.1,
                 task_executor: Optional[Callable[[str, str], Tuple[bool, str, float]]] = None,
                 security_gate: Optional[Callable[[str], bool]] = None):
        self.skill_library = skill_library
        self.llm = llm or MockLLMAdapter()
        self.population_size = population_size
        self.elite_count = elite_count
        self.mutation_rate = mutation_rate
        self.migration_rate = migration_rate
        self.scout_ratio = scout_ratio
        self.task_executor = task_executor
        self.security_gate = security_gate or (lambda code: True)

        self.agents: List[SwarmAgent] = []
        self.task_queue: List[Dict[str, Any]] = []
        self.assignments: List[TaskAssignment] = []
        self.selector = TournamentSelector(tournament_size=3)

        # 统计
        self.generations_run = 0
        self.total_tasks_processed = 0
        self.skill_migrations_done = 0
        self.mutations_done = 0

    # ==================== 种群初始化 ====================

    def initialize(self, seed_skills: List[str] = None) -> None:
        """
        初始化种群

        Args:
            seed_skills: 初始 Skill ID 列表，每个 Agent 随机分配子集
        """
        seed_skills = seed_skills or []
        roles = [AgentRole.EMPLOYED, AgentRole.ONLOOKER, AgentRole.SCOUT]

        for i in range(self.population_size):
            # 随机分配角色（大部分雇佣蜂，少量观察蜂和侦察蜂）
            r = random.random()
            if r < self.scout_ratio:
                role = AgentRole.SCOUT
            elif r < self.scout_ratio + 0.3:
                role = AgentRole.ONLOOKER
            else:
                role = AgentRole.EMPLOYED

            # 随机分配 Skill 子集
            agent_skills = []
            if seed_skills:
                n_skills = random.randint(1, min(3, len(seed_skills)))
                agent_skills = random.sample(seed_skills, n_skills)

            agent = SwarmAgent(
                name=f"agent_{i:03d}",
                role=role,
                skills=agent_skills,
                mutation_rate=self.mutation_rate * random.uniform(0.5, 1.5),
            )
            self.agents.append(agent)

    # ==================== 任务分配与执行 ====================

    def submit_task(self, task_content: str, task_id: str = "") -> str:
        """提交任务到队列"""
        if not task_id:
            task_id = f"task_{int(time.time()*1000)}_{random.randint(0,9999)}"
        self.task_queue.append({"task_id": task_id, "content": task_content})
        return task_id

    def assign_tasks(self) -> List[TaskAssignment]:
        """
        分配任务给 Agent（蜂群算法的雇佣蜂+观察蜂阶段）

        策略：
        - 雇佣蜂：按适应度优先分配任务
        - 观察蜂：选择适应度高的 Agent 的任务（跟随优秀者）
        - 侦察蜂：随机分配任务（探索）
        """
        assignments = []
        if not self.task_queue:
            return assignments

        # 按角色分组
        employed = [a for a in self.agents if a.role == AgentRole.EMPLOYED]
        onlookers = [a for a in self.agents if a.role == AgentRole.ONLOOKER]
        scouts = [a for a in self.agents if a.role == AgentRole.SCOUT]

        # 雇佣蜂优先分配（按适应度排序）
        employed.sort(key=lambda a: a.fitness, reverse=True)

        task_idx = 0
        for agent in employed:
            if task_idx >= len(self.task_queue):
                break
            task = self.task_queue[task_idx]
            assignment = TaskAssignment(
                task_id=task["task_id"],
                task_content=task["content"],
                agent_id=agent.agent_id,
            )
            assignments.append(assignment)
            task_idx += 1

        # 观察蜂：跟随优秀雇佣蜂（选择相同类型的任务）
        for agent in onlookers:
            if task_idx >= len(self.task_queue):
                break
            # 观察蜂选择适应度最高的雇佣蜂正在处理的任务类型
            if employed:
                best_employed = max(employed, key=lambda a: a.fitness)
                # 简化：分配下一个任务
                task = self.task_queue[task_idx]
                assignment = TaskAssignment(
                    task_id=task["task_id"],
                    task_content=task["content"],
                    agent_id=agent.agent_id,
                )
                assignments.append(assignment)
                task_idx += 1

        # 侦察蜂：随机分配（探索新任务）
        for agent in scouts:
            if task_idx >= len(self.task_queue):
                break
            task = random.choice(self.task_queue[task_idx:]) if task_idx < len(self.task_queue) else None
            if task:
                assignment = TaskAssignment(
                    task_id=task["task_id"],
                    task_content=task["content"],
                    agent_id=agent.agent_id,
                )
                assignments.append(assignment)
                task_idx += 1

        # 移除已分配的任务
        assigned_ids = {a.task_id for a in assignments}
        self.task_queue = [t for t in self.task_queue if t["task_id"] not in assigned_ids]
        self.assignments.extend(assignments)
        return assignments

    def execute_assignments(self) -> List[TaskAssignment]:
        """
        执行所有已分配的任务

        如果设置了 task_executor，使用它执行；否则模拟执行。
        """
        completed = []
        for assignment in self.assignments:
            if assignment.completed:
                continue

            agent = self._get_agent(assignment.agent_id)
            if not agent:
                continue

            if self.task_executor:
                success, result, reward = self.task_executor(assignment.task_content, assignment.agent_id)
            else:
                # 模拟执行：根据 Agent 适应度随机决定成功
                success = random.random() < (0.3 + agent.fitness * 0.6)
                result = f"{'Success' if success else 'Failed'}: {assignment.task_content[:50]}"
                reward = 1.0 if success else 0.0

            assignment.completed = True
            assignment.success = success
            assignment.result = result
            assignment.reward = reward
            assignment.completed_at = time.time()

            agent.record_task(success, reward)
            completed.append(assignment)
            self.total_tasks_processed += 1

        return completed

    # ==================== 个体变异 ====================

    def mutate_agent(self, agent: SwarmAgent) -> SwarmAgent:
        """
        个体变异

        变异类型：
        1. Skill 集合变异：添加/删除/替换 Skill
        2. 参数变异：mutation_rate 调整
        3. 角色变异：角色切换
        """
        if random.random() > agent.mutation_rate:
            return agent

        mutation_type = random.choice(["add_skill", "remove_skill", "replace_skill", "param", "role"])

        if mutation_type == "add_skill" and self.skill_library:
            available = [s.id for s in self.skill_library.skills.values() if s.id not in agent.skills]
            if available:
                new_skill = random.choice(available)
                # 安全门控：检查 Skill 代码
                skill_obj = self.skill_library.get(new_skill)
                if skill_obj and self.security_gate(skill_obj.code):
                    agent.skills.append(new_skill)
                    self.mutations_done += 1

        elif mutation_type == "remove_skill" and len(agent.skills) > 1:
            removed = random.choice(agent.skills)
            agent.skills.remove(removed)
            self.mutations_done += 1

        elif mutation_type == "replace_skill" and self.skill_library and agent.skills:
            available = [s.id for s in self.skill_library.skills.values() if s.id not in agent.skills]
            if available:
                old = random.choice(agent.skills)
                new = random.choice(available)
                skill_obj = self.skill_library.get(new)
                if skill_obj and self.security_gate(skill_obj.code):
                    agent.skills.remove(old)
                    agent.skills.append(new)
                    self.mutations_done += 1

        elif mutation_type == "param":
            agent.mutation_rate *= random.uniform(0.8, 1.2)
            agent.mutation_rate = max(0.01, min(0.5, agent.mutation_rate))
            self.mutations_done += 1

        elif mutation_type == "role":
            roles = list(AgentRole)
            agent.role = random.choice([r for r in roles if r != agent.role])
            self.mutations_done += 1

        return agent

    # ==================== 技能迁移 ====================

    def migrate_skills(self) -> int:
        """
        技能迁移：优秀 Agent 的 Skill 迁移到其他 Agent

        策略：
        1. 找出精英 Agent（fitness >= 0.8）
        2. 找出低适应度 Agent（fitness < 0.3）
        3. 以 migration_rate 概率，将精英的 Skill 迁移给低适应度 Agent
        4. 迁移前经过安全门控

        Returns:
            迁移次数
        """
        elites = [a for a in self.agents if a.is_elite]
        low_fitness = [a for a in self.agents if a.fitness < 0.3 and not a.is_elite]

        if not elites or not low_fitness:
            return 0

        migrations = 0
        for elite in elites:
            for agent in low_fitness:
                if random.random() > self.migration_rate:
                    continue

                # 选择精英有但目标没有的 Skill
                available = [s for s in elite.skills if s not in agent.skills]
                if not available:
                    continue

                skill_to_migrate = random.choice(available)
                skill_obj = self.skill_library.get(skill_to_migrate)

                # 安全门控
                if skill_obj and self.security_gate(skill_obj.code):
                    agent.skills.append(skill_to_migrate)
                    migrations += 1

        self.skill_migrations_done += migrations
        return migrations

    # ==================== 遗传调度：种群更新 ====================

    def evolve_population(self) -> None:
        """
        遗传调度：种群更新（优胜劣汰）

        流程：
        1. 精英保留：Top-N 精英直接保留
        2. 选择：锦标赛选择父代
        3. 变异：子代变异
        4. 淘汰：替换适应度最低的个体
        """
        if len(self.agents) < self.population_size:
            return

        # 按适应度排序
        self.agents.sort(key=lambda a: a.fitness, reverse=True)

        # 精英保留
        elites = self.agents[:self.elite_count]

        # 选择父代（非精英中选择）
        parents = self.selector.select(self.agents[self.elite_count:],
                                         n=self.population_size - self.elite_count)

        # 产生子代（克隆 + 变异）
        offspring = []
        for parent in parents:
            child = parent.clone()
            child = self.mutate_agent(child)
            offspring.append(child)

        # 技能迁移
        self.migrate_skills()

        # 更新种群
        self.agents = elites + offspring
        self.generations_run += 1

    # ==================== 完整蜂群循环 ====================

    def run_cycle(self) -> Dict[str, Any]:
        """
        运行一个完整的蜂群循环

        流程：
        1. 任务分配（雇佣蜂+观察蜂+侦察蜂）
        2. 任务执行
        3. 个体变异
        4. 技能迁移
        5. 种群更新（遗传调度）

        Returns:
            循环统计
        """
        start = time.time()

        # 1. 任务分配
        assignments = self.assign_tasks()

        # 2. 任务执行
        completed = self.execute_assignments()

        # 3. 个体变异（随机选择部分 Agent）
        n_mutate = int(len(self.agents) * 0.3)
        for agent in random.sample(self.agents, min(n_mutate, len(self.agents))):
            self.mutate_agent(agent)

        # 4. 技能迁移
        migrations = self.migrate_skills()

        # 5. 种群更新（每 5 个循环进化一次）
        if self.generations_run % 5 == 0:
            self.evolve_population()

        elapsed = time.time() - start
        return {
            "cycle": self.generations_run,
            "tasks_assigned": len(assignments),
            "tasks_completed": len(completed),
            "success_rate": sum(1 for c in completed if c.success) / max(1, len(completed)),
            "mutations": self.mutations_done,
            "skill_migrations": migrations,
            "population_size": len(self.agents),
            "avg_fitness": sum(a.fitness for a in self.agents) / len(self.agents),
            "elapsed_ms": int(elapsed * 1000),
        }

    # ==================== 工具方法 ====================

    def _get_agent(self, agent_id: str) -> Optional[SwarmAgent]:
        for a in self.agents:
            if a.agent_id == agent_id:
                return a
        return None

    def get_best_agents(self, n: int = 5) -> List[SwarmAgent]:
        """获取最佳 Agent"""
        return sorted(self.agents, key=lambda a: a.fitness, reverse=True)[:n]

    def get_stats(self) -> Dict[str, Any]:
        """获取种群统计"""
        return {
            "population_size": len(self.agents),
            "generations_run": self.generations_run,
            "total_tasks_processed": self.total_tasks_processed,
            "mutations_done": self.mutations_done,
            "skill_migrations_done": self.skill_migrations_done,
            "avg_fitness": sum(a.fitness for a in self.agents) / max(1, len(self.agents)),
            "best_fitness": max(a.fitness for a in self.agents) if self.agents else 0,
            "elite_count": sum(1 for a in self.agents if a.is_elite),
            "role_distribution": {
                "employed": sum(1 for a in self.agents if a.role == AgentRole.EMPLOYED),
                "onlooker": sum(1 for a in self.agents if a.role == AgentRole.ONLOOKER),
                "scout": sum(1 for a in self.agents if a.role == AgentRole.SCOUT),
            },
        }

    def save(self, filepath: str) -> None:
        """保存种群状态"""
        data = {
            "agents": [a.to_dict() for a in self.agents],
            "stats": self.get_stats(),
            "config": {
                "population_size": self.population_size,
                "elite_count": self.elite_count,
                "mutation_rate": self.mutation_rate,
                "migration_rate": self.migration_rate,
            },
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
