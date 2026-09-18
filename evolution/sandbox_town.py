"""
Sandbox Town — PhotonBox 沙盒小镇

在安全沙盒中运行的 AI 多智能体小镇模拟：
- 居民：名字、职业、性格、家、位置、短期记忆、关系图谱
- 地点：网格地图上的功能区（家、咖啡馆、公园、工厂、市场）
- 日常循环：醒来→移动→活动→社交→回家
- 社交：同地点相遇触发对话，关系信任度动态变化
- 突发事件：随机注入（火灾、八卦、新居民），居民记忆并传播
- 输出：事件日志流 + 关系图谱快照（与 RealDataAdapter 事件格式兼容）

设计原则（借鉴 AI-Town / Generative Agents）：
- 内核（本模块）与渲染完全解耦，只输出标准事件流
- 规则驱动，无 LLM API 依赖，可离线批量跑
- 居民记忆复用 memory_engine.ShortTermMemory
"""

from __future__ import annotations

import random
import time
import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any

from evolution.memory_engine import ShortTermMemory


class Personality(Enum):
    """性格倾向"""
    OUTGOING = "outgoing"      # 外向：爱社交，主动搭话
    INTROVERT = "introvert"    # 内向：少社交，独来独往
    CURIOUS = "curious"        # 好奇：爱探索新地点
    CAUTIOUS = "cautious"      # 谨慎：避开冲突，晚归早回


class LocationType(Enum):
    HOME = "home"
    CAFE = "cafe"
    PARK = "park"
    FACTORY = "factory"
    MARKET = "market"
    SQUARE = "square"


class ActivityType(Enum):
    SLEEPING = "sleeping"
    WAKING = "waking"
    MOVING = "moving"
    WORKING = "working"
    SOCIALIZING = "socializing"
    EATING = "eating"
    EXPLORING = "exploring"
    EVENT_REACTING = "event_reacting"


@dataclass
class TownLocation:
    """小镇地点"""
    loc_id: str
    name: str
    loc_type: LocationType
    x: int
    y: int
    capacity: int = 10


@dataclass
class TownEvent:
    """小镇事件（与 SecurityEvent 风格一致，便于审计）"""
    event_id: str
    tick: int
    event_type: str            # social / incident / gossip / move / work
    actor: str                 # 居民名
    location: str
    description: str
    target: Optional[str] = None
    severity: str = "info"     # info / notice / warning / critical
    timestamp: float = field(default_factory=time.time)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TownResident:
    """小镇居民"""

    FAMALE_NAMES = ["林夏", "苏晚", "陈墨", "周野", "沈星", "叶知秋", "顾清", "白露"]
    MALE_NAMES = ["陈默", "江离", "赵山河", "周正", "吴忧", "郑好", "王拓", "李野"]
    PROFESSIONS = ["木匠", "咖啡师", "园丁", "教师", "厨师", "医生", "程序员", "诗人"]

    def __init__(self, name: str, home: TownLocation,
                 personality: Personality = Personality.OUTGOING,
                 profession: str = "居民"):
        self.name = name
        self.home = home
        self.personality = personality
        self.profession = profession
        self.location = home
        self.memory = ShortTermMemory(max_items=30, ttl_seconds=86400 * 7)
        # 关系图谱：对方居民名 -> 信任度 0.0(敌对)..1.0(信任)
        self.relationships: Dict[str, float] = {}
        self.energy: float = 1.0           # 精力 0-1
        self.money: float = 100.0
        self.social_score: float = 0.0     # 社交活跃度
        self.event_count: int = 0
        # 反思层（借鉴 Generative Agents 的 Memory Stream）
        self.reflections: List[Dict[str, Any]] = []
        self._memories_since_reflection: int = 0

    def remember(self, content: str, importance: float = 0.5,
                 tags: List[str] = None) -> str:
        """记录一条记忆，并累积待反思计数"""
        self._memories_since_reflection += 1
        return self.memory.add(content, importance=importance,
                               tags=tags or [], source_task="town")

    def reflect(self) -> Optional[str]:
        """
        反思：从近期记忆中提炼高阶洞察（Generative Agents 核心机制）

        当累积记忆达到阈值时，从短期记忆中抽取：
        - 高频社交对象（关系图谱里信任度最高的人）
        - 最近事件印象
        合成一条反思，写入长期反思列表。
        """
        if self._memories_since_reflection < 5:
            return None

        # 找最常来往的人
        if self.relationships:
            top_friend = max(self.relationships, key=self.relationships.get)
            reflection = (
                f"我觉得{top_friend}是我在镇上最聊得来的人，"
                f"相处久了对他/她更信任了。"
            )
        elif self.energy < 0.3:
            reflection = "最近有点累，得好好休息一下。"
        else:
            reflection = "今天镇上还算平静，没什么特别的事。"

        self.reflections.append({
            "content": reflection,
            "tick": int(time.time()),
            "memory_count": self._memories_since_reflection,
        })
        self._memories_since_reflection = 0
        return reflection

    def plan_day(self, tick: int, locations: Dict[str, TownLocation]) -> TownLocation:
        """
        按 tick 时段规划今天的去向（Generative Agents 日程机制）

        一天 8 tick：
        - 0-1 早上：工厂工作
        - 2-3 中午：咖啡馆
        - 4-5 下午：市场/公园
        - 6-7 晚上：广场社交
        """
        hour = tick % 8
        if hour in (0, 1):
            return locations.get("factory", self.home)
        if hour in (2, 3):
            return locations.get("cafe", self.home)
        if hour in (4, 5):
            # 好奇型爱去公园，其他人去市场
            if self.personality == Personality.CURIOUS:
                return locations.get("park", self.home)
            return locations.get("market", self.home)
        return locations.get("square", self.home)

    def move_to(self, loc: TownLocation) -> None:
        self.location = loc
        self.energy = max(0.0, self.energy - 0.05)

    def work(self, hours: int = 4) -> float:
        """工作赚钱"""
        earned = hours * random.uniform(8, 25)  # nosec B311 - 小镇模拟，非加密用途
        self.money += earned
        self.energy = max(0.0, self.energy - hours * 0.08)
        return earned

    def socialize(self, other: "TownResident") -> str:
        """和另一位居民社交，返回对话内容，更新关系"""
        if other.name == self.name:
            return ""
        # 性格影响社交意愿
        base_will = {
            Personality.OUTGOING: 0.9,
            Personality.CURIOUS: 0.7,
            Personality.INTROVERT: 0.3,
            Personality.CAUTIOUS: 0.4,
        }[self.personality]
        if random.random() > base_will:  # nosec B311 - 小镇模拟，非加密用途
            self.social_score -= 0.05
            return ""

        # 更新信任度
        old = self.relationships.get(other.name, 0.5)
        delta = random.uniform(-0.05, 0.15)  # nosec B311 - 小镇模拟，非加密用途
        self.relationships[other.name] = max(0.0, min(1.0, old + delta))
        other.relationships[self.name] = max(0.0, min(1.0,
            other.relationships.get(self.name, 0.5) + delta * 0.8))

        self.social_score += 0.1
        dialogues = [
            f"{self.name}：最近过得怎么样？",
            f"{self.name}：听说镇上发生了点事。",
            f"{self.name}：你听说{other.name}的新鲜事了吗？",
            f"{self.name}：天气不错，适合出去走走。",
            f"{self.name}：我最近在忙{self.profession}的事。",
        ]
        line = random.choice(dialogues)  # nosec B311 - 小镇模拟，非加密用途
        self.remember(f"和{other.name}在{self.location.name}聊天", importance=0.4,
                      tags=["social", other.name])
        return line

    def rest(self, hours: float = 6.0) -> None:
        self.energy = min(1.0, self.energy + hours * 0.15)

    def react_to_event(self, event: TownEvent) -> str:
        """对突发事件的反应"""
        reactions = {
            "fire": f"{self.name} 匆忙跑去帮忙",
            "gossip": f"{self.name} 把消息告诉了旁边的人",
            "newcomer": f"{self.name} 热情欢迎新居民",
            "market": f"{self.name} 去市场看看有什么便宜货",
        }
        result = reactions.get(event.event_type, f"{self.name} 注意到了{event.description}")
        self.remember(f"事件：{event.description}", importance=0.8,
                      tags=["event", event.event_type])
        return result

    def stats(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "profession": self.profession,
            "personality": self.personality.value,
            "location": self.location.name,
            "energy": round(self.energy, 2),
            "money": round(self.money, 1),
            "social_score": round(self.social_score, 2),
            "known_people": len(self.relationships),
            "memories": len(self.memory._items),
            "reflections": len(self.reflections),
        }


class SandboxTown:
    """
    PhotonBox 沙盒小镇

    用法：
        town = SandboxTown(grid_size=8, num_residents=12, seed=42)
        for tick in range(20):
            town.step(tick)
        report = town.generate_report()
    """

    INCIDENT_POOL = [
        ("fire", "咖啡馆突然冒出浓烟", "warning"),
        ("gossip", "市场有人在传离奇八卦", "info"),
        ("newcomer", "镇上来了一位陌生人", "info"),
        ("market", "市场大减价，吸引了很多人", "info"),
    ]

    def __init__(self, grid_size: int = 8, num_residents: int = 10,
                 seed: int = 42, active_ratio: float = 0.7,
                 planner: Any = None):
        self.rng = random.Random(seed)  # nosec B311 - 小镇模拟，非加密用途
        random.seed(seed)  # nosec B311 - 小镇模拟，非加密用途
        self.grid_size = grid_size
        self.active_ratio = active_ratio  # 微内核：每tick活跃居民比例
        self.planner = planner  # 可插拔规划器（None=用resident.plan_day）
        self.tick_count = 0
        self.residents: List[TownResident] = []
        self.locations: Dict[str, TownLocation] = {}
        self.event_log: List[TownEvent] = []
        self._build_locations()
        self._spawn_residents(num_residents)

    # ---------- 初始化 ----------

    def _build_locations(self) -> None:
        specs = [
            ("square", "中心广场", LocationType.SQUARE, 4, 4, 20),
            ("cafe", "街角咖啡馆", LocationType.CAFE, 3, 4, 8),
            ("park", "滨河公园", LocationType.PARK, 2, 6, 15),
            ("factory", "老木匠铺", LocationType.FACTORY, 5, 3, 6),
            ("market", "周末市场", LocationType.MARKET, 5, 5, 12),
        ]
        for loc_id, name, lt, x, y, cap in specs:
            self.locations[loc_id] = TownLocation(loc_id, name, lt, x, y, cap)

    def _spawn_residents(self, n: int) -> None:
        pool = TownResident.FAMALE_NAMES + TownResident.MALE_NAMES
        chosen = self.rng.sample(pool, min(n, len(pool)))
        homes = list(self.locations.values())
        for i, name in enumerate(chosen):
            home = self.locations["square"]  # 都住广场附近
            personality = self.rng.choice(list(Personality))
            prof = self.rng.choice(TownResident.PROFESSIONS)
            self.residents.append(TownResident(name, home, personality, prof))

    # ---------- 事件 ----------

    def _log(self, event_type: str, actor: str, location: str,
             description: str, target: Optional[str] = None,
             severity: str = "info") -> TownEvent:
        ev = TownEvent(
            event_id=hashlib.md5(
                f"{self.tick_count}{actor}{description}{time.time()}".encode(),
                usedforsecurity=False).hexdigest()[:10],
            tick=self.tick_count,
            event_type=event_type,
            actor=actor,
            location=location,
            description=description,
            target=target,
            severity=severity,
        )
        self.event_log.append(ev)
        return ev

    def inject_incident(self, kind: Optional[str] = None) -> TownEvent:
        """注入突发事件"""
        kind, desc, sev = self.rng.choice(self.INCIDENT_POOL) if kind is None else \
            next(((k, d, s) for k, d, s in self.INCIDENT_POOL if k == kind),
                 ("gossip", "小镇出了点事", "info"))
        ev = self._log("incident", town_name := "小镇", "中心广场", desc, severity=sev)
        # 通知所有居民
        for r in self.residents:
            r.react_to_event(ev)
        return ev

    # ---------- 每 tick ----------

    def _select_active_residents(self, tick: int) -> List[TownResident]:
        """
        微内核调度：每tick只激活一部分居民（借鉴 Agent-Kernel 分层调度）

        活跃居民：执行完整行为（移动+工作+社交+反思）
        休眠居民：只休息，不参与社交，不消耗"LLM调用"成本
        活跃名单每 8 tick 轮换一次
        """
        n_active = max(1, int(len(self.residents) * self.active_ratio))
        rotation_offset = (tick // 8) % max(1, len(self.residents))
        ordered = self.residents[rotation_offset:] + self.residents[:rotation_offset]
        return ordered[:n_active]

    def step(self, tick: int) -> Dict[str, Any]:
        """推进一步小镇时间（微内核调度：活跃/休眠分层）"""
        self.tick_count = tick
        actions: List[str] = []

        # 1. 微内核调度：选活跃居民
        active = self._select_active_residents(tick)
        active_names = {r.name for r in active}

        # 2. 休眠居民只休息
        for r in self.residents:
            if r.name not in active_names:
                r.rest(1)
                continue
            # 活跃居民的作息
            if tick % 8 == 0:
                r.rest(4)
                actions.append(f"{r.name} 在家休息")

        # 3. 活跃居民按日程移动
        for r in active:
            if r.energy < 0.15:
                r.rest(3)
                continue
            # 可插拔规划器：有 planner 用 planner.plan()，否则用 resident.plan_day()
            if self.planner is not None:
                target = self.planner.plan(r, tick, self.locations)
            else:
                target = r.plan_day(tick, self.locations)
            r.move_to(target)

        # 4. 活跃居民工作
        for r in active:
            if r.location.loc_type == LocationType.FACTORY:
                earned = r.work(2)
                actions.append(f"{r.name} 在{self.locations['factory'].name} 赚了 ${earned:.1f}")

        # 5. 社交：同一地点的活跃居民相遇
        by_loc: Dict[str, List[TownResident]] = {}
        for r in active:
            by_loc.setdefault(r.location.loc_id, []).append(r)
        for loc_id, group in by_loc.items():
            if len(group) < 2:
                continue
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    line = group[i].socialize(group[j])
                    if line:
                        self._log("social", group[i].name,
                                  group[i].location.name, line,
                                  target=group[j].name)

        # 6. 随机突发事件（约 20% 概率）
        if self.rng.random() < 0.2:
            self.inject_incident()

        # 7. 反思层：活跃居民中累积记忆足够多的生成洞察
        for r in active:
            reflection = r.reflect()
            if reflection:
                self._log("reflection", r.name, r.location.name, reflection)

        return {
            "tick": tick,
            "events": len([e for e in self.event_log if e.tick == tick]),
            "residents_active": len(self.residents),
            "actions": actions,
        }

    # ---------- 报告 ----------

    def relationship_graph(self) -> Dict[str, Any]:
        """导出关系图谱：边列表"""
        edges = []
        seen = set()
        for r in self.residents:
            for other, trust in r.relationships.items():
                pair = tuple(sorted([r.name, other]))
                if pair in seen:
                    continue
                seen.add(pair)
                edges.append({
                    "source": r.name,
                    "target": other,
                    "trust": round(trust, 2),
                })
        return {
            "nodes": [r.stats() for r in self.residents],
            "edges": edges,
        }

    def generate_report(self) -> Dict[str, Any]:
        """生成小镇推演报告（借鉴 Foresight 结构化范式）"""
        total_events = len(self.event_log)
        social_events = sum(1 for e in self.event_log if e.event_type == "social")
        incidents = sum(1 for e in self.event_log if e.event_type == "incident")
        most_social = max(self.residents, key=lambda r: r.social_score)
        richest = max(self.residents, key=lambda r: r.money)

        return {
            "town_name": "PhotonBox 沙盒小镇",
            "ticks_run": self.tick_count + 1,
            "residents": len(self.residents),
            "total_events": total_events,
            "social_interactions": social_events,
            "incidents": incidents,
            "most_social_resident": most_social.name,
            "richest_resident": richest.name,
            "relationship_graph": self.relationship_graph(),
            "recent_events": [e.to_dict() for e in self.event_log[-10:]],
        }
