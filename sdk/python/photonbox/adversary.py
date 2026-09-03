"""
PhotonBox SDK - 红蓝对抗模块

简化的自进化安全训练接口。
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

# 导入内部红蓝对抗框架
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))


@dataclass
class AdversaryTrainingResult:
    """红蓝对抗训练结果"""
    rounds: int
    red_wins: int
    blue_wins: int
    red_win_rate: float
    blue_win_rate: float
    new_attack_cases: int
    new_defense_rules: int
    evolved_rules: List[str]
    duration_seconds: float
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rounds": self.rounds,
            "red_wins": self.red_wins,
            "blue_wins": self.blue_wins,
            "red_win_rate": self.red_win_rate,
            "blue_win_rate": self.blue_win_rate,
            "new_attack_cases": self.new_attack_cases,
            "new_defense_rules": self.new_defense_rules,
            "evolved_rules_count": len(self.evolved_rules),
            "duration_seconds": self.duration_seconds,
            "recommendations": self.recommendations,
        }


class AdversaryTrainer:
    """
    红蓝对抗训练器

    简化的自进化安全训练接口，
    自动从真实安全事件中学习并进化防御规则。
    """

    def __init__(self, auto_evolve: bool = True):
        self.auto_evolve = auto_evolve
        self.training_history: List[AdversaryTrainingResult] = []
        self._real_events: List[Dict[str, Any]] = []
        self._initialized = False
        self._trainer = None
        self._adapter = None

    def _ensure_initialized(self):
        """确保内部框架已初始化"""
        if not self._initialized:
            from evolution.red_blue_adversary import RedBlueAdversaryTrainer
            from evolution.real_data_adapter import RealDataAdapter
            self._trainer = RedBlueAdversaryTrainer()
            self._adapter = RealDataAdapter()
            self._initialized = True

    def ingest_real_events(self, events: List[Dict[str, Any]]) -> int:
        """
        摄入真实安全事件

        Args:
            events: 安全事件列表

        Returns:
            触发达尔文进化的事件数
        """
        self._ensure_initialized()
        self._real_events.extend(events)

        from evolution.real_data_adapter import SecurityEvent, EventSource
        evolved_count = 0

        for event_data in events:
            event = SecurityEvent(
                event_id=event_data.get("event_id", "unknown"),
                source=EventSource(event_data.get("source", "seccomp_violation")),
                timestamp=event_data.get("timestamp", time.time()),
                sandbox_id=event_data.get("sandbox_id", "unknown"),
                severity=event_data.get("severity", "medium"),
                description=event_data.get("description", ""),
                payload=event_data.get("payload", {}),
            )
            result = self._trainer.ingest_real_event(event)
            if result.get("triggered_evolution"):
                evolved_count += 1

        return evolved_count

    def train(self, rounds: int = 50) -> AdversaryTrainingResult:
        """
        运行红蓝对抗训练

        Args:
            rounds: 训练轮数

        Returns:
            训练结果
        """
        self._ensure_initialized()
        start_time = time.time()

        initial_attack_count = len(self._trainer.red_agent.attack_cases)
        initial_defense_count = len(self._trainer.blue_agent.defense_rules)

        stats = self._trainer.run_training(num_rounds=rounds)

        duration = time.time() - start_time
        result = AdversaryTrainingResult(
            rounds=stats["total_rounds"],
            red_wins=stats["red_wins"],
            blue_wins=stats["blue_wins"],
            red_win_rate=stats["red_win_rate"],
            blue_win_rate=stats["blue_win_rate"],
            new_attack_cases=len(self._trainer.red_agent.attack_cases) - initial_attack_count,
            new_defense_rules=len(self._trainer.blue_agent.defense_rules) - initial_defense_count,
            evolved_rules=[r.rule_id for r in self._trainer.blue_agent.defense_rules[-10:]],
            duration_seconds=duration,
            recommendations=stats.get("recommendations", []),
        )

        self.training_history.append(result)
        return result

    def get_evolved_defense_rules(self) -> List[Dict[str, Any]]:
        """获取进化后的防御规则"""
        self._ensure_initialized()
        return [
            {
                "rule_id": r.rule_id,
                "type": r.defense_type.value,
                "description": r.description,
                "effectiveness": r.effectiveness,
                "trigger_count": r.trigger_count,
            }
            for r in self._trainer.blue_agent.defense_rules
        ]

    def get_stats(self) -> Dict[str, Any]:
        """获取训练统计"""
        return {
            "training_sessions": len(self.training_history),
            "total_rounds": sum(r.rounds for r in self.training_history),
            "real_events_ingested": len(self._real_events),
            "latest_result": self.training_history[-1].to_dict() if self.training_history else None,
        }
