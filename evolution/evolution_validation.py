"""
进化验证模块——证明"自进化真的有效"，而非数据波动/噪声

核心问题：红方权重更新和蓝方规则进化，是真的因为数据，还是仅仅因为数据波动/噪声？

两个防御性工程：
1. EvolutionDriftMonitor — 进化漂移监控器
   记录每轮训练后红方权重分布的 KL 散度/变化率。
   如果连续 N 轮真实事件流入后权重变化幅度 < 阈值，
   说明框架只消费了数据却没真正学习——需要回查 train_round 的梯度或激励函数是否有 bug。

2. BaselineComparator — 基线对照组 A/B 测试框架
   A 组：开启真实信号进化的 RedBlueAdversaryTrainer
   B 组：关闭进化（固定权重/规则）的对照组
   同时消费相同的真实事件流，对比两组的逃逸拦截率。
   只要 A 组显著优于 B 组，就手握了证明"自进化有效"的黄金证据。

这是未来提交第三方审计或申请专利时最能说服人的材料。
"""

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from evolution.adversarial_strategy_optimizer import (
    AdversarialStrategyOrchestrator,
    AttackPattern,
)
from evolution.real_signal_consumer import EscapeEvent, SignalType


@dataclass
class DriftSnapshot:
    """单轮进化漂移快照"""
    round_idx: int
    timestamp: float = field(default_factory=time.time)
    red_weights: Dict[str, float] = field(default_factory=dict)
    blue_rule_count: int = 0
    blue_avg_effectiveness: float = 0.0
    attack_pattern_count: int = 0
    total_events_consumed: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "round_idx": self.round_idx,
            "timestamp": self.timestamp,
            "red_weights": dict(self.red_weights),
            "blue_rule_count": self.blue_rule_count,
            "blue_avg_effectiveness": self.blue_avg_effectiveness,
            "attack_pattern_count": self.attack_pattern_count,
            "total_events_consumed": self.total_events_consumed,
        }


@dataclass
class DriftAlert:
    """漂移告警"""
    alert_type: str  # "stagnation" / "oscillation" / "spike" / "recovery"
    round_idx: int
    severity: str = "warning"  # "warning" / "critical" / "info"
    message: str = ""
    timestamp: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_type": self.alert_type,
            "round_idx": self.round_idx,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "message": self.message,
            "details": self.details,
        }


class EvolutionDriftMonitor:
    """
    进化漂移监控器

    持续监控红蓝双方的进化漂移，区分"真正学习"和"数据噪声"：

    1. 红方权重漂移监控：
       - 记录每轮进化后的权重分布
       - 计算相邻轮次的 KL 散度 / L1 变化率 / 余弦相似度
       - 连续 N 轮变化 < 阈值 → 停滞告警（"只消费数据但没真正学习"）
       - 单轮变化 > 阈值 → 突变告警（可能是异常事件或 bug）

    2. 蓝方规则漂移监控：
       - 记录规则数量、平均有效性变化
       - 规则数量持续增长但有效性不提升 → 告警

    3. 学习有效性指标：
       - 累计漂移量（总变化幅度）
       - 漂移效率（每事件平均漂移量）
       - 收敛趋势（漂移量是否随轮次递减）
    """

    def __init__(
        self,
        stagnation_threshold: float = 0.01,
        stagnation_rounds: int = 10,
        spike_threshold: float = 0.5,
        oscillation_window: int = 5,
    ):
        """
        初始化进化漂移监控器

        Args:
            stagnation_threshold: 停滞阈值（权重变化率低于此值视为停滞）
            stagnation_rounds: 连续停滞轮数阈值（超过则告警）
            spike_threshold: 突变阈值（单轮权重变化率超过此值视为突变）
            oscillation_window: 振荡检测窗口
        """
        self.stagnation_threshold = stagnation_threshold
        self.stagnation_rounds = stagnation_rounds
        self.spike_threshold = spike_threshold
        self.oscillation_window = oscillation_window

        self.snapshots: List[DriftSnapshot] = []
        self.alerts: List[DriftAlert] = []
        self.consecutive_stagnation = 0

    def record_snapshot(
        self,
        round_idx: int,
        red_weights: Dict[str, float],
        blue_rule_count: int = 0,
        blue_avg_effectiveness: float = 0.0,
        attack_pattern_count: int = 0,
        total_events_consumed: int = 0,
    ) -> DriftSnapshot:
        """
        记录一轮进化后的漂移快照

        Args:
            round_idx: 进化轮次
            red_weights: 红方策略权重分布
            blue_rule_count: 蓝方防御规则数量
            blue_avg_effectiveness: 蓝方平均防御有效性
            attack_pattern_count: 攻击模式数量
            total_events_consumed: 累计消费事件数

        Returns:
            漂移快照
        """
        snapshot = DriftSnapshot(
            round_idx=round_idx,
            red_weights=dict(red_weights),
            blue_rule_count=blue_rule_count,
            blue_avg_effectiveness=blue_avg_effectiveness,
            attack_pattern_count=attack_pattern_count,
            total_events_consumed=total_events_consumed,
        )
        self.snapshots.append(snapshot)

        # 检测漂移异常
        if len(self.snapshots) >= 2:
            self._detect_anomalies(snapshot)

        return snapshot

    def _detect_anomalies(self, current: DriftSnapshot) -> None:
        """检测漂移异常（主入口）"""
        previous = self.snapshots[-2]
        change_rate = self._compute_weight_change_rate(
            previous.red_weights, current.red_weights
        )

        # 1. 停滞检测
        self._detect_stagnation(change_rate, current)

        # 2. 突变检测
        self._detect_spike(change_rate, previous, current)

        # 3. 振荡检测
        self._detect_oscillation(current)

    def _detect_stagnation(self, change_rate: float, current: DriftSnapshot) -> None:
        """停滞检测：变化率 < 阈值时告警，恢复时通知"""
        if change_rate < self.stagnation_threshold:
            self.consecutive_stagnation += 1
            if self.consecutive_stagnation >= self.stagnation_rounds:
                alert = DriftAlert(
                    alert_type="stagnation",
                    round_idx=current.round_idx,
                    severity="critical",
                    message=(
                        f"⚠️ 进化停滞告警：连续 {self.consecutive_stagnation} 轮"
                        f"红方权重变化率 {change_rate:.4f} < 阈值 {self.stagnation_threshold}。"
                        f"框架只消费了数据却没真正学习——需要回查 train_round 的梯度或激励函数是否有 bug。"
                    ),
                    details={
                        "change_rate": change_rate,
                        "consecutive_rounds": self.consecutive_stagnation,
                        "threshold": self.stagnation_threshold,
                        "total_events": current.total_events_consumed,
                    },
                )
                self.alerts.append(alert)
        else:
            # 重置停滞计数（有变化说明在学习）
            if self.consecutive_stagnation >= self.stagnation_rounds:
                # 从停滞中恢复
                recovery_alert = DriftAlert(
                    alert_type="recovery",
                    round_idx=current.round_idx,
                    severity="info",
                    message=f"✅ 进化恢复：权重变化率 {change_rate:.4f}，从停滞中恢复学习",
                    details={"change_rate": change_rate},
                )
                self.alerts.append(recovery_alert)
            self.consecutive_stagnation = 0

    def _detect_spike(
        self, change_rate: float, previous: DriftSnapshot, current: DriftSnapshot
    ) -> None:
        """突变检测：单轮变化率 > 阈值时告警"""
        if change_rate > self.spike_threshold:
            alert = DriftAlert(
                alert_type="spike",
                round_idx=current.round_idx,
                severity="warning",
                message=(
                    f"⚡ 进化突变告警：单轮权重变化率 {change_rate:.4f} > 阈值 {self.spike_threshold}。"
                    f"可能是异常事件冲击或进化逻辑 bug，建议检查该轮输入事件。"
                ),
                details={
                    "change_rate": change_rate,
                    "threshold": self.spike_threshold,
                    "events_this_round": current.total_events_consumed - previous.total_events_consumed,
                },
            )
            self.alerts.append(alert)

    def _detect_oscillation(self, current: DriftSnapshot) -> None:
        """振荡检测：权重在窗口内反复大幅变化时告警"""
        if len(self.snapshots) < self.oscillation_window:
            return

        # 计算最近窗口内的变化率
        recent_changes = []
        for i in range(-self.oscillation_window, -1):
            if i + 1 < 0:
                c = self._compute_weight_change_rate(
                    self.snapshots[i].red_weights,
                    self.snapshots[i + 1].red_weights,
                )
                recent_changes.append(c)

        if not recent_changes or not all(c > self.stagnation_threshold * 5 for c in recent_changes):
            return

        # 检查是否在振荡（变化方向交替）
        directions = []
        for i in range(-self.oscillation_window, -1):
            if i + 1 < 0:
                d = self._compute_weight_direction(
                    self.snapshots[i].red_weights,
                    self.snapshots[i + 1].red_weights,
                )
                directions.append(d)

        if len(directions) >= 3 and self._is_oscillating(directions):
            alert = DriftAlert(
                alert_type="oscillation",
                round_idx=current.round_idx,
                severity="warning",
                message=(
                    f"🔄 进化振荡告警：最近 {self.oscillation_window} 轮权重反复大幅变化，"
                    f"可能是进化不稳定或激励函数设计有问题。"
                ),
                details={"recent_changes": recent_changes},
            )
            self.alerts.append(alert)


    def _compute_weight_change_rate(
        self,
        prev_weights: Dict[str, float],
        curr_weights: Dict[str, float],
    ) -> float:
        """
        计算权重分布变化率（L1 距离归一化）

        Returns:
            0.0 - 1.0，0 表示完全相同，1 表示完全不同
        """
        all_keys = set(prev_weights.keys()) | set(curr_weights.keys())
        if not all_keys:
            return 0.0

        total_diff = 0.0
        total_weight = 0.0
        for key in all_keys:
            prev = prev_weights.get(key, 0.0)
            curr = curr_weights.get(key, 0.0)
            total_diff += abs(curr - prev)
            total_weight += max(abs(prev), abs(curr))

        if total_weight == 0:
            return 0.0
        return min(1.0, total_diff / total_weight)

    def _compute_kl_divergence(
        self,
        prev_weights: Dict[str, float],
        curr_weights: Dict[str, float],
    ) -> float:
        """
        计算权重分布的 KL 散度（相对熵）

        KL(curr || prev) 衡量 curr 分布相对于 prev 分布的信息量差异。
        """
        all_keys = set(prev_weights.keys()) | set(curr_weights.keys())
        if not all_keys:
            return 0.0

        # 归一化为概率分布
        prev_total = sum(max(0, v) for v in prev_weights.values())
        curr_total = sum(max(0, v) for v in curr_weights.values())

        if prev_total == 0 or curr_total == 0:
            return 0.0

        kl = 0.0
        for key in all_keys:
            p = max(0, curr_weights.get(key, 0.0)) / curr_total
            q = max(0, prev_weights.get(key, 0.0)) / prev_total
            if p > 0 and q > 0:
                kl += p * math.log(p / q)

        return kl

    def _compute_weight_direction(
        self,
        prev_weights: Dict[str, float],
        curr_weights: Dict[str, float],
    ) -> Dict[str, int]:
        """计算权重变化方向（+1 增加，-1 减少，0 不变）"""
        direction = {}
        all_keys = set(prev_weights.keys()) | set(curr_weights.keys())
        for key in all_keys:
            prev = prev_weights.get(key, 0.0)
            curr = curr_weights.get(key, 0.0)
            if curr > prev * 1.1:
                direction[key] = 1
            elif curr < prev * 0.9:
                direction[key] = -1
            else:
                direction[key] = 0
        return direction

    def _is_oscillating(self, directions: List[Dict[str, int]]) -> bool:
        """检测权重变化方向是否在振荡（交替变化）"""
        if len(directions) < 3:
            return False

        oscillation_count = 0
        for i in range(1, len(directions)):
            # 检查相邻轮次的主要变化方向是否相反
            prev_main = self._get_main_direction(directions[i - 1])
            curr_main = self._get_main_direction(directions[i])
            if prev_main != 0 and curr_main != 0 and prev_main != curr_main:
                oscillation_count += 1

        return oscillation_count >= len(directions) - 2

    def _get_main_direction(self, direction: Dict[str, int]) -> int:
        """获取主要变化方向"""
        positives = sum(1 for v in direction.values() if v > 0)
        negatives = sum(1 for v in direction.values() if v < 0)
        if positives > negatives:
            return 1
        elif negatives > positives:
            return -1
        return 0

    def get_learning_effectiveness(self) -> Dict[str, Any]:
        """
        获取学习有效性指标

        用于判断框架是"真正学习"还是"只消费数据"：
        - 累计漂移量：总变化幅度（越大说明学习越多）
        - 漂移效率：每事件平均漂移量
        - 收敛趋势：最近 N 轮漂移量是否递减（收敛说明学到了稳定策略）
        - 停滞轮数：连续无变化的轮数
        """
        if len(self.snapshots) < 2:
            return {"available": False, "reason": "快照不足"}

        # 计算每轮变化率
        changes = []
        kl_divergences = []
        for i in range(1, len(self.snapshots)):
            change = self._compute_weight_change_rate(
                self.snapshots[i - 1].red_weights,
                self.snapshots[i].red_weights,
            )
            changes.append(change)

            kl = self._compute_kl_divergence(
                self.snapshots[i - 1].red_weights,
                self.snapshots[i].red_weights,
            )
            kl_divergences.append(kl)

        total_drift = sum(changes)
        total_events = self.snapshots[-1].total_events_consumed - self.snapshots[0].total_events_consumed
        drift_efficiency = total_drift / total_events if total_events > 0 else 0.0

        # 收敛趋势：最近半段平均变化 vs 前半段
        mid = len(changes) // 2
        if mid > 0:
            first_half_avg = sum(changes[:mid]) / mid
            second_half_avg = sum(changes[mid:]) / len(changes[mid:])
            convergence_ratio = second_half_avg / first_half_avg if first_half_avg > 0 else 1.0
        else:
            convergence_ratio = 1.0

        return {
            "available": True,
            "total_rounds": len(self.snapshots),
            "total_drift": total_drift,
            "avg_drift_per_round": total_drift / len(changes) if changes else 0.0,
            "drift_efficiency_per_event": drift_efficiency,
            "convergence_ratio": convergence_ratio,
            "is_converging": convergence_ratio < 0.8,
            "consecutive_stagnation": self.consecutive_stagnation,
            "total_alerts": len(self.alerts),
            "critical_alerts": sum(1 for a in self.alerts if a.severity == "critical"),
            "recent_kl_divergence": kl_divergences[-1] if kl_divergences else 0.0,
            "avg_kl_divergence": sum(kl_divergences) / len(kl_divergences) if kl_divergences else 0.0,
        }

    def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """获取最近的告警"""
        return [a.to_dict() for a in self.alerts[-limit:]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_snapshots": len(self.snapshots),
            "total_alerts": len(self.alerts),
            "consecutive_stagnation": self.consecutive_stagnation,
            "learning_effectiveness": self.get_learning_effectiveness(),
            "recent_alerts": self.get_recent_alerts(5),
            "stagnation_threshold": self.stagnation_threshold,
            "stagnation_rounds": self.stagnation_rounds,
        }


@dataclass
class GroupMetrics:
    """单组实验指标"""
    group_name: str
    total_events: int = 0
    total_attacks: int = 0
    successful_escapes: int = 0  # 攻击成功（逃逸）
    blocked_attacks: int = 0     # 被拦截
    false_positives: int = 0     # 误报（正常事件被拦截）
    evolution_rounds: int = 0
    red_weight_changes: float = 0.0
    blue_rule_count: int = 0

    @property
    def escape_block_rate(self) -> float:
        """逃逸拦截率 = 被拦截 / 总攻击"""
        if self.total_attacks == 0:
            return 0.0
        return self.blocked_attacks / self.total_attacks

    @property
    def false_positive_rate(self) -> float:
        """误报率"""
        total = self.blocked_attacks + self.false_positives
        if total == 0:
            return 0.0
        return self.false_positives / total

    def to_dict(self) -> Dict[str, Any]:
        return {
            "group_name": self.group_name,
            "total_events": self.total_events,
            "total_attacks": self.total_attacks,
            "successful_escapes": self.successful_escapes,
            "blocked_attacks": self.blocked_attacks,
            "false_positives": self.false_positives,
            "escape_block_rate": self.escape_block_rate,
            "false_positive_rate": self.false_positive_rate,
            "evolution_rounds": self.evolution_rounds,
            "red_weight_changes": self.red_weight_changes,
            "blue_rule_count": self.blue_rule_count,
        }


@dataclass
class ABTestResult:
    """A/B 测试结果"""
    test_id: str
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    duration_hours: float = 0.0
    group_a: GroupMetrics = field(default_factory=lambda: GroupMetrics("A_evolution_enabled"))
    group_b: GroupMetrics = field(default_factory=lambda: GroupMetrics("B_fixed_baseline"))
    is_statistically_significant: bool = False
    p_value: float = 1.0
    effect_size: float = 0.0
    confidence_interval: Tuple[float, float] = (0.0, 0.0)
    conclusion: str = ""
    gold_evidence: bool = False  # 是否构成"自进化有效"的黄金证据

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id,
            "duration_hours": self.duration_hours,
            "group_a": self.group_a.to_dict(),
            "group_b": self.group_b.to_dict(),
            "is_statistically_significant": self.is_statistically_significant,
            "p_value": self.p_value,
            "effect_size": self.effect_size,
            "confidence_interval": list(self.confidence_interval),
            "conclusion": self.conclusion,
            "gold_evidence": self.gold_evidence,
        }


class BaselineComparator:
    """
    基线对照组 A/B 测试框架

    用于证明"自进化真的有效"，而非数据波动/噪声：

    A 组（实验组）：RedBlueAdversaryTrainer 开启真实信号进化
    B 组（对照组）：关闭进化（固定权重/规则）

    两组同时消费相同的真实事件流，对比逃逸拦截率。
    使用统计显著性检验（双比例 Z 检验）判断 A 组是否显著优于 B 组。

    只要 A 组显著优于 B 组（p < 0.05，效应量 > 0.1），
    就手握了证明"自进化有效"的黄金证据——
    这是未来提交第三方审计或申请专利时最能说服人的材料。
    """

    def __init__(
        self,
        test_id: str = "ab_test_default",
        significance_level: float = 0.05,
        min_effect_size: float = 0.1,
        min_sample_size: int = 100,
    ):
        """
        初始化 A/B 测试框架

        Args:
            test_id: 测试 ID
            significance_level: 统计显著性水平（p < 此值视为显著）
            min_effect_size: 最小效应量（Cohen's h，超过此值视为有实际意义）
            min_sample_size: 最小样本量（每组攻击数，低于此值结论不可靠）
        """
        self.test_id = test_id
        self.significance_level = significance_level
        self.min_effect_size = min_effect_size
        self.min_sample_size = min_sample_size

        self.result = ABTestResult(test_id=test_id)
        self._event_buffer: List[EscapeEvent] = []

    def feed_event(
        self,
        event: EscapeEvent,
        group_a_blocked: bool,
        group_b_blocked: bool,
        is_attack: bool = True,
        is_false_positive_a: bool = False,
        is_false_positive_b: bool = False,
    ) -> None:
        """
        向两组同时投喂一个真实事件，并记录拦截结果

        Args:
            event: 真实逃逸事件
            group_a_blocked: A 组（开启进化）是否拦截了该攻击
            group_b_blocked: B 组（固定基线）是否拦截了该攻击
            is_attack: 是否为真实攻击（否则为正常事件，用于误报统计）
            is_false_positive_a: A 组是否误报
            is_false_positive_b: B 组是否误报
        """
        self.result.group_a.total_events += 1
        self.result.group_b.total_events += 1

        if is_attack:
            self.result.group_a.total_attacks += 1
            self.result.group_b.total_attacks += 1

            if group_a_blocked:
                self.result.group_a.blocked_attacks += 1
            else:
                self.result.group_a.successful_escapes += 1

            if group_b_blocked:
                self.result.group_b.blocked_attacks += 1
            else:
                self.result.group_b.successful_escapes += 1

        if is_false_positive_a:
            self.result.group_a.false_positives += 1
        if is_false_positive_b:
            self.result.group_b.false_positives += 1

    def feed_event_batch(
        self,
        events: List[EscapeEvent],
        group_a_results: List[bool],
        group_b_results: List[bool],
        are_attacks: Optional[List[bool]] = None,
    ) -> None:
        """批量投喂事件"""
        if are_attacks is None:
            are_attacks = [True] * len(events)

        for event, a_blocked, b_blocked, is_attack in zip(
            events, group_a_results, group_b_results, are_attacks
        ):
            self.feed_event(event, a_blocked, b_blocked, is_attack)

    def run_evaluation(self) -> ABTestResult:
        """
        运行 A/B 测试评估，计算统计显著性

        使用双比例 Z 检验比较两组的逃逸拦截率：
        - H0: A 组拦截率 = B 组拦截率（自进化无效）
        - H1: A 组拦截率 > B 组拦截率（自进化有效）

        Returns:
            A/B 测试结果
        """
        self.result.end_time = time.time()
        self.result.duration_hours = (self.result.end_time - self.result.start_time) / 3600

        a = self.result.group_a
        b = self.result.group_b

        # 样本量检查
        if a.total_attacks < self.min_sample_size or b.total_attacks < self.min_sample_size:
            self.result.conclusion = (
                f"⚠️ 样本量不足：A组{a.total_attacks}次攻击，B组{b.total_attacks}次攻击，"
                f"均低于最小样本量{self.min_sample_size}。结论不可靠，需要更多数据。"
            )
            self.result.gold_evidence = False
            return self.result

        # 双比例 Z 检验
        p_value, z_score = self._two_proportion_z_test(
            a.blocked_attacks, a.total_attacks,
            b.blocked_attacks, b.total_attacks,
        )

        # 效应量（Cohen's h）
        effect_size = self._cohens_h(
            a.escape_block_rate, b.escape_block_rate
        )

        # 置信区间（95%）
        ci = self._proportion_diff_ci(
            a.escape_block_rate, a.total_attacks,
            b.escape_block_rate, b.total_attacks,
        )

        self.result.p_value = p_value
        self.result.effect_size = effect_size
        self.result.confidence_interval = ci

        # 判断统计显著性
        is_significant = p_value < self.significance_level
        is_meaningful = effect_size > self.min_effect_size
        a_better = a.escape_block_rate > b.escape_block_rate

        self.result.is_statistically_significant = is_significant and a_better

        # 生成结论
        if is_significant and a_better and is_meaningful:
            improvement = (a.escape_block_rate - b.escape_block_rate) * 100
            self.result.conclusion = (
                f"✅ 黄金证据：A组（开启进化）逃逸拦截率 {a.escape_block_rate:.1%} "
                f"显著优于 B组（固定基线）{b.escape_block_rate:.1%}，"
                f"提升 {improvement:.1f} 个百分点（p={p_value:.4f}, Cohen's h={effect_size:.3f}）。"
                f"自进化有效性得到统计显著验证，可作为第三方审计和专利申请的核心证据。"
            )
            self.result.gold_evidence = True
        elif is_significant and a_better and not is_meaningful:
            self.result.conclusion = (
                f"📊 统计显著但效应量小：A组拦截率显著高于B组（p={p_value:.4f}），"
                f"但 Cohen's h={effect_size:.3f} < 阈值{self.min_effect_size}，"
                f"实际提升幅度有限。需要更长时间测试或优化进化策略。"
            )
            self.result.gold_evidence = False
        elif not is_significant and a_better:
            self.result.conclusion = (
                f"⚠️ A组拦截率略高于B组（{a.escape_block_rate:.1%} vs {b.escape_block_rate:.1%}），"
                f"但差异不显著（p={p_value:.4f} >= {self.significance_level}）。"
                f"无法排除数据波动/噪声的可能性，需要更多数据或更长测试时间。"
            )
            self.result.gold_evidence = False
        elif not a_better:
            self.result.conclusion = (
                f"❌ 自进化未显示优势：A组拦截率 {a.escape_block_rate:.1%} "
                f"未优于 B组 {b.escape_block_rate:.1%}（p={p_value:.4f}）。"
                f"可能原因：进化策略需要调优、测试时间不足、或当前事件流缺乏足够多样性。"
                f"建议检查进化漂移监控是否有停滞告警。"
            )
            self.result.gold_evidence = False

        return self.result

    def _two_proportion_z_test(
        self,
        x1: int, n1: int,
        x2: int, n2: int,
    ) -> Tuple[float, float]:
        """
        双比例 Z 检验（单侧，检验 p1 > p2）

        Returns:
            (p_value, z_score)
        """
        p1 = x1 / n1 if n1 > 0 else 0
        p2 = x2 / n2 if n2 > 0 else 0

        # 合并比例
        p_pool = (x1 + x2) / (n1 + n2) if (n1 + n2) > 0 else 0
        se = math.sqrt(p_pool * (1 - p_pool) * (1 / n1 + 1 / n2)) if n1 > 0 and n2 > 0 else 0

        if se == 0:
            return 1.0, 0.0

        z_score = (p1 - p2) / se

        # 单侧 p 值（使用正态分布近似）
        p_value = self._normal_cdf(-z_score)

        return p_value, z_score

    def _normal_cdf(self, x: float) -> float:
        """标准正态分布累积分布函数"""
        return 0.5 * (1 + math.erf(x / math.sqrt(2)))

    def _cohens_h(self, p1: float, p2: float) -> float:
        """
        Cohen's h 效应量（两个比例之间的差异）

        h = 2 * arcsin(sqrt(p1)) - 2 * arcsin(sqrt(p2))
        """
        h1 = 2 * math.asin(math.sqrt(max(0, min(1, p1))))
        h2 = 2 * math.asin(math.sqrt(max(0, min(1, p2))))
        return abs(h1 - h2)

    def _proportion_diff_ci(
        self,
        p1: float, n1: int,
        p2: float, n2: int,
        confidence: float = 0.95,
    ) -> Tuple[float, float]:
        """两个比例差异的置信区间"""
        diff = p1 - p2
        se = math.sqrt(
            p1 * (1 - p1) / n1 + p2 * (1 - p2) / n2
        ) if n1 > 0 and n2 > 0 else 0

        z = 1.96  # 95% 置信度
        margin = z * se
        return (diff - margin, diff + margin)

    def get_result(self) -> ABTestResult:
        """获取当前测试结果"""
        return self.result

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id,
            "significance_level": self.significance_level,
            "min_effect_size": self.min_effect_size,
            "min_sample_size": self.min_sample_size,
            "result": self.result.to_dict(),
        }


class EvolutionValidationSuite:
    """
    进化验证套件——整合漂移监控和 A/B 测试

    一站式验证"自进化真的有效"：
    1. 每轮进化后记录漂移快照
    2. 持续监控停滞/突变/振荡
    3. 并行运行 A/B 测试对比进化组 vs 固定组
    4. 生成综合验证报告

    这是持续集成必加项，也是第三方审计的核心证据材料。
    """

    def __init__(
        self,
        test_id: str = "evolution_validation",
        stagnation_threshold: float = 0.01,
        stagnation_rounds: int = 10,
        significance_level: float = 0.05,
    ):
        self.drift_monitor = EvolutionDriftMonitor(
            stagnation_threshold=stagnation_threshold,
            stagnation_rounds=stagnation_rounds,
        )
        self.ab_test = BaselineComparator(
            test_id=test_id,
            significance_level=significance_level,
        )
        self.validation_rounds = 0

    def record_evolution_round(
        self,
        red_weights: Dict[str, float],
        blue_rule_count: int = 0,
        blue_avg_effectiveness: float = 0.0,
        attack_pattern_count: int = 0,
        total_events_consumed: int = 0,
    ) -> DriftSnapshot:
        """记录一轮进化后的漂移快照"""
        self.validation_rounds += 1
        return self.drift_monitor.record_snapshot(
            round_idx=self.validation_rounds,
            red_weights=red_weights,
            blue_rule_count=blue_rule_count,
            blue_avg_effectiveness=blue_avg_effectiveness,
            attack_pattern_count=attack_pattern_count,
            total_events_consumed=total_events_consumed,
        )

    def feed_ab_event(
        self,
        event: EscapeEvent,
        group_a_blocked: bool,
        group_b_blocked: bool,
        is_attack: bool = True,
    ) -> None:
        """向 A/B 测试投喂事件"""
        self.ab_test.feed_event(event, group_a_blocked, group_b_blocked, is_attack)

    def generate_validation_report(self) -> Dict[str, Any]:
        """
        生成综合验证报告

        包含：
        - 漂移监控状态（是否有停滞/突变/振荡告警）
        - 学习有效性指标（累计漂移量/漂移效率/收敛趋势）
        - A/B 测试结果（统计显著性/效应量/黄金证据）
        - 综合结论
        """
        # 运行 A/B 测试评估
        ab_result = self.ab_test.run_evaluation()

        # 获取学习有效性
        learning = self.drift_monitor.get_learning_effectiveness()

        # 综合判断
        has_gold_evidence = ab_result.gold_evidence
        has_stagnation = learning.get("consecutive_stagnation", 0) >= self.drift_monitor.stagnation_rounds
        is_learning = learning.get("available", False) and learning.get("total_drift", 0) > 0

        if has_gold_evidence and not has_stagnation:
            overall = "✅ 验证通过：自进化有效性得到统计显著验证（黄金证据），且无进化停滞"
        elif has_gold_evidence and has_stagnation:
            overall = "⚠️ 部分验证：A/B测试显示自进化有效，但漂移监控检测到进化停滞，建议检查进化逻辑"
        elif not has_gold_evidence and is_learning:
            overall = "🔄 验证中：框架正在学习（有漂移），但A/B测试尚未达到统计显著性，需要更多数据"
        elif has_stagnation:
            overall = "❌ 验证失败：检测到进化停滞，框架只消费数据但没真正学习，需要回查 train_round 逻辑"
        else:
            overall = "📊 数据不足：需要更多进化轮次和事件数据才能得出可靠结论"

        return {
            "validation_rounds": self.validation_rounds,
            "overall_conclusion": overall,
            "drift_monitor": self.drift_monitor.to_dict(),
            "learning_effectiveness": learning,
            "ab_test": ab_result.to_dict(),
            "has_gold_evidence": has_gold_evidence,
            "has_stagnation": has_stagnation,
            "is_learning": is_learning,
            "recommendations": self._generate_recommendations(has_gold_evidence, has_stagnation, is_learning),
        }

    def _generate_recommendations(
        self,
        has_gold_evidence: bool,
        has_stagnation: bool,
        is_learning: bool,
    ) -> List[str]:
        """生成验证建议"""
        recommendations = []

        if has_stagnation:
            recommendations.append(
                "🔴 紧急：回查 train_round 的梯度或激励函数是否有 bug——"
                "连续多轮权重无变化说明框架只消费数据但没真正学习"
            )
            recommendations.append(
                "检查进化触发器是否过于保守（冷却期过长/批量阈值过高），"
                "导致真实事件无法触发有效进化"
            )

        if not has_gold_evidence and is_learning:
            recommendations.append(
                "🟡 延长 A/B 测试时间（建议 48 小时以上），积累更多样本以达到统计显著性"
            )
            recommendations.append(
                "增加事件流多样性——当前事件类型可能过于单一，导致进化效果不明显"
            )

        if has_gold_evidence:
            recommendations.append(
                "✅ 将 A/B 测试报告归档为第三方审计和专利申请的核心证据材料"
            )
            recommendations.append(
                "在 CI/CD 中集成进化验证套件，每次代码变更后自动验证自进化有效性"
            )

        recommendations.append(
            "持续监控进化漂移——停滞/突变/振荡告警应接入运维告警平台"
        )

        return recommendations

    def to_dict(self) -> Dict[str, Any]:
        return {
            "validation_rounds": self.validation_rounds,
            "drift_monitor": self.drift_monitor.to_dict(),
            "ab_test": self.ab_test.to_dict(),
        }
