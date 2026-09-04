"""
红蓝对抗进化策略优化器

基于真实数据链路，观察并迭代红蓝双方的进化策略：
1. AdversarialEvaluator — 对抗评估器：红方攻击 vs 蓝方防御的对抗评估
2. RedStrategyOptimizer — 红方策略优化器：从真实事件提取攻击模式，基于防御盲区调整权重
3. BlueStrategyOptimizer — 蓝方策略优化器：针对性防御规则生成，有效性评估，规则淘汰
4. EvolutionTrigger — 智能进化触发器：基于频率/严重程度/新颖性的智能触发

核心改进（相比简单进化逻辑）：
- 红方：不再盲目添加攻击用例，而是基于防御盲区和历史成功率优化策略
- 蓝方：不再固定0.6有效性，而是基于真实攻击频率和严重程度动态评估
- 对抗：真正的红方攻击 vs 蓝方防御对抗评估，识别防御盲区和无效规则
- 触发：基于事件频率/严重程度/新颖性的智能触发，避免重复进化
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from evolution.real_data_adapter import EventSource, SecurityEvent
from evolution.real_signal_consumer import EscapeEvent, SignalType


class EvolutionPhase(Enum):
    """进化阶段"""
    IDLE = "idle"
    OBSERVING = "observing"           # 观察真实事件
    EVALUATING = "evaluating"         # 对抗评估
    EVOLVING_RED = "evolving_red"     # 红方进化
    EVOLVING_BLUE = "evolving_blue"   # 蓝方进化
    COOLDOWN = "cooldown"             # 进化冷却期


@dataclass
class AttackPattern:
    """从真实事件提取的攻击模式"""
    pattern_id: str
    attack_type: str
    signal_type: SignalType
    severity: str
    syscall: Optional[str] = None
    vm_exit_reason: Optional[str] = None
    description: str = ""
    occurrence_count: int = 1
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    success_count: int = 0  # 攻击成功次数（绕过防御）
    blocked_count: int = 0  # 被防御拦截次数

    @property
    def success_rate(self) -> float:
        """攻击成功率"""
        total = self.success_count + self.blocked_count
        return self.success_count / total if total > 0 else 0.0

    @property
    def is_high_priority(self) -> bool:
        """是否为高优先级攻击模式（高频或高危或高成功率）"""
        return (
            self.occurrence_count >= 5
            or self.severity in ("critical", "high")
            or self.success_rate >= 0.5
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "attack_type": self.attack_type,
            "signal_type": self.signal_type.value,
            "severity": self.severity,
            "syscall": self.syscall,
            "vm_exit_reason": self.vm_exit_reason,
            "occurrence_count": self.occurrence_count,
            "success_rate": self.success_rate,
            "is_high_priority": self.is_high_priority,
        }


@dataclass
class DefenseGap:
    """防御盲区（攻击类型没有对应防御规则，或防御有效性不足）"""
    attack_type: str
    signal_type: SignalType
    occurrence_count: int
    severity: str
    current_defense_count: int
    avg_defense_effectiveness: float
    gap_severity: str  # "critical" / "high" / "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_type": self.attack_type,
            "signal_type": self.signal_type.value,
            "occurrence_count": self.occurrence_count,
            "severity": self.severity,
            "current_defense_count": self.current_defense_count,
            "avg_defense_effectiveness": self.avg_defense_effectiveness,
            "gap_severity": self.gap_severity,
        }


@dataclass
class AdversarialEvaluationResult:
    """对抗评估结果"""
    timestamp: float = field(default_factory=time.time)
    total_attack_cases: int = 0
    total_defense_rules: int = 0
    attack_success_rate: float = 0.0  # 红方攻击成功率（绕过防御的比例）
    defense_success_rate: float = 0.0  # 蓝方防御成功率（拦截攻击的比例）
    false_positive_rate: float = 0.0   # 蓝方误报率
    defense_gaps: List[DefenseGap] = field(default_factory=list)
    ineffective_rules: List[str] = field(default_factory=list)  # 从未命中的规则
    high_risk_attack_patterns: List[AttackPattern] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "total_attack_cases": self.total_attack_cases,
            "total_defense_rules": self.total_defense_rules,
            "attack_success_rate": self.attack_success_rate,
            "defense_success_rate": self.defense_success_rate,
            "false_positive_rate": self.false_positive_rate,
            "defense_gaps": [g.to_dict() for g in self.defense_gaps],
            "ineffective_rules": self.ineffective_rules,
            "high_risk_attack_patterns": [p.to_dict() for p in self.high_risk_attack_patterns],
            "recommendations": self.recommendations,
        }


class AdversarialEvaluator:
    """
    对抗评估器

    评估红方攻击用例 vs 蓝方防御规则的对抗效果：
    - 攻击成功率 / 防御成功率 / 误报率
    - 防御盲区识别（哪些攻击类型没有对应防御）
    - 无效防御规则识别（哪些规则从未命中或有效性过低）
    - 高风险攻击模式识别
    - 生成进化建议
    """

    def __init__(self, effectiveness_threshold: float = 0.5, min_hits_for_effective: int = 1):
        """
        初始化对抗评估器

        Args:
            effectiveness_threshold: 防御规则有效性阈值（低于此值视为低效）
            min_hits_for_effective: 规则被视为有效的最少命中次数
        """
        self.effectiveness_threshold = effectiveness_threshold
        self.min_hits_for_effective = min_hits_for_effective
        self.evaluation_history: List[AdversarialEvaluationResult] = []

    def evaluate(
        self,
        attack_cases: List[Any],
        defense_rules: List[Any],
        attack_patterns: List[AttackPattern],
    ) -> AdversarialEvaluationResult:
        """
        执行对抗评估

        Args:
            attack_cases: 红方攻击用例列表
            defense_rules: 蓝方防御规则列表
            attack_patterns: 从真实事件提取的攻击模式

        Returns:
            对抗评估结果
        """
        result = AdversarialEvaluationResult(
            total_attack_cases=len(attack_cases),
            total_defense_rules=len(defense_rules),
        )

        # 1. 计算攻击成功率和防御成功率（基于攻击模式的历史数据）
        total_attempts = 0
        total_success = 0
        total_blocked = 0
        for pattern in attack_patterns:
            total_attempts += pattern.occurrence_count
            total_success += pattern.success_count
            total_blocked += pattern.blocked_count

        if total_attempts > 0:
            result.attack_success_rate = total_success / total_attempts
            result.defense_success_rate = total_blocked / total_attempts

        # 2. 识别防御盲区
        result.defense_gaps = self._identify_defense_gaps(attack_patterns, defense_rules)

        # 3. 识别无效防御规则
        result.ineffective_rules = self._identify_ineffective_rules(defense_rules)

        # 4. 识别高风险攻击模式
        result.high_risk_attack_patterns = [
            p for p in attack_patterns if p.is_high_priority
        ][:10]

        # 5. 生成进化建议
        result.recommendations = self._generate_recommendations(result)

        # 6. 记录历史
        self.evaluation_history.append(result)
        if len(self.evaluation_history) > 50:
            self.evaluation_history = self.evaluation_history[-50:]

        return result

    def _identify_defense_gaps(
        self,
        attack_patterns: List[AttackPattern],
        defense_rules: List[Any],
    ) -> List[DefenseGap]:
        """识别防御盲区"""
        gaps = []

        # 按攻击类型分组
        patterns_by_type: Dict[str, List[AttackPattern]] = defaultdict(list)
        for pattern in attack_patterns:
            patterns_by_type[pattern.attack_type].append(pattern)

        # 检查每种攻击类型是否有对应防御
        for attack_type, patterns in patterns_by_type.items():
            # 查找针对此攻击类型的防御规则
            matching_rules = []
            for rule in defense_rules:
                target_types = getattr(rule, 'target_attack_types', [])
                if attack_type in [str(t) for t in target_types]:
                    matching_rules.append(rule)

            # 计算平均防御有效性
            avg_effectiveness = 0.0
            if matching_rules:
                avg_effectiveness = sum(
                    getattr(r, 'effectiveness', 0.0) for r in matching_rules
                ) / len(matching_rules)

            # 判断是否为盲区
            total_occurrences = sum(p.occurrence_count for p in patterns)
            max_severity = max(p.severity for p in patterns)

            is_gap = (
                len(matching_rules) == 0
                or (avg_effectiveness < self.effectiveness_threshold and total_occurrences >= 3)
            )

            if is_gap:
                if max_severity == "critical" or total_occurrences >= 10:
                    gap_severity = "critical"
                elif max_severity == "high" or total_occurrences >= 5:
                    gap_severity = "high"
                else:
                    gap_severity = "medium"

                gaps.append(DefenseGap(
                    attack_type=attack_type,
                    signal_type=patterns[0].signal_type,
                    occurrence_count=total_occurrences,
                    severity=max_severity,
                    current_defense_count=len(matching_rules),
                    avg_defense_effectiveness=avg_effectiveness,
                    gap_severity=gap_severity,
                ))

        # 按盲区严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        gaps.sort(key=lambda g: (severity_order.get(g.gap_severity, 99), -g.occurrence_count))
        return gaps[:10]

    def _identify_ineffective_rules(self, defense_rules: List[Any]) -> List[str]:
        """识别无效防御规则（有效性过低或从未命中）"""
        ineffective = []
        for rule in defense_rules:
            effectiveness = getattr(rule, 'effectiveness', 0.0)
            trigger_count = getattr(rule, 'trigger_count', 0)

            if effectiveness < self.effectiveness_threshold:
                ineffective.append(f"{getattr(rule, 'rule_id', 'unknown')}(有效性{effectiveness:.2f})")
            elif trigger_count < self.min_hits_for_effective:
                ineffective.append(f"{getattr(rule, 'rule_id', 'unknown')}(从未命中)")

        return ineffective[:10]

    def _generate_recommendations(self, result: AdversarialEvaluationResult) -> List[str]:
        """生成进化建议"""
        recommendations = []

        # 基于防御盲区的建议
        critical_gaps = [g for g in result.defense_gaps if g.gap_severity == "critical"]
        high_gaps = [g for g in result.defense_gaps if g.gap_severity == "high"]

        if critical_gaps:
            recommendations.append(
                f"🔴 紧急：发现 {len(critical_gaps)} 个临界防御盲区，"
                f"优先针对 {critical_gaps[0].attack_type} 生成防御规则"
            )
        if high_gaps:
            recommendations.append(
                f"🟠 高优先级：发现 {len(high_gaps)} 个高优先级防御盲区，"
                f"建议在下一轮进化中覆盖"
            )

        # 基于攻击成功率的建议
        if result.attack_success_rate > 0.5:
            recommendations.append(
                f"⚠️ 红方攻击成功率 {result.attack_success_rate:.1%} 过高，"
                f"蓝方需要加强防御规则有效性"
            )
        elif result.defense_success_rate > 0.8:
            recommendations.append(
                f"✅ 蓝方防御成功率 {result.defense_success_rate:.1%} 良好，"
                f"红方需要探索新的攻击模式"
            )

        # 基于无效规则的建议
        if result.ineffective_rules:
            recommendations.append(
                f"🔧 发现 {len(result.ineffective_rules)} 个低效/未命中防御规则，"
                f"建议淘汰或重新进化"
            )

        # 基于高风险攻击模式的建议
        if result.high_risk_attack_patterns:
            top_pattern = result.high_risk_attack_patterns[0]
            recommendations.append(
                f"🎯 最高风险攻击模式：{top_pattern.attack_type} "
                f"(出现{top_pattern.occurrence_count}次，成功率{top_pattern.success_rate:.0%})，"
                f"红方应重点变异此方向"
            )

        return recommendations[:5]

    def get_trend(self) -> Dict[str, Any]:
        """获取评估趋势（最近 N 次评估的变化）"""
        if len(self.evaluation_history) < 2:
            return {"trend_available": False}

        latest = self.evaluation_history[-1]
        previous = self.evaluation_history[-2]

        return {
            "trend_available": True,
            "attack_success_rate_change": latest.attack_success_rate - previous.attack_success_rate,
            "defense_success_rate_change": latest.defense_success_rate - previous.defense_success_rate,
            "defense_gaps_count_change": len(latest.defense_gaps) - len(previous.defense_gaps),
            "evaluations_count": len(self.evaluation_history),
        }


class RedStrategyOptimizer:
    """
    红方策略优化器

    从真实事件中提取攻击模式，基于防御盲区和历史成功率优化红方策略：
    - 攻击模式提取与聚类
    - 基于防御盲区的攻击优先级调整
    - 基于历史成功率的变异方向优化
    - 攻击用例新颖性评估（避免重复）
    """

    def __init__(self, novelty_threshold: float = 0.7):
        """
        初始化红方策略优化器

        Args:
            novelty_threshold: 新颖性阈值（低于此值视为重复攻击）
        """
        self.novelty_threshold = novelty_threshold
        self.attack_patterns: Dict[str, AttackPattern] = {}
        self.attack_case_signatures: Set[str] = set()
        self.strategy_weights: Dict[str, float] = defaultdict(lambda: 1.0)

    def extract_attack_pattern(self, event: EscapeEvent) -> AttackPattern:
        """
        从真实逃逸事件提取攻击模式

        Args:
            event: 真实逃逸事件

        Returns:
            攻击模式（新建或更新已有模式）
        """
        # 生成模式 ID（基于信号类型 + syscall/vm_exit_reason）
        if event.syscall:
            pattern_key = f"seccomp_{event.syscall}"
            attack_type = f"syscall_{event.syscall}"
        elif event.vm_exit_reason:
            pattern_key = f"vmexit_{event.vm_exit_reason}"
            attack_type = f"vmexit_{event.vm_exit_reason}"
        else:
            pattern_key = f"{event.signal_type.value}_{event.severity}"
            attack_type = event.signal_type.value

        # 更新或创建模式
        if pattern_key in self.attack_patterns:
            pattern = self.attack_patterns[pattern_key]
            pattern.occurrence_count += 1
            pattern.last_seen = event.timestamp
            if event.severity == "critical":
                pattern.severity = "critical"
        else:
            pattern = AttackPattern(
                pattern_id=pattern_key,
                attack_type=attack_type,
                signal_type=event.signal_type,
                severity=event.severity,
                syscall=event.syscall,
                vm_exit_reason=event.vm_exit_reason,
                description=event.description,
            )
            self.attack_patterns[pattern_key] = pattern

        return pattern

    def record_attack_result(self, pattern_key: str, success: bool) -> None:
        """记录攻击结果（用于更新成功率）"""
        if pattern_key in self.attack_patterns:
            pattern = self.attack_patterns[pattern_key]
            if success:
                pattern.success_count += 1
            else:
                pattern.blocked_count += 1

    def optimize_strategy_weights(self, evaluation_result: AdversarialEvaluationResult) -> Dict[str, float]:
        """
        基于对抗评估结果优化攻击策略权重

        优先攻击防御盲区和高成功率攻击模式。

        Args:
            evaluation_result: 对抗评估结果

        Returns:
            优化后的策略权重
        """
        # 重置权重
        self.strategy_weights.clear()

        # 基于防御盲区提升权重
        for gap in evaluation_result.defense_gaps:
            weight = 3.0 if gap.gap_severity == "critical" else 2.0 if gap.gap_severity == "high" else 1.5
            self.strategy_weights[gap.attack_type] = weight

        # 基于高成功率攻击模式提升权重
        for pattern in self.attack_patterns.values():
            if pattern.success_rate >= 0.5:
                current = self.strategy_weights.get(pattern.attack_type, 1.0)
                self.strategy_weights[pattern.attack_type] = current * (1 + pattern.success_rate)

        # 基于高频攻击模式提升权重
        for pattern in self.attack_patterns.values():
            if pattern.occurrence_count >= 5:
                current = self.strategy_weights.get(pattern.attack_type, 1.0)
                self.strategy_weights[pattern.attack_type] = current * 1.2

        return dict(self.strategy_weights)

    def get_priority_attack_patterns(self, top_n: int = 5) -> List[AttackPattern]:
        """获取优先级最高的攻击模式（用于红方重点变异）"""
        patterns = list(self.attack_patterns.values())
        patterns.sort(key=lambda p: (
            p.is_high_priority,
            p.success_rate,
            p.occurrence_count,
        ), reverse=True)
        return patterns[:top_n]

    def compute_novelty(self, attack_case_signature: str) -> float:
        """
        计算攻击用例的新颖性（0-1，越高越新颖）

        Args:
            attack_case_signature: 攻击用例签名（哈希或特征字符串）

        Returns:
            新颖性分数
        """
        if attack_case_signature in self.attack_case_signatures:
            return 0.0  # 完全重复
        # 简化：检查签名与已有签名的相似度
        # 实际实现可以用编辑距离或嵌入相似度
        similarity = 0.0
        for existing in self.attack_case_signatures:
            if attack_case_signature[:20] == existing[:20]:
                similarity = max(similarity, 0.5)
        novelty = 1.0 - similarity
        if novelty >= self.novelty_threshold:
            self.attack_case_signatures.add(attack_case_signature)
        return novelty

    def get_stats(self) -> Dict[str, Any]:
        """获取红方策略统计"""
        total_patterns = len(self.attack_patterns)
        high_risk = sum(1 for p in self.attack_patterns.values() if p.is_high_priority)
        total_occurrences = sum(p.occurrence_count for p in self.attack_patterns.values())
        avg_success_rate = 0.0
        if total_patterns > 0:
            avg_success_rate = sum(p.success_rate for p in self.attack_patterns.values()) / total_patterns

        return {
            "total_attack_patterns": total_patterns,
            "high_risk_patterns": high_risk,
            "total_occurrences": total_occurrences,
            "avg_success_rate": avg_success_rate,
            "unique_attack_cases": len(self.attack_case_signatures),
            "strategy_weights_count": len(self.strategy_weights),
        }


class BlueStrategyOptimizer:
    """
    蓝方策略优化器

    基于真实攻击生成针对性防御规则，动态评估有效性，淘汰低效规则：
    - 基于攻击模式生成针对性防御规则
    - 防御规则有效性动态评估
    - 防御规则优先级排序
    - 低效规则淘汰
    - 误报率控制
    """

    def __init__(
        self,
        min_effectiveness: float = 0.4,
        max_rules: int = 100,
        false_positive_threshold: float = 0.3,
    ):
        """
        初始化蓝方策略优化器

        Args:
            min_effectiveness: 规则最低有效性阈值（低于此值考虑淘汰）
            max_rules: 最大防御规则数量（超过则淘汰最低优先级规则）
            false_positive_threshold: 误报率阈值（超过此值的规则需要调整）
        """
        self.min_effectiveness = min_effectiveness
        self.max_rules = max_rules
        self.false_positive_threshold = false_positive_threshold
        self.rule_effectiveness_history: Dict[str, List[float]] = defaultdict(list)
        self.rule_false_positives: Dict[str, int] = defaultdict(int)

    def generate_targeted_defense(
        self,
        attack_pattern: AttackPattern,
        gap: Optional[DefenseGap] = None,
    ) -> Dict[str, Any]:
        """
        基于攻击模式生成针对性防御规则建议

        Args:
            attack_pattern: 攻击模式
            gap: 防御盲区（可选）

        Returns:
            防御规则建议
        """
        # 基于信号类型确定防御类型
        defense_type_map = {
            SignalType.SECCOMP_VIOLATION: "system_call_monitor",
            SignalType.KVM_VM_EXIT: "process_isolation",
            SignalType.AUDIT_CHAIN_ANOMALY: "audit_logging",
            SignalType.NETWORK_BLOCK: "network_filter",
            SignalType.RESOURCE_EXCEED: "resource_limit",
            SignalType.CAPABILITY_DROP: "capability_drop",
        }

        # 计算初始有效性（基于攻击模式特征）
        base_effectiveness = 0.5
        if attack_pattern.occurrence_count >= 10:
            base_effectiveness += 0.1  # 高频攻击更容易设计有效防御
        if attack_pattern.success_rate >= 0.7:
            base_effectiveness -= 0.1  # 高成功率攻击更难防御
        if gap and gap.gap_severity == "critical":
            base_effectiveness += 0.1  # 临界盲区优先投入资源

        effectiveness = min(0.9, max(0.3, base_effectiveness))

        # 生成检测逻辑建议
        detection_logic = self._generate_detection_logic(attack_pattern)

        return {
            "rule_id": f"targeted_{attack_pattern.pattern_id}_{int(time.time())}",
            "defense_type": defense_type_map.get(attack_pattern.signal_type, "audit_logging"),
            "description": f"[针对性防御] 针对{attack_pattern.attack_type}攻击模式（出现{attack_pattern.occurrence_count}次）",
            "target_attack_types": [attack_pattern.attack_type],
            "detection_logic": detection_logic,
            "effectiveness": effectiveness,
            "priority": self._compute_priority(attack_pattern, gap),
            "source_pattern": attack_pattern.pattern_id,
        }

    def _generate_detection_logic(self, attack_pattern: AttackPattern) -> str:
        """生成检测逻辑建议"""
        if attack_pattern.syscall:
            return f"监控系统调用 {attack_pattern.syscall}，当出现异常参数或频率时触发告警"
        if attack_pattern.vm_exit_reason:
            return f"监控 VM-Exit 原因 {attack_pattern.vm_exit_reason}，异常频率或组合触发告警"
        return f"监控 {attack_pattern.signal_type.value} 事件，基于异常模式检测"

    def _compute_priority(self, attack_pattern: AttackPattern, gap: Optional[DefenseGap]) -> int:
        """计算防御规则优先级（1-10，越高越优先）"""
        priority = 5  # 默认中等优先级

        if attack_pattern.severity == "critical":
            priority += 3
        elif attack_pattern.severity == "high":
            priority += 2

        if attack_pattern.occurrence_count >= 10:
            priority += 2
        elif attack_pattern.occurrence_count >= 5:
            priority += 1

        if gap:
            if gap.gap_severity == "critical":
                priority += 2
            elif gap.gap_severity == "high":
                priority += 1

        return min(10, priority)

    def update_rule_effectiveness(self, rule_id: str, effectiveness: float) -> None:
        """更新规则有效性历史"""
        self.rule_effectiveness_history[rule_id].append(effectiveness)
        if len(self.rule_effectiveness_history[rule_id]) > 20:
            self.rule_effectiveness_history[rule_id] = self.rule_effectiveness_history[rule_id][-20:]

    def record_false_positive(self, rule_id: str) -> None:
        """记录规则误报"""
        self.rule_false_positives[rule_id] += 1

    def get_rule_avg_effectiveness(self, rule_id: str) -> float:
        """获取规则平均有效性"""
        history = self.rule_effectiveness_history.get(rule_id, [])
        if not history:
            return 0.0
        return sum(history) / len(history)

    def identify_rules_to_prune(self, defense_rules: List[Any]) -> List[str]:
        """
        识别需要淘汰的防御规则

        淘汰条件：
        1. 平均有效性低于阈值
        2. 误报率超过阈值
        3. 规则数量超过上限时淘汰最低优先级规则

        Args:
            defense_rules: 当前防御规则列表

        Returns:
            需要淘汰的规则 ID 列表
        """
        to_prune = []

        for rule in defense_rules:
            rule_id = getattr(rule, 'rule_id', 'unknown')
            avg_effectiveness = self.get_rule_avg_effectiveness(rule_id)
            current_effectiveness = getattr(rule, 'effectiveness', 0.0)
            false_positives = self.rule_false_positives.get(rule_id, 0)
            trigger_count = getattr(rule, 'trigger_count', 0)

            # 条件1：有效性过低
            if avg_effectiveness < self.min_effectiveness and current_effectiveness < self.min_effectiveness:
                to_prune.append(rule_id)
                continue

            # 条件2：误报率过高
            if trigger_count > 0 and false_positives / trigger_count > self.false_positive_threshold:
                to_prune.append(rule_id)
                continue

        # 条件3：规则数量超过上限，淘汰最低优先级规则
        if len(defense_rules) > self.max_rules:
            sorted_rules = sorted(
                defense_rules,
                key=lambda r: (
                    self.get_rule_avg_effectiveness(getattr(r, 'rule_id', '')),
                    getattr(r, 'effectiveness', 0.0),
                )
            )
            excess = len(defense_rules) - self.max_rules
            for rule in sorted_rules[:excess]:
                rule_id = getattr(rule, 'rule_id', 'unknown')
                if rule_id not in to_prune:
                    to_prune.append(rule_id)

        return to_prune

    def get_stats(self) -> Dict[str, Any]:
        """获取蓝方策略统计"""
        total_rules_tracked = len(self.rule_effectiveness_history)
        total_false_positives = sum(self.rule_false_positives.values())

        return {
            "rules_tracked": total_rules_tracked,
            "total_false_positives": total_false_positives,
            "min_effectiveness_threshold": self.min_effectiveness,
            "max_rules_limit": self.max_rules,
        }


class EvolutionTrigger:
    """
    智能进化触发器

    基于真实事件的频率、严重程度、新颖性智能触发红蓝进化：
    - 严重程度触发：critical 事件立即触发进化
    - 频率触发：某类事件频率超过阈值触发进化
    - 新颖性触发：新类型事件首次出现触发进化
    - 进化冷却期：避免短时间内重复进化同一类型
    - 批量处理：积累 N 个事件后批量进化
    """

    def __init__(
        self,
        cooldown_seconds: float = 60.0,
        batch_size: int = 10,
        frequency_threshold: int = 5,
        frequency_window_seconds: float = 300.0,
    ):
        """
        初始化智能进化触发器

        Args:
            cooldown_seconds: 进化冷却期（秒），同一类型事件在此期间不重复触发
            batch_size: 批量进化的事件数量阈值
            frequency_threshold: 频率触发阈值（时间窗口内出现次数）
            frequency_window_seconds: 频率统计时间窗口（秒）
        """
        self.cooldown_seconds = cooldown_seconds
        self.batch_size = batch_size
        self.frequency_threshold = frequency_threshold
        self.frequency_window_seconds = frequency_window_seconds

        self.event_buffer: List[EscapeEvent] = []
        self.last_evolution_time: Dict[str, float] = {}
        self.event_type_timestamps: Dict[str, List[float]] = defaultdict(list)
        self.seen_event_types: Set[str] = set()

        self.trigger_stats = {
            "total_triggers": 0,
            "severity_triggers": 0,
            "frequency_triggers": 0,
            "novelty_triggers": 0,
            "batch_triggers": 0,
            "cooldown_skipped": 0,
        }

    def should_evolve(self, event: EscapeEvent) -> Tuple[bool, str]:
        """
        判断是否应该触发进化

        Args:
            event: 真实逃逸事件

        Returns:
            (是否触发进化, 触发原因)
        """
        event_type = self._get_event_type(event)
        now = event.timestamp

        # 记录事件
        self.event_buffer.append(event)
        self.event_type_timestamps[event_type].append(now)

        # 清理过期时间戳
        self._cleanup_old_timestamps(now)

        # 检查冷却期
        if self._is_in_cooldown(event_type, now):
            self.trigger_stats["cooldown_skipped"] += 1
            return False, "cooldown"

        # 触发条件1：严重程度触发（critical 事件立即触发）
        if event.severity == "critical":
            self._record_trigger(event_type, now)
            self.trigger_stats["severity_triggers"] += 1
            return True, "critical_severity"

        # 触发条件2：新颖性触发（新类型事件首次出现）
        if event_type not in self.seen_event_types:
            self.seen_event_types.add(event_type)
            self._record_trigger(event_type, now)
            self.trigger_stats["novelty_triggers"] += 1
            return True, "novel_event_type"

        # 触发条件3：频率触发（时间窗口内出现次数超过阈值）
        frequency = len(self.event_type_timestamps[event_type])
        if frequency >= self.frequency_threshold:
            self._record_trigger(event_type, now)
            self.trigger_stats["frequency_triggers"] += 1
            return True, f"high_frequency({frequency}次)"

        # 触发条件4：批量触发（缓冲事件数量超过阈值）
        if len(self.event_buffer) >= self.batch_size:
            self._record_trigger(event_type, now)
            self.trigger_stats["batch_triggers"] += 1
            return True, f"batch_full({len(self.event_buffer)}事件)"

        return False, "waiting"

    def get_pending_events(self) -> List[EscapeEvent]:
        """获取待处理的事件缓冲（进化时使用）"""
        return self.event_buffer.copy()

    def clear_buffer(self) -> None:
        """清空事件缓冲（进化完成后调用）"""
        self.event_buffer.clear()

    def _get_event_type(self, event: EscapeEvent) -> str:
        """获取事件类型标识"""
        if event.syscall:
            return f"seccomp_{event.syscall}"
        if event.vm_exit_reason:
            return f"vmexit_{event.vm_exit_reason}"
        return event.signal_type.value

    def _is_in_cooldown(self, event_type: str, now: float) -> bool:
        """检查是否在冷却期内"""
        last_time = self.last_evolution_time.get(event_type, 0)
        return (now - last_time) < self.cooldown_seconds

    def _record_trigger(self, event_type: str, now: float) -> None:
        """记录触发时间"""
        self.last_evolution_time[event_type] = now
        self.trigger_stats["total_triggers"] += 1

    def _cleanup_old_timestamps(self, now: float) -> None:
        """清理过期的时间戳"""
        cutoff = now - self.frequency_window_seconds
        for event_type in list(self.event_type_timestamps.keys()):
            self.event_type_timestamps[event_type] = [
                t for t in self.event_type_timestamps[event_type] if t >= cutoff
            ]

    def get_stats(self) -> Dict[str, Any]:
        """获取触发器统计"""
        return {
            **self.trigger_stats,
            "pending_events": len(self.event_buffer),
            "seen_event_types": len(self.seen_event_types),
            "cooldown_seconds": self.cooldown_seconds,
            "batch_size": self.batch_size,
        }


class AdversarialStrategyOrchestrator:
    """
    红蓝对抗进化策略编排器

    整合对抗评估器、红方策略优化器、蓝方策略优化器、智能进化触发器，
    实现基于真实数据的完整红蓝进化闭环：

    真实事件 → 智能触发 → 对抗评估 → 红方策略优化 → 蓝方策略优化 → 进化执行 → 反馈
    """

    def __init__(
        self,
        cooldown_seconds: float = 60.0,
        batch_size: int = 10,
    ):
        self.evaluator = AdversarialEvaluator()
        self.red_optimizer = RedStrategyOptimizer()
        self.blue_optimizer = BlueStrategyOptimizer()
        self.trigger = EvolutionTrigger(cooldown_seconds=cooldown_seconds, batch_size=batch_size)
        self.evolution_history: List[Dict[str, Any]] = []

    def process_real_event(
        self,
        event: EscapeEvent,
        red_agent=None,
        blue_agent=None,
    ) -> Dict[str, Any]:
        """
        处理真实事件，判断是否触发进化

        Args:
            event: 真实逃逸事件
            red_agent: 红方代理（可选，用于执行进化）
            blue_agent: 蓝方代理（可选，用于执行进化）

        Returns:
            处理结果
        """
        # 1. 红方提取攻击模式
        pattern = self.red_optimizer.extract_attack_pattern(event)

        # 2. 智能触发判断
        should_evolve, reason = self.trigger.should_evolve(event)

        result = {
            "event_id": event.event_id,
            "pattern_extracted": pattern.pattern_id,
            "should_evolve": should_evolve,
            "trigger_reason": reason,
        }

        # 3. 如果触发进化，执行完整进化流程
        if should_evolve:
            evolution_result = self._execute_evolution(red_agent, blue_agent)
            result["evolution"] = evolution_result
            self.trigger.clear_buffer()

        return result

    def _execute_evolution(self, red_agent=None, blue_agent=None) -> Dict[str, Any]:
        """执行完整进化流程"""
        start_time = time.time()

        # 1. 获取当前攻击用例和防御规则
        attack_cases = getattr(red_agent, 'attack_cases', []) if red_agent else []
        defense_rules = getattr(blue_agent, 'defense_rules', []) if blue_agent else []
        attack_patterns = list(self.red_optimizer.attack_patterns.values())

        # 2. 对抗评估
        eval_result = self.evaluator.evaluate(attack_cases, defense_rules, attack_patterns)

        # 3. 红方策略优化
        red_weights = self.red_optimizer.optimize_strategy_weights(eval_result)
        priority_patterns = self.red_optimizer.get_priority_attack_patterns()

        # 4. 蓝方策略优化
        # 基于防御盲区生成针对性防御建议
        targeted_defenses = []
        for gap in eval_result.defense_gaps[:3]:
            matching_patterns = [
                p for p in attack_patterns
                if p.attack_type == gap.attack_type
            ]
            if matching_patterns:
                defense = self.blue_optimizer.generate_targeted_defense(
                    matching_patterns[0], gap
                )
                targeted_defenses.append(defense)

        # 5. 识别需要淘汰的规则
        rules_to_prune = self.blue_optimizer.identify_rules_to_prune(defense_rules)

        # 6. 记录进化历史
        evolution_result = {
            "timestamp": start_time,
            "duration_ms": (time.time() - start_time) * 1000,
            "evaluation": eval_result.to_dict(),
            "red_strategy_weights": red_weights,
            "priority_attack_patterns": [p.to_dict() for p in priority_patterns],
            "targeted_defenses": targeted_defenses,
            "rules_to_prune": rules_to_prune,
            "trigger_stats": self.trigger.get_stats(),
            "red_stats": self.red_optimizer.get_stats(),
            "blue_stats": self.blue_optimizer.get_stats(),
        }

        self.evolution_history.append(evolution_result)
        if len(self.evolution_history) > 100:
            self.evolution_history = self.evolution_history[-100:]

        return evolution_result

    def get_summary(self) -> Dict[str, Any]:
        """获取策略编排器摘要"""
        return {
            "total_evolutions": len(self.evolution_history),
            "evaluator_trend": self.evaluator.get_trend(),
            "trigger_stats": self.trigger.get_stats(),
            "red_stats": self.red_optimizer.get_stats(),
            "blue_stats": self.blue_optimizer.get_stats(),
            "latest_evolution": self.evolution_history[-1] if self.evolution_history else None,
        }
