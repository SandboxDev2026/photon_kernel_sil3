"""
PhotonBox 量子启发安全引擎（Quantum-Inspired Security Engine）

不需要量子硬件，用量子算法思想优化经典安全系统：

1. QuantumAnomalyDetector — 量子退火启发的异常检测（QAOA思想优化安全策略参数）
2. QuantumEventCorrelator — 量子概率论启发的事件关联（叠加态表示+量子干涉建模）
3. QuantumSearchReranker — Grover量子搜索思想的RAG重排序（幅度放大）
4. SNNIntrusionDetector — 脉冲神经网络实时入侵检测（LIF神经元模型，事件驱动）

设计参考：
- 量子退火/QAOA（Quantum Approximate Optimization Algorithm）
- 量子概率论（叠加态、量子干涉、测量坍缩）
- Grover量子搜索算法（幅度放大）
- 脉冲神经网络（Spiking Neural Network, LIF神经元模型）
"""

from __future__ import annotations

import math
import time
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ============================================================
# 1. 量子退火启发的异常检测
# ============================================================

@dataclass
class AnomalyScore:
    """异常评分结果"""
    score: float  # 0.0-1.0，越高越异常
    is_anomaly: bool
    contributing_features: List[str]
    energy: float  # 量子退火中的能量值（越低越正常）
    iterations: int
    convergence: bool


class QuantumAnomalyDetector:
    """
    量子退火启发的异常检测

    核心思想：
    - 将安全策略参数优化建模为 Ising 模型能量最小化问题
    - 用 QAOA（Quantum Approximate Optimization Algorithm）思想
      交替应用"成本哈密顿量"和"混合哈密顿量"
    - 多目标优化：检测率 vs 误报率 vs 延迟
    - 比经典梯度下降更易跳出局部最优

    适用场景：
    - 安全策略参数自动调优
    - 多维度异常评分
    - 实时入侵检测
    """

    def __init__(self, n_qubits: int = 8, n_layers: int = 4,
                 threshold: float = 0.7, learning_rate: float = 0.01):
        self.n_qubits = n_qubits
        self.n_layers = n_layers
        self.threshold = threshold
        self.learning_rate = learning_rate

        # QAOA 参数（角度）
        self.gamma = [random.uniform(0, math.pi) for _ in range(n_layers)]  # nosec B311: QAOA参数初始化，非密码学用途
        self.beta = [random.uniform(0, math.pi / 2) for _ in range(n_layers)]  # nosec B311: QAOA参数初始化，非密码学用途

        # Ising 模型耦合系数（特征间交互）
        self.couplings: Dict[Tuple[int, int], float] = {}
        self.fields: List[float] = [0.0] * n_qubits

        # 统计
        self._stats = {
            "total_detections": 0,
            "anomalies_detected": 0,
            "avg_iterations": 0,
            "convergence_rate": 0,
        }

    def set_coupling(self, i: int, j: int, value: float) -> None:
        """设置 Ising 模型耦合系数（特征i和j的交互强度）"""
        if i == j:
            self.fields[i] = value
        else:
            key = (min(i, j), max(i, j))
            self.couplings[key] = value

    def detect(self, features: List[float], max_iterations: int = 100) -> AnomalyScore:
        """
        检测异常

        Args:
            features: 特征向量（长度应等于n_qubits）
            max_iterations: 最大迭代次数

        Returns:
            异常评分结果
        """
        self._stats["total_detections"] += 1

        # 归一化特征到 [-1, 1]
        normalized = self._normalize_features(features)

        # QAOA 模拟：计算期望能量
        energy, iterations, convergence = self._qaoa_optimize(normalized, max_iterations)

        # 能量转换为异常分数（能量越低越正常，越高越异常）
        # 归一化能量到 [0, 1]
        max_possible_energy = self.n_qubits + len(self.couplings)
        score = min(abs(energy) / max(max_possible_energy, 1), 1.0)

        # 特征贡献分析
        contributing = self._analyze_contributions(normalized)

        is_anomaly = score >= self.threshold
        if is_anomaly:
            self._stats["anomalies_detected"] += 1

        self._stats["avg_iterations"] = (
            (self._stats["avg_iterations"] * (self._stats["total_detections"] - 1) + iterations)
            / self._stats["total_detections"]
        )
        if convergence:
            self._stats["convergence_rate"] = (
                (self._stats["convergence_rate"] * (self._stats["total_detections"] - 1) + 1)
                / self._stats["total_detections"]
            )

        return AnomalyScore(
            score=score,
            is_anomaly=is_anomaly,
            contributing_features=contributing,
            energy=energy,
            iterations=iterations,
            convergence=convergence,
        )

    def _normalize_features(self, features: List[float]) -> List[float]:
        """归一化特征到 [-1, 1]（Ising 自旋值）"""
        if not features:
            return [0.0] * self.n_qubits

        # 截断到 n_qubits
        truncated = features[:self.n_qubits]
        # 补零
        while len(truncated) < self.n_qubits:
            truncated.append(0.0)

        # 归一化到 [-1, 1]
        max_abs = max(abs(x) for x in truncated) if truncated else 1.0
        if max_abs == 0:
            max_abs = 1.0
        return [x / max_abs for x in truncated]

    def _qaoa_optimize(self, spins: List[float], max_iterations: int) -> Tuple[float, int, bool]:
        """
        QAOA 模拟优化

        交替应用：
        - 成本哈密顿量（gamma角度）：降低能量
        - 混合哈密顿量（beta角度）：量子隧穿，跳出局部最优
        """
        current_spins = spins[:]
        prev_energy = self._ising_energy(current_spins)
        convergence = False

        for iteration in range(max_iterations):
            layer = iteration % self.n_layers

            # 成本层：降低能量（类似量子退火中的退火调度）
            temperature = max(0.01, 1.0 - iteration / max_iterations)
            current_spins = self._cost_layer(current_spins, self.gamma[layer], temperature)

            # 混合层：量子隧穿（随机翻转，模拟量子叠加）
            if random.random() < self.beta[layer] / (math.pi / 2):  # nosec B311: 量子隧穿模拟，非密码学用途
                flip_idx = random.randint(0, self.n_qubits - 1)  # nosec B311: 量子隧穿模拟，非密码学用途
                current_spins[flip_idx] *= -1

            # 计算能量
            energy = self._ising_energy(current_spins)

            # 收敛判断
            if abs(energy - prev_energy) < 1e-6:
                convergence = True
                break
            prev_energy = energy

        return energy, iteration + 1, convergence

    def _cost_layer(self, spins: List[float], gamma: float,
                     temperature: float) -> List[float]:
        """成本层：模拟退火，降低 Ising 能量"""
        new_spins = spins[:]
        for i in range(self.n_qubits):
            # 计算自旋i的局部场
            local_field = self.fields[i]
            for (j, k), coupling in self.couplings.items():
                if j == i:
                    local_field += coupling * spins[k]
                elif k == i:
                    local_field += coupling * spins[j]

            # 模拟退火：以概率翻转自旋
            delta_energy = 2 * spins[i] * local_field
            if delta_energy > 0:
                flip_prob = math.exp(-delta_energy / temperature)
                if random.random() < flip_prob:  # nosec B311: 模拟退火随机翻转，非密码学用途
                    new_spins[i] *= -1
            else:
                # 能量降低，直接翻转
                new_spins[i] *= -1

        return new_spins

    def _ising_energy(self, spins: List[float]) -> float:
        """计算 Ising 模型能量"""
        energy = 0.0
        # 场项
        for i in range(self.n_qubits):
            energy -= self.fields[i] * spins[i]
        # 耦合项
        for (i, j), coupling in self.couplings.items():
            energy -= coupling * spins[i] * spins[j]
        return energy

    def _analyze_contributions(self, spins: List[float]) -> List[str]:
        """分析各特征对异常的贡献"""
        contributions = []
        for i in range(self.n_qubits):
            local_field = self.fields[i]
            for (j, k), coupling in self.couplings.items():
                if j == i:
                    local_field += coupling * spins[k]
                elif k == i:
                    local_field += coupling * spins[j]
            if abs(local_field) > 0.5:
                contributions.append(f"feature_{i}")
        return contributions

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return dict(self._stats)


# ============================================================
# 2. 量子概率论启发的事件关联
# ============================================================

@dataclass
class QuantumEventState:
    """量子事件状态（叠加态表示）"""
    event_id: str
    amplitudes: Dict[str, complex]  # 各可能状态的概率幅
    measured: bool = False
    measured_state: Optional[str] = None

    def get_probabilities(self) -> Dict[str, float]:
        """获取各状态的概率（|幅度|^2）"""
        return {state: abs(amp) ** 2 for state, amp in self.amplitudes.items()}

    def measure(self) -> str:
        """测量（坍缩到确定状态）"""
        if self.measured:
            return self.measured_state  # type: ignore

        probs = self.get_probabilities()
        total = sum(probs.values())
        if total == 0:
            self.measured_state = "unknown"
        else:
            r = random.random() * total  # nosec B311: 量子测量坍缩模拟，非密码学用途
            cumulative = 0.0
            for state, prob in probs.items():
                cumulative += prob
                if r <= cumulative:
                    self.measured_state = state
                    break
            if self.measured_state is None:
                self.measured_state = list(probs.keys())[-1]

        self.measured = True
        return self.measured_state


class QuantumEventCorrelator:
    """
    量子概率论启发的事件关联

    核心思想：
    - 叠加态表示："可能是攻击也可能不是"，用概率幅表示
    - 量子干涉建模：多事件关联时，概率幅相加再取模平方
      （而非概率直接相加），可以产生相长/相消干涉
    - 测量（决策）时坍缩到确定状态

    与经典概率论的区别：
    - 经典：P(A∪B) = P(A) + P(B) - P(A∩B)
    - 量子：P(A∪B) = |ψ_A + ψ_B|² = P(A) + P(B) + 2Re(ψ_A*ψ_B*)
      干涉项 2Re(ψ_A*ψ_B*) 可以增强或减弱关联强度

    适用场景：
    - RealDataAdapter 事件关联
    - 攻击链检测
    - 多源证据融合
    """

    def __init__(self, interference_strength: float = 0.5):
        self.interference_strength = interference_strength
        self.event_states: Dict[str, QuantumEventState] = {}
        self._stats = {
            "total_correlations": 0,
            "constructive_interference": 0,
            "destructive_interference": 0,
        }

    def add_event(self, event_id: str,
                  initial_amplitudes: Optional[Dict[str, complex]] = None) -> QuantumEventState:
        """
        添加事件（初始化为叠加态）

        Args:
            event_id: 事件ID
            initial_amplitudes: 初始概率幅（如不提供，均匀分布）

        Returns:
            量子事件状态
        """
        if initial_amplitudes is None:
            # 默认状态：normal / suspicious / attack
            initial_amplitudes = {
                "normal": complex(1 / math.sqrt(3), 0),
                "suspicious": complex(1 / math.sqrt(3), 0),
                "attack": complex(1 / math.sqrt(3), 0),
            }

        state = QuantumEventState(
            event_id=event_id,
            amplitudes=initial_amplitudes,
        )
        self.event_states[event_id] = state
        return state

    def correlate(self, event_ids: List[str]) -> Dict[str, Any]:
        """
        关联多个事件（量子干涉）

        将多个事件的概率幅相加，产生干涉效应，
        然后测量得到最终关联结果。

        Args:
            event_ids: 要关联的事件ID列表

        Returns:
            关联结果（包含干涉类型、最终概率、测量结果）
        """
        self._stats["total_correlations"] += 1

        if not event_ids:
            return {"correlated": False, "reason": "no events"}

        # 收集所有事件的概率幅
        all_amplitudes: Dict[str, complex] = {}
        for eid in event_ids:
            if eid in self.event_states:
                state = self.event_states[eid]
                for state_name, amp in state.amplitudes.items():
                    if state_name not in all_amplitudes:
                        all_amplitudes[state_name] = complex(0, 0)
                    # 量子叠加：概率幅相加
                    all_amplitudes[state_name] += amp * self.interference_strength

        if not all_amplitudes:
            return {"correlated": False, "reason": "no valid event states"}

        # 归一化
        total_norm = math.sqrt(sum(abs(a) ** 2 for a in all_amplitudes.values()))
        if total_norm > 0:
            all_amplitudes = {k: v / total_norm for k, v in all_amplitudes.items()}

        # 计算干涉类型
        interference_type = self._classify_interference(event_ids, all_amplitudes)

        # 测量（坍缩）
        combined_state = QuantumEventState(
            event_id="combined",
            amplitudes=all_amplitudes,
        )
        measured = combined_state.measure()
        probabilities = combined_state.get_probabilities()

        return {
            "correlated": True,
            "event_count": len(event_ids),
            "interference_type": interference_type,
            "probabilities": probabilities,
            "measured_state": measured,
            "attack_probability": probabilities.get("attack", 0.0),
            "suspicious_probability": probabilities.get("suspicious", 0.0),
        }

    def _classify_interference(self, event_ids: List[str],
                                 combined_amplitudes: Dict[str, complex]) -> str:
        """分类干涉类型（相长/相消/中性）"""
        # 计算单个事件的平均概率
        single_probs: Dict[str, float] = {}
        for eid in event_ids:
            if eid in self.event_states:
                probs = self.event_states[eid].get_probabilities()
                for state, prob in probs.items():
                    if state not in single_probs:
                        single_probs[state] = 0.0
                    single_probs[state] += prob

        n_events = len([e for e in event_ids if e in self.event_states])
        if n_events > 0:
            single_probs = {k: v / n_events for k, v in single_probs.items()}

        # 比较组合概率与平均概率
        combined_probs = {k: abs(v) ** 2 for k, v in combined_amplitudes.items()}

        constructive = 0
        destructive = 0
        for state in combined_probs:
            if state in single_probs:
                diff = combined_probs[state] - single_probs[state]
                if diff > 0.05:
                    constructive += 1
                elif diff < -0.05:
                    destructive += 1

        if constructive > destructive:
            self._stats["constructive_interference"] += 1
            return "constructive"  # 相长干涉（关联增强）
        elif destructive > constructive:
            self._stats["destructive_interference"] += 1
            return "destructive"  # 相消干涉（关联减弱）
        else:
            return "neutral"  # 中性干涉

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return dict(self._stats)


# ============================================================
# 3. Grover 量子搜索思想的 RAG 重排序
# ============================================================

class QuantumSearchReranker:
    """
    Grover 量子搜索思想的 RAG 重排序

    核心思想：
    - Grover 算法通过"幅度放大"（Amplitude Amplification）
      在无序搜索中达到 O(√N) 复杂度
    - 经典重排序只看相似度分数，Grover 思想引入：
      1. 预言机（Oracle）：标记"好"结果（相关文档）
      2. 扩散算子（Diffusion）：放大好结果的幅度，抑制坏结果
    - 多次迭代后，相关文档的"幅度"（分数）被显著放大

    适用场景：
    - RAG 检索结果重排序
    - 知识库搜索优化
    - 攻击模式匹配
    """

    def __init__(self, n_iterations: int = 3, oracle_threshold: float = 0.3):
        self.n_iterations = n_iterations
        self.oracle_threshold = oracle_threshold
        self._stats = {
            "total_reranks": 0,
            "avg_amplification": 0.0,
        }

    def rerank(self, results: List[Dict[str, Any]],
                query: str, score_key: str = "score") -> List[Dict[str, Any]]:
        """
        用 Grover 思想重排序检索结果

        Args:
            results: 检索结果列表（每个包含score_key）
            query: 查询文本（用于预言机判断相关性）
            score_key: 分数字段名

        Returns:
            重排序后的结果列表（按放大后的分数降序）
        """
        self._stats["total_reranks"] += 1

        if not results:
            return results

        n = len(results)
        if n == 1:
            result = dict(results[0])
            result["original_score"] = result.get(score_key, 0.0)
            result["amplified_score"] = result.get(score_key, 0.0)
            result["amplification_prob"] = 1.0 / n
            result["rank"] = 1
            return [result]

        # 初始化幅度（均匀分布）
        amplitudes = [1.0 / math.sqrt(n)] * n

        # 统计相关结果数量（预言机判断）
        n_relevant = sum(1 for r in results if self._oracle(r, query, score_key))

        # Grover 算法只在相关结果 < 一半时有效
        # 当相关结果 >= 一半时，Grover会反向放大不相关结果，此时直接按原始分数排序
        if n_relevant >= n / 2:
            # 直接按原始分数降序排序
            sorted_results = sorted(
                [dict(r) for r in results],
                key=lambda x: x.get(score_key, 0.0),
                reverse=True
            )
            for i, r in enumerate(sorted_results):
                r["original_score"] = r.get(score_key, 0.0)
                r["amplified_score"] = r.get(score_key, 0.0)
                r["amplification_prob"] = 1.0 / n
                r["rank"] = i + 1
            self._stats["total_reranks"] += 1
            self._stats["avg_amplification"] = (
                (self._stats["avg_amplification"] * (self._stats["total_reranks"] - 1) + 1.0 / n)
                / self._stats["total_reranks"]
            )
            return sorted_results

        # Grover 迭代（最佳迭代次数约为 pi/4 * sqrt(n/k)，k为相关结果数）
        optimal_iters = max(1, int(math.pi / 4 * math.sqrt(n / max(n_relevant, 1))))
        for _ in range(min(self.n_iterations, optimal_iters)):
            # 1. 预言机：标记相关结果（相位翻转）
            for i, result in enumerate(results):
                if self._oracle(result, query, score_key):
                    amplitudes[i] *= -1  # 相位翻转

            # 2. 扩散算子：关于平均值反转（幅度放大）
            mean_amp = sum(amplitudes) / n
            for i in range(n):
                amplitudes[i] = 2 * mean_amp - amplitudes[i]

        # 将幅度转换为最终分数
        amplified_scores = []
        for i, result in enumerate(results):
            original_score = result.get(score_key, 0.0)
            # 幅度平方 = 概率（放大后的相关性）
            amplified_prob = amplitudes[i] ** 2
            # 融合原始分数和放大概率
            final_score = 0.6 * original_score + 0.4 * amplified_prob * n
            amplified_scores.append((i, final_score, amplified_prob))

        # 统计平均放大倍数
        avg_amp = sum(p for _, _, p in amplified_scores) / n
        self._stats["avg_amplification"] = (
            (self._stats["avg_amplification"] * (self._stats["total_reranks"] - 1) + avg_amp)
            / self._stats["total_reranks"]
        )

        # 按放大后的分数降序排序
        amplified_scores.sort(key=lambda x: x[1], reverse=True)

        # 重建结果列表
        reranked = []
        for original_idx, final_score, amplified_prob in amplified_scores:
            result = dict(results[original_idx])
            result["original_score"] = result.get(score_key, 0.0)
            result["amplified_score"] = final_score
            result["amplification_prob"] = amplified_prob
            result[score_key] = final_score
            result["rank"] = len(reranked) + 1
            reranked.append(result)

        return reranked

    def _oracle(self, result: Dict[str, Any], query: str,
                score_key: str) -> bool:
        """
        预言机：判断结果是否相关

        简化实现：基于分数阈值和关键词匹配
        真实场景可以用更复杂的相关性判断
        """
        score = result.get(score_key, 0.0)
        if score >= self.oracle_threshold:
            return True

        # 关键词匹配（内容中包含查询关键词）
        content = result.get("content", "").lower()
        query_words = [w.lower() for w in query.split() if len(w) > 2]
        if query_words and any(w in content for w in query_words):
            return True

        return False

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return dict(self._stats)


# ============================================================
# 4. 脉冲神经网络实时入侵检测
# ============================================================

@dataclass
class LIFNeuron:
    """LIF（Leaky Integrate-and-Fire）神经元"""
    neuron_id: int
    threshold: float = 1.0
    resting_potential: float = 0.0
    reset_potential: float = 0.0
    tau: float = 10.0  # 膜时间常数（ms）
    refractory_period: float = 2.0  # 不应期（ms）

    membrane_potential: float = 0.0
    last_spike_time: float = -float('inf')
    spike_count: int = 0
    input_history: List[Tuple[float, float]] = field(default_factory=list)  # (time, current)

    def step(self, t: float, input_current: float) -> bool:
        """
        前进一步，返回是否产生脉冲

        Args:
            t: 当前时间（ms）
            input_current: 输入电流

        Returns:
            是否产生脉冲（spike）
        """
        # 不应期检查
        if t - self.last_spike_time < self.refractory_period:
            self.membrane_potential = self.reset_potential
            return False

        # LIF 膜电位更新（欧拉法）
        # dV/dt = (V_rest - V + R*I) / tau
        dt = 1.0  # 时间步长（ms）
        dv = (self.resting_potential - self.membrane_potential + input_current) / self.tau * dt
        self.membrane_potential += dv

        # 记录输入历史
        self.input_history.append((t, input_current))
        if len(self.input_history) > 1000:
            self.input_history.pop(0)

        # 阈值检测
        if self.membrane_potential >= self.threshold:
            self.spike_count += 1
            self.last_spike_time = t
            self.membrane_potential = self.reset_potential
            return True

        return False

    def reset(self) -> None:
        """重置神经元状态"""
        self.membrane_potential = self.resting_potential
        self.last_spike_time = -float('inf')
        self.spike_count = 0
        self.input_history.clear()


class SNNIntrusionDetector:
    """
    脉冲神经网络实时入侵检测

    核心思想：
    - 事件驱动：只有输入电流超过阈值时才产生脉冲，低功耗
    - 时空处理：模拟生物神经元的时空信息处理能力
    - 微秒级延迟：适合高速网络流量分析
    - 无监督学习：STDP（脉冲时序依赖可塑性）自动调整权重

    网络结构：
    - 输入层：每个安全特征对应一个输入神经元
    - 隐藏层：脉冲模式识别
    - 输出层：正常/异常/攻击 三类神经元

    适用场景：
    - 实时入侵检测
    - 高速网络流量分析
    - 异常模式识别
    - 低延迟安全监控
    """

    def __init__(self, n_input: int = 8, n_hidden: int = 16,
                 n_output: int = 3, simulation_time: float = 100.0):
        self.n_input = n_input
        self.n_hidden = n_hidden
        self.n_output = n_output
        self.simulation_time = simulation_time
        self.current_gain = 5.0  # 电流放大系数，确保脉冲传递

        # 创建神经元
        self.input_neurons = [LIFNeuron(i, threshold=0.8) for i in range(n_input)]
        self.hidden_neurons = [LIFNeuron(n_input + i, threshold=0.5) for i in range(n_hidden)]
        self.output_neurons = [
            LIFNeuron(n_input + n_hidden + i, threshold=0.8)
            for i in range(n_output)
        ]
        self.output_labels = ["normal", "suspicious", "attack"]

        # 突触权重（输入→隐藏，隐藏→输出）
        self.weights_input_hidden = self._init_weights(n_input, n_hidden)
        self.weights_hidden_output = self._init_weights(n_hidden, n_output)

        # STDP 学习参数
        self.stdp_lr = 0.05
        self.stdp_tau_plus = 20.0
        self.stdp_tau_minus = 20.0

        # 统计
        self._stats = {
            "total_detections": 0,
            "attack_detected": 0,
            "suspicious_detected": 0,
            "normal_detected": 0,
            "avg_latency_ms": 0.0,
        }

    def _init_weights(self, n_pre: int, n_post: int) -> List[List[float]]:
        """初始化突触权重（随机均匀分布，较大范围确保脉冲传递）"""
        return [[random.uniform(-1.0, 1.0) for _ in range(n_post)] for _ in range(n_pre)]  # nosec B311: 突触权重初始化，非密码学用途

    def detect(self, features: List[float]) -> Dict[str, Any]:
        """
        检测入侵

        Args:
            features: 特征向量（安全指标）

        Returns:
            检测结果（分类、脉冲计数、置信度）
        """
        start_time = time.time()
        self._stats["total_detections"] += 1

        # 重置所有神经元
        for neuron in self.input_neurons + self.hidden_neurons + self.output_neurons:
            neuron.reset()

        # 归一化特征到 [0, 1]
        normalized = self._normalize(features)

        # SNN 仿真
        input_spike_times = [[] for _ in range(self.n_input)]
        hidden_spike_times = [[] for _ in range(self.n_hidden)]
        output_spike_times = [[] for _ in range(self.n_output)]

        for t in range(int(self.simulation_time)):
            # 输入层：特征值转换为输入电流（频率编码）
            for i, neuron in enumerate(self.input_neurons):
                feature_val = normalized[i] if i < len(normalized) else 0.0
                # 频率编码：特征值越大，输入电流越大
                input_current = feature_val * 2.0
                if neuron.step(t, input_current):
                    input_spike_times[i].append(t)

            # 隐藏层：输入脉冲通过突触权重传递
            for j, hidden_neuron in enumerate(self.hidden_neurons):
                hidden_current = 0.0
                for i, input_neuron in enumerate(self.input_neurons):
                    if input_spike_times[i] and input_spike_times[i][-1] == t:
                        hidden_current += self.weights_input_hidden[i][j] * self.current_gain
                if hidden_neuron.step(t, hidden_current):
                    hidden_spike_times[j].append(t)

            # 输出层：隐藏脉冲通过突触权重传递
            for k, output_neuron in enumerate(self.output_neurons):
                output_current = 0.0
                for j, hidden_neuron in enumerate(self.hidden_neurons):
                    if hidden_spike_times[j] and hidden_spike_times[j][-1] == t:
                        output_current += self.weights_hidden_output[j][k] * self.current_gain
                if output_neuron.step(t, output_current):
                    output_spike_times[k].append(t)

        # 解码：脉冲最多的输出神经元为分类结果
        output_counts = [len(times) for times in output_spike_times]
        total_spikes = sum(output_counts)

        if total_spikes == 0:
            predicted = "normal"
            confidence = 0.5
        else:
            max_idx = output_counts.index(max(output_counts))
            predicted = self.output_labels[max_idx]
            confidence = output_counts[max_idx] / total_spikes

        # STDP 学习（无监督，基于脉冲时序）
        self._stdp_update(input_spike_times, hidden_spike_times,
                          hidden_spike_times, output_spike_times)

        # 更新统计
        if predicted == "attack":
            self._stats["attack_detected"] += 1
        elif predicted == "suspicious":
            self._stats["suspicious_detected"] += 1
        else:
            self._stats["normal_detected"] += 1

        latency = (time.time() - start_time) * 1000  # ms
        self._stats["avg_latency_ms"] = (
            (self._stats["avg_latency_ms"] * (self._stats["total_detections"] - 1) + latency)
            / self._stats["total_detections"]
        )

        return {
            "predicted": predicted,
            "confidence": confidence,
            "output_spike_counts": dict(zip(self.output_labels, output_counts)),
            "total_spikes": total_spikes,
            "latency_ms": latency,
            "is_attack": predicted == "attack",
            "is_suspicious": predicted in ("attack", "suspicious"),
        }

    def _normalize(self, features: List[float]) -> List[float]:
        """归一化特征到 [0, 1]"""
        if not features:
            return [0.0] * self.n_input

        truncated = features[:self.n_input]
        while len(truncated) < self.n_input:
            truncated.append(0.0)

        max_val = max(abs(x) for x in truncated) if truncated else 1.0
        if max_val == 0:
            max_val = 1.0
        return [abs(x) / max_val for x in truncated]

    def _stdp_update(self, pre_spikes_1: List[List[float]],
                      post_spikes_1: List[List[float]],
                      pre_spikes_2: List[List[float]],
                      post_spikes_2: List[List[float]]) -> None:
        """
        STDP（脉冲时序依赖可塑性）权重更新

        - 突触前脉冲在突触后之前 → 权重增强（LTP）
        - 突触前脉冲在突触后之后 → 权重抑制（LTD）
        """
        # 输入→隐藏层 STDP
        for i in range(self.n_input):
            for j in range(self.n_hidden):
                for pre_t in pre_spikes_1[i]:
                    for post_t in post_spikes_1[j]:
                        delta_t = post_t - pre_t
                        if delta_t > 0:
                            # LTP：突触前先脉冲，权重增强
                            self.weights_input_hidden[i][j] += (
                                self.stdp_lr * math.exp(-delta_t / self.stdp_tau_plus)
                            )
                        elif delta_t < 0:
                            # LTD：突触后先脉冲，权重抑制
                            self.weights_input_hidden[i][j] -= (
                                self.stdp_lr * math.exp(delta_t / self.stdp_tau_minus)
                            )

        # 隐藏→输出层 STDP
        for j in range(self.n_hidden):
            for k in range(self.n_output):
                for pre_t in pre_spikes_2[j]:
                    for post_t in post_spikes_2[k]:
                        delta_t = post_t - pre_t
                        if delta_t > 0:
                            self.weights_hidden_output[j][k] += (
                                self.stdp_lr * math.exp(-delta_t / self.stdp_tau_plus)
                            )
                        elif delta_t < 0:
                            self.weights_hidden_output[j][k] -= (
                                self.stdp_lr * math.exp(delta_t / self.stdp_tau_minus)
                            )

        # 权重裁剪
        for i in range(self.n_input):
            for j in range(self.n_hidden):
                self.weights_input_hidden[i][j] = max(-1.0, min(1.0, self.weights_input_hidden[i][j]))
        for j in range(self.n_hidden):
            for k in range(self.n_output):
                self.weights_hidden_output[j][k] = max(-1.0, min(1.0, self.weights_hidden_output[j][k]))

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return dict(self._stats)


# ============================================================
# 统一入口：量子启发安全引擎
# ============================================================

class QuantumInspiredSecurityEngine:
    """
    量子启发安全引擎（统一入口）

    整合四个量子启发组件：
    1. QuantumAnomalyDetector — 量子退火异常检测
    2. QuantumEventCorrelator — 量子概率事件关联
    3. QuantumSearchReranker — Grover搜索重排序
    4. SNNIntrusionDetector — 脉冲神经网络入侵检测

    设计原则：
    - 不需要量子硬件，纯经典实现
    - 量子算法思想优化经典安全系统
    - 可独立使用，也可组合使用
    - 低延迟，适合实时安全监控
    """

    def __init__(self, n_qubits: int = 8, n_snn_input: int = 8):
        self.anomaly_detector = QuantumAnomalyDetector(n_qubits=n_qubits)
        self.event_correlator = QuantumEventCorrelator()
        self.search_reranker = QuantumSearchReranker()
        self.intrusion_detector = SNNIntrusionDetector(n_input=n_snn_input)

    def full_analysis(self, features: List[float],
                      events: Optional[List[Dict[str, Any]]] = None,
                      search_results: Optional[List[Dict[str, Any]]] = None,
                      query: str = "") -> Dict[str, Any]:
        """
        完整安全分析（四组件联动）

        Args:
            features: 安全特征向量
            events: 安全事件列表（用于事件关联）
            search_results: RAG检索结果（用于重排序）
            query: 查询文本（用于重排序预言机）

        Returns:
            完整分析结果
        """
        # 1. 量子退火异常检测
        anomaly = self.anomaly_detector.detect(features)

        # 2. SNN 入侵检测
        intrusion = self.intrusion_detector.detect(features)

        # 3. 量子概率事件关联（如果有事件）
        correlation = None
        if events:
            event_ids = []
            for i, event in enumerate(events):
                eid = event.get("event_id", f"event_{i}")
                # 根据事件严重程度设置初始幅度
                severity = event.get("severity", "medium")
                if severity == "critical":
                    amps = {"normal": complex(0.1, 0), "suspicious": complex(0.3, 0), "attack": complex(0.95, 0)}
                elif severity == "high":
                    amps = {"normal": complex(0.2, 0), "suspicious": complex(0.5, 0), "attack": complex(0.84, 0)}
                else:
                    amps = None  # 默认均匀分布
                self.event_correlator.add_event(eid, amps)
                event_ids.append(eid)
            correlation = self.event_correlator.correlate(event_ids)

        # 4. Grover 搜索重排序（如果有检索结果）
        reranked = None
        if search_results:
            reranked = self.search_reranker.rerank(search_results, query)

        # 综合评分
        anomaly_score = anomaly.score
        intrusion_attack_prob = 1.0 if intrusion["predicted"] == "attack" else (
            0.5 if intrusion["predicted"] == "suspicious" else 0.1)
        correlation_attack_prob = correlation["attack_probability"] if correlation else 0.0

        combined_risk = (
            0.35 * anomaly_score +
            0.35 * intrusion_attack_prob +
            0.30 * correlation_attack_prob
        )

        return {
            "anomaly_detection": {
                "score": anomaly.score,
                "is_anomaly": anomaly.is_anomaly,
                "energy": anomaly.energy,
                "iterations": anomaly.iterations,
                "convergence": anomaly.convergence,
            },
            "intrusion_detection": intrusion,
            "event_correlation": correlation,
            "search_reranking": reranked,
            "combined_risk_score": combined_risk,
            "risk_level": "critical" if combined_risk >= 0.8 else (
                "high" if combined_risk >= 0.6 else (
                    "medium" if combined_risk >= 0.4 else "low"
                )
            ),
            "stats": {
                "anomaly": self.anomaly_detector.get_stats(),
                "correlation": self.event_correlator.get_stats(),
                "reranker": self.search_reranker.get_stats(),
                "intrusion": self.intrusion_detector.get_stats(),
            },
        }
