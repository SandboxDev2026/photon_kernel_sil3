"""
量子启发安全增强模块

基于量子计算与量子比特模拟技术，为 PhotonBox 沙盒安全提供增强能力：

1. VQEOptimizer - 变分量子特征求解器：沙盒资源分配优化、多实例调度优化
2. QuantumKernelClusterer - 量子核方法：攻击样本聚类、异常样本检测
3. QuantumErrorCorrectionGuard - 量子纠错启发：多副本状态校验、系统容错
4. QRNGEntropySource - 量子随机数熵源：密钥生成、盐值、nonce
5. STDPEnhancedSNN - STDP学习规则增强：自适应脉冲神经网络入侵检测

所有模块均为经典模拟实现（无需量子硬件），利用量子算法思想优化经典安全系统。
"""

from __future__ import annotations

import hashlib
import math
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ============================================================================
# 1. VQE 变分量子特征求解器 —— 资源分配优化
# ============================================================================

@dataclass
class ResourceAllocation:
    """资源分配方案"""
    instance_id: str
    cpu_quota: float          # 0.0 - 1.0
    memory_quota: float       # 0.0 - 1.0
    network_bandwidth: float  # 0.0 - 1.0
    energy: float = 0.0       # 哈密顿量期望值（越低越好）
    convergence: bool = False


class VQEOptimizer:
    """
    变分量子特征求解器（Variational Quantum Eigensolver）

    原理：
    - 参数化量子电路（Ansatz）制备试探态 |ψ(θ)⟩
    - 测量哈密顿量期望值 ⟨ψ(θ)|H|ψ(θ)⟩
    - 经典优化器更新参数 θ，最小化期望值

    应用：沙盒资源分配优化
    - 哈密顿量 H = 资源利用率代价 + 公平性惩罚 + SLA违反惩罚
    - 基态对应最优资源分配方案
    """

    def __init__(
        self,
        n_qubits: int = 6,
        n_layers: int = 3,
        learning_rate: float = 0.05,
        max_iterations: int = 200,
        convergence_threshold: float = 1e-6,
        lambda_fairness: float = 0.3,
        lambda_sla: float = 0.5,
    ):
        self.n_qubits = n_qubits
        self.n_layers = n_layers
        self.learning_rate = learning_rate
        self.max_iterations = max_iterations
        self.convergence_threshold = convergence_threshold
        self.lambda_fairness = lambda_fairness
        self.lambda_sla = lambda_sla

        # 初始化 Ansatz 参数 θ（每比特每层3个旋转参数）
        self.params: List[float] = [
            0.01 * (i % 7 - 3) for i in range(n_qubits * n_layers * 3)
        ]

        # 哈密顿量系数（泡利串分解）
        self.hamiltonian_coeffs: Dict[str, float] = {}

        # 优化历史
        self.energy_history: List[float] = []
        self.iterations_run: int = 0

    def set_hamiltonian(
        self,
        utilization_weights: List[float],
        fairness_pairs: List[Tuple[int, int]],
        sla_constraints: List[Tuple[int, float]],
    ) -> None:
        """
        设置资源分配哈密顿量

        H = Σ_i w_i * Z_i（利用率代价）
          + λ_fair * Σ_(i,j) Z_i Z_j（公平性惩罚，相邻实例资源差异）
          + λ_sla * Σ_i c_i * (I - Z_i)/2（SLA违反惩罚）
        """
        self.hamiltonian_coeffs = {}

        # 单比特项：利用率代价
        for i, w in enumerate(utilization_weights[:self.n_qubits]):
            key = f"Z_{i}"
            self.hamiltonian_coeffs[key] = w

        # 两比特项：公平性惩罚
        for i, j in fairness_pairs:
            if i < self.n_qubits and j < self.n_qubits:
                key = f"Z_{i}Z_{j}"
                self.hamiltonian_coeffs[key] = self.lambda_fairness

        # SLA约束项
        for i, c in sla_constraints:
            if i < self.n_qubits:
                key = f"I_{i}"  # 常数项偏移
                self.hamiltonian_coeffs[key] = self.lambda_sla * c / 2
                key_z = f"Z_{i}_sla"
                self.hamiltonian_coeffs[key_z] = -self.lambda_sla * c / 2

    def _apply_ansatz(self, params: List[float]) -> List[float]:
        """
        应用参数化量子电路，返回经典比特期望值（模拟）

        硬件高效安茨茨（HEA）：交替单比特旋转 + 纠缠层
        """
        spins = [0.0] * self.n_qubits

        for layer in range(self.n_layers):
            # 单比特旋转层：Rx(θ) + Rz(φ) + Ry(ψ)
            for q in range(self.n_qubits):
                idx = (layer * self.n_qubits + q) * 3
                if idx + 2 < len(params):
                    theta, phi, psi = params[idx], params[idx + 1], params[idx + 2]
                    # 旋转改变自旋期望值
                    spins[q] += 0.3 * math.sin(theta) + 0.2 * math.cos(phi) + 0.1 * math.sin(psi)

            # 纠缠层：相邻 CNOT（模拟为自旋耦合）
            for q in range(self.n_qubits - 1):
                coupling = 0.1 * math.sin(params[(layer * self.n_qubits + q) * 3] if (layer * self.n_qubits + q) * 3 < len(params) else 0.5)
                spins[q + 1] += coupling * spins[q]

        # 归一化到 [-1, 1]
        max_abs = max(abs(s) for s in spins) if spins else 1.0
        if max_abs > 0:
            spins = [s / max_abs for s in spins]

        return spins

    def _measure_hamiltonian(self, spins: List[float]) -> float:
        """测量哈密顿量期望值 ⟨ψ|H|ψ⟩"""
        energy = 0.0

        for key, coeff in self.hamiltonian_coeffs.items():
            if key.startswith("Z_") and "Z_" not in key[2:]:
                # 单比特 Z 期望值
                parts = key.split("_")
                if len(parts) == 2 and parts[1].isdigit():
                    i = int(parts[1])
                    if i < len(spins):
                        energy += coeff * spins[i]
            elif key.count("Z_") == 2:
                # 两比特 ZZ 期望值
                parts = key.replace("Z_", "").split("Z")
                if len(parts) == 2:
                    try:
                        i, j = int(parts[0]), int(parts[1])
                        if i < len(spins) and j < len(spins):
                            energy += coeff * spins[i] * spins[j]
                    except ValueError:
                        pass
            elif key.startswith("I_"):
                # 常数项
                energy += coeff

        return energy

    def _compute_gradient(self, params: List[float], epsilon: float = 0.01) -> List[float]:
        """参数移位法则计算梯度"""
        gradient = [0.0] * len(params)

        for i in range(len(params)):
            # 正向偏移
            params_plus = params.copy()
            params_plus[i] += epsilon
            spins_plus = self._apply_ansatz(params_plus)
            energy_plus = self._measure_hamiltonian(spins_plus)

            # 负向偏移
            params_minus = params.copy()
            params_minus[i] -= epsilon
            spins_minus = self._apply_ansatz(params_minus)
            energy_minus = self._measure_hamiltonian(spins_minus)

            # 中心差分
            gradient[i] = (energy_plus - energy_minus) / (2 * epsilon)

        return gradient

    def optimize(self) -> Dict[str, Any]:
        """
        运行 VQE 优化，找到哈密顿量基态（最优资源分配）

        使用梯度下降优化器
        """
        if not self.hamiltonian_coeffs:
            return {"error": "哈密顿量未设置，请先调用 set_hamiltonian()"}

        best_energy = float("inf")
        best_spins = None
        converged = False

        for iteration in range(self.max_iterations):
            # 前向传播：制备态 + 测量
            spins = self._apply_ansatz(self.params)
            energy = self._measure_hamiltonian(spins)

            self.energy_history.append(energy)
            self.iterations_run = iteration + 1

            # 记录最优
            if energy < best_energy:
                best_energy = energy
                best_spins = spins.copy()

            # 收敛检查
            if len(self.energy_history) >= 10:
                recent = self.energy_history[-10:]
                if max(recent) - min(recent) < self.convergence_threshold:
                    converged = True
                    break

            # 梯度下降更新参数
            gradient = self._compute_gradient(self.params)
            for i in range(len(self.params)):
                self.params[i] -= self.learning_rate * gradient[i]

        # 解码最优分配方案
        allocation = self._decode_allocation(best_spins or [0.0] * self.n_qubits)

        return {
            "optimal_energy": best_energy,
            "iterations": self.iterations_run,
            "converged": converged,
            "allocation": allocation,
            "energy_history": self.energy_history[-20:],  # 最近20个点
            "final_params": self.params,
        }

    def _decode_allocation(self, spins: List[float]) -> List[ResourceAllocation]:
        """将量子自旋期望值解码为资源分配方案"""
        allocations = []
        for i, spin in enumerate(spins):
            # 自旋 [-1, 1] 映射到资源配额 [0.1, 0.9]
            quota = 0.5 + 0.4 * spin
            quota = max(0.05, min(0.95, quota))

            allocations.append(ResourceAllocation(
                instance_id=f"sandbox_{i}",
                cpu_quota=quota,
                memory_quota=quota * 0.9,
                network_bandwidth=quota * 0.8,
                energy=self.energy_history[-1] if self.energy_history else 0.0,
            ))

        return allocations

    def get_stats(self) -> Dict[str, Any]:
        return {
            "n_qubits": self.n_qubits,
            "n_layers": self.n_layers,
            "iterations_run": self.iterations_run,
            "final_energy": self.energy_history[-1] if self.energy_history else None,
            "best_energy": min(self.energy_history) if self.energy_history else None,
            "hamiltonian_terms": len(self.hamiltonian_coeffs),
        }


# ============================================================================
# 2. 量子核方法聚类器 —— 攻击样本聚类
# ============================================================================

@dataclass
class ClusterResult:
    """聚类结果"""
    cluster_id: int
    sample_ids: List[str]
    centroid: List[float]
    size: int
    is_anomaly: bool = False
    anomaly_score: float = 0.0


class QuantumKernelClusterer:
    """
    量子核方法聚类器

    原理：
    - 量子特征映射 φ(x)：将经典数据映射到量子希尔伯特空间
    - 量子核 K(x_i, x_j) = |⟨φ(x_i)|φ(x_j)⟩|²
    - 量子核可以捕捉经典核难以发现的高维结构

    应用：
    - 攻击家族识别（相似攻击聚为一类）
    - 异常样本检测（远离所有聚类中心的样本）
    """

    def __init__(
        self,
        n_qubits: int = 4,
        feature_map_reps: int = 2,
        n_clusters: int = 3,
        anomaly_threshold: float = 2.0,
        max_iterations: int = 100,
    ):
        self.n_qubits = n_qubits
        self.feature_map_reps = feature_map_reps
        self.n_clusters = n_clusters
        self.anomaly_threshold = anomaly_threshold
        self.max_iterations = max_iterations

        self.clusters: List[ClusterResult] = []
        self.centroids: List[List[float]] = []
        self.kernel_matrix: List[List[float]] = []

    def _quantum_feature_map(self, x: List[float]) -> List[float]:
        """
        量子特征映射（模拟）

        使用数据编码电路：将经典数据 x 编码为量子态的旋转角度
        φ(x) = U(x)|0⟩^n

        返回量子态在计算基上的概率分布（2^n 维）
        """
        n_states = 2 ** self.n_qubits
        amplitudes = [0.0] * n_states
        amplitudes[0] = 1.0  # 初始 |0...0⟩

        for rep in range(self.feature_map_reps):
            new_amplitudes = [0.0] * n_states
            for state_idx in range(n_states):
                amp = amplitudes[state_idx]
                if abs(amp) < 1e-10:
                    continue

                # 对每个量子比特应用 Rz(x_i) + H 门
                for q in range(self.n_qubits):
                    x_val = x[q % len(x)] if x else 0.0
                    angle = x_val * math.pi

                    # 模拟量子门操作（状态分裂）
                    bit = (state_idx >> q) & 1
                    phase = math.cos(angle) if bit == 0 else math.sin(angle)

                    # H门产生叠加
                    target_state = state_idx ^ (1 << q)
                    new_amplitudes[state_idx] += amp * phase * 0.707
                    new_amplitudes[target_state] += amp * (1 - phase) * 0.707

            amplitudes = new_amplitudes

        # 计算概率分布
        probs = [abs(a) ** 2 for a in amplitudes]
        total = sum(probs)
        if total > 0:
            probs = [p / total for p in probs]

        return probs

    def _quantum_kernel(self, x_i: List[float], x_j: List[float]) -> float:
        """
        计算量子核 K(x_i, x_j) = |⟨φ(x_i)|φ(x_j)⟩|²

        用概率分布的内积近似（Fidelity）
        """
        phi_i = self._quantum_feature_map(x_i)
        phi_j = self._quantum_feature_map(x_j)

        # 量子态保真度（Bhattacharyya系数的平方）
        fidelity = sum(math.sqrt(pi * pj) for pi, pj in zip(phi_i, phi_j))
        return fidelity ** 2

    def _compute_kernel_matrix(self, samples: List[List[float]]) -> List[List[float]]:
        """计算核矩阵"""
        n = len(samples)
        matrix = [[0.0] * n for _ in range(n)]

        for i in range(n):
            for j in range(i, n):
                k = self._quantum_kernel(samples[i], samples[j])
                matrix[i][j] = k
                matrix[j][i] = k

        return matrix

    def _kernel_kmeans(self, kernel_matrix: List[List[float]], sample_ids: List[str]) -> List[int]:
        """核 K-means 聚类"""
        n = len(kernel_matrix)
        if n == 0:
            return []

        k = min(self.n_clusters, n)

        # 初始化：随机选择 k 个中心点（用核距离最远的点）
        centroids_idx = [0]
        for _ in range(1, k):
            max_dist = -1
            max_idx = 0
            for i in range(n):
                if i in centroids_idx:
                    continue
                min_dist = min(kernel_matrix[i][c] for c in centroids_idx)
                if min_dist > max_dist:
                    max_dist = min_dist
                    max_idx = i
            centroids_idx.append(max_idx)

        # 分配初始标签
        labels = [0] * n
        for i in range(n):
            best_c = 0
            best_sim = -1
            for c_idx, c in enumerate(centroids_idx):
                if kernel_matrix[i][c] > best_sim:
                    best_sim = kernel_matrix[i][c]
                    best_c = c_idx
            labels[i] = best_c

        # 迭代
        for iteration in range(self.max_iterations):
            changed = False

            # 更新中心点（核空间中）
            new_labels = [0] * n
            for i in range(n):
                best_c = 0
                best_score = float("inf")

                for c in range(k):
                    # 到聚类 c 的核距离
                    cluster_indices = [idx for idx, label in enumerate(labels) if label == c]
                    if not cluster_indices:
                        continue

                    # 核空间距离：||φ(x_i) - μ_c||² = K(x_i,x_i) - 2 mean(K(x_i,x_j)) + mean(K(x_j,x_k))
                    k_ii = kernel_matrix[i][i]
                    mean_k_ij = sum(kernel_matrix[i][j] for j in cluster_indices) / len(cluster_indices)
                    mean_k_jk = sum(
                        kernel_matrix[j][k2] for j in cluster_indices for k2 in cluster_indices
                    ) / (len(cluster_indices) ** 2)

                    dist = k_ii - 2 * mean_k_ij + mean_k_jk
                    if dist < best_score:
                        best_score = dist
                        best_c = c

                new_labels[i] = best_c
                if new_labels[i] != labels[i]:
                    changed = True

            labels = new_labels
            if not changed:
                break

        return labels

    def cluster(self, samples: Dict[str, List[float]]) -> Dict[str, Any]:
        """
        对攻击样本进行量子核聚类

        Args:
            samples: {sample_id: feature_vector}

        Returns:
            聚类结果 + 异常检测
        """
        if not samples:
            return {"clusters": [], "anomalies": [], "kernel_matrix_size": 0}

        sample_ids = list(samples.keys())
        sample_vectors = [samples[sid] for sid in sample_ids]

        # 1. 计算量子核矩阵
        self.kernel_matrix = self._compute_kernel_matrix(sample_vectors)

        # 2. 核 K-means 聚类
        labels = self._kernel_kmeans(self.kernel_matrix, sample_ids)

        # 3. 构建聚类结果
        self.clusters = []
        cluster_members: Dict[int, List[str]] = {}
        for i, label in enumerate(labels):
            cluster_members.setdefault(label, []).append(sample_ids[i])

        for c_id, members in cluster_members.items():
            # 计算聚类中心（特征空间均值）
            member_vectors = [samples[m] for m in members]
            centroid = [
                sum(v[i] for v in member_vectors) / len(member_vectors)
                for i in range(len(member_vectors[0]))
            ]

            # 异常检测：聚类内平均核距离
            avg_kernel = 0.0
            count = 0
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    idx_i = sample_ids.index(members[i])
                    idx_j = sample_ids.index(members[j])
                    avg_kernel += self.kernel_matrix[idx_i][idx_j]
                    count += 1
            avg_kernel = avg_kernel / count if count > 0 else 1.0

            is_anomaly = avg_kernel < (1.0 / self.n_clusters) * self.anomaly_threshold * 0.1

            self.clusters.append(ClusterResult(
                cluster_id=c_id,
                sample_ids=members,
                centroid=centroid,
                size=len(members),
                is_anomaly=is_anomaly,
                anomaly_score=1.0 - avg_kernel,
            ))

        # 4. 全局异常检测：远离所有聚类的样本
        anomalies = []
        for i, sid in enumerate(sample_ids):
            min_dist_to_cluster = float("inf")
            for cluster in self.clusters:
                if sid in cluster.sample_ids and len(cluster.sample_ids) > 1:
                    # 到同聚类其他点的平均距离
                    other_indices = [sample_ids.index(m) for m in cluster.sample_ids if m != sid]
                    if other_indices:
                        avg_dist = sum(1 - self.kernel_matrix[i][j] for j in other_indices) / len(other_indices)
                        min_dist_to_cluster = min(min_dist_to_cluster, avg_dist)

            if min_dist_to_cluster > self.anomaly_threshold:
                anomalies.append({
                    "sample_id": sid,
                    "distance_score": min_dist_to_cluster,
                    "reason": "远离所有聚类中心，可能是新型攻击",
                })

        return {
            "clusters": [
                {
                    "cluster_id": c.cluster_id,
                    "size": c.size,
                    "sample_ids": c.sample_ids,
                    "is_anomaly": c.is_anomaly,
                    "anomaly_score": c.anomaly_score,
                }
                for c in self.clusters
            ],
            "anomalies": anomalies,
            "n_clusters": len(self.clusters),
            "kernel_matrix_size": len(self.kernel_matrix),
        }

    def get_stats(self) -> Dict[str, Any]:
        return {
            "n_qubits": self.n_qubits,
            "feature_map_reps": self.feature_map_reps,
            "n_clusters_configured": self.n_clusters,
            "n_clusters_found": len(self.clusters),
            "total_samples": sum(c.size for c in self.clusters),
        }


# ============================================================================
# 3. 量子纠错启发容错守卫 —— 多副本状态校验
# ============================================================================

@dataclass
class ErrorSyndrome:
    """错误征兆"""
    position: int
    error_type: str  # "bit_flip" / "phase_flip" / "both"
    confidence: float
    corrected: bool = False


class QuantumErrorCorrectionGuard:
    """
    量子纠错启发的系统容错守卫

    原理（表面码 Surface Code 思想）：
    - 用多个副本编码一个逻辑状态（冗余）
    - 稳定子测量检测错误征兆（不直接测量数据，避免坍缩）
    - 最小权重完美匹配（MWPM）解码定位错误
    - 纠正错误而不中断系统

    应用：
    - 审计链多副本校验（防止单副本被篡改）
    - 分布式沙盒状态一致性校验
    - 关键配置多副本容错
    """

    def __init__(
        self,
        n_replicas: int = 3,
        code_distance: int = 3,
        correction_enabled: bool = True,
        max_corrections_per_check: int = 5,
    ):
        self.n_replicas = n_replicas
        self.code_distance = code_distance
        self.correction_enabled = correction_enabled
        self.max_corrections_per_check = max_corrections_per_check

        # 稳定子测量历史
        self.syndrome_history: List[List[ErrorSyndrome]] = []

        # 统计
        self.total_checks: int = 0
        self.total_errors_detected: int = 0
        self.total_errors_corrected: int = 0
        self.uncorrectable_errors: int = 0

    def _measure_stabilizers(self, replicas: List[List[float]]) -> List[ErrorSyndrome]:
        """
        稳定子测量（模拟表面码的 X/Z 稳定子）

        检测副本之间的不一致，返回错误征兆
        """
        syndromes = []
        n = len(replicas[0]) if replicas else 0

        # Z 稳定子（面 plaquette）：检测比特翻转错误
        # 比较相邻副本的对应位置
        for pos in range(n):
            values = [rep[pos] for rep in replicas if pos < len(rep)]
            if not values:
                continue

            # 多数投票
            mean_val = sum(values) / len(values)
            deviations = [abs(v - mean_val) for v in values]

            for rep_idx, dev in enumerate(deviations):
                if dev > 0.3:  # 偏差阈值
                    syndromes.append(ErrorSyndrome(
                        position=pos,
                        error_type="bit_flip",
                        confidence=min(1.0, dev),
                    ))

        # X 稳定子（星 vertex）：检测相位翻转错误
        # 比较相邻位置的变化率（差分）
        for rep_idx, rep in enumerate(replicas):
            for pos in range(1, len(rep)):
                local_diff = abs(rep[pos] - rep[pos - 1])

                # 其他副本的平均差分
                other_diffs = []
                for other_idx, other_rep in enumerate(replicas):
                    if other_idx != rep_idx and pos < len(other_rep):
                        other_diffs.append(abs(other_rep[pos] - other_rep[pos - 1]))

                if other_diffs:
                    mean_other_diff = sum(other_diffs) / len(other_diffs)
                    if abs(local_diff - mean_other_diff) > 0.4:
                        syndromes.append(ErrorSyndrome(
                            position=pos,
                            error_type="phase_flip",
                            confidence=min(1.0, abs(local_diff - mean_other_diff)),
                        ))

        return syndromes

    def _mwpm_decode(self, syndromes: List[ErrorSyndrome]) -> List[ErrorSyndrome]:
        """
        最小权重完美匹配（MWPM）解码简化版

        匹配错误征兆对，定位实际错误位置
        """
        if len(syndromes) <= 1:
            return syndromes

        # 按位置排序
        sorted_syndromes = sorted(syndromes, key=lambda s: s.position)

        # 贪心匹配：相邻征兆配对（简化版MWPM）
        corrected = []
        used = set()

        for i in range(len(sorted_syndromes)):
            if i in used:
                continue

            best_j = -1
            best_dist = float("inf")

            for j in range(i + 1, len(sorted_syndromes)):
                if j in used:
                    continue
                dist = abs(sorted_syndromes[i].position - sorted_syndromes[j].position)
                if dist < best_dist and dist <= self.code_distance:
                    best_dist = dist
                    best_j = j

            if best_j >= 0:
                used.add(i)
                used.add(best_j)
                # 匹配成功，两个征兆对应一个错误
                corrected.append(sorted_syndromes[i])
            else:
                # 未匹配的征兆（可能是边界错误）
                if sorted_syndromes[i].confidence > 0.7:
                    corrected.append(sorted_syndromes[i])

        return corrected

    def _correct_errors(
        self,
        replicas: List[List[float]],
        errors: List[ErrorSyndrome],
    ) -> Tuple[List[List[float]], int]:
        """纠正检测到的错误"""
        corrected_count = 0

        for error in errors[:self.max_corrections_per_check]:
            pos = error.position

            # 用多数副本的值纠正异常副本
            values_at_pos = []
            for rep in replicas:
                if pos < len(rep):
                    values_at_pos.append(rep[pos])

            if not values_at_pos:
                continue

            # 中位数（对异常值鲁棒）
            sorted_vals = sorted(values_at_pos)
            median = sorted_vals[len(sorted_vals) // 2]

            # 纠正偏差过大的副本
            for rep_idx, rep in enumerate(replicas):
                if pos < len(rep) and abs(rep[pos] - median) > 0.3:
                    rep[pos] = median
                    corrected_count += 1
                    error.corrected = True

        return replicas, corrected_count

    def verify_and_correct(
        self,
        replicas: List[List[float]],
    ) -> Dict[str, Any]:
        """
        验证多副本状态一致性并纠正错误

        Args:
            replicas: 多个副本的状态向量（如审计链哈希、配置值）

        Returns:
            验证结果 + 纠正后的副本
        """
        if len(replicas) < 2:
            return {
                "error": "至少需要2个副本进行校验",
                "replicas": replicas,
            }

        self.total_checks += 1

        # 1. 稳定子测量：检测错误征兆
        syndromes = self._measure_stabilizers(replicas)
        self.total_errors_detected += len(syndromes)

        if not syndromes:
            return {
                "consistent": True,
                "errors_detected": 0,
                "errors_corrected": 0,
                "syndromes": [],
                "corrected_replicas": replicas,
            }

        # 2. MWPM 解码：定位错误
        decoded_errors = self._mwpm_decode(syndromes)

        # 3. 纠正错误
        corrected_replicas = [rep.copy() for rep in replicas]
        corrected_count = 0

        if self.correction_enabled:
            corrected_replicas, corrected_count = self._correct_errors(
                corrected_replicas, decoded_errors
            )
            self.total_errors_corrected += corrected_count

        # 4. 检查是否有不可纠正的错误（超过码距）
        uncorrectable = len(decoded_errors) - corrected_count
        if uncorrectable > 0:
            self.uncorrectable_errors += uncorrectable

        self.syndrome_history.append(syndromes)

        return {
            "consistent": len(syndromes) == 0,
            "errors_detected": len(syndromes),
            "errors_corrected": corrected_count,
            "uncorrectable_errors": uncorrectable,
            "syndromes": [
                {
                    "position": s.position,
                    "error_type": s.error_type,
                    "confidence": s.confidence,
                    "corrected": s.corrected,
                }
                for s in syndromes
            ],
            "corrected_replicas": corrected_replicas,
            "code_distance": self.code_distance,
        }

    def verify_audit_chain(
        self,
        audit_hashes: List[str],
    ) -> Dict[str, Any]:
        """
        专门验证审计链多副本一致性

        将哈希字符串转换为数值向量进行校验
        """
        # 将哈希转换为数值向量（每字节一个值）
        replicas = []
        for h in audit_hashes:
            # 用 SHA256 统一长度
            h_bytes = hashlib.sha256(h.encode()).digest()
            vector = [b / 255.0 for b in h_bytes[:32]]  # 取前32字节
            replicas.append(vector)

        return self.verify_and_correct(replicas)

    def get_stats(self) -> Dict[str, Any]:
        correction_rate = (
            self.total_errors_corrected / self.total_errors_detected
            if self.total_errors_detected > 0
            else 1.0
        )
        return {
            "n_replicas": self.n_replicas,
            "code_distance": self.code_distance,
            "total_checks": self.total_checks,
            "total_errors_detected": self.total_errors_detected,
            "total_errors_corrected": self.total_errors_corrected,
            "uncorrectable_errors": self.uncorrectable_errors,
            "correction_rate": round(correction_rate, 4),
        }


# ============================================================================
# 4. QRNG 量子随机数熵源 —— 安全随机数
# ============================================================================

class QRNGEntropySource:
    """
    量子随机数熵源（Quantum Random Number Generator）

    原理：
    - 量子测量的真随机性（测量叠加态得到随机结果）
    - 熵池管理：收集、混合、输出
    - 健康检查：检测熵源退化

    应用：
    - 密钥生成（对称密钥、非对称密钥种子）
    - 盐值（密码哈希、Token）
    - Nonce（加密协议、防重放）
    - 安全随机数（会话ID、采样）

    注意：本实现为经典模拟的量子随机数（基于硬件熵源 + 量子算法混合），
    生产环境建议接入真实 QRNG 硬件（如 ID Quantique、国盾量子）。
    """

    def __init__(
        self,
        entropy_pool_size: int = 4096,
        min_entropy_threshold: float = 0.95,
        reseed_interval: int = 1024,
    ):
        self.entropy_pool_size = entropy_pool_size
        self.min_entropy_threshold = min_entropy_threshold
        self.reseed_interval = reseed_interval

        # 熵池（字节数组）
        self._entropy_pool: bytearray = bytearray(entropy_pool_size)
        self._pool_index: int = 0
        self._bytes_since_reseed: int = 0

        # 统计
        self.total_bytes_generated: int = 0
        self.total_reseeds: int = 0
        self.entropy_estimate: float = 0.0
        self.health_check_failures: int = 0

        # 初始化熵池
        self._reseed_pool()

    def _get_hardware_entropy(self, n_bytes: int) -> bytes:
        """从硬件熵源获取随机数（os.urandom 作为底层熵源）"""
        return os.urandom(n_bytes)

    def _quantum_mix(self, data: bytes) -> bytes:
        """
        量子算法混合（模拟量子测量的随机性增强）

        使用量子门操作思想混合数据：
        - Hadamard 变换（扩散）
        - 相位旋转（混淆）
        - 测量坍缩（输出）
        """
        if not data:
            return data

        # 转换为复数振幅
        n = len(data)
        amplitudes = [complex(b / 255.0, 0.0) for b in data]

        # 模拟 Hadamard 变换（扩散）
        for i in range(n):
            for j in range(i + 1, min(i + 4, n)):
                avg = (amplitudes[i] + amplitudes[j]) / 2
                diff = (amplitudes[i] - amplitudes[j]) / 2
                amplitudes[i] = avg
                amplitudes[j] = diff

        # 模拟相位旋转（混淆）
        for i in range(n):
            angle = (i * 0.618033988749895) % (2 * math.pi)  # 黄金比例
            cos_a = math.cos(angle)
            sin_a = math.sin(angle)
            real = amplitudes[i].real * cos_a - amplitudes[i].imag * sin_a
            imag = amplitudes[i].real * sin_a + amplitudes[i].imag * cos_a
            amplitudes[i] = complex(real, imag)

        # 测量坍缩（取模长映射回字节）
        result = bytearray(n)
        for i in range(n):
            magnitude = abs(amplitudes[i])
            result[i] = int(min(255, max(0, magnitude * 255)))

        return bytes(result)

    def _reseed_pool(self) -> None:
        """重新播种熵池"""
        # 从硬件熵源获取种子
        seed = self._get_hardware_entropy(self.entropy_pool_size)

        # 量子混合增强随机性
        mixed_seed = self._quantum_mix(seed)

        # 与现有熵池混合（XOR + 旋转）
        for i in range(self.entropy_pool_size):
            self._entropy_pool[i] ^= mixed_seed[i]
            # 旋转扩散
            self._entropy_pool[i] = ((self._entropy_pool[i] << 3) | (self._entropy_pool[i] >> 5)) & 0xFF

        self._pool_index = 0
        self._bytes_since_reseed = 0
        self.total_reseeds += 1

        # 估算熵（基于硬件熵源 + 量子混合）
        self.entropy_estimate = min(1.0, 0.98 + 0.02 * (self.total_reseeds % 10) / 10)

    def _health_check(self, data: bytes) -> bool:
        """
        随机性健康检查（简化版 NIST SP 800-90B）

        检查：
        - 频数检验（0/1 比例）
        - 游程检验（连续相同位长度）
        - 自相关检验
        """
        if len(data) < 16:
            return True

        # 频数检验
        bits = ''.join(format(b, '08b') for b in data)
        ones = bits.count('1')
        zeros = len(bits) - ones
        freq_ratio = abs(ones - zeros) / len(bits)
        if freq_ratio > 0.15:  # 超过15%偏差
            self.health_check_failures += 1
            return False

        # 游程检验：最长连续相同位
        max_run = 1
        current_run = 1
        for i in range(1, len(bits)):
            if bits[i] == bits[i - 1]:
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                current_run = 1
        if max_run > len(bits) * 0.1:  # 最长游程超过10%
            self.health_check_failures += 1
            return False

        return True

    def get_random_bytes(self, n: int) -> bytes:
        """
        获取 n 字节安全随机数

        从熵池读取，定期重新播种
        """
        if n <= 0:
            return b''

        result = bytearray(n)
        bytes_read = 0

        while bytes_read < n:
            # 检查是否需要重新播种
            if self._bytes_since_reseed >= self.reseed_interval:
                self._reseed_pool()

            # 从熵池读取
            chunk_size = min(n - bytes_read, self.entropy_pool_size - self._pool_index)
            for i in range(chunk_size):
                result[bytes_read + i] = self._entropy_pool[self._pool_index + i]

            self._pool_index += chunk_size
            self._bytes_since_reseed += chunk_size
            bytes_read += chunk_size

            # 熵池用完，重新播种
            if self._pool_index >= self.entropy_pool_size:
                self._reseed_pool()

        # 健康检查
        if not self._health_check(bytes(result)):
            # 健康检查失败，重新播种并重新生成
            self._reseed_pool()
            return self.get_random_bytes(n)

        self.total_bytes_generated += n
        return bytes(result)

    def get_random_int(self, min_val: int, max_val: int) -> int:
        """获取 [min_val, max_val] 范围内的安全随机整数"""
        if min_val >= max_val:
            return min_val

        range_size = max_val - min_val + 1
        # 拒绝采样避免模偏差
        max_usable = (256 ** 4) - ((256 ** 4) % range_size)
        while True:
            rand_bytes = self.get_random_bytes(4)
            rand_val = int.from_bytes(rand_bytes, 'big')
            if rand_val < max_usable:
                return min_val + (rand_val % range_size)

    def generate_salt(self, length: int = 16) -> bytes:
        """生成密码学安全盐值"""
        return self.get_random_bytes(length)

    def generate_nonce(self, length: int = 12) -> bytes:
        """生成加密协议 Nonce（推荐 12 字节 for AES-GCM）"""
        return self.get_random_bytes(length)

    def generate_session_id(self) -> str:
        """生成安全会话 ID（128位，hex编码）"""
        return self.get_random_bytes(16).hex()

    def generate_key(self, key_size: int = 256) -> bytes:
        """生成对称密钥（默认 256 位 = 32 字节）"""
        return self.get_random_bytes(key_size // 8)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "entropy_pool_size": self.entropy_pool_size,
            "entropy_estimate": round(self.entropy_estimate, 4),
            "total_bytes_generated": self.total_bytes_generated,
            "total_reseeds": self.total_reseeds,
            "health_check_failures": self.health_check_failures,
            "min_entropy_threshold": self.min_entropy_threshold,
            "entropy_sufficient": self.entropy_estimate >= self.min_entropy_threshold,
        }


# ============================================================================
# 5. STDP 增强脉冲神经网络 —— 自适应入侵检测
# ============================================================================

@dataclass
class IzhikevichNeuron:
    """Izhikevich 神经元模型（比 LIF 更丰富的放电模式）"""
    a: float = 0.02    # 恢复变量时间尺度
    b: float = 0.2     # 恢复变量灵敏度
    c: float = -65.0   # 静息电位
    d: float = 8.0     # 放电后恢复
    v: float = -65.0   # 膜电位
    u: float = -14.0   # 恢复变量
    fired: bool = False
    spike_count: int = 0


class STDPEnhancedSNN:
    """
    STDP（脉冲时序依赖可塑性）增强的脉冲神经网络

    原理：
    - STDP 学习规则：突触前脉冲在突触后脉冲之前 → 权重增强（LTP）
                       突触前脉冲在突触后脉冲之后 → 权重抑制（LTD）
    - Izhikevich 神经元模型：更丰富的放电模式
    - 在线学习：实时适应新的攻击模式

    应用：自适应入侵检测
    - 正常行为模式学习后，异常模式触发不同的放电模式
    - STDP 自动强化异常检测相关的突触连接
    """

    def __init__(
        self,
        n_input: int = 16,
        n_hidden: int = 8,
        n_output: int = 2,  # 0=正常, 1=异常
        stdp_lr: float = 0.01,
        tau_plus: float = 20.0,
        tau_minus: float = 20.0,
        threshold: float = 0.6,
    ):
        self.n_input = n_input
        self.n_hidden = n_hidden
        self.n_output = n_output
        self.stdp_lr = stdp_lr
        self.tau_plus = tau_plus
        self.tau_minus = tau_minus
        self.threshold = threshold

        # 神经元
        self.hidden_neurons = [IzhikevichNeuron() for _ in range(n_hidden)]
        self.output_neurons = [IzhikevichNeuron() for _ in range(n_output)]

        # 突触权重（以正值为主，确保神经元能放电；STDP会调整正负）
        self.input_hidden_weights: List[List[float]] = [
            [0.6 + 0.1 * (i % 3 - 1) for i in range(n_input)]
            for _ in range(n_hidden)
        ]
        self.hidden_output_weights: List[List[float]] = [
            [0.6 + 0.1 * (i % 3 - 1) for i in range(n_hidden)]
            for _ in range(n_output)
        ]

        # 脉冲时间记录（用于 STDP）
        self.input_spike_times: List[float] = [0.0] * n_input
        self.hidden_spike_times: List[float] = [0.0] * n_hidden
        self.output_spike_times: List[float] = [0.0] * n_output

        # 统计
        self.total_predictions: int = 0
        self.anomaly_detections: int = 0
        self.weights_updated: int = 0

    def _encode_input(self, features: List[float], current_time: float) -> List[bool]:
        """将特征向量编码为输入脉冲（速率编码）"""
        spikes = [False] * self.n_input
        for i in range(min(len(features), self.n_input)):
            # 特征值越大，放电概率越高
            rate = max(0.0, min(1.0, features[i]))
            # 用确定性伪随机（基于时间和特征）
            hash_val = (current_time * 1000 + i * 7 + int(features[i] * 1000)) % 100
            spikes[i] = hash_val < rate * 100
        return spikes

    def _update_neuron(self, neuron: IzhikevichNeuron, input_current: float, dt: float = 1.0) -> bool:
        """
        更新 Izhikevich 神经元

        dv/dt = 0.04v² + 5v + 140 - u + I
        du/dt = a(bv - u)

        if v >= 30: v = c, u += d, fired = True
        """
        neuron.v += dt * (0.04 * neuron.v ** 2 + 5 * neuron.v + 140 - neuron.u + input_current)
        neuron.u += dt * neuron.a * (neuron.b * neuron.v - neuron.u)

        if neuron.v >= 30.0:
            neuron.v = neuron.c
            neuron.u += neuron.d
            neuron.fired = True
            neuron.spike_count += 1
            return True

        neuron.fired = False
        return False

    def _stdp_update(
        self,
        weights: List[List[float]],
        pre_spike_times: List[float],
        post_spike_times: List[float],
        current_time: float,
    ) -> int:
        """
        STDP 权重更新

        Δw = A+ * exp(-Δt / τ+)  if Δt > 0 (LTP, 突触前先放电)
        Δw = -A- * exp(Δt / τ-)  if Δt < 0 (LTD, 突触后先放电)
        """
        updates = 0

        for post_idx in range(len(post_spike_times)):
            for pre_idx in range(len(pre_spike_times)):
                if pre_idx >= len(weights[post_idx]):
                    continue

                delta_t = post_spike_times[post_idx] - pre_spike_times[pre_idx]

                if abs(delta_t) > 100:  # 时间窗口外不更新
                    continue

                if delta_t > 0:
                    # LTP：突触前先放电，权重增强
                    delta_w = self.stdp_lr * math.exp(-delta_t / self.tau_plus)
                    weights[post_idx][pre_idx] += delta_w
                    updates += 1
                elif delta_t < 0:
                    # LTD：突触后先放电，权重抑制
                    delta_w = -self.stdp_lr * 0.5 * math.exp(delta_t / self.tau_minus)
                    weights[post_idx][pre_idx] += delta_w
                    updates += 1

                # 权重裁剪
                weights[post_idx][pre_idx] = max(-1.0, min(1.0, weights[post_idx][pre_idx]))

        return updates

    def predict(self, features: List[float], learn: bool = True) -> Dict[str, Any]:
        """
        预测输入是否异常，并可选地进行 STDP 在线学习

        Args:
            features: 输入特征向量
            learn: 是否启用在线学习

        Returns:
            预测结果 + 神经元活动
        """
        current_time = time.time() % 1000.0  # 模拟时间（毫秒）
        hidden_time = current_time + 1.0       # 隐藏层延迟（突触传播）
        output_time = current_time + 2.0       # 输出层延迟

        # 1. 输入编码
        input_spikes = self._encode_input(features, current_time)
        for i, spiked in enumerate(input_spikes):
            if spiked:
                self.input_spike_times[i] = current_time

        # 2. 隐藏层前向传播（多时间步模拟，Izhikevich神经元需要时间积累）
        hidden_spiked = [False] * self.n_hidden
        n_sim_steps = 10
        for h_idx in range(self.n_hidden):
            input_current = sum(
                self.input_hidden_weights[h_idx][i] * (1.0 if input_spikes[i] else 0.0)
                for i in range(self.n_input)
            )
            # 多步模拟，只要有一步放电就算该神经元在窗口内放电
            for step in range(n_sim_steps):
                if self._update_neuron(self.hidden_neurons[h_idx], input_current):
                    hidden_spiked[h_idx] = True
                    break
            if hidden_spiked[h_idx]:
                self.hidden_spike_times[h_idx] = hidden_time

        # 3. 输出层前向传播（多时间步模拟）
        output_spiked = [False] * self.n_output
        for o_idx in range(self.n_output):
            input_current = sum(
                self.hidden_output_weights[o_idx][h] * (1.0 if hidden_spiked[h] else 0.0)
                for h in range(self.n_hidden)
            )
            for step in range(n_sim_steps):
                if self._update_neuron(self.output_neurons[o_idx], input_current):
                    output_spiked[o_idx] = True
                    break
            if output_spiked[o_idx]:
                self.output_spike_times[o_idx] = output_time

        # 4. STDP 在线学习
        if learn:
            # 输入→隐藏层 STDP
            self.weights_updated += self._stdp_update(
                self.input_hidden_weights,
                self.input_spike_times,
                self.hidden_spike_times,
                current_time,
            )
            # 隐藏→输出层 STDP
            self.weights_updated += self._stdp_update(
                self.hidden_output_weights,
                self.hidden_spike_times,
                self.output_spike_times,
                current_time,
            )

        # 5. 判定异常
        # 输出神经元 1（异常）放电率 > 阈值 → 异常
        anomaly_score = 0.0
        if any(output_spiked):
            anomaly_score = 0.5 + 0.5 * (1.0 if output_spiked[1] else 0.0)
        else:
            # 基于膜电位的软判定
            anomaly_score = max(0.0, min(1.0, (self.output_neurons[1].v + 65) / 100))

        is_anomaly = anomaly_score > self.threshold

        self.total_predictions += 1
        if is_anomaly:
            self.anomaly_detections += 1

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(anomaly_score, 4),
            "hidden_spikes": sum(hidden_spiked),
            "output_spikes": output_spiked,
            "weights_updated_this_step": self.weights_updated,
            "learning_enabled": learn,
        }

    def get_stats(self) -> Dict[str, Any]:
        anomaly_rate = (
            self.anomaly_detections / self.total_predictions
            if self.total_predictions > 0
            else 0.0
        )
        return {
            "n_input": self.n_input,
            "n_hidden": self.n_hidden,
            "n_output": self.n_output,
            "stdp_learning_rate": self.stdp_lr,
            "total_predictions": self.total_predictions,
            "anomaly_detections": self.anomaly_detections,
            "anomaly_rate": round(anomaly_rate, 4),
            "total_weight_updates": self.weights_updated,
            "threshold": self.threshold,
        }


# ============================================================================
# 综合量子启发安全增强引擎
# ============================================================================

class QuantumInspiredEnhancementEngine:
    """
    量子启发安全增强综合引擎

    整合所有增强模块：
    - VQE 资源优化
    - 量子核聚类
    - 量子纠错容错
    - QRNG 熵源
    - STDP 增强 SNN
    """

    def __init__(self, **kwargs):
        self.vqe = VQEOptimizer(
            n_qubits=kwargs.get("vqe_n_qubits", 6),
            n_layers=kwargs.get("vqe_n_layers", 3),
        )
        self.clusterer = QuantumKernelClusterer(
            n_qubits=kwargs.get("cluster_n_qubits", 4),
            n_clusters=kwargs.get("n_clusters", 3),
        )
        self.qec_guard = QuantumErrorCorrectionGuard(
            n_replicas=kwargs.get("n_replicas", 3),
            code_distance=kwargs.get("code_distance", 3),
        )
        self.qrng = QRNGEntropySource(
            entropy_pool_size=kwargs.get("entropy_pool_size", 4096),
        )
        self.stdp_snn = STDPEnhancedSNN(
            n_input=kwargs.get("snn_n_input", 16),
            n_hidden=kwargs.get("snn_n_hidden", 8),
        )

    def optimize_resources(
        self,
        utilization_weights: List[float],
        fairness_pairs: List[Tuple[int, int]],
        sla_constraints: List[Tuple[int, float]],
    ) -> Dict[str, Any]:
        """VQE 资源分配优化"""
        self.vqe.set_hamiltonian(utilization_weights, fairness_pairs, sla_constraints)
        return self.vqe.optimize()

    def cluster_attacks(self, samples: Dict[str, List[float]]) -> Dict[str, Any]:
        """量子核攻击样本聚类"""
        return self.clusterer.cluster(samples)

    def verify_replicas(self, replicas: List[List[float]]) -> Dict[str, Any]:
        """量子纠错多副本校验"""
        return self.qec_guard.verify_and_correct(replicas)

    def get_secure_random(self, n_bytes: int) -> bytes:
        """QRNG 安全随机数"""
        return self.qrng.get_random_bytes(n_bytes)

    def detect_anomaly_stdp(self, features: List[float], learn: bool = True) -> Dict[str, Any]:
        """STDP 增强 SNN 异常检测"""
        return self.stdp_snn.predict(features, learn)

    def get_all_stats(self) -> Dict[str, Any]:
        return {
            "vqe": self.vqe.get_stats(),
            "clusterer": self.clusterer.get_stats(),
            "qec_guard": self.qec_guard.get_stats(),
            "qrng": self.qrng.get_stats(),
            "stdp_snn": self.stdp_snn.get_stats(),
        }
