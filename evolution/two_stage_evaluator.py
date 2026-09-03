"""
两阶段评估器（Two-Stage Evaluator）

借鉴 OASIS 框架的"LLM智能体+规则智能体混合"设计：
- 第一阶段：规则智能体快速预筛选（<10ms/个体），淘汰明显不合格个体
- 第二阶段：只有 Top-N 高潜力个体才用 LLM 深度评估（沙盒执行）

目标：遗传算法评估成本降低 70%+，同时保持评估质量。

设计原则：
1. 第一阶段纯规则，不调用 LLM，不执行代码，快速安全
2. 第二阶段调用沙盒执行，只评估通过第一阶段的高潜力个体
3. 可配置通过率、Top-N 比例、评估权重
4. 完整统计：各阶段通过数、淘汰数、平均耗时、成本节省
"""

import time
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Callable, Any, Dict

from .rule_based_evaluator import RuleBasedEvaluator, RuleScore
from .individual import Individual


@dataclass
class TwoStageStats:
    """两阶段评估统计"""
    total_individuals: int = 0
    stage1_passed: int = 0
    stage1_skipped: int = 0
    stage2_evaluated: int = 0
    stage1_avg_time_ms: float = 0.0
    stage2_avg_time_ms: float = 0.0
    cost_saved_pct: float = 0.0
    stage1_penalties: List[str] = field(default_factory=list)


class TwoStageEvaluator:
    """
    两阶段评估器

    工作流程：
    1. 第一阶段：对所有个体运行规则评估器，快速打分
    2. 筛选：按分数降序，取 Top-N（或按通过率筛选）
    3. 第二阶段：对筛选后的个体调用 LLM/沙盒深度评估
    4. 返回：所有个体的最终评估结果（未进入第二阶段的标记为淘汰）

    使用示例：
        evaluator = TwoStageEvaluator(top_n_ratio=0.3)
        results = evaluator.evaluate(population, deep_eval_fn)
    """

    def __init__(self,
                 top_n_ratio: float = 0.3,
                 min_score: float = 30.0,
                 max_penalties: int = 5,
                 enable_safety_check: bool = True,
                 stage1_weight: float = 0.3,
                 stage2_weight: float = 0.7,
                 language: str = "python"):
        """
        初始化两阶段评估器

        Args:
            top_n_ratio: 第二阶段评估比例（0-1），如 0.3 表示只评估前 30%
            min_score: 第一阶段最低通过分数
            max_penalties: 第一阶段最大扣分项数
            enable_safety_check: 是否启用安全检查
            stage1_weight: 第一阶段分数在最终得分中的权重
            stage2_weight: 第二阶段分数在最终得分中的权重
            language: 编程语言
        """
        self.top_n_ratio = max(0.01, min(1.0, top_n_ratio))
        self.stage1_weight = stage1_weight
        self.stage2_weight = stage2_weight
        self.language = language

        # 第一阶段规则评估器
        self.rule_evaluator = RuleBasedEvaluator(
            min_score=min_score,
            max_penalties=max_penalties,
            enable_safety_check=enable_safety_check,
        )

        # 统计
        self.stats = TwoStageStats()

    def _evaluate_stage1(self, population: List[Individual]) -> List[Tuple[Individual, Any]]:
        """第一阶段：规则快速评估"""
        stage1_start = time.time()
        stage1_results = []

        for ind in population:
            code = self._extract_code(ind)
            score = self.rule_evaluator.evaluate(code, self.language)
            stage1_results.append((ind, score))

            # 记录扣分项（用于统计）
            if score.penalties:
                self.stats.stage1_penalties.extend(score.penalties[:3])

        stage1_time = (time.time() - stage1_start) * 1000
        self.stats.stage1_avg_time_ms = stage1_time / len(population) if population else 0

        return stage1_results

    def _evaluate_stage2(self,
                          passed_stage1: List[Tuple[Individual, Any]],
                          top_n: int,
                          deep_eval_fn: Optional[Callable[[Individual], float]]
                          ) -> Dict[str, float]:
        """第二阶段：LLM/沙盒深度评估"""
        stage2_scores = {}  # ind.id -> stage2_score
        if deep_eval_fn is None or top_n <= 0:
            return stage2_scores

        stage2_start = time.time()

        for i in range(top_n):
            ind, _ = passed_stage1[i]
            try:
                s2_score = deep_eval_fn(ind)
                stage2_scores[ind.id] = max(0.0, min(100.0, s2_score))
            except Exception as e:
                # 深度评估失败，使用第一阶段分数
                stage2_scores[ind.id] = passed_stage1[i][1].total * 0.5

        stage2_time = (time.time() - stage2_start) * 1000
        self.stats.stage2_avg_time_ms = stage2_time / top_n if top_n > 0 else 0
        self.stats.stage2_evaluated = top_n

        # 计算成本节省
        if self.stats.stage2_avg_time_ms > 0:
            full_cost = self.stats.total_individuals * self.stats.stage2_avg_time_ms
            actual_cost = (self.stats.total_individuals * self.stats.stage1_avg_time_ms +
                           top_n * self.stats.stage2_avg_time_ms)
            self.stats.cost_saved_pct = max(0.0, (1 - actual_cost / full_cost) * 100)

        return stage2_scores

    def _calculate_final_scores(self,
                                  stage1_results: List[Tuple[Individual, Any]],
                                  stage2_scores: Dict[str, float]
                                  ) -> List[Tuple[Individual, float, bool]]:
        """计算最终得分"""
        results = []
        stage2_ids = set(stage2_scores.keys())

        for ind, s1 in stage1_results:
            if ind.id in stage2_ids:
                # 进入第二阶段：加权综合
                s2 = stage2_scores[ind.id]
                final_score = s1.total * self.stage1_weight + s2 * self.stage2_weight
                results.append((ind, final_score, True))
            else:
                # 第一阶段淘汰：使用第一阶段分数（打折）
                final_score = s1.total * 0.5  # 淘汰个体分数打折
                results.append((ind, final_score, False))

        return results

    def evaluate(self,
                 population: List[Individual],
                 deep_eval_fn: Optional[Callable[[Individual], float]] = None
                 ) -> List[Tuple[Individual, float, bool]]:
        """
        执行两阶段评估（优化版：拆分为子函数）

        Args:
            population: 个体列表
            deep_eval_fn: 第二阶段深度评估函数，输入 Individual，返回 float 分数
                         如果为 None，则只执行第一阶段

        Returns:
            [(individual, final_score, passed_stage2), ...]
            - passed_stage2: 是否进入了第二阶段（True=深度评估，False=第一阶段淘汰）
        """
        self.stats = TwoStageStats()
        self.stats.total_individuals = len(population)

        if not population:
            return []

        # ===== 第一阶段：规则快速评估 =====
        stage1_results = self._evaluate_stage1(population)

        # 筛选通过第一阶段的个体
        passed_stage1 = [(ind, s) for ind, s in stage1_results if s.passed]
        self.stats.stage1_passed = len(passed_stage1)
        self.stats.stage1_skipped = len(population) - len(passed_stage1)

        # 按第一阶段分数降序
        passed_stage1.sort(key=lambda x: x[1].total, reverse=True)

        # 计算第二阶段评估数量
        top_n = max(1, int(len(population) * self.top_n_ratio))
        top_n = min(top_n, len(passed_stage1))  # 不超过通过数

        # ===== 第二阶段：LLM/沙盒深度评估 =====
        stage2_scores = self._evaluate_stage2(passed_stage1, top_n, deep_eval_fn)

        # ===== 计算最终得分 =====
        return self._calculate_final_scores(stage1_results, stage2_scores)

    def get_stats(self) -> TwoStageStats:
        """获取评估统计"""
        return self.stats

    def _extract_code(self, ind: Individual) -> str:
        """从 Individual 中提取代码"""
        # Individual 的 payload 可能是 dict，包含 code 字段
        if hasattr(ind, 'payload') and isinstance(ind.payload, dict):
            return ind.payload.get('code', ind.payload.get('prompt', ''))
        if hasattr(ind, 'code'):
            return ind.code
        if hasattr(ind, 'payload') and isinstance(ind.payload, str):
            return ind.payload
        return str(ind) if ind else ''
