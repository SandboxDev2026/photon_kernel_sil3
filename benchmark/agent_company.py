"""
Agent Company Benchmark — 真实工作任务评估框架

借鉴 Carnegie Mellon TheAgentCompany benchmark (arXiv 2412.14161) 的设计：
- 模拟软件公司环境，任务=写代码+运行+验证+与同事沟通
- 细粒度检查点（checkpoints）+ 部分信用评分（partial credit）
- 自包含环境，不依赖外部服务

与 TheAgentCompany 的区别：
- 任务在 photon 沙盒中执行（StrongPool MicroVM 隔离）
- 聚焦代码生成+执行+验证类任务
- 轻量级，可快速运行

评分方法：
- 每个任务有多个检查点（checkpoints）
- 每个检查点独立评分（0/部分/满分）
- 最终得分 = 各检查点加权平均
- 支持部分信用（partial credit）
"""

import json
import time
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Tuple
from enum import Enum


class TaskDifficulty(Enum):
    """任务难度"""
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXPERT = "expert"


class TaskCategory(Enum):
    """任务类别"""
    CODE_GENERATION = "code_generation"
    CODE_EXECUTION = "code_execution"
    DEBUGGING = "debugging"
    REFACTORING = "refactoring"
    TESTING = "testing"
    DATA_PROCESSING = "data_processing"
    ALGORITHM = "algorithm"
    SYSTEM_DESIGN = "system_design"


@dataclass
class Checkpoint:
    """检查点"""
    id: str
    description: str
    weight: float = 1.0
    max_score: float = 1.0
    required: bool = False  # 是否必须通过（不通过则任务失败）


@dataclass
class CheckpointResult:
    """检查点结果"""
    checkpoint_id: str
    score: float = 0.0
    max_score: float = 1.0
    passed: bool = False
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TaskResult:
    """任务结果"""
    task_id: str
    task_name: str
    difficulty: TaskDifficulty
    category: TaskCategory
    total_score: float = 0.0
    max_score: float = 1.0
    passed: bool = False
    checkpoints: List[CheckpointResult] = field(default_factory=list)
    execution_time_ms: float = 0.0
    error: Optional[str] = None
    output: str = ""
    artifacts: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BenchmarkStats:
    """Benchmark 统计"""
    total_tasks: int = 0
    passed_tasks: int = 0
    failed_tasks: int = 0
    avg_score: float = 0.0
    avg_time_ms: float = 0.0
    by_difficulty: Dict[str, Dict[str, float]] = field(default_factory=dict)
    by_category: Dict[str, Dict[str, float]] = field(default_factory=dict)
    checkpoint_pass_rates: Dict[str, float] = field(default_factory=dict)


class AgentCompanyTask:
    """
    单个任务定义

    每个任务包含：
    - 任务描述（给智能体的指令）
    - 检查点列表（评分标准）
    - 验证函数（检查点评分逻辑）
    - 预期输出/参考实现
    """

    def __init__(self,
                 task_id: str,
                 name: str,
                 description: str,
                 difficulty: TaskDifficulty,
                 category: TaskCategory,
                 checkpoints: List[Checkpoint],
                 validator: Optional[Callable[[str, Dict[str, Any]], List[CheckpointResult]]] = None,
                 reference_solution: str = "",
                 timeout_seconds: int = 30,
                 metadata: Dict[str, Any] = None):
        self.task_id = task_id
        self.name = name
        self.description = description
        self.difficulty = difficulty
        self.category = category
        self.checkpoints = checkpoints
        self.validator = validator
        self.reference_solution = reference_solution
        self.timeout_seconds = timeout_seconds
        self.metadata = metadata or {}

    def get_max_score(self) -> float:
        """获取满分"""
        return sum(cp.weight * cp.max_score for cp in self.checkpoints)

    def validate(self, output: str, context: Dict[str, Any] = None) -> List[CheckpointResult]:
        """
        验证输出，返回各检查点结果

        Args:
            output: 智能体的输出（代码/执行结果/文本）
            context: 额外上下文（执行结果、文件内容等）

        Returns:
            检查点结果列表
        """
        if self.validator:
            return self.validator(output, context or {})

        # 默认验证器：检查输出非空 + 包含关键模式
        results = []
        for cp in self.checkpoints:
            result = CheckpointResult(
                checkpoint_id=cp.id,
                max_score=cp.max_score,
            )
            # 简单检查：输出非空
            if output and output.strip():
                result.score = cp.max_score
                result.passed = True
                result.message = "输出非空"
            else:
                result.message = "输出为空"
            results.append(result)
        return results


class AgentCompanyBenchmark:
    """
    Agent Company Benchmark 运行器

    使用示例：
        benchmark = AgentCompanyBenchmark()
        benchmark.add_task(task1)
        results = benchmark.run(agent_fn)
        stats = benchmark.get_stats()
    """

    def __init__(self, name: str = "agent_company_v1"):
        self.name = name
        self.tasks: List[AgentCompanyTask] = []
        self.results: List[TaskResult] = []
        self._task_map: Dict[str, AgentCompanyTask] = {}

    def add_task(self, task: AgentCompanyTask) -> None:
        """添加任务"""
        self.tasks.append(task)
        self._task_map[task.task_id] = task

    def add_tasks(self, tasks: List[AgentCompanyTask]) -> None:
        """批量添加任务"""
        for task in tasks:
            self.add_task(task)

    def get_task(self, task_id: str) -> Optional[AgentCompanyTask]:
        """按 ID 获取任务"""
        return self._task_map.get(task_id)

    def run(self,
            agent_fn: Callable[[str, Dict[str, Any]], Tuple[str, Dict[str, Any]]],
            task_ids: Optional[List[str]] = None,
            verbose: bool = False
            ) -> List[TaskResult]:
        """
        运行 Benchmark

        Args:
            agent_fn: 智能体函数，输入(任务描述, 上下文)，返回(输出, 额外上下文)
            task_ids: 指定运行的任务 ID，None 表示全部
            verbose: 是否打印详细信息

        Returns:
            任务结果列表
        """
        self.results = []
        tasks_to_run = (
            [self._task_map[tid] for tid in task_ids if tid in self._task_map]
            if task_ids else self.tasks
        )

        for task in tasks_to_run:
            result = self._run_single_task(task, agent_fn, verbose)
            self.results.append(result)

        return self.results

    def _run_single_task(self,
                          task: AgentCompanyTask,
                          agent_fn: Callable,
                          verbose: bool
                          ) -> TaskResult:
        """运行单个任务"""
        result = TaskResult(
            task_id=task.task_id,
            task_name=task.name,
            difficulty=task.difficulty,
            category=task.category,
            max_score=task.get_max_score(),
        )

        start_time = time.time()
        try:
            # 调用智能体
            output, context = agent_fn(task.description, {
                "task_id": task.task_id,
                "difficulty": task.difficulty.value,
                "category": task.category.value,
                "timeout": task.timeout_seconds,
            })
            result.output = output or ""

            # 验证检查点
            checkpoint_results = task.validate(result.output, context or {})
            result.checkpoints = checkpoint_results

            # 计算总分
            total = 0.0
            all_required_passed = True
            for cp_res, cp_def in zip(checkpoint_results, task.checkpoints):
                total += cp_res.score * cp_def.weight
                if cp_def.required and not cp_res.passed:
                    all_required_passed = False

            result.total_score = total
            result.passed = (
                total > 0 and
                all_required_passed and
                total >= task.get_max_score() * 0.5  # 至少 50% 分
            )

        except Exception as e:
            result.error = str(e)
            result.passed = False

        result.execution_time_ms = (time.time() - start_time) * 1000

        if verbose:
            status = "PASS" if result.passed else "FAIL"
            print(f"  [{status}] {task.name}: {result.total_score:.1f}/{result.max_score:.1f} "
                  f"({result.execution_time_ms:.0f}ms)")

        return result

    def get_stats(self) -> BenchmarkStats:
        """获取统计信息"""
        stats = BenchmarkStats(total_tasks=len(self.results))

        if not self.results:
            return stats

        scores = [r.total_score for r in self.results]
        times = [r.execution_time_ms for r in self.results]

        stats.passed_tasks = sum(1 for r in self.results if r.passed)
        stats.failed_tasks = stats.total_tasks - stats.passed_tasks
        stats.avg_score = sum(scores) / len(scores) if scores else 0
        stats.avg_time_ms = sum(times) / len(times) if times else 0

        # 按难度统计
        for diff in TaskDifficulty:
            diff_results = [r for r in self.results if r.difficulty == diff]
            if diff_results:
                stats.by_difficulty[diff.value] = {
                    "count": len(diff_results),
                    "passed": sum(1 for r in diff_results if r.passed),
                    "avg_score": sum(r.total_score for r in diff_results) / len(diff_results),
                }

        # 按类别统计
        for cat in TaskCategory:
            cat_results = [r for r in self.results if r.category == cat]
            if cat_results:
                stats.by_category[cat.value] = {
                    "count": len(cat_results),
                    "passed": sum(1 for r in cat_results if r.passed),
                    "avg_score": sum(r.total_score for r in cat_results) / len(cat_results),
                }

        # 检查点通过率
        cp_counts: Dict[str, List[int]] = {}
        for r in self.results:
            for cp_res in r.checkpoints:
                if cp_res.checkpoint_id not in cp_counts:
                    cp_counts[cp_res.checkpoint_id] = [0, 0]
                cp_counts[cp_res.checkpoint_id][0] += 1
                if cp_res.passed:
                    cp_counts[cp_res.checkpoint_id][1] += 1

        for cp_id, (total, passed) in cp_counts.items():
            stats.checkpoint_pass_rates[cp_id] = passed / total if total > 0 else 0

        return stats

    def export_report(self, filepath: str) -> None:
        """导出报告为 JSON"""
        stats = self.get_stats()
        report = {
            "benchmark_name": self.name,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "stats": {
                "total_tasks": stats.total_tasks,
                "passed_tasks": stats.passed_tasks,
                "failed_tasks": stats.failed_tasks,
                "avg_score": round(stats.avg_score, 3),
                "avg_time_ms": round(stats.avg_time_ms, 1),
                "by_difficulty": stats.by_difficulty,
                "by_category": stats.by_category,
                "checkpoint_pass_rates": {k: round(v, 3) for k, v in stats.checkpoint_pass_rates.items()},
            },
            "results": [
                {
                    "task_id": r.task_id,
                    "task_name": r.task_name,
                    "difficulty": r.difficulty.value,
                    "category": r.category.value,
                    "score": round(r.total_score, 3),
                    "max_score": r.max_score,
                    "passed": r.passed,
                    "execution_time_ms": round(r.execution_time_ms, 1),
                    "error": r.error,
                    "checkpoints": [
                        {"id": cp.checkpoint_id, "score": cp.score, "passed": cp.passed, "message": cp.message}
                        for cp in r.checkpoints
                    ],
                }
                for r in self.results
            ],
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

    def print_summary(self) -> None:
        """打印摘要"""
        stats = self.get_stats()
        print(f"\n{'='*60}")
        print(f"  Agent Company Benchmark: {self.name}")
        print(f"{'='*60}")
        print(f"  总任务数: {stats.total_tasks}")
        print(f"  通过: {stats.passed_tasks}  失败: {stats.failed_tasks}")
        print(f"  通过率: {stats.passed_tasks/stats.total_tasks*100:.1f}%" if stats.total_tasks else "  通过率: N/A")
        print(f"  平均得分: {stats.avg_score:.2f}")
        print(f"  平均耗时: {stats.avg_time_ms:.0f}ms")
        print(f"{'='*60}\n")
