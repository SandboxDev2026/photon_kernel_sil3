"""
Agent Company Benchmark — 真实工作任务评估框架

借鉴 Carnegie Mellon TheAgentCompany benchmark (arXiv 2412.14161) 的设计：
- 模拟软件公司环境，任务=写代码+运行+验证
- 细粒度检查点（checkpoints）+ 部分信用评分（partial credit）
- 任务在 photon 沙盒中执行（StrongPool MicroVM 隔离）

模块结构：
- agent_company.py: 核心框架（Task/Checkpoint/Benchmark/Stats）
- tasks.py: 预设任务集（10个真实工作任务）
"""

from .agent_company import (
    AgentCompanyBenchmark,
    AgentCompanyTask,
    BenchmarkStats,
    Checkpoint,
    CheckpointResult,
    TaskCategory,
    TaskDifficulty,
    TaskResult,
)
from .tasks import (
    get_default_tasks,
    get_tasks_by_category,
    get_tasks_by_difficulty,
)

__all__ = [
    "AgentCompanyBenchmark",
    "AgentCompanyTask",
    "BenchmarkStats",
    "Checkpoint",
    "CheckpointResult",
    "TaskCategory",
    "TaskDifficulty",
    "TaskResult",
    "get_default_tasks",
    "get_tasks_by_category",
    "get_tasks_by_difficulty",
]
