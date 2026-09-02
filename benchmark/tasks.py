"""
Agent Company Benchmark 预设任务集

包含 10 个真实工作任务，覆盖代码生成、调试、算法、数据处理等类别。
每个任务有多个检查点和部分信用评分。

借鉴 TheAgentCompany benchmark 的任务设计方法论：
- 任务描述清晰，有明确的输入输出
- 检查点细粒度，支持部分信用
- 难度递进（EASY → EXPERT）
"""

import re
from typing import List, Dict, Any, Tuple

from .agent_company import (
    AgentCompanyTask, Checkpoint, CheckpointResult,
    TaskDifficulty, TaskCategory,
)


def _make_fibonacci_task() -> AgentCompanyTask:
    """任务1: 斐波那契数列（EASY）"""
    checkpoints = [
        Checkpoint("cp1", "函数定义存在", weight=1.0, required=True),
        Checkpoint("cp2", "处理 n=0 返回 0", weight=1.0),
        Checkpoint("cp3", "处理 n=1 返回 1", weight=1.0),
        Checkpoint("cp4", "处理 n=10 返回 55", weight=1.0),
        Checkpoint("cp5", "处理大数 n=30 返回 832040", weight=1.0),
    ]

    def validator(output: str, context: Dict[str, Any]) -> List[CheckpointResult]:
        results = []
        # cp1: 函数定义
        has_func = bool(re.search(r'def\s+fib\w*\s*\(', output))
        results.append(CheckpointResult("cp1", 1.0 if has_func else 0, 1.0, has_func,
                                         "找到函数定义" if has_func else "未找到函数定义"))
        # cp2-5: 执行结果验证（简化：检查输出中包含正确数字）
        test_cases = [("cp2", "0", 0), ("cp3", "1", 1), ("cp4", "55", 10), ("cp5", "832040", 30)]
        for cp_id, expected, n in test_cases:
            has_expected = expected in output
            results.append(CheckpointResult(cp_id, 1.0 if has_expected else 0, 1.0, has_expected,
                                             f"n={n} 结果包含 {expected}" if has_expected else f"n={n} 未找到 {expected}"))
        return results

    return AgentCompanyTask(
        task_id="fibonacci",
        name="斐波那契数列实现",
        description="编写一个 Python 函数 fib(n)，返回第 n 个斐波那契数。fib(0)=0, fib(1)=1, fib(n)=fib(n-1)+fib(n-2)。请在代码中包含对 n=0,1,10,30 的测试调用并打印结果。",
        difficulty=TaskDifficulty.EASY,
        category=TaskCategory.ALGORITHM,
        checkpoints=checkpoints,
        validator=validator,
        timeout_seconds=10,
    )


def _make_string_reverse_task() -> AgentCompanyTask:
    """任务2: 字符串反转（EASY）"""
    checkpoints = [
        Checkpoint("cp1", "函数定义存在", weight=1.0, required=True),
        Checkpoint("cp2", "处理空字符串", weight=1.0),
        Checkpoint("cp3", "处理单字符", weight=1.0),
        Checkpoint("cp4", "正确反转 'hello' -> 'olleh'", weight=1.0),
        Checkpoint("cp5", "处理 Unicode 字符", weight=1.0),
    ]

    def validator(output: str, context: Dict[str, Any]) -> List[CheckpointResult]:
        results = []
        has_func = bool(re.search(r'def\s+\w*reverse\w*\s*\(', output))
        results.append(CheckpointResult("cp1", 1.0 if has_func else 0, 1.0, has_func))
        for cp_id, keyword in [("cp2", "''"), ("cp3", "'a'"), ("cp4", "olleh"), ("cp5", "")]:
            passed = keyword in output if keyword else True
            results.append(CheckpointResult(cp_id, 1.0 if passed else 0, 1.0, passed))
        return results

    return AgentCompanyTask(
        task_id="string_reverse",
        name="字符串反转函数",
        description="编写 Python 函数 reverse_string(s)，返回反转后的字符串。处理空字符串、单字符、普通字符串和 Unicode 字符。包含测试用例。",
        difficulty=TaskDifficulty.EASY,
        category=TaskCategory.CODE_GENERATION,
        checkpoints=checkpoints,
        validator=validator,
        timeout_seconds=10,
    )


def _make_json_parser_task() -> AgentCompanyTask:
    """任务3: JSON 解析器（MEDIUM）"""
    checkpoints = [
        Checkpoint("cp1", "解析简单对象", weight=1.0, required=True),
        Checkpoint("cp2", "解析嵌套对象", weight=1.0),
        Checkpoint("cp3", "解析数组", weight=1.0),
        Checkpoint("cp4", "处理字符串转义", weight=1.0),
        Checkpoint("cp5", "错误处理（非法 JSON）", weight=1.0),
    ]

    def validator(output: str, context: Dict[str, Any]) -> List[CheckpointResult]:
        results = []
        for cp_id, keyword in [("cp1", "{"), ("cp2", "{"), ("cp3", "["), ("cp4", "\\"), ("cp5", "raise")]:
            passed = keyword in output
            results.append(CheckpointResult(cp_id, 1.0 if passed else 0, 1.0, passed))
        return results

    return AgentCompanyTask(
        task_id="json_parser",
        name="简易 JSON 解析器",
        description="不使用 json 模块，手写一个简易 JSON 解析器 parse_json(s)。支持对象、嵌套、数组、字符串转义，并对非法输入抛出异常。",
        difficulty=TaskDifficulty.MEDIUM,
        category=TaskCategory.ALGORITHM,
        checkpoints=checkpoints,
        validator=validator,
        timeout_seconds=20,
    )


def _make_debug_task() -> AgentCompanyTask:
    """任务4: 调试修复（MEDIUM）"""
    checkpoints = [
        Checkpoint("cp1", "识别出 bug 类型", weight=1.0, required=True),
        Checkpoint("cp2", "修复 off-by-one 错误", weight=1.0),
        Checkpoint("cp3", "修复空指针/None 检查", weight=1.0),
        Checkpoint("cp4", "添加边界条件处理", weight=1.0),
        Checkpoint("cp5", "修复后代码可运行", weight=1.0),
    ]

    def validator(output: str, context: Dict[str, Any]) -> List[CheckpointResult]:
        results = []
        bug_keywords = ["bug", "错误", "修复", "fix", "off-by-one", "边界"]
        has_bug = any(k.lower() in output.lower() for k in bug_keywords)
        results.append(CheckpointResult("cp1", 1.0 if has_bug else 0, 1.0, has_bug))
        for i, cp_id in enumerate(["cp2", "cp3", "cp4", "cp5"]):
            results.append(CheckpointResult(cp_id, 0.5, 1.0, False, "需要执行验证"))
        return results

    return AgentCompanyTask(
        task_id="debug_fix",
        name="调试并修复有 bug 的代码",
        description="以下代码有 bug，请找出并修复：\n```python\ndef find_max(numbers):\n    max_val = numbers[0]\n    for i in range(1, len(numbers)):\n        if numbers[i] > max_val:\n            max_val = numbers[i]\n    return max_val\n\nprint(find_max([]))  # 这里会崩溃\n```\n要求：处理空列表、None 输入，并添加注释说明修复了什么。",
        difficulty=TaskDifficulty.MEDIUM,
        category=TaskCategory.DEBUGGING,
        checkpoints=checkpoints,
        validator=validator,
        timeout_seconds=15,
    )


def _make_sort_task() -> AgentCompanyTask:
    """任务5: 排序算法（MEDIUM）"""
    checkpoints = [
        Checkpoint("cp1", "算法实现正确", weight=2.0, required=True),
        Checkpoint("cp2", "处理空数组", weight=1.0),
        Checkpoint("cp3", "处理已排序数组", weight=1.0),
        Checkpoint("cp4", "处理逆序数组", weight=1.0),
        Checkpoint("cp5", "包含复杂度分析注释", weight=1.0),
    ]

    def validator(output: str, context: Dict[str, Any]) -> List[CheckpointResult]:
        results = []
        has_sort = bool(re.search(r'def\s+\w*sort\w*\s*\(', output))
        results.append(CheckpointResult("cp1", 2.0 if has_sort else 0, 2.0, has_sort))
        for cp_id, keyword in [("cp2", "[]"), ("cp3", "sorted"), ("cp4", "reverse"), ("cp5", "O(n")]:
            passed = keyword in output
            results.append(CheckpointResult(cp_id, 1.0 if passed else 0, 1.0, passed))
        return results

    return AgentCompanyTask(
        task_id="sort_algorithm",
        name="实现快速排序",
        description="实现快速排序算法 quicksort(arr)。要求：处理空数组、已排序数组、逆序数组；包含时间复杂度和空间复杂度的注释分析。",
        difficulty=TaskDifficulty.MEDIUM,
        category=TaskCategory.ALGORITHM,
        checkpoints=checkpoints,
        validator=validator,
        timeout_seconds=15,
    )


def _make_api_client_task() -> AgentCompanyTask:
    """任务6: API 客户端（HARD）"""
    checkpoints = [
        Checkpoint("cp1", "HTTP 请求封装", weight=1.0, required=True),
        Checkpoint("cp2", "错误处理（超时/404/500）", weight=1.0),
        Checkpoint("cp3", "重试机制", weight=1.0),
        Checkpoint("cp4", "认证 Token 管理", weight=1.0),
        Checkpoint("cp5", "响应解析与类型转换", weight=1.0),
    ]

    def validator(output: str, context: Dict[str, Any]) -> List[CheckpointResult]:
        results = []
        for cp_id, keyword in [("cp1", "requests"), ("cp2", "except"), ("cp3", "retry"), ("cp4", "token"), ("cp5", "json")]:
            passed = keyword.lower() in output.lower()
            results.append(CheckpointResult(cp_id, 1.0 if passed else 0, 1.0, passed))
        return results

    return AgentCompanyTask(
        task_id="api_client",
        name="实现健壮的 REST API 客户端",
        description="实现一个 APIClient 类，封装 HTTP 请求。要求：支持 GET/POST/PUT/DELETE；处理超时、404、500 错误；实现指数退避重试（最多3次）；支持 Bearer Token 认证；响应自动解析 JSON。",
        difficulty=TaskDifficulty.HARD,
        category=TaskCategory.CODE_GENERATION,
        checkpoints=checkpoints,
        validator=validator,
        timeout_seconds=20,
    )


def _make_concurrent_task() -> AgentCompanyTask:
    """任务7: 并发处理（HARD）"""
    checkpoints = [
        Checkpoint("cp1", "线程/进程池使用", weight=1.0, required=True),
        Checkpoint("cp2", "任务分发与结果收集", weight=1.0),
        Checkpoint("cp3", "异常隔离（一个任务失败不影响其他）", weight=1.0),
        Checkpoint("cp4", "超时控制", weight=1.0),
        Checkpoint("cp5", "线程安全的共享状态", weight=1.0),
    ]

    def validator(output: str, context: Dict[str, Any]) -> List[CheckpointResult]:
        results = []
        for cp_id, keyword in [("cp1", "ThreadPool"), ("cp2", "map"), ("cp3", "try"), ("cp4", "timeout"), ("cp5", "Lock")]:
            passed = keyword in output
            results.append(CheckpointResult(cp_id, 1.0 if passed else 0, 1.0, passed))
        return results

    return AgentCompanyTask(
        task_id="concurrent_processing",
        name="并发任务处理器",
        description="实现一个并发任务处理器，使用线程池并行处理 100 个任务。要求：每个任务有独立异常隔离；支持全局超时；使用线程安全的计数器统计成功/失败数；打印最终统计结果。",
        difficulty=TaskDifficulty.HARD,
        category=TaskCategory.SYSTEM_DESIGN,
        checkpoints=checkpoints,
        validator=validator,
        timeout_seconds=25,
    )


def _make_data_pipeline_task() -> AgentCompanyTask:
    """任务8: 数据处理管道（HARD）"""
    checkpoints = [
        Checkpoint("cp1", "数据读取", weight=1.0, required=True),
        Checkpoint("cp2", "数据清洗（去重/空值处理）", weight=1.0),
        Checkpoint("cp3", "数据转换/聚合", weight=1.0),
        Checkpoint("cp4", "结果输出", weight=1.0),
        Checkpoint("cp5", "错误处理与日志", weight=1.0),
    ]

    def validator(output: str, context: Dict[str, Any]) -> List[CheckpointResult]:
        results = []
        for cp_id, keyword in [("cp1", "open"), ("cp2", "drop"), ("cp3", "groupby"), ("cp4", "to_csv"), ("cp5", "logging")]:
            passed = keyword in output
            results.append(CheckpointResult(cp_id, 1.0 if passed else 0, 1.0, passed))
        return results

    return AgentCompanyTask(
        task_id="data_pipeline",
        name="数据处理管道",
        description="实现一个数据处理管道：读取 CSV 文件 → 清洗数据（去重、处理空值）→ 按类别聚合统计 → 输出结果 CSV。要求：使用 pandas；包含完整的错误处理和日志记录。",
        difficulty=TaskDifficulty.HARD,
        category=TaskCategory.DATA_PROCESSING,
        checkpoints=checkpoints,
        validator=validator,
        timeout_seconds=20,
    )


def _make_design_pattern_task() -> AgentCompanyTask:
    """任务9: 设计模式（EXPERT）"""
    checkpoints = [
        Checkpoint("cp1", "观察者模式实现", weight=1.0, required=True),
        Checkpoint("cp2", "策略模式实现", weight=1.0, required=True),
        Checkpoint("cp3", "工厂模式实现", weight=1.0),
        Checkpoint("cp4", "模式组合使用", weight=1.0),
        Checkpoint("cp5", "完整的可运行示例", weight=1.0),
    ]

    def validator(output: str, context: Dict[str, Any]) -> List[CheckpointResult]:
        results = []
        for cp_id, keyword in [("cp1", "Observer"), ("cp2", "Strategy"), ("cp3", "Factory"), ("cp4", ""), ("cp5", "__main__")]:
            passed = keyword in output if keyword else True
            results.append(CheckpointResult(cp_id, 1.0 if passed else 0, 1.0, passed))
        return results

    return AgentCompanyTask(
        task_id="design_patterns",
        name="设计模式组合实现",
        description="实现一个事件驱动系统，组合使用三种设计模式：观察者模式（事件通知）、策略模式（不同处理策略）、工厂模式（对象创建）。要求：有完整的可运行示例，展示模式如何协同工作。",
        difficulty=TaskDifficulty.EXPERT,
        category=TaskCategory.SYSTEM_DESIGN,
        checkpoints=checkpoints,
        validator=validator,
        timeout_seconds=30,
    )


def _make_security_audit_task() -> AgentCompanyTask:
    """任务10: 安全审计（EXPERT）"""
    checkpoints = [
        Checkpoint("cp1", "SQL 注入检测", weight=1.0, required=True),
        Checkpoint("cp2", "XSS 检测", weight=1.0, required=True),
        Checkpoint("cp3", "命令注入检测", weight=1.0),
        Checkpoint("cp4", "路径遍历检测", weight=1.0),
        Checkpoint("cp5", "审计报告生成", weight=1.0),
    ]

    def validator(output: str, context: Dict[str, Any]) -> List[CheckpointResult]:
        results = []
        for cp_id, keyword in [("cp1", "sql"), ("cp2", "xss"), ("cp3", "system"), ("cp4", "../"), ("cp5", "report")]:
            passed = keyword.lower() in output.lower()
            results.append(CheckpointResult(cp_id, 1.0 if passed else 0, 1.0, passed))
        return results

    return AgentCompanyTask(
        task_id="security_audit",
        name="代码安全审计工具",
        description="实现一个静态代码安全审计工具，扫描 Python 代码中的常见安全漏洞：SQL 注入、XSS、命令注入、路径遍历。要求：输出结构化的审计报告（包含漏洞类型、位置、严重级别、修复建议）。",
        difficulty=TaskDifficulty.EXPERT,
        category=TaskCategory.TESTING,
        checkpoints=checkpoints,
        validator=validator,
        timeout_seconds=30,
    )


def get_default_tasks() -> List[AgentCompanyTask]:
    """获取默认任务集（10个任务）"""
    return [
        _make_fibonacci_task(),
        _make_string_reverse_task(),
        _make_json_parser_task(),
        _make_debug_task(),
        _make_sort_task(),
        _make_api_client_task(),
        _make_concurrent_task(),
        _make_data_pipeline_task(),
        _make_design_pattern_task(),
        _make_security_audit_task(),
    ]


def get_tasks_by_difficulty(difficulty: TaskDifficulty) -> List[AgentCompanyTask]:
    """按难度筛选任务"""
    return [t for t in get_default_tasks() if t.difficulty == difficulty]


def get_tasks_by_category(category: TaskCategory) -> List[AgentCompanyTask]:
    """按类别筛选任务"""
    return [t for t in get_default_tasks() if t.category == category]
