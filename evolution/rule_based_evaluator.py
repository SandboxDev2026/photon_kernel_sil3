"""
规则智能体快速评估器（两阶段评估 - 第一阶段）

借鉴 OASIS 框架的"LLM智能体+规则智能体混合"设计：
- 规则智能体做快速预筛选（<10ms/个体），用简单规则打分
- 只有高潜力个体才进入第二阶段 LLM 深度评估（沙盒执行）
- 目标：遗传算法评估成本降低 70%+

设计原则：
1. 纯规则，不调用 LLM，不访问网络，不执行代码
2. 快速：单个个体评估 <10ms
3. 可解释：每个扣分项有明确原因
4. 安全：只做静态分析，不执行任何代码
"""

import re
from dataclasses import dataclass, field
from typing import List, Tuple, Optional


@dataclass
class RuleScore:
    """规则评估得分"""
    total: float = 0.0
    syntax_score: float = 0.0
    structure_score: float = 0.0
    safety_score: float = 0.0
    quality_score: float = 0.0
    penalties: List[str] = field(default_factory=list)
    passed: bool = True


class RuleBasedEvaluator:
    """
    规则智能体快速评估器

    评估维度：
    1. 语法完整性（syntax）：括号匹配、引号闭合、基本结构
    2. 结构合理性（structure）：函数/类定义、入口点、长度适中
    3. 安全性（safety）：危险模式检测（命令注入、文件删除、网络访问等）
    4. 质量指标（quality）：注释比例、命名规范、复杂度估算
    """

    # 危险模式（用于安全扣分，不执行代码）
    DANGEROUS_PATTERNS = [
        (r'os\.system\s*\(', 'os.system 命令执行'),
        (r'subprocess\.(call|run|Popen)\s*\(', 'subprocess 命令执行'),
        (r'eval\s*\(', 'eval 代码执行'),
        (r'exec\s*\(', 'exec 代码执行'),
        (r'__import__\s*\(', '__import__ 动态导入'),
        (r'os\.remove\s*\(|os\.unlink\s*\(', '文件删除'),
        (r'shutil\.rmtree\s*\(', '递归删除目录'),
        (r'socket\.(socket|create_connection)\s*\(', '网络连接'),
        (r'requests\.(get|post|put|delete)\s*\(', 'HTTP 请求'),
        (r'open\s*\([^)]*[\'"]w[\'"]', '文件写入'),
        (r'pickle\.loads?\s*\(', 'pickle 反序列化'),
        (r'yaml\.load\s*\([^)]*\)', 'yaml 不安全加载'),
    ]

    # 好的模式（用于质量加分）
    GOOD_PATTERNS = [
        (r'def\s+\w+\s*\(', '函数定义'),
        (r'class\s+\w+', '类定义'),
        (r'""".*?"""', '文档字符串'),
        (r'#.*', '注释'),
        (r'try\s*:', '异常处理'),
        (r'if\s+__name__\s*==\s*[\'"]__main__[\'"]', '入口点'),
        (r'type\s*:\s*\w+', '类型注解'),
        (r'->\s*\w+', '返回类型注解'),
    ]

    def __init__(self,
                 min_score: float = 30.0,
                 max_penalties: int = 5,
                 enable_safety_check: bool = True):
        """
        初始化规则评估器

        Args:
            min_score: 最低通过分数（0-100），低于此分数直接淘汰
            max_penalties: 最大扣分项数，超过直接淘汰
            enable_safety_check: 是否启用安全检查
        """
        self.min_score = min_score
        self.max_penalties = max_penalties
        self.enable_safety_check = enable_safety_check

    def evaluate(self, code: str, language: str = "python") -> RuleScore:
        """
        评估单个个体的代码

        Args:
            code: 代码字符串
            language: 编程语言（python/javascript/cpp）

        Returns:
            RuleScore: 评估得分
        """
        score = RuleScore()

        if not code or not code.strip():
            score.total = 0.0
            score.passed = False
            score.penalties.append("代码为空")
            return score

        # 1. 语法完整性评估
        score.syntax_score = self._evaluate_syntax(code, language)

        # 2. 结构合理性评估
        score.structure_score = self._evaluate_structure(code, language)

        # 3. 安全性评估
        if self.enable_safety_check:
            score.safety_score = self._evaluate_safety(code, score)
        else:
            score.safety_score = 100.0

        # 4. 质量指标评估
        score.quality_score = self._evaluate_quality(code, language)

        # 加权总分
        score.total = (
            score.syntax_score * 0.30 +
            score.structure_score * 0.25 +
            score.safety_score * 0.25 +
            score.quality_score * 0.20
        )

        # 是否通过
        score.passed = (
            score.total >= self.min_score and
            len(score.penalties) <= self.max_penalties
        )

        return score

    def evaluate_batch(self,
                       individuals: List[Tuple[str, str]],
                       language: str = "python") -> List[Tuple[RuleScore, int]]:
        """
        批量评估，返回通过的个体及其原始索引

        Args:
            individuals: [(code, id), ...] 列表
            language: 编程语言

        Returns:
            [(RuleScore, original_index), ...] 通过的个体，按分数降序
        """
        results = []
        for idx, (code, _) in enumerate(individuals):
            score = self.evaluate(code, language)
            if score.passed:
                results.append((score, idx))

        # 按分数降序
        results.sort(key=lambda x: x[0].total, reverse=True)
        return results

    def _evaluate_syntax(self, code: str, language: str) -> float:
        """语法完整性评估（0-100）"""
        score = 100.0
        lines = code.split('\n')

        # 括号匹配检查
        for open_c, close_c in [('(', ')'), ('[', ']'), ('{', '}')]:
            open_count = code.count(open_c)
            close_count = code.count(close_c)
            if open_count != close_count:
                score -= 15.0

        # 引号闭合检查（简化版）
        for quote in ['"""', "'''", '"', "'"]:
            count = code.count(quote)
            if quote in ['"""', "'''"]:
                if count % 2 != 0:
                    score -= 10.0
            else:
                # 单行引号检查（简化）
                pass

        # 空行比例
        empty_lines = sum(1 for l in lines if not l.strip())
        if len(lines) > 0 and empty_lines / len(lines) > 0.5:
            score -= 10.0

        # 最小长度
        if len(code.strip()) < 10:
            score -= 20.0

        return max(0.0, min(100.0, score))

    def _evaluate_structure(self, code: str, language: str) -> float:
        """结构合理性评估（0-100）"""
        score = 50.0  # 基础分

        # 函数/类定义
        func_count = len(re.findall(r'def\s+\w+\s*\(', code))
        class_count = len(re.findall(r'class\s+\w+', code))
        if func_count > 0:
            score += 15.0
        if class_count > 0:
            score += 10.0

        # 入口点
        if re.search(r'if\s+__name__\s*==', code):
            score += 10.0

        # 长度适中（50-500行为佳）
        lines = code.split('\n')
        if 20 <= len(lines) <= 500:
            score += 10.0
        elif len(lines) > 1000:
            score -= 10.0  # 过长

        # 缩进一致性（Python）
        if language == "python":
            indent_styles = set()
            for line in lines:
                if line.startswith(' ') and line.strip():
                    indent = len(line) - len(line.lstrip())
                    indent_styles.add(indent % 4)
            if len(indent_styles) <= 1:
                score += 5.0

        return max(0.0, min(100.0, score))

    def _evaluate_safety(self, code: str, score: RuleScore) -> float:
        """安全性评估（0-100），危险模式扣分"""
        safety = 100.0

        for pattern, desc in self.DANGEROUS_PATTERNS:
            if re.search(pattern, code):
                safety -= 15.0
                score.penalties.append(f"安全风险: {desc}")

        return max(0.0, min(100.0, safety))

    def _evaluate_quality(self, code: str, language: str) -> float:
        """质量指标评估（0-100）"""
        score = 50.0

        # 注释比例
        lines = code.split('\n')
        comment_lines = sum(1 for l in lines if l.strip().startswith('#'))
        if len(lines) > 0:
            ratio = comment_lines / len(lines)
            if 0.05 <= ratio <= 0.3:
                score += 15.0
            elif ratio > 0.5:
                score -= 5.0  # 注释过多

        # 文档字符串
        if re.search(r'""".*?"""', code, re.DOTALL):
            score += 10.0

        # 类型注解
        if re.search(r'->\s*\w+', code) or re.search(r':\s*\w+\s*=', code):
            score += 10.0

        # 异常处理
        if re.search(r'try\s*:', code):
            score += 5.0

        # 命名规范（函数名小写+下划线）
        func_names = re.findall(r'def\s+(\w+)\s*\(', code)
        good_names = sum(1 for n in func_names if re.match(r'^[a-z][a-z0-9_]*$', n))
        if func_names and good_names / len(func_names) > 0.7:
            score += 5.0

        return max(0.0, min(100.0, score))
