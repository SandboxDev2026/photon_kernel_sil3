"""
evolution.evaluator — 评估器抽象

关键点：评估不本地执行，下发沙盒服务获取分数。
必须包含安全惩罚项：访问内网、超时、内存爆炸直接打极低分淘汰。
"""
from __future__ import annotations
import time
from typing import List, Callable, Optional, Dict, Any
from abc import ABC, abstractmethod
from .individual import Individual
from .sandbox_client import SandboxClient, SandboxResult


class EvaluationResult:
    """评估结果"""
    def __init__(self, fitness: float, test_pass: int = 0, test_total: int = 0,
                 fail_cases: List[str] = None, security_alerts: List[str] = None,
                 execution_time_ms: int = 0):
        self.fitness = max(0.0, min(1.0, fitness))  # 限制在 0-1
        self.test_pass = test_pass
        self.test_total = test_total
        self.fail_cases = fail_cases or []
        self.security_alerts = security_alerts or []
        self.execution_time_ms = execution_time_ms


class BaseEvaluator(ABC):
    """
    评估器抽象基类

    关键点：
    1. 评估不本地执行，全部下发沙盒服务
    2. 适应度必须包含安全惩罚项
    3. 记录失败用例（用于失败驱动变异）
    """
    def __init__(self, sandbox: SandboxClient,
                 security_penalty_weight: float = 0.5,
                 timeout_ms: int = 10000):
        self.sandbox = sandbox
        self.security_penalty_weight = security_penalty_weight
        self.timeout_ms = timeout_ms

    @abstractmethod
    def get_test_cases(self) -> List[Dict[str, Any]]:
        """获取测试用例列表"""
        pass

    @abstractmethod
    def run_single_test(self, code: str, test_case: Dict[str, Any]) -> tuple:
        """
        运行单个测试用例（通过沙盒执行）

        Returns:
            (passed: bool, output: str, error: str, security_alert: bool)
        """
        pass

    def _run_all_tests(self, code: str) -> Tuple[int, List[str], List[str], int]:
        """运行所有测试用例，返回(通过数,失败用例,安全告警,总耗时ms)"""
        test_cases = self.get_test_cases()
        test_pass = 0
        fail_cases = []
        security_alerts = []
        total_time_ms = 0

        for i, tc in enumerate(test_cases):
            start = time.time()
            passed, output, error, sec_alert = self.run_single_test(code, tc)
            elapsed_ms = int((time.time() - start) * 1000)
            total_time_ms += elapsed_ms

            if passed:
                test_pass += 1
            else:
                fail_cases.append(f"test_{i}: {error or output[:200]}")

            if sec_alert:
                security_alerts.append(f"test_{i}: security violation")

            # 超时检测
            if elapsed_ms > self.timeout_ms:
                fail_cases.append(f"test_{i}: timeout ({elapsed_ms}ms > {self.timeout_ms}ms)")

        return test_pass, fail_cases, security_alerts, total_time_ms

    def _calculate_fitness(self,
                            test_pass: int,
                            test_total: int,
                            fail_cases: List[str],
                            security_alerts: List[str]) -> float:
        """计算适应度（含安全惩罚和超时惩罚）"""
        base_fitness = test_pass / test_total if test_total > 0 else 0.0

        # 安全惩罚：任何安全告警大幅降低分数
        security_penalty = min(1.0, len(security_alerts) * self.security_penalty_weight)

        # 超时惩罚
        timeout_count = sum(1 for fc in fail_cases if "timeout" in fc)
        timeout_penalty = min(0.5, timeout_count * 0.1)

        final_fitness = base_fitness * (1.0 - security_penalty) - timeout_penalty
        return max(0.0, min(1.0, final_fitness))

    def _update_individual(self,
                            ind: Individual,
                            fitness: float,
                            test_pass: int,
                            test_total: int,
                            fail_cases: List[str],
                            security_alerts: List[str]):
        """更新个体评估状态"""
        ind.fitness = fitness
        ind.test_pass = test_pass
        ind.test_total = test_total
        ind.fail_cases = fail_cases
        ind.security_alerts = security_alerts
        ind.sandbox_violations = len(security_alerts)
        ind.evaluated = True

    def evaluate(self, ind: Individual) -> EvaluationResult:
        """
        评估个体（全部通过沙盒执行，禁止本地exec）（优化版：拆分为子函数）

        适应度计算：
        base_fitness = test_pass / test_total
        security_penalty = security_alerts * penalty_weight
        timeout_penalty = timeout_count * 0.1
        final_fitness = base_fitness * (1 - security_penalty) - timeout_penalty
        """
        code = ind.payload.get("code", "")
        if not code:
            return EvaluationResult(fitness=0.0, fail_cases=["empty code"])

        # 1. 运行所有测试用例
        test_pass, fail_cases, security_alerts, total_time_ms = self._run_all_tests(code)
        test_total = len(self.get_test_cases())

        # 2. 计算适应度（含安全惩罚）
        final_fitness = self._calculate_fitness(test_pass, test_total, fail_cases, security_alerts)

        # 3. 更新个体状态
        self._update_individual(ind, final_fitness, test_pass, test_total, fail_cases, security_alerts)

        return EvaluationResult(
            fitness=final_fitness,
            test_pass=test_pass,
            test_total=test_total,
            fail_cases=fail_cases,
            security_alerts=security_alerts,
            execution_time_ms=total_time_ms,
        )

    def get_test_cases(self) -> List[Dict[str, Any]]:
        """获取测试用例列表"""
        pass

    @abstractmethod
    def run_single_test(self, code: str, test_case: Dict[str, Any]) -> tuple:
        """
        运行单个测试用例（通过沙盒执行）

        Returns:
            (passed: bool, output: str, error: str, security_alert: bool)
        """
        pass

    def evaluate(self, ind: Individual) -> EvaluationResult:
        """
        评估个体（全部通过沙盒执行，禁止本地exec）

        适应度计算：
        base_fitness = test_pass / test_total
        security_penalty = security_alerts * penalty_weight
        timeout_penalty = timeout_count * 0.1
        final_fitness = base_fitness * (1 - security_penalty) - timeout_penalty
        """
        code = ind.payload.get("code", "")
        if not code:
            return EvaluationResult(fitness=0.0, fail_cases=["empty code"])

        test_cases = self.get_test_cases()
        test_pass = 0
        fail_cases = []
        security_alerts = []
        total_time_ms = 0

        for i, tc in enumerate(test_cases):
            start = time.time()
            passed, output, error, sec_alert = self.run_single_test(code, tc)
            elapsed_ms = int((time.time() - start) * 1000)
            total_time_ms += elapsed_ms

            if passed:
                test_pass += 1
            else:
                fail_cases.append(f"test_{i}: {error or output[:200]}")

            if sec_alert:
                security_alerts.append(f"test_{i}: security violation")

            # 超时检测
            if elapsed_ms > self.timeout_ms:
                fail_cases.append(f"test_{i}: timeout ({elapsed_ms}ms > {self.timeout_ms}ms)")

        # 计算适应度（含安全惩罚）
        test_total = len(test_cases)
        base_fitness = test_pass / test_total if test_total > 0 else 0.0

        # 安全惩罚：任何安全告警大幅降低分数
        security_penalty = min(1.0, len(security_alerts) * self.security_penalty_weight)

        # 超时惩罚
        timeout_count = sum(1 for fc in fail_cases if "timeout" in fc)
        timeout_penalty = min(0.5, timeout_count * 0.1)

        final_fitness = base_fitness * (1.0 - security_penalty) - timeout_penalty
        final_fitness = max(0.0, min(1.0, final_fitness))

        # 更新个体
        ind.fitness = final_fitness
        ind.test_pass = test_pass
        ind.test_total = test_total
        ind.fail_cases = fail_cases
        ind.security_alerts = security_alerts
        ind.sandbox_violations = len(security_alerts)
        ind.evaluated = True

        return EvaluationResult(
            fitness=final_fitness,
            test_pass=test_pass,
            test_total=test_total,
            fail_cases=fail_cases,
            security_alerts=security_alerts,
            execution_time_ms=total_time_ms,
        )


class CodeGenerationEvaluator(BaseEvaluator):
    """
    代码生成评估器 — 用于进化代码片段

    测试用例格式：{"input": "...", "expected": "...", "description": "..."}
    """
    def __init__(self, sandbox: SandboxClient, test_cases: List[Dict[str, Any]],
                 language: str = "python", **kwargs):
        super().__init__(sandbox, **kwargs)
        self._test_cases = test_cases
        self.language = language

    def get_test_cases(self) -> List[Dict[str, Any]]:
        return self._test_cases

    def run_single_test(self, code: str, test_case: Dict[str, Any]) -> tuple:
        """通过沙盒执行代码并验证输出"""
        # 构造完整可执行代码（注入测试输入）
        test_input = test_case.get("input", "")
        expected = test_case.get("expected", "")

        full_code = self._wrap_code(code, test_input)

        result: SandboxResult = self.sandbox.execute(
            full_code, language=self.language,
            task_id=f"eval_{test_case.get('description', 'test')}"
        )

        if not result.success:
            return False, result.output, result.error, result.security_alert

        # 简单输出匹配（可扩展为更复杂的断言）
        output_clean = result.output.strip()
        expected_clean = str(expected).strip()

        passed = (expected_clean in output_clean) or (output_clean == expected_clean)
        error = "" if passed else f"expected '{expected_clean}', got '{output_clean[:100]}'"

        return passed, result.output, error, result.security_alert

    def _wrap_code(self, code: str, test_input: str) -> str:
        """包装代码，注入测试输入（Python 示例）"""
        if self.language == "python":
            return f"""
# Generated code (executed in sandbox, NEVER locally)
{code}

# Test input
_input = {repr(test_input)}
try:
    result = solve(_input)
    print(result)
except Exception as e:
    print(f"ERROR: {{e}}")
"""
        return code


class PromptEvolutionEvaluator(BaseEvaluator):
    """
    Prompt 进化评估器 — 用于进化提示词

    不执行代码，而是通过 LLM-as-Judge 打分。
    （LLM 调用通过 llm_adapter，不本地执行）
    """
    def __init__(self, sandbox: SandboxClient, test_cases: List[Dict[str, Any]],
                 llm_judge=None, **kwargs):
        super().__init__(sandbox, **kwargs)
        self._test_cases = test_cases
        self.llm_judge = llm_judge  # LLM-as-Judge 评分函数

    def get_test_cases(self) -> List[Dict[str, Any]]:
        return self._test_cases

    def run_single_test(self, code: str, test_case: Dict[str, Any]) -> tuple:
        """通过 LLM-as-Judge 评估 prompt 质量"""
        if self.llm_judge is None:
            return True, "", "", False

        prompt = code  # payload 中存的是 prompt
        test_input = test_case.get("input", "")
        expected = test_case.get("expected", "")

        try:
            score = self.llm_judge(prompt, test_input, expected)
            passed = score >= 0.5
            error = "" if passed else f"judge score {score:.2f} < 0.5"
            return passed, f"score={score}", error, False
        except Exception as e:
            return False, "", str(e), False
