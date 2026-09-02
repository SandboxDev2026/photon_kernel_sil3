"""
evolution.prompts — 变异/交叉/反思提示词模板

参考 EvoPrompt / Prompt-Darwinism / AutoEvolve / AgentEvolver 的提示词设计。
关键点：不是简单文本拼接，用 LLM 做语义层面合并改写。
"""
from __future__ import annotations
from typing import List, Optional


class MutationPrompts:
    """变异提示词模板"""

    @staticmethod
    def rewrite(code: str, fail_cases: List[str] = None) -> str:
        """
        完整重写变异（参考 AutoEvolve rewrite 模式）

        让 LLM 完整重写代码，探索更大搜索空间。
        """
        fail_context = ""
        if fail_cases:
            fail_context = "\n\n已知失败用例:\n" + "\n".join(f"- {fc}" for fc in fail_cases[:5])

        return f"""你是一个代码进化专家。请完整重写以下代码，使其更正确、更高效。

要求：
1. 保持相同的函数签名和输入输出格式
2. 修复所有已知 bug
3. 可以自由重构，但必须保证语法正确
4. 不要添加不必要的依赖
5. 输出完整可运行的代码，不要解释

{fail_context}

原始代码：
```python
{code}
```

请输出重写后的完整代码："""

    @staticmethod
    def patch(code: str, fail_cases: List[str] = None) -> str:
        """
        局部补丁变异（参考 AutoEvolve patch 模式）

        让 LLM 生成 diff 补丁，只修改必要部分。
        """
        fail_context = ""
        if fail_cases:
            fail_context = "\n\n需要修复的问题:\n" + "\n".join(f"- {fc}" for fc in fail_cases[:5])

        return f"""你是一个代码修复专家。请对以下代码生成最小化补丁，只修改必要的部分。

要求：
1. 最小改动原则，不要大改
2. 只修复指定的问题
3. 保持代码风格一致
4. 输出 unified diff 格式，或完整修改后的代码

{fail_context}

当前代码：
```python
{code}
```

请输出补丁或修改后的完整代码："""

    @staticmethod
    def nl_feedback(code: str, fail_cases: List[str]) -> str:
        """
        自然语言反馈变异（参考 AutoEvolve nl_feedback 模式）

        把测试失败案例塞给 LLM，针对性变异修复 bug。
        参考 CodeEvolve 的失败用例驱动变异。
        """
        return f"""你是一个调试专家。以下代码在测试中失败了，请根据失败信息修复。

失败用例：
{chr(10).join(f'- {fc}' for fc in fail_cases[:10])}

要求：
1. 精准定位失败原因
2. 只修复导致失败的代码
3. 不要修改不相关的部分
4. 保持函数签名不变
5. 输出完整修复后的代码

有问题的代码：
```python
{code}
```

请输出修复后的完整代码："""

    @staticmethod
    def seven_strategies(code: str, strategy: str = "expand") -> str:
        """
        7种变异策略（参考 Prompt-Darwinism）

        策略：复述、增加例子、增加约束、修改语气、精简、扩展、视角转换
        """
        strategies = {
            "paraphrase": "用不同的表达方式重写，保持语义不变",
            "add_example": "增加更多使用示例和边界情况处理",
            "add_constraint": "增加输入校验和约束条件",
            "change_tone": "修改代码风格，更简洁/更详细",
            "simplify": "精简代码，去除冗余",
            "expand": "扩展功能，增加更多处理逻辑",
            "change_perspective": "换一种实现思路",
        }
        instruction = strategies.get(strategy, strategies["expand"])

        return f"""请对以下代码进行变异，策略：{instruction}

要求：
1. 保持核心功能不变
2. 按照指定策略进行变异
3. 输出完整可运行的代码

原始代码：
```python
{code}
```

请输出变异后的代码："""


class CrossoverPrompts:
    """交叉提示词模板"""

    @staticmethod
    def semantic(code_a: str, code_b: str,
                 fitness_a: float, fitness_b: float) -> str:
        """
        语义交叉（参考 AutoEvolve 灵感式交叉）

        不是字符串剪切拼接，提示词让 LLM 吸收两份代码优点输出新代码。
        """
        return f"""你是一个代码融合专家。请融合以下两份代码的优点，生成更好的版本。

代码 A（适应度 {fitness_a:.2f}）：
```python
{code_a}
```

代码 B（适应度 {fitness_b:.2f}）：
```python
{code_b}
```

要求：
1. 吸收两份代码各自的优点
2. 避免简单拼接，要语义层面融合
3. 保持相同的函数签名
4. 修复两份代码中可能存在的问题
5. 输出完整可运行的代码，不要解释

请输出融合后的完整代码："""

    @staticmethod
    def inspiratory(code_a: str, code_b: str) -> str:
        """
        灵感式交叉（参考 AutoEvolve）

        让 LLM 从代码 B 中汲取灵感，改进代码 A。
        """
        return f"""你是一个代码改进专家。请参考代码 B 的设计思路，改进代码 A。

代码 A（需要改进）：
```python
{code_a}
```

代码 B（参考灵感来源）：
```python
{code_b}
```

要求：
1. 保持代码 A 的核心功能和接口
2. 从代码 B 中汲取好的设计思路
3. 不要简单复制代码 B
4. 输出完整改进后的代码

请输出改进后的代码："""


class ReflectionPrompts:
    """反思提示词模板（参考 AgentEvolver / Darwin-Agent GEPA）"""

    @staticmethod
    def geppa(trajectory: str, fail_cases: List[str]) -> str:
        """
        GEPA 反思提示词（参考 Darwin-Agent Closed-Loop）

        针对失败样本最小改动原则，不要大改，只修复失效点。
        """
        return f"""你是一个反思专家。请分析以下执行轨迹和失败案例，找出根因并提出最小化改进方案。

执行轨迹：
{trajectory[:2000]}

失败案例：
{chr(10).join(f'- {fc}' for fc in fail_cases[:5])}

要求：
1. 精准定位失败根因
2. 最小改动原则，只修复失效点
3. 不要大改整体架构
4. 输出：根因分析 + 具体改进建议

请输出分析和改进建议："""

    @staticmethod
    def review(trajectory: str, success_count: int, total_count: int) -> str:
        """
        Review 提示词（参考 Darwin-Agent Closed-Learning-Loop）

        LLM 复盘执行日志，定位根因。
        """
        return f"""你是一个执行复盘专家。请复盘以下 Agent 执行轨迹，找出改进点。

执行统计：成功 {success_count}/{total_count}

执行轨迹：
{trajectory[:3000]}

要求：
1. 分析成功和失败的原因
2. 找出可以改进的 Prompt / Skill / 工具调用
3. 提出具体的改进方案
4. 区分：必须修复的问题 / 可以优化的点

请输出复盘报告："""

    @staticmethod
    def skill_improvement(skill_code: str, fail_cases: List[str]) -> str:
        """
        Skill 改进提示词（参考 AgentEvolver 生成层）

        改写 Prompt / Skill 工具函数。
        """
        return f"""你是一个技能改进专家。请根据失败案例改进以下 Skill 代码。

Skill 代码：
```python
{skill_code}
```

失败案例：
{chr(10).join(f'- {fc}' for fc in fail_cases[:5])}

要求：
1. 保持 Skill 的接口不变
2. 修复导致失败的逻辑
3. 增加错误处理和边界情况
4. 输出完整改进后的代码

请输出改进后的 Skill 代码："""


class LLMJudgePrompts:
    """LLM-as-Judge 评分提示词（参考 Prompt-Darwinism）"""

    @staticmethod
    def judge(prompt: str, test_input: str, expected: str,
              actual_output: str) -> str:
        """
        LLM-as-Judge 打分

        输入测试样例+输出，返回 0-1 浮点数适应度。
        """
        return f"""你是一个严格的评分专家。请评估以下 Prompt 在测试用例上的表现。

Prompt:
{prompt[:1000]}

测试输入:
{test_input}

期望输出:
{expected}

实际输出:
{actual_output}

评分标准：
- 正确性（0.5）：输出是否正确
- 完整性（0.2）：是否覆盖所有要求
- 格式（0.15）：格式是否符合要求
- 效率（0.15）：是否简洁高效

请输出一个 0.0 到 1.0 之间的分数，只输出数字："""
