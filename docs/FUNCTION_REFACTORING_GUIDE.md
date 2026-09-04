# PhotonBox 函数拆分指南

**版本**: 1.0
**日期**: 2026-09-04
**状态**: 团队规范草案

---

## 一、50 行规则

> **超过 50 行的函数必须解释为何不能拆分。**

这是 PhotonBox 代码库的硬性规范。所有超过 50 行的函数，必须在代码注释中说明不可拆分的原因，否则在代码审查中会被要求拆分。

### 1.1 为什么是 50 行？

- **认知负荷**：人类短期记忆容量约为 7±2 个信息块，50 行函数通常包含 3-5 个逻辑步骤，已接近认知上限
- **可测试性**：超过 50 行的函数通常有多个职责，难以编写单元测试
- **可维护性**：长函数的修改容易引入回归 bug，因为逻辑耦合度高
- **可读性**：代码审查时，长函数需要反复滚动查看，降低审查效率

### 1.2 例外情况（必须注释说明）

以下情况可以超过 50 行，但必须在函数开头用 `# 不可拆分原因：` 注释说明：

1. **数据初始化函数**：硬编码的知识库、规则库、POC 样本等数据初始化函数，拆分反而降低可读性
   - 示例：`_init_builtin_cves()`、`_initialize_builtin_pocs()`、`_init_builtin_rules()`
2. **状态机/调度主循环**：包含多个 case 分支的状态机，拆分可能破坏状态流转的完整性
3. **数学/算法核心实现**：需要保持公式完整性的算法实现，拆分可能引入计算错误
4. **外部接口兼容性**：需要保持特定签名的公共 API，拆分可能破坏向后兼容

---

## 二、拆分原则

### 2.1 单一职责原则（SRP）

每个函数应该只做一件事，并且做好。拆分时按照职责划分，而不是按照代码行数机械切割。

**好的拆分**：
```python
def retrieve(self, query, kb_names, top_k, strategy, use_cache):
    cached = self._check_cache(...)          # 职责：缓存检查
    if cached: return cached
    query = self._query_rewriter.rewrite(query)  # 职责：查询重写
    results = self._search_all_knowledge_bases(...)  # 职责：多库检索
    results = self._apply_retrieval_strategy(...)    # 职责：策略应用
    results = self._truncate_and_rank(...)            # 职责：截断排名
    self._update_retrieval_stats(...)                 # 职责：统计更新
    context = self._build_context(...)                # 职责：上下文构建
    self._cache_result(...)                            # 职责：结果缓存
    return context
```

**坏的拆分**（机械切割）：
```python
def retrieve(self, query, ...):
    # 前30行
    self._retrieve_part1(...)
    # 中间30行
    self._retrieve_part2(...)
    # 后30行
    self._retrieve_part3(...)
```

### 2.2 提取而非切割

拆分函数时，应该**提取有意义的子函数**，而不是把长函数切成几段。子函数应该：
- 有清晰的函数名，描述其职责
- 有明确的输入输出契约
- 可以独立测试
- 内部逻辑内聚

### 2.3 保持主函数可读性

拆分后的主函数应该像一个"目录"，读者通过主函数就能了解整个流程，不需要深入每个子函数。

**好的主函数**（20-35行）：
```python
def full_analysis(self, features, events, search_results, query):
    anomaly = self._run_anomaly_detection(features)
    intrusion = self._run_intrusion_detection(features)
    correlation = self._run_event_correlation(events)
    reranked = self._run_search_reranking(search_results, query)
    combined_risk = self._compute_combined_risk(anomaly, intrusion, correlation)
    risk_level = self._determine_risk_level(combined_risk)
    return self._build_full_analysis_result(...)
```

---

## 三、拆分反模式（拆分后反而降低可读性）

### 3.1 过度拆分

把只有 3-5 行的简单逻辑也提取成子函数，导致函数调用层级过深，读者需要频繁跳转才能理解逻辑。

**反模式**：
```python
def _add(a, b):  # 过度拆分：简单加法不需要单独函数
    return a + b

def _multiply(a, b):  # 过度拆分
    return a * b
```

**判断标准**：如果子函数只被调用一次，且逻辑简单（<5行），通常不需要拆分。

### 3.2 拆分破坏内聚

把紧密相关的逻辑拆到不同函数中，导致需要在多个函数之间跳转才能理解完整逻辑。

**反模式**：把一个 for 循环的初始化、循环体、收尾拆成三个函数，而循环体本身只有几行。

### 3.3 参数爆炸

拆分后的子函数需要传递大量参数（>5个），说明拆分边界不合理，应该重新考虑拆分方式。

**反模式**：
```python
def _process(self, a, b, c, d, e, f, g, h):  # 参数爆炸：8个参数
    ...
```

**解决方案**：将相关参数封装成数据类（dataclass）或字典传递。

### 3.4 状态泄露

子函数依赖主函数的局部变量，但通过参数传递不完整，导致子函数的行为依赖调用顺序或隐式状态。

**反模式**：子函数修改主函数的可变对象，但没有明确的返回值说明修改了什么。

---

## 四、拆分检查清单

拆分函数后，逐项检查：

- [ ] **主函数 <= 35 行**：主函数应该像目录，简洁清晰
- [ ] **子函数 <= 50 行**：所有子函数都不超过 50 行
- [ ] **子函数有清晰命名**：函数名描述职责，动词开头（`_check_`、`_build_`、`_extract_`、`_compute_`）
- [ ] **子函数可独立测试**：为每个子函数编写契约测试（输入输出边界条件）
- [ ] **无重复代码**：拆分后消除了重复逻辑（如缓存键计算、统计更新）
- [ ] **无参数爆炸**：每个子函数参数 <= 5 个，超过则考虑封装数据类
- [ ] **无隐式状态**：子函数不依赖调用顺序，输入输出明确
- [ ] **全量测试通过**：拆分后所有现有测试仍然通过
- [ ] **新增契约测试**：为新拆分的子函数补充边界条件测试

---

## 五、已完成拆分的函数清单

| 模块 | 函数 | 重构前 | 重构后 | 子函数数 | 契约测试 |
|------|------|--------|--------|---------|---------|
| quantum_inspired_security.py | `full_analysis()` | 81 行 | 20 行 | 8 | ✅ |
| quantum_inspired_security.py | `correlate()` | 57 行 | 18 行 | 5 | ✅ |
| quantum_inspired_security.py | `detect()` | 49 行 | 20 行 | 3 | ✅ |
| quantum_inspired_security.py | `_stdp_update()` | 49 行 | 16 行 | 3 | ✅ |
| rag_engine.py | `retrieve()` | 94 行 | 35 行 | 6 | ✅ |
| red_blue_adversary.py | `generate_defense_rule_with_rag()` | 76 行 | 30 行 | 5 | ✅ (15个) |

---

## 六、待拆分函数清单（优先级排序）

| 优先级 | 模块 | 函数 | 行数 | 备注 |
|--------|------|------|------|------|
| P1 | red_blue_adversary.py | `generate_attack_case_with_rag()` | 72 | 有实际逻辑，建议拆分 |
| P1 | real_data_adapter.py | `correlate_events_with_rag()` | 66 | 有实际逻辑，建议拆分 |
| P1 | red_blue_adversary.py | `ingest_real_event()` | 62 | 有实际逻辑，建议拆分 |
| P2 | wiki_skill_evolver.py | `evolve_skill()` | 73 | 有实际逻辑，建议拆分 |
| P2 | adversary_loop_orchestrator.py | `start()` | 61 | 调度主循环，需评估是否可拆分 |
| P2 | wiki_skill_evolver.py | `record_execution()` | 61 | 有实际逻辑，建议拆分 |
| P2 | agent_policy_rag.py | `check_with_rag()` | 57 | 有实际逻辑，建议拆分 |
| P3 | poc_event_library.py | `run_closed_loop_test()` | 83 | 测试流程，可拆分 |
| 例外 | security_knowledge_base.py | `_init_builtin_cves()` | 160 | 数据初始化，不可拆分 |
| 例外 | poc_event_library.py | `_initialize_builtin_pocs()` | 173 | 数据初始化，不可拆分 |
| 例外 | policy_guard.py | `_init_builtin_rules()` | 77 | 数据初始化，不可拆分 |

---

## 七、契约测试模板

为拆分后的子函数编写契约测试时，覆盖以下边界条件：

```python
class TestSubFunctionContract(unittest.TestCase):
    """子函数契约测试"""

    def test_normal_input(self):
        """正常输入应返回预期结果"""
        result = obj._sub_function(normal_input)
        self.assertEqual(result, expected)

    def test_empty_input(self):
        """空输入应安全处理，不抛异常"""
        result = obj._sub_function([])
        self.assertIsNotNone(result)

    def test_none_input(self):
        """None 输入应安全处理"""
        result = obj._sub_function(None)
        self.assertIsNotNone(result)

    def test_missing_keys(self):
        """字典缺少键应使用默认值"""
        result = obj._sub_function({"unknown": "value"})
        self.assertIsInstance(result, ExpectedType)

    def test_malicious_input(self):
        """恶意输入（XSS/SQL注入）应安全处理"""
        result = obj._sub_function({"description": "<script>alert(1)</script>"})
        self.assertIsNotNone(result)

    def test_extreme_values(self):
        """超大/超小/负值应安全处理"""
        result = obj._sub_function([1e10, -1e10, 0])
        self.assertIsNotNone(result)

    def test_return_type(self):
        """返回值类型应符合契约"""
        result = obj._sub_function(input)
        self.assertIsInstance(result, ExpectedType)

    def test_return_structure(self):
        """返回值结构应包含所有必需字段"""
        result = obj._sub_function(input)
        self.assertIn("required_field", result)
```

---

## 八、参考资料

- 《Clean Code》Robert C. Martin — 函数应该短小、只做一件事
- 《Refactoring》Martin Fowler — 提取方法（Extract Method）重构模式
- Python 代码风格指南（PEP 8）— 函数设计建议
