# PhotonBox RAG 检索增强生成四方向集成架构

## 概述

PhotonBox 集成 RAG（Retrieval-Augmented Generation）检索增强生成技术，将知识库检索与大模型生成结合，应用于四个核心方向：

1. **方向1：红方攻击用例 RAG 增强** — 基于 CVE 漏洞知识库和逃逸技术知识库，生成高质量攻击用例
2. **方向2：蓝方防御规则 RAG 增强** — 基于防御规则知识库和安全最佳实践，生成有效防御规则
3. **方向3：事件关联 RAG** — 基于攻击模式知识库，将多个安全事件关联为攻击链
4. **方向4：Agent 策略 RAG** — 基于安全策略知识库，增强 PolicyGuard 的工具调用校验

## 架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                      RAG 四方向集成架构                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │  方向1: 红方  │  │  方向2: 蓝方  │  │  方向3: 事件  │         │
│  │  攻击用例RAG  │  │  防御规则RAG  │  │  关联RAG     │         │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘         │
│         │                   │                   │                 │
│         └───────────────────┼───────────────────┘                 │
│                             │                                     │
│  ┌──────────────────────────┼──────────────────────────┐         │
│  │                    RAGEngine 核心引擎                  │         │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │         │
│  │  │ QueryRewriter│  │  Retriever  │  │  Reranker   │ │         │
│  │  │ 查询重写     │  │  检索器      │  │  重排序     │ │         │
│  │  └─────────────┘  └─────────────┘  └─────────────┘ │         │
│  └──────────────────────────────────────────────────────┘         │
│                             │                                     │
│  ┌──────────────────────────┼──────────────────────────┐         │
│  │                    统一向量知识库                        │         │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ │         │
│  │  │ CVE漏洞  │ │ 防御规则 │ │攻击模式  │ │安全策略│ │         │
│  │  │ 知识库   │ │ 知识库   │ │ 知识库   │ │ 知识库 │ │         │
│  │  │ (6条)   │ │ (8条)   │ │ (7条)   │ │ (8条)  │ │         │
│  │  └──────────┘ └──────────┘ └──────────┘ └────────┘ │         │
│  └──────────────────────────────────────────────────────┘         │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │              方向4: Agent 策略 RAG (AgentPolicyRAG)      │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │    │
│  │  │ 策略检索     │  │ 增强校验     │  │ 策略推荐     │    │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘    │    │
│  │         │                │                │               │    │
│  │  ┌──────┴────────────────┴────────────────┴──────┐     │    │
│  │  │              PolicyGuard 策略校验框架            │     │    │
│  │  └─────────────────────────────────────────────────┘     │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

## 核心组件

### 1. RAGEngine（`evolution/rag_engine.py`）

RAG 核心引擎，提供统一的检索增强生成接口。

**主要类：**
- `RAGEngine` — 核心引擎，管理多个知识库，提供检索接口
- `QueryRewriter` — 查询重写器，支持同义词扩展和查询分解
- `Reranker` — 重排序器，基于关键词密度、重要性、时效性重新排序
- `RetrievalResult` — 检索结果数据类
- `RAGContext` — RAG 上下文，包含检索结果、重写后的查询、统计信息

**检索策略：**
- `KEYWORD` — 纯关键词检索（TF-IDF）
- `SEMANTIC` — 语义检索（向量相似度）
- `HYBRID` — 混合检索（关键词 + 语义，默认）

**核心方法：**
```python
engine = RAGEngine(knowledge_dir="evolution/rag_knowledge")
context = engine.retrieve("container escape vulnerability", kb_names=["cve_knowledge"])
prompt = engine.build_prompt("问题：{query}\n参考：{context}", context)
```

### 2. 统一向量知识库（`evolution/rag_knowledge/`）

四个 JSON 格式知识库，共 29 条知识：

| 知识库 | 文件 | 条数 | 用途 |
|--------|------|------|------|
| CVE 漏洞知识库 | `cve_knowledge.json` | 6 | 红方攻击用例生成 |
| 防御规则知识库 | `defense_knowledge.json` | 8 | 蓝方防御规则生成 |
| 攻击模式知识库 | `attack_pattern_knowledge.json` | 7 | 事件关联、攻击链检测 |
| 安全策略知识库 | `policy_knowledge.json` | 8 | Agent 策略校验 |

**知识库格式：**
```json
{
  "id": "CVE-2022-0185",
  "content": "Linux内核fsconfig整数溢出...",
  "cve_id": "CVE-2022-0185",
  "cvss": 7.8,
  "type": "privilege_escalation",
  "severity": "high",
  "metadata": {...}
}
```

### 3. 方向1：红方攻击用例 RAG 增强（`evolution/red_blue_adversary.py`）

在 `RedBlueAdversaryTrainer` 中新增 RAG 增强方法：

**核心方法：**
- `set_rag_engine(rag_engine)` — 设置 RAG 引擎
- `generate_attack_case_with_rag(target_sandbox_type)` — 基于 CVE 知识库生成攻击用例
- `get_rag_stats()` — 获取 RAG 增强统计

**工作流程：**
1. 从 CVE 知识库和攻击模式知识库检索相关漏洞
2. 选择最高相关性的 CVE 作为基础
3. 基于真实 PoC 变异生成攻击用例
4. 记录 RAG 增强统计

### 4. 方向2：蓝方防御规则 RAG 增强（`evolution/red_blue_adversary.py`）

**核心方法：**
- `generate_defense_rule_with_rag(attack_event)` — 基于防御规则知识库生成防御规则

**工作流程：**
1. 从防御规则知识库和安全策略知识库检索相关规则
2. 选择最高相关性的规则作为基础
3. 基于已有规则变异生成新防御规则
4. 新规则默认 LOG_ONLY 模式（只记录不拦截）

### 5. 方向3：事件关联 RAG（`evolution/real_data_adapter.py`）

在 `RealDataAdapter` 中新增 RAG 事件关联方法：

**核心方法：**
- `set_rag_engine(rag_engine)` — 设置 RAG 引擎
- `correlate_events_with_rag(events, time_window_seconds)` — 基于 RAG 的事件关联
- `detect_attack_chain_with_rag(events)` — 攻击链检测
- `get_rag_correlation_stats()` — 获取 RAG 关联统计

**工作流程：**
1. 按时间窗口聚合事件
2. 构建事件聚合描述文本
3. 从攻击模式知识库检索相关攻击模式
4. 计算风险评分（事件严重程度 + 数量加成 + 模式匹配加成）
5. 识别攻击链阶段（侦察→利用→提权→逃逸等）

### 6. 方向4：Agent 策略 RAG（`evolution/agent_policy_rag.py`）

独立的 Agent 策略 RAG 集成器，将 RAG 检索与 PolicyGuard 结合。

**核心类：**
- `AgentPolicyRAG` — Agent 策略 RAG 集成器
- `PolicyRecommendation` — 策略推荐结果数据类

**核心方法：**
- `check_with_rag(agent_id, tool_name, params, ...)` — 带 RAG 增强的工具调用校验
- `recommend_policy(tool_name, tool_description)` — 为新工具推荐安全策略
- `learn_policy_from_event(event)` — 从安全事件学习新策略
- `get_stats()` — 获取统计信息

**工作流程（check_with_rag）：**
1. 构建策略检索 query
2. 从安全策略知识库检索相关策略
3. 将检索到的策略临时注入 PolicyGuard
4. 执行 PolicyGuard 校验
5. 清理临时注入的策略
6. 返回校验结果（包含 RAG 上下文信息）

## 数据流

### 方向1+2：红蓝对抗 RAG 数据流

```
用户/系统触发
    │
    ▼
RedBlueAdversaryTrainer
    │
    ├─→ generate_attack_case_with_rag()
    │       │
    │       ├─→ RAGEngine.retrieve("container escape vulnerability")
    │       │       └─→ CVE知识库 + 攻击模式知识库
    │       │
    │       └─→ 基于检索结果生成 AttackCase
    │
    └─→ generate_defense_rule_with_rag()
            │
            ├─→ RAGEngine.retrieve("defense against container_escape")
            │       └─→ 防御规则知识库 + 安全策略知识库
            │
            └─→ 基于检索结果生成 DefenseRule
```

### 方向3：事件关联 RAG 数据流

```
真实安全事件流（seccomp违规 / KVM VM-Exit / 审计链异常）
    │
    ▼
RealDataAdapter
    │
    ├─→ 按时间窗口聚合事件
    │
    ├─→ correlate_events_with_rag()
    │       │
    │       ├─→ 构建事件描述文本
    │       ├─→ RAGEngine.retrieve(事件描述)
    │       │       └─→ 攻击模式知识库
    │       ├─→ 匹配攻击模式
    │       └─→ 计算风险评分
    │
    └─→ detect_attack_chain_with_rag()
            │
            └─→ 识别攻击链阶段（侦察→利用→提权→逃逸）
```

### 方向4：Agent 策略 RAG 数据流

```
Agent 调用工具
    │
    ▼
AgentPolicyRAG.check_with_rag()
    │
    ├─→ 构建策略检索 query（工具名 + 参数 + Agent角色）
    │
    ├─→ RAGEngine.retrieve(query)
    │       └─→ 安全策略知识库
    │
    ├─→ 临时注入检索到的策略到 PolicyGuard
    │
    ├─→ PolicyGuard.check_tool_call() 执行校验
    │
    ├─→ 清理临时注入的策略
    │
    └─→ 返回校验结果（含 RAG 来源信息）
```

## 设计原则

### 1. 知识库与引擎解耦
- RAGEngine 不绑定特定知识库，可动态注册新知识库
- 知识库以 JSON 文件存储，易于维护和扩展
- 支持运行时添加文档（`add_document`）

### 2. 检索策略可配置
- 支持关键词、语义、混合三种检索策略
- 支持查询重写（同义词扩展、查询分解）
- 支持重排序（关键词密度、重要性、时效性）

### 3. 安全优先
- RAG 生成的攻击用例仅用于内部红蓝对抗测试
- RAG 生成的防御规则默认 LOG_ONLY 模式，需人工确认后启用
- Agent 策略 RAG 的临时注入策略在校验后立即清理
- 从安全事件学习的新策略默认 LOG_ONLY，不自动拦截

### 4. 可观测性
- 每次检索记录查询、结果数量、耗时
- 支持缓存命中统计
- 红蓝对抗 RAG 增强统计独立记录
- 事件关联 RAG 统计独立记录

## 扩展指南

### 添加新知识库

1. 在 `evolution/rag_knowledge/` 创建 JSON 文件
2. 格式：`[{"id": "...", "content": "...", "metadata": {...}}]`
3. RAGEngine 自动加载（文件名即知识库名）

### 扩展检索策略

1. 在 `RetrievalStrategy` 枚举中添加新策略
2. 在 `RAGEngine.retrieve()` 中实现对应检索逻辑
3. 更新 `RAG_ARCHITECTURE.md` 文档

### 集成新方向

1. 在目标模块中调用 `set_rag_engine(rag_engine)`
2. 实现 `generate_xxx_with_rag()` 方法
3. 添加对应的单元测试
4. 更新本文档的架构图和数据流

## 测试覆盖

`evolution/tests/test_rag_integration.py` 包含 65 个单元测试，覆盖：

| 测试类 | 测试数 | 覆盖范围 |
|--------|--------|----------|
| TestQueryRewriter | 7 | 查询重写、同义词扩展、分解 |
| TestReranker | 4 | 重排序、排名分配、空输入 |
| TestRAGEngine | 18 | 引擎初始化、知识库加载、检索、缓存、统计 |
| TestDirection1AttackRAG | 7 | 红方攻击用例 RAG 增强 |
| TestDirection2DefenseRAG | 6 | 蓝方防御规则 RAG 增强 |
| TestDirection3EventCorrelationRAG | 8 | 事件关联 RAG、攻击链检测 |
| TestDirection4AgentPolicyRAG | 8 | Agent 策略 RAG、策略推荐、策略学习 |
| TestKnowledgeBaseIntegrity | 5 | 知识库结构、总条目数 |
| TestEndToEndWorkflow | 2 | 完整工作流、持久化 |

## 已知限制

1. **当前使用 TF-IDF 关键词检索** — 语义检索为模拟实现，生产环境建议接入 Milvus/Qdrant 等向量数据库
2. **知识库规模较小** — 当前 29 条知识，生产环境需持续扩充
3. **RAG 生成的内容需人工审核** — 攻击用例和防御规则由 LLM 生成，可能存在不准确
4. **事件关联基于时间窗口** — 复杂攻击链可能跨越多时间窗口，需要更高级的关联算法
5. **Agent 策略 RAG 临时注入有性能开销** — 每次校验都需要注入和清理策略，高并发场景需优化

## 未来优化方向

1. 接入真实向量数据库（Milvus/Qdrant），替换 TF-IDF 模拟实现
2. 扩充知识库至 1000+ 条，覆盖更多 CVE、防御规则、攻击模式
3. 实现 RAG 生成内容的自动审核机制
4. 优化事件关联算法，支持跨时间窗口的攻击链检测
5. 实现 Agent 策略 RAG 的策略缓存，减少临时注入开销
6. 支持知识库的增量更新和版本管理
