# PhotonBox 模块成熟度分级与治理文档

> **版本**：1.0
> **生效日期**：2026-09-15
> **维护者**：PhotonBox Team

---

## 一、分级标准

| 等级 | 标识 | 判定条件 | 使用约束 |
|------|------|---------|---------|
| **M3 高成熟** | ✅ | 独立单元测试完整（≥25个），分支覆盖率≥80%；SAST零High/Medium；异常/边界全覆盖；日志完善；文档齐全 | 可用于内网生产 |
| **M2 中等成熟** | ⚠️ | 具备基础单元测试（10-25个），覆盖率40-80%；SAST无High；部分边界缺失；文档简略 | 仅允许内测，禁止核心安全链路直接依赖 |
| **M1 低成熟** | 🔴 | 无独立单元测试；缺少边界用例；文档残缺；代码未充分压测 | 仅开发调试使用，禁止上线任何环境 |

---

## 二、当前模块成熟度盘点

### M3 高成熟（✅ 可用于内网生产）

| 模块 | 行数 | 测试数 | 说明 |
|------|------|--------|------|
| event_input_validator | 442 | 49 | 事件输入校验，7步校验链 |
| policy_guard | 572 | 42 | Agent策略校验，提示注入检测 |
| defense_enforcer | 632 | 26 | 防御规则下发层，配置更新/回滚 |
| security_circuit_breaker | 650 | 28 | 安全熔断隔离引擎，4级熔断 |
| session_state_manager | 927 | 55 | 服务器端会话状态管理 |
| unified_rag_orchestrator | 686 | 41 | 统一RAG编排引擎 |
| slm_query_intent | 1257 | 75 | SLM查询意图理解，5阶段流水线 |
| intelligent_query_router | 1158 | 58 | 智能查询路由与统一检索 |
| security_knowledge_graph | 912 | 42 | 三元组安全知识图谱 |
| hybrid_retrieval | 1160 | 69 | RRF混合检索 |
| post_quantum_crypto | 963 | 36 | 后量子密码迁移 |
| real_signal_consumer | 949 | 31 | 真实信号消费者 |
| evolution_defense_bridge | 554 | 27 | 进化防御桥接 |
| evolution_validation | 937 | 38 | 进化验证 |
| adversarial_strategy_optimizer | 1007 | 39 | 对抗策略优化 |
| quantum_inspired_security | 1062 | 47 | 量子启发安全 |
| boundary_conditions | - | 35 | 边界条件与稳定性测试 |

### M2 中等成熟（⚠️ 仅内测）

| 模块 | 行数 | 测试数 | 待提升项 |
|------|------|--------|---------|
| m2_gateway | 612 | 24 | 补充边界测试，目标≥40 |
| strong_pool (C++) | - | 22 | 裸机E2E验证（需KVM硬件） |
| security_posture (C++) | - | 27 | 补充eBPF相关检测项测试 |

### M1 低成熟（🔴 禁止上线）

| 模块 | 行数 | 测试数 | 升级计划 |
|------|------|--------|---------|
| **real_data_adapter** | 1128 | 0 | **本轮补测试→M2** |
| **red_blue_adversary** | 1476 | 0 | **本轮补核心测试→M2** |
| memory_enhancement | 833 | 0 | 下一轮 |
| wiki_layer | 646 | 0 | 下一轮 |
| leader_teammate | 614 | 0 | 下一轮 |
| security_knowledge_base | 601 | 0 | 下一轮 |
| swarm | 576 | 0 | 下一轮 |
| memory_engine | 552 | 0 | 下一轮 |
| log_consumer | 532 | 0 | 下一轮 |
| rag_engine | 528 | 0 | 下一轮 |
| pipeline_enhancements | 525 | 0 | 下一轮 |
| gang_scheduler | 503 | 0 | 下一轮 |
| sandbox_resource_plugin | 503 | 0 | 下一轮 |
| alert_integration | 497 | 0 | 下一轮 |
| defense_rule_persistence | 473 | 0 | 下一轮 |
| nested_vm_detector | 446 | 0 | 下一轮 |
| poc_event_library | 455 | 0 | 下一轮 |
| ab_test_runner | 412 | 0 | 下一轮 |

---

## 三、治理策略

### P0：上线门限
1. M1模块不作为主链路必经路径，设计开关隔离，可降级到M3兜底
2. CI输出成熟度标签：M1模块修改触发红色告警，PR需人工确认
3. 红蓝对抗/真实数据适配器为增强能力，关闭后沙盒基础防御仍完整

### P1：分批补齐M1→M2
- **本轮**：real_data_adapter + red_blue_adversary（核心安全链路）
- **下一轮**：memory_enhancement + security_knowledge_base + log_consumer
- **后续**：其余M1模块按安全重要性排序补齐

### P2：M2→M3演进
- M2模块补充边界条件测试、异常注入测试
- 覆盖率门禁：M1→M2需≥40%，M2→M3需≥80%

---

## 四、关键风险提醒

> 即使补齐单元测试，**StrongPool(KVM)裸机E2E实测、独立第三方安全审计依然是公网生产上线的硬性前提**。单元测试只能发现代码逻辑bug，无法发现虚拟化逃逸、内核层面漏洞。

当前仅建议**内网可信/半可信场景**使用。
