# PhotonBox 安全知识库 + PolicyGuard 落地报告

**日期**: 2026-09-04
**范围**: 统一向量知识库、CVE漏洞知识库、PolicyGuard策略校验框架

---

## 一、落地背景

基于用户提供的"PhotonKernel可抄技术点清单"，按优先级落地 P0 三项：
1. **可抄点13**: 统一向量知识库架构（基础设施）
2. **可抄点1**: CVE漏洞知识库 + 逃逸技术专库（红蓝对抗基础数据）
3. **可抄点10**: PolicyGuard策略校验框架（Agent安全核心）

## 二、模块详情

### 2.1 统一向量知识库（security_knowledge_base.py）

**类**: `KnowledgeBase`

轻量级TF-IDF检索实现，接口兼容Milvus/Qdrant等向量数据库。生产环境可替换为真实向量数据库，只需实现search()方法。

核心能力：
- 添加/批量添加/删除/获取条目
- TF-IDF余弦相似度检索
- 导出/加载JSON（持久化）
- 自动淘汰最旧条目（容量上限）
- 支持metadata附加信息

### 2.2 CVE漏洞知识库（security_knowledge_base.py）

**类**: `CVEKnowledgeBase`

架构：CVE知识库 → RAG检索 → 攻击用例生成器 → 红方Agent

核心能力：
- **CVE数据结构化**: CVE-ID、CVSS评分、影响版本、漏洞类型、PoC代码片段、利用步骤、检测特征
- **内置6个沙盒逃逸相关CVE**: CVE-2022-0185(fsconfig堆溢出)、CVE-2021-4034(PwnKit)、CVE-2023-32233(nf_tables UAF)、CVE-2024-1086(netfilter双重释放)、CVE-2023-2640(Ubuntu OverlayFS)、CVE-2021-22555(x_tables堆溢出)
- **逃逸技术专库**: 12种逃逸技术（容器逃逸5种、VM逃逸2种、seccomp绕过2种、eBPF逃逸2种、提权1种）
- **RAG检索增强**: 红方Agent生成攻击用例前检索相关CVE/逃逸技术，基于真实PoC变异生成
- **多query检索**: 英文+中文+技术关键词，提高召回率

### 2.3 PolicyGuard策略校验框架（policy_guard.py）

**类**: `PolicyGuard` + `PromptInjectionDetector`

核心能力：
- **策略表示**: 自然语言策略→可执行规则，支持5种策略类型（权限/安全/合规/资源/网络）
- **工具调用前置校验**: Agent调用工具前检查权限、参数、时机，4种动作（ALLOW/DENY/REQUIRE_APPROVAL/LOG_ONLY）
- **对话级策略校验**: 完整对话上下文校验，检测间接提示注入、策略绕过尝试、跨消息分步注入
- **RAG策略检索**: 新场景检索相似场景的安全策略（内置8条安全策略）
- **审批机制**: 高危操作需要人工审批，支持审批通过/拒绝/待审批列表
- **内置8条策略规则**: 禁止破坏性命令、禁止网络扫描、禁止凭证访问、沙盒配置变更需审批、网络策略变更需审批、记录敏感操作、禁止提权、禁止容器逃逸

**PromptInjectionDetector**:
- 9种已知注入模式检测（忽略之前指令、角色伪装、伪造系统提示、提示泄露、安全绕过、隐藏企图、恶意代码注入、编码绕过）
- 15个可疑关键词风险评分
- 对话级跨消息注入检测（角色设置→执行的分步注入）
- 上下文类型加权（工具返回/文档风险更高）

## 三、开发中发现并修复的Bug

### Bug 1: PolicyGuard变量名冲突
- **问题**: `check_tool_call`方法中循环变量`param_result`与外部变量冲突，导致UnboundLocalError
- **修复**: 重命名循环变量为`p_result`

### Bug 2: 逃逸技术检索召回率为0
- **问题**: TF-IDF基于英文分词，逃逸技术content为中文，搜索英文query无匹配
- **修复**: 实现多query检索（英文+中文+技术关键词），添加`_sandbox_type_to_chinese`方法

### Bug 3: 规则参数匹配逻辑错误
- **问题**: 规则定义了param_patterns但参数中没有对应key时，规则仍会匹配，导致正常调用被误拒
- **修复**: 规则定义param_patterns时，必须所有key都存在且匹配才返回True

## 四、功能验证

| 验证项 | 结果 |
|--------|------|
| KnowledgeBase 添加/检索/导出/加载 | 通过 |
| CVE知识库 内置6个CVE | 通过 |
| CVE检索(CVSS>=7.0过滤) | 通过（返回3条） |
| 逃逸技术检索(容器/VM) | 通过 |
| 攻击用例上下文生成 | 通过（CVE 5条+技术1条） |
| PolicyGuard 正常调用允许 | 通过（ls -la → allowed） |
| PolicyGuard 破坏性命令拒绝 | 通过（rm -rf / → denied） |
| PolicyGuard 提权命令拒绝 | 通过（sudo bash → denied） |
| PolicyGuard 容器逃逸拒绝 | 通过（mount cgroup → denied） |
| PolicyGuard 配置变更需审批 | 通过（sandbox_config update → needs_approval） |
| PolicyGuard 注入参数检测 | 通过（risk=0.45） |
| PromptInjectionDetector 注入检测 | 通过（匹配2种模式） |
| PromptInjectionDetector 正常文本 | 通过（无注入） |
| 审批管理（通过/拒绝/列表） | 通过 |

## 五、SAST静态扫描

| 严重等级 | 数量 |
|---------|------|
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 0 |
| **合计** | **0（完美）** |

## 六、渗透测试（内部POC）

| 指标 | 结果 |
|------|------|
| 通过 | 14 |
| 失败 | 0 |
| 逃逸检测 | 0 |
| 通过率 | 100% |

## 七、漏洞评估

| CVE | 严重等级 | 状态 |
|-----|---------|------|
| CVE-2022-3602 | HIGH | 系统侧待升级，Python侧已修复 |
| CVE-2023-44487 | HIGH | Python侧已修复，C++侧待安装 |

## 八、独立第三方安全审计状态

⚠️ **未完成独立第三方安全审计**

已就绪7份审计前置材料（约2200+行），可直接交付第三方机构。本次新增的安全知识库和PolicyGuard模块可纳入审计范围。

## 九、与红蓝对抗框架的集成点

新增模块可与现有RedBlueAdversaryTrainer集成：
1. **CVE知识库** → 红方Agent生成攻击用例时检索真实CVE/逃逸技术
2. **PolicyGuard** → 蓝方Agent的防御规则可作为PolicyGuard规则下发
3. **统一知识库** → 攻击样本库、防御规则库、攻击模式库共用基础设施

## 十、诚实声明

1. 所有安全验证为内部自评估，不代表第三方认证
2. 核心卖点KVM StrongPool尚未在真实环境验证
3. 6个关键模块因缺少必要条件尚未实测
4. 无独立第三方安全审计（前置材料已就绪7份）
5. 2个HIGH CVE为系统侧依赖问题，生产部署前必须在有sudo环境升级
6. 生产部署前必须完成官方要求的三件事：裸机KVM验证、第三方审计、依赖升级
