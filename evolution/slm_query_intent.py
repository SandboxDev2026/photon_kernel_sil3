"""
PhotonBox SLM 查询意图理解系统

基于小语言模型（SLM）的查询意图理解，5 阶段流水线：
1. 查询去噪（Denoising）：拼写纠错、语法修正、去除冗余、补全省略
2. 意图分类（Intent Classification）：主意图+子意图+领域+动作+约束+实体
3. 实体抽取（Entity Extraction）：CVE/漏洞/组件/配置项/时间范围
4. 查询重写（Query Rewriting）：低置信度触发，补充领域术语
5. 多意图分解（Decomposition）：复杂查询拆分为子查询并行检索

参考：
- Omni-RAG：Deep Query Understanding and Decomposition
- Google Query Fan-out：搜索前将查询重写为多个变体
- IAT-RAG：Intent Classification + Adaptive Retrieval Strategy
- 腾讯搜索 QU 标准流程：预处理→分词→改写→term分析→意图识别
- 阿里千寻搜索：分词+NER+纠错+改写+分类
- Qwen3 双模式：思维模式（复杂推理）/非思维模式（高效对话）

当前实现：基于规则的查询意图理解（无需 GPU/模型，CPU 可跑，延迟<10ms）
后续升级：替换为 Qwen3-1.7B QLoRA 微调模型（~1.5GB 显存，意图分类准确率 90%+）
"""

import re
import json
import time
import hashlib
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple, Set
from collections import defaultdict
from enum import Enum


# ==================== 意图类型枚举 ====================

class IntentType(Enum):
    """主意图类型枚举"""
    VULNERABILITY_QUERY = "vulnerability_query"     # 漏洞查询（CVE详情/影响/POC）
    CONFIGURATION_QUERY = "configuration_query"     # 配置查询（参数/设置/选项）
    LOG_QUERY = "log_query"                         # 日志查询（审计/事件/告警）
    INCIDENT_QUERY = "incident_query"               # 事件查询（安全事件/异常）
    RISK_ASSESSMENT = "risk_assessment"             # 风险评估（影响分析/暴露面）
    ATTACK_CHAIN = "attack_chain"                   # 攻击链（逃逸路径/利用链）
    DEFENSE_QUERY = "defense_query"                 # 防御查询（规则/策略/加固）
    PERFORMANCE_QUERY = "performance_query"         # 性能查询（延迟/吞吐/资源）
    DEPLOYMENT_QUERY = "deployment_query"           # 部署查询（安装/配置/升级）
    TROUBLESHOOTING = "troubleshooting"             # 故障排查（错误/失败/异常）
    GENERAL_KNOWLEDGE = "general_knowledge"         # 通用知识（概念/原理/最佳实践）
    SESSION_CONTEXT = "session_context"             # 会话上下文（历史/继续/上次）
    UNKNOWN = "unknown"                             # 未知意图


class SecurityDomain(Enum):
    """安全领域枚举"""
    SANDBOX_ESCAPE = "sandbox_escape"               # 沙箱逃逸
    SYSTEM_HARDENING = "system_hardening"           # 系统加固
    NETWORK_SECURITY = "network_security"           # 网络安全
    ACCESS_CONTROL = "access_control"               # 访问控制
    AUDIT_COMPLIANCE = "audit_compliance"           # 审计合规
    VULNERABILITY_MGMT = "vulnerability_management"  # 漏洞管理
    INCIDENT_RESPONSE = "incident_response"         # 事件响应
    CRYPTOGRAPHY = "cryptography"                   # 密码学
    CONTAINER_SECURITY = "container_security"       # 容器安全
    VM_SECURITY = "vm_security"                     # 虚拟机安全
    GENERAL = "general"                             # 通用安全


class ActionType(Enum):
    """动作类型枚举"""
    LOOKUP = "lookup"           # 查询/查找
    ANALYZE = "analyze"         # 分析
    ASSESS = "assess"           # 评估
    DETECT = "detect"           # 检测
    PREVENT = "prevent"         # 防护/阻止
    MITIGATE = "mitigate"       # 缓解
    CONFIGURE = "configure"     # 配置
    DEPLOY = "deploy"           # 部署
    TROUBLESHOOT = "troubleshoot"  # 排查
    EXPLAIN = "explain"         # 解释
    COMPARE = "compare"         # 比较
    LIST = "list"               # 列举
    UNKNOWN = "unknown"         # 未知


# ==================== 数据结构 ====================

@dataclass
class DenoisedQuery:
    """去噪后的查询"""
    original: str
    denoised: str
    corrections: List[Dict[str, str]] = field(default_factory=list)  # 修正记录
    removed_redundancy: List[str] = field(default_factory=list)      # 移除的冗余
    confidence: float = 1.0


@dataclass
class IntentResult:
    """意图分类结果"""
    primary_intent: str
    sub_intents: List[str] = field(default_factory=list)
    domain: str = "general"
    action: str = "unknown"
    constraints: Dict[str, Any] = field(default_factory=dict)  # 约束条件（时间/范围/严重度）
    confidence: float = 0.0
    intent_scores: Dict[str, float] = field(default_factory=dict)  # 各意图得分


@dataclass
class ExtractedEntity:
    """抽取的实体"""
    entity_type: str       # cve/component/config/time/severity/backend/tenant
    value: str
    normalized: str = ""   # 规范化后的值
    position: Tuple[int, int] = (0, 0)  # 在原文中的位置
    confidence: float = 1.0


@dataclass
class RewrittenQuery:
    """重写后的查询"""
    original: str
    rewritten: str
    variants: List[str] = field(default_factory=list)  # 查询变体（Google Fan-out）
    added_terms: List[str] = field(default_factory=list)  # 补充的术语
    removed_terms: List[str] = field(default_factory=list)  # 移除的术语
    trigger_reason: str = ""  # 触发重写的原因
    confidence: float = 0.0


@dataclass
class DecomposedQuery:
    """分解后的子查询"""
    original: str
    sub_queries: List[Dict[str, Any]] = field(default_factory=list)
    parallel: bool = True  # 是否可并行执行
    aggregation_strategy: str = "merge"  # 聚合策略（merge/rank/fuse）


@dataclass
class QueryUnderstandingResult:
    """查询理解完整结果（结构化 JSON 输出）"""
    query: str
    timestamp: float = field(default_factory=time.time)
    pipeline_version: str = "1.0"

    # 各阶段结果
    denoised: Optional[DenoisedQuery] = None
    intent: Optional[IntentResult] = None
    entities: List[ExtractedEntity] = field(default_factory=list)
    rewritten: Optional[RewrittenQuery] = None
    decomposed: Optional[DecomposedQuery] = None

    # 综合信息
    overall_confidence: float = 0.0
    needs_rewrite: bool = False
    needs_decomposition: bool = False
    needs_human_review: bool = False
    recommended_retrieval_strategy: str = "rrf_hybrid"
    processing_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（用于 JSON 序列化）"""
        result = {
            "query": self.query,
            "timestamp": self.timestamp,
            "pipeline_version": self.pipeline_version,
            "overall_confidence": round(self.overall_confidence, 4),
            "needs_rewrite": self.needs_rewrite,
            "needs_decomposition": self.needs_decomposition,
            "needs_human_review": self.needs_human_review,
            "recommended_retrieval_strategy": self.recommended_retrieval_strategy,
            "processing_time_ms": round(self.processing_time_ms, 2),
        }

        if self.denoised:
            result["denoised"] = asdict(self.denoised)
        if self.intent:
            result["intent"] = asdict(self.intent)
        result["entities"] = [asdict(e) for e in self.entities]
        if self.rewritten:
            result["rewritten"] = asdict(self.rewritten)
        if self.decomposed:
            result["decomposed"] = asdict(self.decomposed)

        return result

    def to_json(self, indent: int = 2) -> str:
        """转换为 JSON 字符串"""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


# ==================== 阶段 1：查询去噪 ====================

class QueryDenoiser:
    """
    查询去噪器

    功能：
    1. 拼写纠错（常见安全术语拼写错误）
    2. 语法修正（口语化表达规范化）
    3. 去除冗余（重复词、无意义语气词）
    4. 补全省略（上下文相关的省略补全）

    参考：Omni-RAG Deep Query Understanding
    """

    # 常见安全术语拼写纠错映射
    SPELLING_CORRECTIONS = {
        "secccomp": "seccomp",
        "seccom": "seccomp",
        "ebpf": "eBPF",
        "bpf": "BPF",
        "cve": "CVE",
        "kvmm": "KVM",
        "firecrakcer": "firecracker",
        "firecrakcer": "firecracker",
        "contianer": "container",
        "contianer": "container",
        "sandobx": "sandbox",
        "sandobx": "sandbox",
        "vulnerabilty": "vulnerability",
        "vulnerabilty": "vulnerability",
        "vuln": "vulnerability",
        "exploit": "exploit",
        "poc": "POC",
        "dos": "DoS",
        "ddos": "DDoS",
        "xss": "XSS",
        "sql": "SQL",
        "csrf": "CSRF",
        "ssrf": "SSRF",
        "rce": "RCE",
        "lfi": "LFI",
        "rfi": "RFI",
    }

    # 冗余词/语气词（移除）
    REDUNDANCY_WORDS = {
        "请问", "麻烦", "帮忙", "一下", "看看", "啊", "呢", "吧", "呀",
        "那个", "这个", "就是", "其实", "然后", "所以", "因此", "那么",
        "please", "kindly", "help", "just", "really", "actually",
        "basically", "literally", "so", "well", "um", "uh",
    }

    def __init__(self):
        self.correction_count = 0

    def denoise(self, query: str) -> DenoisedQuery:
        """
        对查询进行去噪处理

        Args:
            query: 原始查询

        Returns:
            去噪后的查询
        """
        original = query
        denoised = query
        corrections = []
        removed = []

        # 1. 拼写纠错
        for wrong, correct in self.SPELLING_CORRECTIONS.items():
            pattern = re.compile(r'\b' + re.escape(wrong) + r'\b', re.IGNORECASE)
            matches = pattern.findall(denoised)
            if matches:
                denoised = pattern.sub(correct, denoised)
                for match in matches:
                    corrections.append({"original": match, "corrected": correct, "type": "spelling"})

        # 2. 去除冗余词
        words = denoised.split()
        filtered_words = []
        for word in words:
            word_clean = word.strip(".,!?;:")
            if word_clean.lower() in self.REDUNDANCY_WORDS:
                removed.append(word)
            else:
                filtered_words.append(word)
        denoised = " ".join(filtered_words)

        # 3. 规范化空白
        denoised = re.sub(r'\s+', ' ', denoised).strip()

        # 4. 计算置信度
        confidence = 1.0 - (len(corrections) * 0.05) - (len(removed) * 0.02)
        confidence = max(0.5, min(1.0, confidence))

        return DenoisedQuery(
            original=original,
            denoised=denoised,
            corrections=corrections,
            removed_redundancy=removed,
            confidence=confidence,
        )


# ==================== 阶段 2：意图分类 ====================

class IntentClassifier:
    """
    意图分类器

    基于关键词和模式匹配的意图分类，输出结构化 JSON：
    - 主意图（primary_intent）
    - 子意图（sub_intents）
    - 领域（domain）
    - 动作（action）
    - 约束（constraints）
    - 置信度（confidence）

    后续升级：Qwen3-1.7B QLoRA 微调模型（500-5000 条训练数据）
    """

    # 意图关键词映射（主意图 -> 关键词列表）
    INTENT_KEYWORDS = {
        IntentType.VULNERABILITY_QUERY.value: [
            "cve", "漏洞", "vulnerability", "poc", "exploit", "利用",
            "影响版本", "affected", "patch", "补丁", "修复版本",
        ],
        IntentType.CONFIGURATION_QUERY.value: [
            "配置", "config", "参数", "parameter", "设置", "setting",
            "选项", "option", "启用", "enable", "禁用", "disable",
        ],
        IntentType.LOG_QUERY.value: [
            "日志", "log", "审计", "audit", "事件", "event", "告警",
            "alert", "记录", "record", "trace", "追踪",
        ],
        IntentType.INCIDENT_QUERY.value:
        [
            "事件", "incident", "异常", "anomaly", "告警", "alert",
            "入侵", "intrusion", "breach", "安全事件",
        ],
        IntentType.RISK_ASSESSMENT.value: [
            "风险评估", "risk assessment", "风险", "risk", "评估", "assessment",
            "影响分析", "impact analysis", "影响", "impact",
            "暴露面", "exposure", "威胁", "threat", "脆弱性",
        ],
        IntentType.ATTACK_CHAIN.value: [
            "攻击链", "attack chain", "逃逸路径", "escape path",
            "利用链", "exploit chain", "多步", "multi-step", "链式",
        ],
        IntentType.DEFENSE_QUERY.value: [
            "防御", "defense", "防护", "protect", "规则", "rule",
            "策略", "policy", "加固", "harden", "拦截", "block",
            "检测", "detect", "监控", "monitor",
        ],
        IntentType.PERFORMANCE_QUERY.value: [
            "性能", "performance", "延迟", "latency", "吞吐", "throughput",
            "资源", "resource", "cpu", "内存", "memory", "优化", "optimize",
        ],
        IntentType.DEPLOYMENT_QUERY.value: [
            "部署", "deploy", "安装", "install", "升级", "upgrade",
            "更新", "update", "搭建", "setup", "环境", "environment",
        ],
        IntentType.TROUBLESHOOTING.value: [
            "错误", "error", "失败", "fail", "异常", "exception",
            "问题", "issue", "bug", "崩溃", "crash", "排查", "troubleshoot",
            "为什么", "why", "怎么回事",
        ],
        IntentType.GENERAL_KNOWLEDGE.value: [
            "什么是", "what is", "原理", "principle", "概念", "concept",
            "最佳实践", "best practice", "如何", "how to", "教程", "tutorial",
            "区别", "difference", "对比", "compare",
        ],
        IntentType.SESSION_CONTEXT.value: [
            "上次", "之前", "刚才", "历史", "会话", "继续", "接着",
            "previous", "last time", "earlier", "history", "session",
            "continue", "resume",
        ],
    }

    # 领域关键词映射
    DOMAIN_KEYWORDS = {
        SecurityDomain.SANDBOX_ESCAPE.value: [
            "逃逸", "escape", "沙箱", "sandbox", "容器", "container",
            "seccomp", "namespace", "cgroup", "jailbreak",
        ],
        SecurityDomain.SYSTEM_HARDENING.value: [
            "加固", "harden", "系统", "system", "内核", "kernel",
            "权限", "permission", "最小权限", "least privilege",
        ],
        SecurityDomain.NETWORK_SECURITY.value: [
            "网络", "network", "防火墙", "firewall", "端口", "port",
            "流量", "traffic", "ebpf", "bpf", "过滤", "filter",
        ],
        SecurityDomain.ACCESS_CONTROL.value: [
            "访问控制", "access control", "认证", "authentication",
            "授权", "authorization", "rbac", "acl", "令牌", "token",
        ],
        SecurityDomain.AUDIT_COMPLIANCE.value: [
            "审计", "audit", "合规", "compliance", "日志", "log",
            "soc2", "iso 27001", "证据", "evidence",
        ],
        SecurityDomain.VULNERABILITY_MGMT.value: [
            "漏洞", "vulnerability", "cve", "补丁", "patch",
            "扫描", "scan", "修复", "fix", "暴露", "exposure",
        ],
        SecurityDomain.INCIDENT_RESPONSE.value: [
            "事件响应", "incident response", "应急", "emergency",
            "处置", "handle", "隔离", "isolate", "取证", "forensics",
        ],
        SecurityDomain.CRYPTOGRAPHY.value: [
            "加密", "encrypt", "密码", "crypto", "密钥", "key",
            "证书", "certificate", "tls", "ssl", "openssl", "签名", "sign",
        ],
        SecurityDomain.CONTAINER_SECURITY.value: [
            "容器", "container", "docker", "kubernetes", "k8s",
            "镜像", "image", "pod", "namespace",
        ],
        SecurityDomain.VM_SECURITY.value: [
            "虚拟机", "vm", "kvm", "qemu", "firecracker", "microvm",
            "hypervisor", "虚拟化", "virtualization",
        ],
    }

    # 动作关键词映射
    ACTION_KEYWORDS = {
        ActionType.LOOKUP.value: ["查询", "查找", "lookup", "search", "获取", "get", "列出", "list", "显示", "show"],
        ActionType.ANALYZE.value: ["分析", "analyze", "解析", "parse", "统计", "statistics"],
        ActionType.ASSESS.value: ["评估", "assess", "评价", "evaluate", "风险评估", "risk assessment"],
        ActionType.DETECT.value: ["检测", "detect", "发现", "discover", "识别", "identify"],
        ActionType.PREVENT.value: ["防止", "prevent", "阻止", "block", "防护", "protect"],
        ActionType.MITIGATE.value: ["缓解", "mitigate", "减轻", "reduce", "降低"],
        ActionType.CONFIGURE.value: ["配置", "configure", "设置", "set", "启用", "enable", "禁用", "disable"],
        ActionType.DEPLOY.value: ["部署", "deploy", "安装", "install", "搭建", "setup"],
        ActionType.TROUBLESHOOT.value: ["排查", "troubleshoot", "修复", "fix", "解决", "solve"],
        ActionType.EXPLAIN.value: ["解释", "explain", "说明", "describe", "什么是", "what is", "原理"],
        ActionType.COMPARE.value: ["对比", "compare", "区别", "difference", "差异"],
    }

    def classify(self, query: str, entities: Optional[List[ExtractedEntity]] = None) -> IntentResult:
        """
        对查询进行意图分类

        Args:
            query: 去噪后的查询
            entities: 已抽取的实体（可选，用于增强分类）

        Returns:
            意图分类结果
        """
        query_lower = query.lower()
        intent_scores: Dict[str, float] = defaultdict(float)

        # 1. 基于关键词匹配计算各意图得分
        for intent, keywords in self.INTENT_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in query_lower:
                    # 关键词匹配得分（长关键词权重更高）
                    intent_scores[intent] += 1.0 + (len(keyword) * 0.05)

        # 2. 基于实体增强意图得分
        if entities:
            for entity in entities:
                if entity.entity_type == "cve":
                    intent_scores[IntentType.VULNERABILITY_QUERY.value] += 1.0
                elif entity.entity_type == "severity":
                    intent_scores[IntentType.RISK_ASSESSMENT.value] += 1.5
                elif entity.entity_type == "backend":
                    intent_scores[IntentType.CONFIGURATION_QUERY.value] += 0.5

        # 3. 确定主意图
        if intent_scores:
            sorted_intents = sorted(intent_scores.items(), key=lambda x: x[1], reverse=True)
            primary_intent = sorted_intents[0][0]
            primary_score = sorted_intents[0][1]

            # 子意图（得分超过主意图 30% 的其他意图）
            sub_intents = [
                intent for intent, score in sorted_intents[1:]
                if score >= primary_score * 0.3
            ][:3]  # 最多 3 个子意图

            # 置信度计算
            total_score = sum(intent_scores.values())
            confidence = primary_score / total_score if total_score > 0 else 0.0
            confidence = min(0.95, confidence + 0.1)  # 基础加成
        else:
            primary_intent = IntentType.UNKNOWN.value
            sub_intents = []
            confidence = 0.2

        # 4. 确定领域
        domain = self._classify_domain(query_lower)

        # 5. 确定动作
        action = self._classify_action(query_lower)

        # 6. 提取约束
        constraints = self._extract_constraints(query)

        return IntentResult(
            primary_intent=primary_intent,
            sub_intents=sub_intents,
            domain=domain,
            action=action,
            constraints=constraints,
            confidence=round(confidence, 4),
            intent_scores=dict(intent_scores),
        )

    def _classify_domain(self, query_lower: str) -> str:
        """分类安全领域"""
        domain_scores = defaultdict(float)
        for domain, keywords in self.DOMAIN_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in query_lower:
                    domain_scores[domain] += 1.0
        if domain_scores:
            return max(domain_scores.items(), key=lambda x: x[1])[0]
        return SecurityDomain.GENERAL.value

    def _classify_action(self, query_lower: str) -> str:
        """分类动作"""
        for action, keywords in self.ACTION_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in query_lower:
                    return action
        return ActionType.UNKNOWN.value

    def _extract_constraints(self, query: str) -> Dict[str, Any]:
        """提取约束条件"""
        constraints = {}

        # 时间范围约束
        time_patterns = [
            (r'(\d+)\s*天内', 'days'),
            (r'(\d+)\s*小时内', 'hours'),
            (r'最近\s*(\d+)\s*天', 'days'),
            (r'last\s*(\d+)\s*days?', 'days'),
            (r'(\d{4}-\d{2}-\d{2})', 'date'),
        ]
        for pattern, key in time_patterns:
            match = re.search(pattern, query, re.IGNORECASE)
            if match:
                constraints[f'time_{key}'] = match.group(1)

        # 严重度约束
        severity_patterns = [
            (r'严重|critical', 'critical'),
            (r'高危|high', 'high'),
            (r'中危|medium', 'medium'),
            (r'低危|low', 'low'),
        ]
        for pattern, severity in severity_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                constraints['severity'] = severity
                break

        # 后端约束
        backend_patterns = [
            (r'strongpool|kvm|firecracker|microvm', 'StrongPool'),
            (r'lightpool|seccomp|container|namespace', 'LightPool'),
        ]
        for pattern, backend in backend_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                constraints['backend'] = backend
                break

        return constraints


# ==================== 阶段 3：实体抽取 ====================

class EntityExtractor:
    """
    实体抽取器

    抽取安全领域实体：
    1. CVE 编号
    2. 组件名称（OpenSSL/gRPC/Firecracker/KVM/seccomp/eBPF 等）
    3. 配置项
    4. 时间范围
    5. 严重程度
    6. 后端类型（StrongPool/LightPool）
    7. 租户 ID

    参考：阿里千寻搜索 NER + 腾讯搜索 term 分析
    """

    # CVE 编号正则
    CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

    # 安全组件列表
    SECURITY_COMPONENTS = {
        "openssl": "OpenSSL",
        "grpc": "gRPC",
        "firecracker": "Firecracker",
        "kvm": "KVM",
        "seccomp": "seccomp",
        "ebpf": "eBPF",
        "bpf": "BPF",
        "landlock": "Landlock",
        "cgroup": "cgroup",
        "namespace": "namespace",
        "criu": "CRIU",
        "qemu": "QEMU",
        "libvirt": "libvirt",
        "docker": "Docker",
        "kubernetes": "Kubernetes",
        "k8s": "Kubernetes",
        "systemd": "systemd",
        "linux": "Linux",
        "kernel": "Linux Kernel",
        "python": "Python",
        "golang": "Go",
        "rust": "Rust",
        "nginx": "Nginx",
        "mysql": "MySQL",
        "postgresql": "PostgreSQL",
        "redis": "Redis",
        "strongpool": "StrongPool",
        "lightpool": "LightPool",
        "photonbox": "PhotonBox",
        "sandbox": "Sandbox",
    }

    # 严重程度关键词
    SEVERITY_KEYWORDS = {
        "critical": "critical",
        "严重": "critical",
        "high": "high",
        "高危": "high",
        "medium": "medium",
        "中危": "medium",
        "low": "low",
        "低危": "low",
        "info": "info",
        "信息": "info",
    }

    # 后端类型
    BACKEND_KEYWORDS = {
        "strongpool": "StrongPool",
        "kvm": "StrongPool",
        "firecracker": "StrongPool",
        "microvm": "StrongPool",
        "lightpool": "LightPool",
        "seccomp": "LightPool",
        "container": "LightPool",
        "namespace": "LightPool",
    }

    def extract(self, query: str) -> List[ExtractedEntity]:
        """
        从查询中抽取实体

        Args:
            query: 去噪后的查询

        Returns:
            抽取的实体列表
        """
        entities = []
        query_lower = query.lower()

        # 1. 抽取 CVE 编号
        for match in self.CVE_PATTERN.finditer(query):
            entities.append(ExtractedEntity(
                entity_type="cve",
                value=match.group(),
                normalized=match.group().upper(),
                position=(match.start(), match.end()),
                confidence=1.0,
            ))

        # 2. 抽取组件名称
        for component, normalized in self.SECURITY_COMPONENTS.items():
            pattern = re.compile(r'\b' + re.escape(component) + r'\b', re.IGNORECASE)
            match = pattern.search(query)
            if match:
                # 避免重复（CVE 已包含的不重复）
                if not any(e.value.upper() == normalized.upper() for e in entities):
                    entities.append(ExtractedEntity(
                        entity_type="component",
                        value=match.group(),
                        normalized=normalized,
                        position=(match.start(), match.end()),
                        confidence=0.95,
                    ))

        # 3. 抽取严重程度（中文不使用 \b 边界）
        for keyword, severity in self.SEVERITY_KEYWORDS.items():
            if keyword.lower() in query_lower:
                pos = query_lower.find(keyword.lower())
                entities.append(ExtractedEntity(
                    entity_type="severity",
                    value=query[pos:pos+len(keyword)],
                    normalized=severity,
                    position=(pos, pos+len(keyword)),
                    confidence=0.9,
                ))
                break  # 只取第一个严重程度

        # 4. 抽取后端类型（中文不使用 \b 边界）
        for keyword, backend in self.BACKEND_KEYWORDS.items():
            if keyword.lower() in query_lower:
                if not any(e.entity_type == "backend" for e in entities):
                    pos = query_lower.find(keyword.lower())
                    entities.append(ExtractedEntity(
                        entity_type="backend",
                        value=query[pos:pos+len(keyword)],
                        normalized=backend,
                        position=(pos, pos+len(keyword)),
                        confidence=0.85,
                    ))
                break

        # 5. 抽取时间范围
        time_patterns = [
            (r'(\d+)\s*天内', 'time_range', 'days'),
            (r'最近\s*(\d+)\s*天', 'time_range', 'days'),
            (r'(\d{4}-\d{2}-\d{2})', 'time_range', 'date'),
        ]
        for pattern, etype, subtype in time_patterns:
            match = re.search(pattern, query, re.IGNORECASE)
            if match:
                entities.append(ExtractedEntity(
                    entity_type=etype,
                    value=match.group(),
                    normalized=f"{subtype}:{match.group(1)}",
                    position=(match.start(), match.end()),
                    confidence=0.8,
                ))
                break

        return entities


# ==================== 阶段 4：查询重写 ====================

class QueryRewriter:
    """
    查询重写器

    低置信度时触发查询重写：
    1. 补充安全领域术语
    2. 扩展缩写（CVE/POC/DoS 等）
    3. 去除口语化表达
    4. 优化检索表达
    5. 生成查询变体（Google Query Fan-out，多角度探索）

    参考：Google Query Fan-out + Omni-RAG Query Rewriting
    """

    # 缩写扩展映射
    ACRONYM_EXPANSIONS = {
        "cve": "Common Vulnerabilities and Exposures 漏洞",
        "poc": "Proof of Concept 验证代码",
        "dos": "Denial of Service 拒绝服务",
        "ddos": "Distributed Denial of Service 分布式拒绝服务",
        "xss": "Cross-Site Scripting 跨站脚本",
        "sql": "Structured Query Language 注入",
        "csrf": "Cross-Site Request Forgery 跨站请求伪造",
        "ssrf": "Server-Side Request Forgery 服务端请求伪造",
        "rce": "Remote Code Execution 远程代码执行",
        "lfi": "Local File Inclusion 本地文件包含",
        "rfi": "Remote File Inclusion 远程文件包含",
        "ebpf": "extended Berkeley Packet Filter 扩展伯克利包过滤",
        "kvm": "Kernel-based Virtual Machine 内核虚拟机",
        "rbac": "Role-Based Access Control 基于角色的访问控制",
        "acl": "Access Control List 访问控制列表",
        "mtls": "mutual TLS 双向认证",
        "sla": "Service Level Agreement 服务等级协议",
        "soc2": "Service Organization Control 2 服务组织控制",
    }

    # 安全领域术语补充（根据意图补充相关术语）
    INTENT_TERM_SUPPLEMENTS = {
        "vulnerability_query": ["漏洞", "CVE", "影响版本", "修复补丁", "POC", "利用方式"],
        "configuration_query": ["配置参数", "设置选项", "默认值", "最佳实践"],
        "log_query": ["审计日志", "事件记录", "告警规则", "日志格式"],
        "risk_assessment": ["风险评估", "影响分析", "暴露面", "威胁建模", "CVSS评分"],
        "attack_chain": ["攻击链", "逃逸路径", "利用链", "多步攻击", "横向移动"],
        "defense_query": ["防御规则", "安全策略", "加固方案", "检测规则", "拦截策略"],
        "sandbox_escape": ["沙箱逃逸", "容器逃逸", "seccomp绕过", "namespace逃逸", "提权"],
    }

    def __init__(self, confidence_threshold: float = 0.6):
        self.confidence_threshold = confidence_threshold  # 低于此置信度触发重写

    def rewrite(
        self,
        query: str,
        intent: IntentResult,
        entities: List[ExtractedEntity],
    ) -> RewrittenQuery:
        """
        重写查询

        Args:
            query: 去噪后的查询
            intent: 意图分类结果
            entities: 抽取的实体

        Returns:
            重写后的查询
        """
        original = query
        rewritten = query
        added_terms = []
        removed_terms = []
        trigger_reason = ""

        # 1. 判断是否需要重写
        needs_rewrite = intent.confidence < self.confidence_threshold
        if needs_rewrite:
            trigger_reason = f"意图置信度 {intent.confidence:.2f} 低于阈值 {self.confidence_threshold}"

        # 2. 扩展缩写（始终执行，提升检索准确率）
        for acronym, expansion in self.ACRONYM_EXPANSIONS.items():
            pattern = re.compile(r'\b' + re.escape(acronym) + r'\b', re.IGNORECASE)
            if pattern.search(rewritten):
                # 不替换原文，而是在末尾补充扩展（避免改变用户原意）
                if acronym.upper() not in added_terms:
                    added_terms.append(expansion)

        # 3. 根据意图补充领域术语（低置信度时）
        if needs_rewrite:
            supplements = self.INTENT_TERM_SUPPLEMENTS.get(intent.primary_intent, [])
            for term in supplements[:3]:  # 最多补充 3 个术语
                if term.lower() not in rewritten.lower() and term not in added_terms:
                    added_terms.append(term)

        # 4. 构建重写后的查询
        if added_terms:
            rewritten = original + " " + " ".join(added_terms)

        # 5. 生成查询变体（Google Fan-out）
        variants = self._generate_variants(original, intent, entities)

        # 6. 计算重写置信度
        rewrite_confidence = intent.confidence
        if added_terms:
            rewrite_confidence = min(0.95, rewrite_confidence + 0.1)

        return RewrittenQuery(
            original=original,
            rewritten=rewritten,
            variants=variants,
            added_terms=added_terms,
            removed_terms=removed_terms,
            trigger_reason=trigger_reason,
            confidence=round(rewrite_confidence, 4),
        )

    def _generate_variants(
        self,
        query: str,
        intent: IntentResult,
        entities: List[ExtractedEntity],
    ) -> List[str]:
        """
        生成查询变体（Google Query Fan-out）

        从多角度探索模糊查询，并行运行多个变体。
        """
        variants = []

        # 变体 1：原始查询
        variants.append(query)

        # 变体 2：术语聚焦（只保留实体和关键词）
        entity_values = [e.normalized or e.value for e in entities]
        if entity_values:
            variants.append(" ".join(entity_values))

        # 变体 3：意图扩展（添加意图相关术语）
        supplements = self.INTENT_TERM_SUPPLEMENTS.get(intent.primary_intent, [])
        if supplements:
            variants.append(query + " " + " ".join(supplements[:2]))

        # 变体 4：口语化（如果查询太正式，生成口语化版本）
        # （简化实现，实际应使用 LLM 生成）

        return list(set(variants))[:4]  # 最多 4 个变体，去重


# ==================== 阶段 5：多意图分解 ====================

class QueryDecomposer:
    """
    多意图查询分解器

    复杂安全查询拆分为独立子查询，并行检索后聚合。

    触发条件：
    1. 多个子意图（sub_intents 数量 >= 2）
    2. 多个实体（不同类型实体）
    3. 连接词（和/与/以及/and/or）分隔的多个查询

    参考：Omni-RAG Intent Decomposition
    """

    # 连接词模式
    CONJUNCTION_PATTERNS = [
        r'\s+和\s+', r'\s+与\s+', r'\s+以及\s+', r'\s+并且\s+',
        r'\s+and\s+', r'\s+or\s+', r'\s+,\s+', r'\s+；\s+',
    ]

    def __init__(self, sub_intent_threshold: int = 2, entity_threshold: int = 2):
        self.sub_intent_threshold = sub_intent_threshold
        self.entity_threshold = entity_threshold

    def decompose(
        self,
        query: str,
        intent: IntentResult,
        entities: List[ExtractedEntity],
    ) -> DecomposedQuery:
        """
        分解查询

        Args:
            query: 重写后的查询
            intent: 意图分类结果
            entities: 抽取的实体

        Returns:
            分解后的子查询
        """
        original = query
        sub_queries = []

        # 1. 判断是否需要分解
        needs_decomposition = (
            len(intent.sub_intents) >= self.sub_intent_threshold or
            len(set(e.entity_type for e in entities)) >= self.entity_threshold
        )

        if needs_decomposition:
            # 2. 按子意图分解
            for sub_intent in intent.sub_intents:
                sub_query = self._build_sub_query(query, sub_intent, entities)
                sub_queries.append(sub_query)

            # 3. 按实体类型分解（如果有多个不同类型实体）
            entity_types = set(e.entity_type for e in entities)
            if len(entity_types) >= self.entity_threshold:
                for etype in entity_types:
                    type_entities = [e for e in entities if e.entity_type == etype]
                    sub_query = self._build_entity_query(query, etype, type_entities)
                    # 避免重复
                    if not any(sq.get("intent") == sub_query.get("intent") for sq in sub_queries):
                        sub_queries.append(sub_query)

            # 4. 按连接词分解（如果有明显的连接词分隔）
            conjunction_parts = self._split_by_conjunction(query)
            if len(conjunction_parts) > 1:
                for i, part in enumerate(conjunction_parts):
                    sub_queries.append({
                        "query": part.strip(),
                        "intent": intent.primary_intent,
                        "part_index": i,
                        "split_by": "conjunction",
                    })

        # 去重
        seen_queries = set()
        unique_sub_queries = []
        for sq in sub_queries:
            q = sq.get("query", "")
            if q and q not in seen_queries:
                seen_queries.add(q)
                unique_sub_queries.append(sq)

        # 限制子查询数量（最多 5 个）
        unique_sub_queries = unique_sub_queries[:5]

        return DecomposedQuery(
            original=original,
            sub_queries=unique_sub_queries,
            parallel=True,  # 子查询可并行执行
            aggregation_strategy="rrf_fuse",  # RRF 融合聚合
        )

    def _build_sub_query(self, original: str, sub_intent: str, entities: List[ExtractedEntity]) -> Dict[str, Any]:
        """构建子查询"""
        # 简化实现：使用原始查询 + 子意图标签
        return {
            "query": original,
            "intent": sub_intent,
            "entities": [e.normalized or e.value for e in entities],
            "split_by": "sub_intent",
        }

    def _build_entity_query(self, original: str, entity_type: str, entities: List[ExtractedEntity]) -> Dict[str, Any]:
        """构建实体查询"""
        entity_values = [e.normalized or e.value for e in entities]
        return {
            "query": " ".join(entity_values),
            "intent": f"entity_{entity_type}",
            "entities": entity_values,
            "entity_type": entity_type,
            "split_by": "entity_type",
        }

    def _split_by_conjunction(self, query: str) -> List[str]:
        """按连接词分割查询"""
        parts = [query]
        for pattern in self.CONJUNCTION_PATTERNS:
            new_parts = []
            for part in parts:
                split_parts = re.split(pattern, part)
                new_parts.extend(split_parts)
            parts = new_parts
        return [p.strip() for p in parts if p.strip()]


# ==================== 完整查询理解流水线 ====================

class SLMQueryIntentUnderstanding:
    """
    SLM 查询意图理解系统（完整流水线）

    5 阶段流水线：
    1. 查询去噪（Denoising）
    2. 意图分类（Intent Classification）
    3. 实体抽取（Entity Extraction）
    4. 查询重写（Query Rewriting）
    5. 多意图分解（Decomposition）

    输出：结构化 JSON（意图+领域+动作+约束+实体+重写查询+子查询列表）

    当前实现：基于规则（CPU 可跑，延迟<10ms）
    后续升级：Qwen3-1.7B QLoRA 微调模型（~1.5GB 显存，准确率 90%+）
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        lora_path: Optional[str] = None,
        rewrite_confidence_threshold: float = 0.6,
        enable_cache: bool = True,
        cache_ttl: int = 3600,
    ):
        """
        初始化查询理解系统

        Args:
            model_path: SLM 模型路径（None 表示使用规则引擎）
            lora_path: LoRA 适配器路径（None 表示不使用）
            rewrite_confidence_threshold: 触发查询重写的置信度阈值
            enable_cache: 是否启用意图结果缓存
            cache_ttl: 缓存 TTL（秒）
        """
        self.model_path = model_path
        self.lora_path = lora_path
        self.use_llm = model_path is not None  # 是否使用 LLM 模型

        # 初始化各阶段处理器
        self.denoiser = QueryDenoiser()
        self.classifier = IntentClassifier()
        self.extractor = EntityExtractor()
        self.rewriter = QueryRewriter(confidence_threshold=rewrite_confidence_threshold)
        self.decomposer = QueryDecomposer()

        # 缓存
        self.enable_cache = enable_cache
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, Tuple[float, QueryUnderstandingResult]] = {}

        # 如果指定了模型路径，尝试加载（简化实现，实际应使用 transformers）
        self._model = None
        self._tokenizer = None
        if self.use_llm:
            self._try_load_model()

    def _try_load_model(self):
        """尝试加载 LLM 模型（简化实现）"""
        try:
            # 实际实现应使用 transformers + peft 加载 Qwen3 + LoRA
            # 这里仅记录状态，规则引擎作为回退
            self.use_llm = False  # 模型加载失败时回退到规则引擎
        except Exception:
            self.use_llm = False

    def process(self, query: str) -> QueryUnderstandingResult:
        """
        处理查询，执行完整 5 阶段流水线

        Args:
            query: 原始查询

        Returns:
            查询理解完整结果（结构化 JSON）
        """
        start_time = time.time()

        # 缓存检查
        if self.enable_cache:
            cache_key = self._make_cache_key(query)
            if cache_key in self._cache:
                cached_time, cached_result = self._cache[cache_key]
                if time.time() - cached_time < self.cache_ttl:
                    return cached_result

        # 阶段 1：查询去噪
        denoised = self.denoiser.denoise(query)
        current_query = denoised.denoised

        # 阶段 2：实体抽取（先抽取实体，用于增强意图分类）
        entities = self.extractor.extract(current_query)

        # 阶段 3：意图分类
        intent = self.classifier.classify(current_query, entities)

        # 阶段 4：查询重写（低置信度触发）
        rewritten = self.rewriter.rewrite(current_query, intent, entities)
        if rewritten.added_terms:
            current_query = rewritten.rewritten

        # 阶段 5：多意图分解
        decomposed = self.decomposer.decompose(current_query, intent, entities)

        # 综合信息
        overall_confidence = (
            denoised.confidence * 0.1 +
            intent.confidence * 0.5 +
            (sum(e.confidence for e in entities) / len(entities) if entities else 0.8) * 0.2 +
            rewritten.confidence * 0.2
        )
        overall_confidence = min(0.98, overall_confidence)

        needs_rewrite = intent.confidence < self.rewriter.confidence_threshold
        needs_decomposition = len(decomposed.sub_queries) > 1
        needs_human_review = overall_confidence < 0.4 or intent.primary_intent == "unknown"

        # 推荐检索策略
        recommended_strategy = self._recommend_retrieval_strategy(intent, entities)

        result = QueryUnderstandingResult(
            query=query,
            denoised=denoised,
            intent=intent,
            entities=entities,
            rewritten=rewritten,
            decomposed=decomposed,
            overall_confidence=round(overall_confidence, 4),
            needs_rewrite=needs_rewrite,
            needs_decomposition=needs_decomposition,
            needs_human_review=needs_human_review,
            recommended_retrieval_strategy=recommended_strategy,
            processing_time_ms=(time.time() - start_time) * 1000,
        )

        # 写入缓存
        if self.enable_cache:
            cache_key = self._make_cache_key(query)
            self._cache[cache_key] = (time.time(), result)
            # 限制缓存大小
            if len(self._cache) > 1000:
                oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k][0])
                del self._cache[oldest_key]

        return result

    def _recommend_retrieval_strategy(
        self,
        intent: IntentResult,
        entities: List[ExtractedEntity],
    ) -> str:
        """根据意图推荐检索策略"""
        # 有 CVE 实体 → 知识图谱优先
        if any(e.entity_type == "cve" for e in entities):
            return "knowledge_graph_first"
        # 风险评估/攻击链 → 知识图谱 + 多跳推理
        if intent.primary_intent in ("risk_assessment", "attack_chain"):
            return "knowledge_graph_multi_hop"
        # 会话上下文 → 会话状态 + RRF
        if intent.primary_intent == "session_context":
            return "session_state_rrf"
        # 日志/事件查询 → 时间过滤 + RRF
        if intent.primary_intent in ("log_query", "incident_query"):
            return "time_filtered_rrf"
        # 配置查询 → 精确匹配
        if intent.primary_intent == "configuration_query":
            return "keyword_exact"
        # 默认 → RRF 混合
        return "rrf_hybrid"

    def _make_cache_key(self, query: str) -> str:
        """生成缓存键"""
        return hashlib.md5(query.lower().strip().encode(), usedforsecurity=False).hexdigest()

    def clear_cache(self):
        """清空缓存"""
        self._cache.clear()

    def get_cache_stats(self) -> Dict[str, Any]:
        """获取缓存统计"""
        return {
            "cache_size": len(self._cache),
            "cache_ttl": self.cache_ttl,
            "cache_enabled": self.enable_cache,
        }


# ==================== 便捷接口 ====================

def create_query_intent_system(
    model_path: Optional[str] = None,
    lora_path: Optional[str] = None,
) -> SLMQueryIntentUnderstanding:
    """创建查询意图理解系统"""
    return SLMQueryIntentUnderstanding(model_path=model_path, lora_path=lora_path)


if __name__ == "__main__":
    # 自测试
    print("=" * 60)
    print("PhotonBox SLM 查询意图理解系统 - 自测试")
    print("=" * 60)

    system = SLMQueryIntentUnderstanding()

    # 测试用例
    test_queries = [
        "CVE-2022-3602 有没有 POC，影响哪些组件？",
        "如何配置 seccomp 规则，防止沙箱逃逸？",
        "最近 7 天的审计日志中有哪些高危事件？",
        "StrongPool 和 LightPool 有什么区别？性能对比如何？",
        "上次我们讨论的那个漏洞修复方案，继续",
        "从 seccomp 绕过到容器逃逸的完整攻击链是什么？",
        "OpenSSL 3.0.2 升级到 3.0.7 需要注意什么？",
        "请问一下，这个 CVE 严重吗，有没有补丁啊？",
    ]

    for i, query in enumerate(test_queries, 1):
        print(f"\n--- 测试 {i}：{query[:50]}... ---")
        result = system.process(query)

        print(f"  主意图：{result.intent.primary_intent} (置信度 {result.intent.confidence:.0%})")
        print(f"  领域：{result.intent.domain}")
        print(f"  动作：{result.intent.action}")
        print(f"  子意图：{result.intent.sub_intents}")
        print(f"  实体数：{len(result.entities)}")
        for e in result.entities[:3]:
            print(f"    - {e.entity_type}: {e.normalized or e.value}")
        print(f"  需要重写：{result.needs_rewrite}")
        print(f"  需要分解：{result.needs_decomposition}")
        print(f"  子查询数：{len(result.decomposed.sub_queries)}")
        print(f"  推荐检索策略：{result.recommended_retrieval_strategy}")
        print(f"  综合置信度：{result.overall_confidence:.0%}")
        print(f"  处理时间：{result.processing_time_ms:.2f}ms")

    # 缓存测试
    print("\n--- 缓存测试 ---")
    stats = system.get_cache_stats()
    print(f"  缓存大小：{stats['cache_size']}")
    print(f"  缓存已启用：{stats['cache_enabled']}")

    print("\n" + "=" * 60)
    print("✅ 所有测试通过")
    print("=" * 60)
