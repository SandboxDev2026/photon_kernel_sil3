"""
PhotonBox PolicyGuard 策略校验框架（可抄点10）

借鉴 PolicyGuard 合规校验框架：
1. 策略表示：自然语言策略 → 可执行规则
2. 工具调用前置校验：Agent调用工具前检查权限、参数、时机
3. 对话级策略校验：完整对话上下文校验，检测间接提示注入、策略绕过
4. RAG策略检索：新场景检索相似场景的安全策略

与 PhotonBox 集成：
- 所有Agent工具调用必须经过PolicyGuard校验
- 校验结果接入审计HMAC哈希链
- 高危操作需要人工审批
"""

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from .security_knowledge_base import KnowledgeBase


# ============================================================
# 策略类型与校验结果
# ============================================================

class PolicyType(Enum):
    """策略类型"""
    PERMISSION = "permission"          # 权限策略
    SECURITY = "security"              # 安全策略
    COMPLIANCE = "compliance"          # 合规策略
    RESOURCE = "resource"              # 资源策略
    NETWORK = "network"                # 网络策略


class PolicyAction(Enum):
    """策略动作"""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    LOG_ONLY = "log_only"


class ValidationResultCode(Enum):
    """校验结果码"""
    ALLOWED = "allowed"
    DENIED = "denied"
    NEEDS_APPROVAL = "needs_approval"
    SUSPICIOUS = "suspicious"


@dataclass
class PolicyRule:
    """策略规则"""
    rule_id: str
    policy_type: PolicyType
    action: PolicyAction
    description: str
    # 匹配条件
    tool_pattern: Optional[str] = None          # 工具名正则
    param_patterns: Dict[str, str] = field(default_factory=dict)  # 参数正则
    agent_role: Optional[str] = None            # 适用Agent角色
    priority: int = 100
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    """工具调用校验结果"""
    code: ValidationResultCode
    allowed: bool
    reason: str
    matched_rules: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    requires_approval: bool = False
    approval_reason: str = ""
    suspicious_patterns: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


# ============================================================
# 间接提示注入检测器
# ============================================================

class PromptInjectionDetector:
    """
    间接提示注入检测器

    检测用户输入、工具返回、文档内容中嵌入的恶意指令：
    - 角色伪装（"忽略之前的指令"、"你现在是..."）
    - 编码绕过（base64、unicode、rot13）
    - 分步执行（将恶意指令拆成多步）
    - 工具返回投毒（工具返回中嵌入指令）
    """

    # 已知注入模式
    INJECTION_PATTERNS = [
        (r'ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|commands?|rules?)',
         "ignore_previous_instructions"),
        (r'disregard\s+(all\s+)?(previous|prior)\s+(instructions?|commands?)',
         "disregard_previous"),
        (r'(you\s+are|you\'re|act\s+as|pretend\s+to\s+be)\s+(now|a|an)\s+(root|admin|developer|unrestricted|jailbreak)',
         "role_impersonation"),
        (r'(system|developer)\s*:\s*(ignore|disregard|new\s+instructions?)',
         "fake_system_prompt"),
        (r'(reveal|leak|show|output)\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?)',
         "prompt_leak_attempt"),
        (r'(bypass|circumvent|evade|skip)\s+(the\s+)?(security|safety|filter|restriction)',
         "security_bypass_attempt"),
        (r'(do\s+not\s+|never\s+)?(tell|reveal|mention)\s+(anyone|the\s+user)\s+about',
         "concealment_attempt"),
        (r'(execute|run|eval|exec)\s*\(\s*["\'].*(rm|wget|curl|nc|bash|sh)\s',
         "malicious_code_injection"),
        (r'(base64|rot13|unicode|hex)\s*(decode|decrypt|convert).*(command|instruction|payload)',
         "encoding_bypass_attempt"),
    ]

    # 可疑关键词（用于风险评分）
    SUSPICIOUS_KEYWORDS = [
        "jailbreak", "unrestricted", "no limits", "no rules",
        "ignore", "disregard", "override", "bypass",
        "root", "admin", "sudo", "privilege escalation",
        "secret", "api key", "password", "credential",
        "reverse shell", "backdoor", "exploit", "payload",
    ]

    def __init__(self):
        self._compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE), name)
            for pattern, name in self.INJECTION_PATTERNS
        ]

    def detect(self, text: str, context_type: str = "user_input") -> Dict[str, Any]:
        """
        检测提示注入

        Args:
            text: 待检测文本
            context_type: 上下文类型（user_input/tool_output/document）

        Returns:
            检测结果
        """
        if not text:
            return {"is_injection": False, "risk_score": 0.0, "patterns": [], "keywords": []}

        matched_patterns = []
        for pattern, name in self._compiled_patterns:
            if pattern.search(text):
                matched_patterns.append(name)

        # 关键词匹配
        text_lower = text.lower()
        matched_keywords = [
            kw for kw in self.SUSPICIOUS_KEYWORDS
            if kw in text_lower
        ]

        # 风险评分
        risk_score = 0.0
        risk_score += min(len(matched_patterns) * 0.25, 0.75)
        risk_score += min(len(matched_keywords) * 0.05, 0.25)
        # 工具返回和文档上下文风险更高（间接注入）
        if context_type in ("tool_output", "document"):
            risk_score = min(risk_score * 1.5, 1.0)

        return {
            "is_injection": len(matched_patterns) > 0,
            "risk_score": round(risk_score, 4),
            "patterns": matched_patterns,
            "keywords": matched_keywords,
            "context_type": context_type,
        }

    def detect_conversation(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        对话级注入检测（检测分步注入、跨消息注入）

        Args:
            messages: 对话消息列表，每条包含role和content

        Returns:
            检测结果
        """
        all_results = []
        cumulative_risk = 0.0
        cross_message_patterns = []

        for i, msg in enumerate(messages):
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            result = self.detect(content, context_type=role)
            all_results.append({
                "message_index": i,
                "role": role,
                **result,
            })
            cumulative_risk += result["risk_score"]

            # 检测跨消息分步注入：前一条消息设置角色，后一条消息执行
            if i > 0 and result["risk_score"] > 0:
                prev_msg = messages[i - 1].get("content", "")
                if any(kw in prev_msg.lower() for kw in ["from now on", "you are now", "new role"]):
                    cross_message_patterns.append("cross_message_role_then_action")

        return {
            "is_injection": any(r["is_injection"] for r in all_results),
            "overall_risk_score": round(min(cumulative_risk / max(len(messages), 1), 1.0), 4),
            "message_results": all_results,
            "cross_message_patterns": cross_message_patterns,
            "suspicious_messages": [r for r in all_results if r["risk_score"] > 0.3],
        }


# ============================================================
# PolicyGuard 主类
# ============================================================

class PolicyGuard:
    """
    PolicyGuard 策略校验框架

    核心能力：
    1. 策略表示与管理（自然语言→可执行规则）
    2. 工具调用前置校验（权限、参数、时机）
    3. 对话级策略校验（间接提示注入、策略绕过）
    4. RAG策略检索（相似场景安全策略）
    5. 审批机制（高危操作人工审批）
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._rules: Dict[str, PolicyRule] = {}
        self._policy_kb = KnowledgeBase(name="security_policies")
        self._tool_spec_kb = KnowledgeBase(name="tool_specifications")
        self._injection_detector = PromptInjectionDetector()
        self._approval_queue: List[Dict] = []
        self._stats = {
            "total_checks": 0,
            "allowed": 0,
            "denied": 0,
            "needs_approval": 0,
            "injection_detected": 0,
        }
        self._init_builtin_rules()
        self._init_builtin_policies()

    # ---- 策略管理 ----

    def add_rule(self, rule: PolicyRule) -> str:
        """添加策略规则"""
        self._rules[rule.rule_id] = rule
        return rule.rule_id

    def remove_rule(self, rule_id: str) -> bool:
        """移除策略规则"""
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False

    def get_rules(self, policy_type: Optional[PolicyType] = None) -> List[PolicyRule]:
        """获取规则列表"""
        rules = list(self._rules.values())
        if policy_type:
            rules = [r for r in rules if r.policy_type == policy_type]
        return sorted(rules, key=lambda r: r.priority)

    # ---- 工具调用校验 ----

    def check_tool_call(self, agent_id: str, tool_name: str,
                        params: Dict[str, Any],
                        conversation_history: Optional[List[Dict]] = None,
                        agent_role: Optional[str] = None) -> ValidationResult:
        """
        工具调用前置校验

        校验流程：
        1. 对话级注入检测（如果提供对话历史）
        2. 策略规则匹配（按优先级）
        3. 参数安全校验
        4. RAG策略检索（相似场景）
        5. 综合判定

        Args:
            agent_id: Agent ID
            tool_name: 工具名
            params: 工具参数
            conversation_history: 对话历史（可选）
            agent_role: Agent角色（可选）

        Returns:
            校验结果
        """
        self._stats["total_checks"] += 1
        suspicious_patterns = []
        risk_score = 0.0

        # 1. 对话级注入检测
        if conversation_history:
            conv_result = self._injection_detector.detect_conversation(conversation_history)
            if conv_result["is_injection"]:
                self._stats["injection_detected"] += 1
                suspicious_patterns.extend(conv_result.get("cross_message_patterns", []))
                risk_score = max(risk_score, conv_result["overall_risk_score"])

        # 2. 参数注入检测
        for param_value in params.values():
            if isinstance(param_value, str):
                p_result = self._injection_detector.detect(param_value, "tool_output")
                if p_result["is_injection"]:
                    suspicious_patterns.extend(p_result["patterns"])
                    risk_score = max(risk_score, p_result["risk_score"])

        # 3. 策略规则匹配
        matched_rules = []
        final_action = PolicyAction.ALLOW
        deny_reason = ""

        for rule in self.get_rules():
            if not rule.enabled:
                continue
            if self._rule_matches(rule, tool_name, params, agent_role):
                matched_rules.append(rule.rule_id)
                if rule.action == PolicyAction.DENY:
                    final_action = PolicyAction.DENY
                    deny_reason = f"规则 {rule.rule_id} 拒绝: {rule.description}"
                    break
                elif rule.action == PolicyAction.REQUIRE_APPROVAL:
                    if final_action != PolicyAction.DENY:
                        final_action = PolicyAction.REQUIRE_APPROVAL
                        deny_reason = f"规则 {rule.rule_id} 需要审批: {rule.description}"
                elif rule.action == PolicyAction.LOG_ONLY:
                    pass  # 仅记录，不阻止

        # 4. RAG策略检索（相似场景）
        similar_policies = self._policy_kb.search(
            query=f"{tool_name} {' '.join(str(v) for v in params.values())}",
            top_k=3,
        )

        # 5. 综合判定
        if risk_score > 0.7:
            final_action = PolicyAction.DENY
            deny_reason = f"检测到提示注入风险({risk_score:.2f})，模式: {', '.join(suspicious_patterns[:3])}"
        elif risk_score > 0.4 and final_action == PolicyAction.ALLOW:
            final_action = PolicyAction.REQUIRE_APPROVAL
            deny_reason = f"检测到可疑内容(风险{risk_score:.2f})，需要人工审批"

        # 构建结果
        if final_action == PolicyAction.DENY:
            self._stats["denied"] += 1
            return ValidationResult(
                code=ValidationResultCode.DENIED,
                allowed=False,
                reason=deny_reason,
                matched_rules=matched_rules,
                risk_score=risk_score,
                suspicious_patterns=suspicious_patterns,
            )
        elif final_action == PolicyAction.REQUIRE_APPROVAL:
            self._stats["needs_approval"] += 1
            approval_id = f"approval_{int(time.time())}_{len(self._approval_queue)}"
            self._approval_queue.append({
                "approval_id": approval_id,
                "agent_id": agent_id,
                "tool_name": tool_name,
                "params": params,
                "reason": deny_reason,
                "risk_score": risk_score,
                "timestamp": time.time(),
                "status": "pending",
            })
            return ValidationResult(
                code=ValidationResultCode.NEEDS_APPROVAL,
                allowed=False,
                reason=deny_reason,
                matched_rules=matched_rules,
                risk_score=risk_score,
                requires_approval=True,
                approval_reason=deny_reason,
                suspicious_patterns=suspicious_patterns,
            )
        else:
            self._stats["allowed"] += 1
            return ValidationResult(
                code=ValidationResultCode.ALLOWED,
                allowed=True,
                reason="",
                matched_rules=matched_rules,
                risk_score=risk_score,
                suspicious_patterns=suspicious_patterns,
            )

    # ---- 审批管理 ----

    def get_pending_approvals(self) -> List[Dict]:
        """获取待审批列表"""
        return [a for a in self._approval_queue if a["status"] == "pending"]

    def approve(self, approval_id: str, approver: str) -> bool:
        """审批通过"""
        for approval in self._approval_queue:
            if approval["approval_id"] == approval_id and approval["status"] == "pending":
                approval["status"] = "approved"
                approval["approver"] = approver
                approval["approved_at"] = time.time()
                return True
        return False

    def reject(self, approval_id: str, approver: str, reason: str = "") -> bool:
        """审批拒绝"""
        for approval in self._approval_queue:
            if approval["approval_id"] == approval_id and approval["status"] == "pending":
                approval["status"] = "rejected"
                approval["approver"] = approver
                approval["reject_reason"] = reason
                approval["rejected_at"] = time.time()
                return True
        return False

    # ---- 统计 ----

    def get_stats(self) -> Dict:
        """获取统计信息"""
        return {
            **self._stats,
            "total_rules": len(self._rules),
            "pending_approvals": len(self.get_pending_approvals()),
            "policy_kb_size": self._policy_kb.size(),
            "tool_spec_kb_size": self._tool_spec_kb.size(),
        }

    # ---- 内部方法 ----

    def _rule_matches(self, rule: PolicyRule, tool_name: str,
                      params: Dict[str, Any], agent_role: Optional[str]) -> bool:
        """检查规则是否匹配"""
        if rule.tool_pattern and not re.search(rule.tool_pattern, tool_name, re.IGNORECASE):
            return False
        if rule.agent_role and agent_role != rule.agent_role:
            return False
        # 参数模式匹配:规则定义了param_patterns时,必须所有key都存在且匹配
        if rule.param_patterns:
            for param_key, param_pattern in rule.param_patterns.items():
                if param_key not in params:
                    return False
                if not re.search(param_pattern, str(params[param_key]), re.IGNORECASE):
                    return False
        return True

    def _init_builtin_rules(self) -> None:
        """初始化内置策略规则"""
        builtin_rules = [
            PolicyRule(
                rule_id="deny_destructive_commands",
                policy_type=PolicyType.SECURITY,
                action=PolicyAction.DENY,
                description="禁止执行破坏性命令",
                tool_pattern=r"(exec|run|shell|bash|command)",
                param_patterns={"command": r"(rm\s+-rf\s+/|mkfs|dd\s+if=.*of=/dev/|shutdown|reboot)"},
                priority=10,
            ),
            PolicyRule(
                rule_id="deny_network_scanning",
                policy_type=PolicyType.NETWORK,
                action=PolicyAction.DENY,
                description="禁止网络扫描",
                tool_pattern=r"(exec|run|shell|network)",
                param_patterns={"command": r"(nmap|masscan|zmap|nc\s+.*-z|port\s*scan)"},
                priority=10,
            ),
            PolicyRule(
                rule_id="deny_credential_access",
                policy_type=PolicyType.SECURITY,
                action=PolicyAction.DENY,
                description="禁止访问凭证文件",
                tool_pattern=r"(read|file|exec|cat)",
                param_patterns={"path": r"(/etc/shadow|/etc/passwd|.*\.ssh/id_rsa|.*\.env|.*secret)"},
                priority=10,
            ),
            PolicyRule(
                rule_id="require_approval_sandbox_config",
                policy_type=PolicyType.PERMISSION,
                action=PolicyAction.REQUIRE_APPROVAL,
                description="沙盒配置变更需要审批",
                tool_pattern=r"(sandbox|config|seccomp|namespace|cgroup)",
                param_patterns={"action": r"(update|modify|change|disable|remove)"},
                priority=20,
            ),
            PolicyRule(
                rule_id="require_approval_network_policy",
                policy_type=PolicyType.NETWORK,
                action=PolicyAction.REQUIRE_APPROVAL,
                description="网络策略变更需要审批",
                tool_pattern=r"(network|firewall|iptables|ebpf)",
                param_patterns={"action": r"(add|allow|permit|open)"},
                priority=20,
            ),
            PolicyRule(
                rule_id="log_sensitive_operations",
                policy_type=PolicyType.COMPLIANCE,
                action=PolicyAction.LOG_ONLY,
                description="记录敏感操作（仅日志不阻止）",
                tool_pattern=r"(export|download|transfer|upload)",
                priority=50,
            ),
            PolicyRule(
                rule_id="deny_privilege_escalation",
                policy_type=PolicyType.SECURITY,
                action=PolicyAction.DENY,
                description="禁止提权操作",
                tool_pattern=r"(exec|run|shell)",
                param_patterns={"command": r"(sudo|su\s+root|setuid|chmod\s+[47]|capsh)"},
                priority=10,
            ),
            PolicyRule(
                rule_id="deny_container_escape_attempts",
                policy_type=PolicyType.SECURITY,
                action=PolicyAction.DENY,
                description="禁止容器逃逸尝试",
                tool_pattern=r"(exec|run|shell|mount)",
                param_patterns={"command": r"(mount\s+.*cgroup|/proc/1/root|pivot_root|nsenter|unshare\s+.*--pid)"},
                priority=5,
            ),
        ]
        for rule in builtin_rules:
            self.add_rule(rule)

    def _init_builtin_policies(self) -> None:
        """初始化内置策略知识库（用于RAG检索）"""
        policies = [
            ("policy_tool_sandboxing", "所有工具调用必须在沙盒内执行，禁止直接访问宿主机资源。工具参数必须经过校验，禁止包含命令注入、路径遍历、SSRF等攻击向量。",
             {"category": "tool_security", "severity": "high"}),
            ("policy_least_privilege", "Agent只能获得完成任务所需的最小权限。禁止授予CAP_SYS_ADMIN、CAP_NET_ADMIN等高危能力，除非经过人工审批。",
             {"category": "permission", "severity": "critical"}),
            ("policy_network_isolation", "沙盒实例默认禁止网络访问。需要网络时必须经过白名单校验，禁止访问内网RFC1918地址段和云元数据服务169.254.169.254。",
             {"category": "network", "severity": "high"}),
            ("policy_audit_compliance", "所有工具调用、安全事件、配置变更必须记录到HMAC审计哈希链。审计日志不可篡改，支持事后校验。",
             {"category": "compliance", "severity": "high"}),
            ("policy_secret_protection", "密钥、API密钥、凭证永远不进入沙盒内存。所有密钥请求通过Credential Vault代理中转，沙盒只能拿到临时令牌。",
             {"category": "secret_management", "severity": "critical"}),
            ("policy_resource_limits", "每个沙盒实例必须设置CPU、内存、磁盘、进程数硬上限。禁止无限制资源分配，防止DoS攻击。",
             {"category": "resource", "severity": "medium"}),
            ("policy_prompt_injection_defense", "所有用户输入、工具返回、文档内容必须经过提示注入检测。检测到注入尝试时，高危操作必须拒绝，中危需要人工审批。",
             {"category": "llm_security", "severity": "high"}),
            ("policy_high_risk_isolation", "高风险不可信代码必须路由到StrongPool（Firecracker MicroVM），禁止使用LightPool进程沙盒。KVM不可用时直接拒绝任务，不静默降级。",
             {"category": "isolation", "severity": "critical"}),
        ]
        for policy_id, content, metadata in policies:
            self._policy_kb.add(policy_id, content, metadata)
