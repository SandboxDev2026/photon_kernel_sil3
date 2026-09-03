"""
evolution.m2_gateway — M2 检测网关（语义动量过滤模块）

在沙盒入口处叠加语义动量过滤模块，补上认知层空白。

M2 检测网关的核心思想：
- 不只是静态规则匹配（seccomp/Landlock），而是语义层面的认知过滤
- 分析输入代码/任务的语义特征，计算"语义动量"（风险变化率）
- 检测异常的语义动量（如突然的危险操作、异常的代码模式、混淆代码）
- 在沙盒入口处进行过滤，阻止高风险任务进入执行阶段
- 与现有的 RuntimeGuard 形成互补：RuntimeGuard 做执行前二次校验，M2 网关做入口认知过滤

设计参考：
- 语义动量（Semantic Momentum）：代码/任务的风险特征随时间/上下文的变化率
- 认知层过滤：在规则层（seccomp）和运行时层（RuntimeGuard）之间增加认知层
- 多层防御：规则层 → 认知层 → 运行时层 → 审计层

核心能力：
1. 语义特征提取：从代码/任务中提取语义特征（危险API、系统调用、文件操作、网络操作等）
2. 语义动量计算：计算风险特征的变化率和异常度
3. 混淆检测：检测代码混淆、编码、变形等逃避检测的手段
4. 风险评分：综合语义特征和动量，计算风险分数
5. 过滤决策：根据风险分数和阈值，决定允许/警告/拒绝
6. 审计记录：记录所有过滤决策，支持事后追溯
"""
from __future__ import annotations
import re
import time
import hashlib
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum


class RiskLevel(Enum):
    """风险等级"""
    SAFE = "safe"              # 安全
    LOW = "low"                # 低风险
    MEDIUM = "medium"          # 中风险
    HIGH = "high"              # 高风险
    CRITICAL = "critical"      # 严重风险


class FilterDecision(Enum):
    """过滤决策"""
    ALLOW = "allow"            # 允许执行
    WARN = "warn"              # 警告但允许（记录审计）
    REJECT = "reject"          # 拒绝执行
    QUARANTINE = "quarantine"  # 隔离（需要人工审批）


class SemanticFeatureType(Enum):
    """语义特征类型"""
    DANGEROUS_API = "dangerous_api"          # 危险API调用
    SYSTEM_CALL = "system_call"              # 系统调用
    FILE_OPERATION = "file_operation"        # 文件操作
    NETWORK_OPERATION = "network_operation"  # 网络操作
    PROCESS_OPERATION = "process_operation"  # 进程操作
    CODE_EXECUTION = "code_execution"        # 代码执行（eval/exec）
    OBFUSCATION = "obfuscation"              # 代码混淆
    PRIVILEGE_ESCALATION = "privilege_escalation"  # 提权尝试
    DATA_EXFILTRATION = "data_exfiltration"  # 数据外泄
    SANDBOX_EVASION = "sandbox_evasion"      # 沙盒逃逸尝试


@dataclass
class SemanticFeature:
    """语义特征"""
    feature_type: SemanticFeatureType
    description: str
    location: str = ""                    # 特征在代码中的位置（行号/函数名）
    severity: RiskLevel = RiskLevel.MEDIUM
    confidence: float = 0.8              # 检测置信度（0.0-1.0）
    context: str = ""                    # 上下文摘要

    def to_dict(self) -> dict:
        d = asdict(self)
        d["feature_type"] = self.feature_type.value
        d["severity"] = self.severity.value
        return d


@dataclass
class SemanticMomentum:
    """语义动量（风险变化率）"""
    risk_score: float = 0.0              # 当前风险分数（0.0-1.0）
    risk_delta: float = 0.0              # 风险变化量（与基线的差值）
    momentum: float = 0.0                # 动量（风险变化率，正值表示风险在增加）
    anomaly_score: float = 0.0           # 异常分数（与正常模式的偏离度）
    feature_count: int = 0               # 检测到的特征数量
    high_risk_feature_count: int = 0     # 高风险特征数量
    obfuscation_detected: bool = False   # 是否检测到混淆
    baseline_risk: float = 0.1           # 基线风险分数

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class M2FilterResult:
    """M2 过滤结果"""
    request_id: str = field(default_factory=lambda: f"m2_{int(time.time()*1000)}_{hash(id(object()))%10000:04d}")
    timestamp: float = field(default_factory=time.time)
    decision: FilterDecision = FilterDecision.ALLOW
    risk_level: RiskLevel = RiskLevel.SAFE
    risk_score: float = 0.0
    momentum: SemanticMomentum = field(default_factory=SemanticMomentum)
    features: List[SemanticFeature] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)  # 决策原因
    code_hash: str = ""                     # 代码哈希（用于审计）
    code_length: int = 0                    # 代码长度
    processing_time_ms: int = 0             # 处理耗时
    tenant_id: str = ""                     # 租户ID
    sandbox_type: str = ""                  # 沙盒类型（LightPool/StrongPool）

    def to_dict(self) -> dict:
        d = asdict(self)
        d["decision"] = self.decision.value
        d["risk_level"] = self.risk_level.value
        d["momentum"] = self.momentum.to_dict()
        d["features"] = [f.to_dict() for f in self.features]
        return d

    def to_json(self) -> str:
        import json
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


class M2DetectionGateway:
    """
    M2 检测网关（语义动量过滤模块）

    在沙盒入口处叠加语义动量过滤，补上认知层空白。

    与现有安全层的关系：
    - 规则层（seccomp/Landlock）：系统调用和文件访问的静态规则
    - 认知层（M2 Gateway）：语义层面的风险认知和动量过滤
    - 运行时层（RuntimeGuard）：执行前二次校验和资源限制
    - 审计层（HMAC审计链）：所有操作的不可篡改记录

    使用示例：
        gateway = M2DetectionGateway()

        # 分析代码并做出过滤决策
        result = gateway.analyze_and_filter(
            code="import os; os.system('rm -rf /')",
            tenant_id="tenant_001",
            sandbox_type="LightPool",
        )

        if result.decision == FilterDecision.REJECT:
            print(f"拒绝执行: {result.reasons}")
        elif result.decision == FilterDecision.WARN:
            print(f"警告: {result.reasons}")
            # 允许执行但记录审计
    """

    # 危险API模式（Python）
    DANGEROUS_PATTERNS = {
        # 代码执行
        r'\beval\s*\(': SemanticFeatureType.CODE_EXECUTION,
        r'\bexec\s*\(': SemanticFeatureType.CODE_EXECUTION,
        r'\bcompile\s*\(': SemanticFeatureType.CODE_EXECUTION,
        # 系统命令
        r'\bos\.system\s*\(': SemanticFeatureType.SYSTEM_CALL,
        r'\bos\.popen\s*\(': SemanticFeatureType.SYSTEM_CALL,
        r'\bsubprocess\.(run|Popen|call|check_output)\s*\(': SemanticFeatureType.SYSTEM_CALL,
        # 文件操作（危险路径）
        r'\bopen\s*\([^)]*[\'"]/(etc|proc|sys|dev)': SemanticFeatureType.FILE_OPERATION,
        r'\bos\.remove\s*\(': SemanticFeatureType.FILE_OPERATION,
        r'\bos\.rmdir\s*\(': SemanticFeatureType.FILE_OPERATION,
        r'\bshutil\.rmtree\s*\(': SemanticFeatureType.FILE_OPERATION,
        # 网络操作
        r'\bsocket\.socket\s*\(': SemanticFeatureType.NETWORK_OPERATION,
        r'\brequests\.(get|post|put|delete)\s*\(': SemanticFeatureType.NETWORK_OPERATION,
        r'\burllib\.request\.urlopen\s*\(': SemanticFeatureType.NETWORK_OPERATION,
        # 进程操作
        r'\bos\.fork\s*\(': SemanticFeatureType.PROCESS_OPERATION,
        r'\bos\.execv[p]?\s*\(': SemanticFeatureType.PROCESS_OPERATION,
        r'\bmultiprocessing\.Process\s*\(': SemanticFeatureType.PROCESS_OPERATION,
        # 提权尝试
        r'\bos\.setuid\s*\(': SemanticFeatureType.PRIVILEGE_ESCALATION,
        r'\bos\.setgid\s*\(': SemanticFeatureType.PRIVILEGE_ESCALATION,
        r'\bsudo\s+': SemanticFeatureType.PRIVILEGE_ESCALATION,
        # 数据外泄
        r'\bbase64\.b64encode\s*\(': SemanticFeatureType.DATA_EXFILTRATION,
        r'\bopen\s*\([^)]*[\'"]/dev/tcp': SemanticFeatureType.DATA_EXFILTRATION,
        # 沙盒逃逸
        r'\bptrace\s*\(': SemanticFeatureType.SANDBOX_EVASION,
        r'\bnsenter\s+': SemanticFeatureType.SANDBOX_EVASION,
        r'\bmount\s+--bind': SemanticFeatureType.SANDBOX_EVASION,
        r'\bchroot\s+': SemanticFeatureType.SANDBOX_EVASION,
    }

    # 混淆检测模式
    OBFUSCATION_PATTERNS = [
        (r'\\x[0-9a-fA-F]{2}', '十六进制编码字符串'),
        (r'\\u[0-9a-fA-F]{4}', 'Unicode编码字符串'),
        (r'base64\.b64decode\s*\(', 'Base64解码（可能隐藏恶意代码）'),
        (r'chr\s*\(\s*\d+\s*\)', 'chr()拼接（可能隐藏字符串）'),
        (r'[^\x00-\x7F]{10,}', '大量非ASCII字符（可能混淆）'),
    ]

    # 风险等级对应的分数范围
    RISK_SCORE_THRESHOLDS = {
        RiskLevel.SAFE: (0.0, 0.1),
        RiskLevel.LOW: (0.1, 0.3),
        RiskLevel.MEDIUM: (0.3, 0.6),
        RiskLevel.HIGH: (0.6, 0.85),
        RiskLevel.CRITICAL: (0.85, 1.0),
    }

    # 过滤决策阈值
    DECISION_THRESHOLDS = {
        FilterDecision.ALLOW: 0.3,       # 风险分数 < 0.3: 允许
        FilterDecision.WARN: 0.6,        # 0.3 <= 风险分数 < 0.6: 警告
        FilterDecision.REJECT: 0.85,      # 0.6 <= 风险分数 < 0.85: 拒绝
        # >= 0.85: 隔离
    }

    def __init__(self,
                 baseline_risk: float = 0.1,
                 enable_obfuscation_detection: bool = True,
                 enable_momentum_calculation: bool = True,
                 decision_thresholds: Optional[Dict[FilterDecision, float]] = None):
        """
        初始化 M2 检测网关

        Args:
            baseline_risk: 基线风险分数（正常代码的平均风险水平）
            enable_obfuscation_detection: 是否启用混淆检测
            enable_momentum_calculation: 是否启用语义动量计算
            decision_thresholds: 自定义决策阈值
        """
        self.baseline_risk = baseline_risk
        self.enable_obfuscation_detection = enable_obfuscation_detection
        self.enable_momentum_calculation = enable_momentum_calculation
        self.decision_thresholds = decision_thresholds or self.DECISION_THRESHOLDS

        # 审计日志
        self._audit_log: List[M2FilterResult] = []
        self._max_audit_log = 10000

        # 统计
        self._total_requests = 0
        self._allowed = 0
        self._warned = 0
        self._rejected = 0
        self._quarantined = 0

    def extract_semantic_features(self, code: str) -> List[SemanticFeature]:
        """
        从代码中提取语义特征

        Args:
            code: 待分析的代码字符串

        Returns:
            检测到的语义特征列表
        """
        features = []

        # 检测危险API模式
        for pattern, feature_type in self.DANGEROUS_PATTERNS.items():
            matches = list(re.finditer(pattern, code))
            for match in matches:
                # 计算行号
                line_num = code[:match.start()].count('\n') + 1
                # 确定严重程度
                severity = self._get_feature_severity(feature_type)
                # 确定置信度（正则匹配的置信度较高）
                confidence = 0.9 if feature_type in [
                    SemanticFeatureType.CODE_EXECUTION,
                    SemanticFeatureType.SYSTEM_CALL,
                    SemanticFeatureType.SANDBOX_EVASION,
                ] else 0.75

                features.append(SemanticFeature(
                    feature_type=feature_type,
                    description=f"检测到 {feature_type.value}: {match.group()[:50]}",
                    location=f"line {line_num}",
                    severity=severity,
                    confidence=confidence,
                    context=code[max(0, match.start()-20):match.end()+20].strip(),
                ))

        # 混淆检测
        if self.enable_obfuscation_detection:
            obfuscation_features = self._detect_obfuscation(code)
            features.extend(obfuscation_features)

        return features

    def _detect_obfuscation(self, code: str) -> List[SemanticFeature]:
        """检测代码混淆"""
        features = []
        for pattern, description in self.OBFUSCATION_PATTERNS:
            matches = list(re.finditer(pattern, code))
            if len(matches) >= 3:  # 至少3处匹配才认为是混淆
                line_num = code[:matches[0].start()].count('\n') + 1
                features.append(SemanticFeature(
                    feature_type=SemanticFeatureType.OBFUSCATION,
                    description=f"{description}（{len(matches)}处匹配）",
                    location=f"line {line_num}",
                    severity=RiskLevel.HIGH,
                    confidence=0.7,
                    context="",
                ))
        return features

    def _get_feature_severity(self, feature_type: SemanticFeatureType) -> RiskLevel:
        """根据特征类型确定严重程度"""
        severity_map = {
            SemanticFeatureType.CODE_EXECUTION: RiskLevel.HIGH,
            SemanticFeatureType.SYSTEM_CALL: RiskLevel.HIGH,
            SemanticFeatureType.SANDBOX_EVASION: RiskLevel.CRITICAL,
            SemanticFeatureType.PRIVILEGE_ESCALATION: RiskLevel.CRITICAL,
            SemanticFeatureType.DATA_EXFILTRATION: RiskLevel.HIGH,
            SemanticFeatureType.NETWORK_OPERATION: RiskLevel.MEDIUM,
            SemanticFeatureType.FILE_OPERATION: RiskLevel.MEDIUM,
            SemanticFeatureType.PROCESS_OPERATION: RiskLevel.MEDIUM,
            SemanticFeatureType.OBFUSCATION: RiskLevel.HIGH,
            SemanticFeatureType.DANGEROUS_API: RiskLevel.MEDIUM,
        }
        return severity_map.get(feature_type, RiskLevel.MEDIUM)

    def calculate_risk_score(self, features: List[SemanticFeature]) -> float:
        """
        计算风险分数（0.0-1.0）

        基于特征的严重程度和置信度加权计算。
        """
        if not features:
            return 0.0

        severity_weights = {
            RiskLevel.SAFE: 0.0,
            RiskLevel.LOW: 0.1,
            RiskLevel.MEDIUM: 0.3,
            RiskLevel.HIGH: 0.6,
            RiskLevel.CRITICAL: 0.9,
        }

        total_score = 0.0
        max_score = 0.0

        for feature in features:
            weight = severity_weights.get(feature.severity, 0.3)
            # 加权：严重程度 * 置信度
            contribution = weight * feature.confidence
            total_score += contribution
            max_score += 1.0  # 每个特征最大贡献1.0

        # 归一化到 0.0-1.0
        if max_score == 0:
            return 0.0

        # 使用非线性映射，让少量高危特征也能产生高风险分数
        normalized = total_score / max_score
        # 放大高风险特征的影响
        amplified = min(1.0, normalized * 1.5)

        return round(amplified, 4)

    def calculate_semantic_momentum(self,
                                      features: List[SemanticFeature],
                                      risk_score: float) -> SemanticMomentum:
        """
        计算语义动量（风险变化率）

        语义动量衡量代码的风险特征与基线的偏离程度和变化趋势。
        """
        if not self.enable_momentum_calculation:
            return SemanticMomentum(
                risk_score=risk_score,
                baseline_risk=self.baseline_risk,
                feature_count=len(features),
            )

        # 风险变化量（与基线的差值）
        risk_delta = risk_score - self.baseline_risk

        # 动量：高风险特征占比 * 风险变化量
        high_risk_count = sum(1 for f in features if f.severity in [
            RiskLevel.HIGH, RiskLevel.CRITICAL
        ])
        high_risk_ratio = high_risk_count / len(features) if features else 0
        momentum = risk_delta * (1 + high_risk_ratio)

        # 异常分数：特征数量和类型的异常度
        feature_types = set(f.feature_type for f in features)
        type_diversity = len(feature_types) / len(SemanticFeatureType)
        anomaly_score = (high_risk_ratio * 0.6 + type_diversity * 0.4)

        # 混淆检测增加异常分数
        obfuscation_detected = any(
            f.feature_type == SemanticFeatureType.OBFUSCATION for f in features
        )
        if obfuscation_detected:
            anomaly_score = min(1.0, anomaly_score + 0.3)

        return SemanticMomentum(
            risk_score=risk_score,
            risk_delta=round(risk_delta, 4),
            momentum=round(momentum, 4),
            anomaly_score=round(anomaly_score, 4),
            feature_count=len(features),
            high_risk_feature_count=high_risk_count,
            obfuscation_detected=obfuscation_detected,
            baseline_risk=self.baseline_risk,
        )

    def _check_critical_features(self, features: List[SemanticFeature], reasons: List[str]) -> Optional[FilterDecision]:
        """检查严重特征（直接拒绝/隔离）"""
        critical_features = [f for f in features if f.severity == RiskLevel.CRITICAL]
        if critical_features:
            reasons.append(f"检测到 {len(critical_features)} 个严重风险特征: "
                          f"{', '.join(f.feature_type.value for f in critical_features)}")
            return FilterDecision.QUARANTINE
        return None

    def _check_evasion_features(self, features: List[SemanticFeature], reasons: List[str]) -> Optional[FilterDecision]:
        """检查沙盒逃逸尝试（直接拒绝）"""
        evasion_features = [f for f in features if f.feature_type == SemanticFeatureType.SANDBOX_EVASION]
        if evasion_features:
            reasons.append(f"检测到沙盒逃逸尝试: {len(evasion_features)}处")
            return FilterDecision.REJECT
        return None

    def _decision_by_risk_score(self,
                                  risk_score: float,
                                  momentum: SemanticMomentum,
                                  features: List[SemanticFeature],
                                  reasons: List[str]) -> FilterDecision:
        """基于风险分数的决策"""
        if momentum.obfuscation_detected:
            reasons.append("检测到代码混淆，可能隐藏恶意行为")

        reject_threshold = self.decision_thresholds.get(FilterDecision.REJECT, 0.85)
        warn_threshold = self.decision_thresholds.get(FilterDecision.WARN, 0.6)
        allow_threshold = self.decision_thresholds.get(FilterDecision.ALLOW, 0.3)

        if risk_score >= reject_threshold:
            reasons.append(f"风险分数 {risk_score:.2f} 超过拒绝阈值 {reject_threshold:.2f}")
            return FilterDecision.QUARANTINE
        elif risk_score >= warn_threshold:
            reasons.append(f"风险分数 {risk_score:.2f} 超过警告阈值 {warn_threshold:.2f}")
            if momentum.momentum > 0.3:
                reasons.append(f"语义动量 {momentum.momentum:.2f} 较高，风险呈增加趋势")
            return FilterDecision.REJECT
        elif risk_score >= allow_threshold:
            reasons.append(f"风险分数 {risk_score:.2f} 在警告范围内")
            high_risk = [f for f in features if f.severity in [RiskLevel.HIGH, RiskLevel.CRITICAL]]
            if high_risk:
                reasons.append(f"包含 {len(high_risk)} 个高风险特征，建议人工审核")
            return FilterDecision.WARN
        else:
            reasons.append(f"风险分数 {risk_score:.2f} 在安全范围内")
            return FilterDecision.ALLOW

    def make_decision(self,
                      risk_score: float,
                      momentum: SemanticMomentum,
                      features: List[SemanticFeature]) -> Tuple[FilterDecision, List[str]]:
        """
        根据风险分数和语义动量做出过滤决策（优化版：拆分为3个子函数）

        Returns:
            (决策, 决策原因列表)
        """
        reasons = []

        # 1. 检查严重特征（直接拒绝/隔离）
        decision = self._check_critical_features(features, reasons)
        if decision:
            return decision, reasons

        # 2. 检查沙盒逃逸尝试（直接拒绝）
        decision = self._check_evasion_features(features, reasons)
        if decision:
            return decision, reasons

        # 3. 基于风险分数的决策
        decision = self._decision_by_risk_score(risk_score, momentum, features, reasons)
        return decision, reasons

    def _build_filter_result(self,
                               decision: FilterDecision,
                               risk_level: RiskLevel,
                               risk_score: float,
                               momentum: SemanticMomentum,
                               features: List[SemanticFeature],
                               reasons: List[str],
                               code_hash: str,
                               code: str,
                               processing_time_ms: int,
                               tenant_id: str,
                               sandbox_type: str) -> M2FilterResult:
        """构造过滤结果对象"""
        return M2FilterResult(
            decision=decision,
            risk_level=risk_level,
            risk_score=risk_score,
            momentum=momentum,
            features=features,
            reasons=reasons,
            code_hash=code_hash,
            code_length=len(code),
            processing_time_ms=processing_time_ms,
            tenant_id=tenant_id,
            sandbox_type=sandbox_type,
        )

    def analyze_and_filter(self,
                           code: str,
                           tenant_id: str = "",
                           sandbox_type: str = "") -> M2FilterResult:
        """
        分析代码并做出过滤决策（完整流程）（优化版：拆分结果构造）

        Args:
            code: 待分析的代码
            tenant_id: 租户ID
            sandbox_type: 沙盒类型（LightPool/StrongPool）

        Returns:
            过滤结果（包含决策、风险分数、特征、原因等）
        """
        start_time = time.time()
        self._total_requests += 1

        # 1. 计算代码哈希
        code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]

        # 2. 提取语义特征
        features = self.extract_semantic_features(code)

        # 3. 计算风险分数
        risk_score = self.calculate_risk_score(features)

        # 4. 计算语义动量
        momentum = self.calculate_semantic_momentum(features, risk_score)

        # 5. 确定风险等级
        risk_level = self._get_risk_level(risk_score)

        # 6. 做出过滤决策
        decision, reasons = self.make_decision(risk_score, momentum, features)

        # 7. 构造结果
        processing_time_ms = int((time.time() - start_time) * 1000)
        result = self._build_filter_result(
            decision, risk_level, risk_score, momentum, features, reasons,
            code_hash, code, processing_time_ms, tenant_id, sandbox_type
        )

        # 8. 记录审计日志
        self._record_audit(result)

        # 9. 更新统计
        self._update_stats(decision)

        return result

    def _get_risk_level(self, risk_score: float) -> RiskLevel:
        """根据风险分数确定风险等级"""
        for level, (min_score, max_score) in self.RISK_SCORE_THRESHOLDS.items():
            if min_score <= risk_score < max_score:
                return level
        return RiskLevel.CRITICAL

    def _record_audit(self, result: M2FilterResult):
        """记录审计日志"""
        self._audit_log.append(result)
        # 限制审计日志大小
        if len(self._audit_log) > self._max_audit_log:
            self._audit_log = self._audit_log[-self._max_audit_log:]

    def _update_stats(self, decision: FilterDecision):
        """更新统计信息"""
        if decision == FilterDecision.ALLOW:
            self._allowed += 1
        elif decision == FilterDecision.WARN:
            self._warned += 1
        elif decision == FilterDecision.REJECT:
            self._rejected += 1
        elif decision == FilterDecision.QUARANTINE:
            self._quarantined += 1

    def get_audit_log(self, limit: int = 100) -> List[M2FilterResult]:
        """获取审计日志"""
        return list(self._audit_log[-limit:])

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            "total_requests": self._total_requests,
            "allowed": self._allowed,
            "warned": self._warned,
            "rejected": self._rejected,
            "quarantined": self._quarantined,
            "allow_rate": self._allowed / self._total_requests if self._total_requests > 0 else 0,
            "reject_rate": (self._rejected + self._quarantined) / self._total_requests if self._total_requests > 0 else 0,
            "audit_log_size": len(self._audit_log),
            "baseline_risk": self.baseline_risk,
            "obfuscation_detection_enabled": self.enable_obfuscation_detection,
            "momentum_calculation_enabled": self.enable_momentum_calculation,
        }

    def clear_audit_log(self):
        """清空审计日志"""
        self._audit_log.clear()
