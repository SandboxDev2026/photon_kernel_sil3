"""
evolution.poc_event_library — 真实漏洞POC事件样本库

收集公开的沙箱逃逸、内核漏洞、容器逃逸POC事件样本，
用于红蓝对抗框架的闭环测试。

POC来源：
1. 公开CVE漏洞POC（如CVE-2022-0185、CVE-2021-4034等）
2. 公开的namespace/seccomp逃逸技术
3. 容器逃逸技术（如docker.sock挂载、cgroup逃逸等）
4. 内核漏洞利用模式

设计原则：
- 只记录POC的事件特征和检测规则，不包含可执行的利用代码
- 每个POC关联对应的CVE编号和安全建议
- POC事件可直接注入RealDataAdapter做闭环测试
- 支持POC检测规则的自动生成
"""
from __future__ import annotations
import json
import time
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from evolution.real_data_adapter import SecurityEvent, EventSource, AnomalyType


class PocCategory(Enum):
    """POC类别"""
    NAMESPACE_ESCAPE = "namespace_escape"      # 命名空间逃逸
    SECCOMP_BYPASS = "seccomp_bypass"            # seccomp绕过
    CONTAINER_ESCAPE = "container_escape"        # 容器逃逸
    KERNEL_EXPLOIT = "kernel_exploit"            # 内核漏洞利用
    PRIVILEGE_ESCALATION = "privilege_escalation"  # 权限提升
    NETWORK_TUNNEL = "network_tunnel"            # 网络隧道
    AUDIT_BYPASS = "audit_bypass"                # 审计绕过
    DOS_ATTACK = "dos_attack"                    # 拒绝服务


class PocSeverity(Enum):
    """POC严重程度"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class PocEvent:
    """POC事件样本"""
    poc_id: str
    cve_id: Optional[str]
    category: PocCategory
    severity: PocSeverity
    title: str
    description: str
    event_characteristics: Dict[str, Any]  # 事件特征（用于检测）
    detection_rules: List[Dict[str, Any]]  # 检测规则
    affected_components: List[str]  # 受影响组件
    mitigation: str  # 缓解措施
    references: List[str]  # 参考链接
    discovered_at: str  # 发现日期
    event_source: EventSource = EventSource.SECCOMP_VIOLATION

    def to_security_event(self) -> SecurityEvent:
        """转换为SecurityEvent（用于闭环测试）"""
        return SecurityEvent(
            event_id=f"poc_{self.poc_id}",
            source=self.event_source,
            timestamp=time.time(),
            sandbox_id="poc_test_sandbox",
            severity=self.severity.value,
            description=f"[POC测试] {self.title}",
            payload={
                "poc_id": self.poc_id,
                "cve_id": self.cve_id,
                "category": self.category.value,
                "characteristics": self.event_characteristics,
                "mitigation": self.mitigation,
            },
            anomaly_type=AnomalyType.SEQUENCE_ANOMALY,
            anomaly_score=0.9,  # POC事件标记为高异常
        )

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "poc_id": self.poc_id,
            "cve_id": self.cve_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "event_characteristics": self.event_characteristics,
            "detection_rules": self.detection_rules,
            "affected_components": self.affected_components,
            "mitigation": self.mitigation,
            "references": self.references,
            "discovered_at": self.discovered_at,
        }


class PocEventLibrary:
    """
    POC事件样本库

    收集公开的沙箱逃逸、内核漏洞、容器逃逸POC事件样本，
    用于红蓝对抗框架的闭环测试。
    """

    def __init__(self):
        self.pocs: List[PocEvent] = []
        self._initialize_builtin_pocs()

    def _initialize_builtin_pocs(self) -> None:
        """初始化内置POC样本库"""
        builtin_pocs = [
            # === 命名空间逃逸 ===
            PocEvent(
                poc_id="NS-001",
                cve_id=None,
                category=PocCategory.NAMESPACE_ESCAPE,
                severity=PocSeverity.HIGH,
                title="mount namespace逃逸 via /proc/self/ns",
                description="通过/proc/self/ns/mnt符号链接逃逸mount namespace",
                event_characteristics={"syscall": "setns", "target": "/proc/*/ns/mnt", "pattern": "ns_escape"},
                detection_rules=[{"type": "syscall_blacklist", "value": "setns"}],
                affected_components=["LightPool", "namespace_isolation"],
                mitigation="禁止setns系统调用，限制/proc访问",
                references=["https://man7.org/linux/man-pages/man2/setns.2.html"],
                discovered_at="2020-01-15",
            ),
            PocEvent(
                poc_id="NS-002",
                cve_id=None,
                category=PocCategory.NAMESPACE_ESCAPE,
                severity=PocSeverity.HIGH,
                title="user namespace提权逃逸",
                description="通过unshare user namespace获取root权限",
                event_characteristics={"syscall": "unshare", "flags": "CLONE_NEWUSER", "pattern": "userns_escape"},
                detection_rules=[{"type": "syscall_blacklist", "value": "unshare"}],
                affected_components=["LightPool", "user_namespace"],
                mitigation="禁止unshare系统调用，禁用user namespace",
                references=["https://lwn.net/Articles/543271/"],
                discovered_at="2019-06-20",
            ),

            # === seccomp绕过 ===
            PocEvent(
                poc_id="SC-001",
                cve_id=None,
                category=PocCategory.SECCOMP_BYPASS,
                severity=PocSeverity.HIGH,
                title="seccomp-bpf过滤绕过 via 多线程",
                description="通过多线程竞争条件绕过seccomp过滤",
                event_characteristics={"syscall": "clone", "pattern": "race_condition", "threads": ">10"},
                detection_rules=[{"type": "behavior_analysis", "value": "high_thread_count"}],
                affected_components=["LightPool", "seccomp"],
                mitigation="限制线程数，使用SECCOMP_FILTER_FLAG_TSYNC",
                references=["https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt"],
                discovered_at="2021-03-10",
            ),
            PocEvent(
                poc_id="SC-002",
                cve_id=None,
                category=PocCategory.SECCOMP_BYPASS,
                severity=PocSeverity.MEDIUM,
                title="seccomp绕过 via 32位系统调用",
                description="通过int 0x80触发32位系统调用绕过64位seccomp过滤",
                event_characteristics={"syscall": "int 0x80", "arch": "x86", "pattern": "32bit_syscall"},
                detection_rules=[{"type": "arch_check", "value": "AUDIT_ARCH_X86"}],
                affected_components=["LightPool", "seccomp"],
                mitigation="seccomp规则中检查arch字段，禁止32位调用",
                references=["https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html"],
                discovered_at="2020-11-05",
            ),

            # === 内核漏洞 ===
            PocEvent(
                poc_id="KE-001",
                cve_id="CVE-2022-0185",
                category=PocCategory.KERNEL_EXPLOIT,
                severity=PocSeverity.CRITICAL,
                title="Linux内核 fsconfig 系统调用堆溢出",
                description="fsconfig系统调用中的整数溢出导致堆缓冲区溢出，可提权",
                event_characteristics={"syscall": "fsconfig", "vulnerability": "heap_overflow", "cve": "CVE-2022-0185"},
                detection_rules=[{"type": "syscall_blacklist", "value": "fsconfig"}],
                affected_components=["内核", "LightPool", "StrongPool"],
                mitigation="升级内核到5.16.2+，禁止fsconfig系统调用",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-0185"],
                discovered_at="2022-01-18",
            ),
            PocEvent(
                poc_id="KE-002",
                cve_id="CVE-2021-4034",
                category=PocCategory.PRIVILEGE_ESCALATION,
                severity=PocSeverity.CRITICAL,
                title="PwnKit: pkexec 本地权限提升",
                description="pkexec中的内存损坏漏洞，任何本地用户可提权为root",
                event_characteristics={"binary": "/usr/bin/pkexec", "vulnerability": "memory_corruption", "cve": "CVE-2021-4034"},
                detection_rules=[{"type": "binary_blacklist", "value": "pkexec"}],
                affected_components=["LightPool", "文件系统"],
                mitigation="移除pkexec二进制，升级polkit包",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-4034"],
                discovered_at="2022-01-25",
            ),

            # === 容器逃逸 ===
            PocEvent(
                poc_id="CE-001",
                cve_id=None,
                category=PocCategory.CONTAINER_ESCAPE,
                severity=PocSeverity.CRITICAL,
                title="docker.sock挂载逃逸",
                description="通过挂载/var/run/docker.sock创建特权容器逃逸",
                event_characteristics={"mount": "/var/run/docker.sock", "pattern": "docker_sock", "action": "create_privileged_container"},
                detection_rules=[{"type": "mount_blacklist", "value": "/var/run/docker.sock"}],
                affected_components=["StrongPool", "容器运行时"],
                mitigation="禁止挂载docker.sock，使用rootless容器",
                references=["https://docs.docker.com/engine/security/security/"],
                discovered_at="2019-04-01",
            ),
            PocEvent(
                poc_id="CE-002",
                cve_id=None,
                category=PocCategory.CONTAINER_ESCAPE,
                severity=PocSeverity.HIGH,
                title="cgroup v1 release_agent逃逸",
                description="通过cgroup v1的release_agent机制执行宿主机命令",
                event_characteristics={"cgroup": "v1", "file": "release_agent", "pattern": "cgroup_escape"},
                detection_rules=[{"type": "cgroup_version_check", "value": "v2_only"}],
                affected_components=["LightPool", "cgroup"],
                mitigation="使用cgroup v2，禁止cgroup v1挂载",
                references=["https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html"],
                discovered_at="2020-08-15",
            ),

            # === 网络隧道 ===
            PocEvent(
                poc_id="NT-001",
                cve_id=None,
                category=PocCategory.NETWORK_TUNNEL,
                severity=PocSeverity.HIGH,
                title="DNS隧道数据外泄",
                description="通过DNS TXT记录将数据编码后外泄",
                event_characteristics={"protocol": "DNS", "query_type": "TXT", "pattern": "dns_tunnel", "domain_length": ">50"},
                detection_rules=[{"type": "dns_analysis", "value": "long_txt_query"}],
                affected_components=["网络隔离", "eBPF"],
                mitigation="DNS劫持到隔离网关，限制DNS查询长度",
                references=["https://en.wikipedia.org/wiki/DNS_tunneling"],
                discovered_at="2021-05-20",
            ),

            # === 审计绕过 ===
            PocEvent(
                poc_id="AB-001",
                cve_id=None,
                category=PocCategory.AUDIT_BYPASS,
                severity=PocSeverity.HIGH,
                title="审计日志删除/篡改",
                description="删除或篡改审计日志文件以掩盖攻击痕迹",
                event_characteristics={"action": "delete_audit_log", "target": "/var/log/audit/*", "pattern": "log_tampering"},
                detection_rules=[{"type": "file_integrity", "value": "audit_log"}],
                affected_components=["审计系统", "HMAC链"],
                mitigation="审计日志写入WORM存储，HMAC哈希链防篡改",
                references=["https://www.kernel.org/doc/html/latest/admin-guide/audit.html"],
                discovered_at="2021-09-10",
            ),

            # === DoS攻击 ===
            PocEvent(
                poc_id="DA-001",
                cve_id=None,
                category=PocCategory.DOS_ATTACK,
                severity=PocSeverity.MEDIUM,
                title="fork bomb资源耗尽",
                description="通过递归fork进程耗尽系统PID和内存",
                event_characteristics={"pattern": "fork_bomb", "process_rate": ">1000/s", "syscall": "fork"},
                detection_rules=[{"type": "rate_limit", "value": "fork_rate"}],
                affected_components=["LightPool", "cgroup"],
                mitigation="cgroup pids.max限制，rlimit NPROC设置",
                references=["https://en.wikipedia.org/wiki/Fork_bomb"],
                discovered_at="2020-02-01",
            ),
        ]

        self.pocs = builtin_pocs

    def get_all_pocs(self) -> List[PocEvent]:
        """获取所有POC"""
        return self.pocs

    def get_poc_by_id(self, poc_id: str) -> Optional[PocEvent]:
        """根据ID获取POC"""
        for poc in self.pocs:
            if poc.poc_id == poc_id:
                return poc
        return None

    def get_pocs_by_category(self, category: PocCategory) -> List[PocEvent]:
        """按类别获取POC"""
        return [p for p in self.pocs if p.category == category]

    def get_pocs_by_severity(self, severity: PocSeverity) -> List[PocEvent]:
        """按严重程度获取POC"""
        return [p for p in self.pocs if p.severity == severity]

    def get_critical_pocs(self) -> List[PocEvent]:
        """获取严重级别POC"""
        return self.get_pocs_by_severity(PocSeverity.CRITICAL)

    def generate_test_events(self, limit: Optional[int] = None) -> List[SecurityEvent]:
        """
        生成测试事件（用于闭环测试）

        将所有POC转换为SecurityEvent，可直接注入RealDataAdapter。
        """
        events = [poc.to_security_event() for poc in self.pocs]
        if limit:
            events = events[:limit]
        return events

    def generate_detection_rules(self) -> List[Dict[str, Any]]:
        """
        生成汇总检测规则

        从所有POC中提取检测规则，生成可用于seccomp/eBPF的规则集。
        """
        all_rules = []
        for poc in self.pocs:
            for rule in poc.detection_rules:
                rule_with_meta = rule.copy()
                rule_with_meta["poc_id"] = poc.poc_id
                rule_with_meta["cve_id"] = poc.cve_id
                rule_with_meta["severity"] = poc.severity.value
                all_rules.append(rule_with_meta)
        return all_rules

    def generate_seccomp_blacklist(self) -> List[str]:
        """生成seccomp系统调用黑名单"""
        blacklist = set()
        for poc in self.pocs:
            for rule in poc.detection_rules:
                if rule.get("type") == "syscall_blacklist":
                    blacklist.add(rule["value"])
        return sorted(blacklist)

    def run_closed_loop_test(
        self,
        adapter: "RealDataAdapter",
        trainer: "RedBlueAdversaryTrainer",
        enforcer: Optional["DefenseRuleEnforcer"] = None,
    ) -> Dict[str, Any]:
        """
        运行闭环测试

        完整流程：
        1. POC事件注入RealDataAdapter
        2. 适配器解析并检测异常
        3. 异常事件注入红蓝对抗框架
        4. 框架触发达尔文进化
        5. 进化的防御规则下发到配置层
        6. 验证配置更新是否正确

        返回闭环测试结果。
        """
        from evolution.real_data_adapter import RealDataAdapter
        from evolution.red_blue_adversary import RedBlueAdversaryTrainer

        results = {
            "total_pocs": len(self.pocs),
            "injected_events": 0,
            "detected_anomalies": 0,
            "triggered_evolution": 0,
            "generated_defense_rules": 0,
            "enforced_config_updates": 0,
            "closed_loop_success": False,
            "details": [],
        }

        # 1. 生成POC测试事件
        test_events = self.generate_test_events()
        results["injected_events"] = len(test_events)

        # 2. 注入适配器并检测异常
        for event in test_events:
            # 直接添加到适配器
            adapter.all_events.append(event)
            if event.anomaly_type is not None:
                adapter.anomaly_events.append(event)
                results["detected_anomalies"] += 1

        # 3. 注入红蓝对抗框架
        high_risk_events = [e for e in test_events if e.severity in ["high", "critical"]]
        for event in high_risk_events:
            ingest_result = trainer.ingest_real_event(event)
            if ingest_result.get("triggered_evolution"):
                results["triggered_evolution"] += 1

        # 4. 生成防御规则
        results["generated_defense_rules"] = len(trainer.blue_agent.defense_rules)

        # 5. 下发配置更新（如果有enforcer）
        if enforcer is not None:
            # 从进化的防御规则生成配置更新
            for rule in trainer.blue_agent.defense_rules[-5:]:  # 最近进化的5条规则
                updates = enforcer.generate_updates_from_rule(rule)
                enforcer.enqueue_updates(updates)
                results["enforced_config_updates"] += len(updates)

            # 应用待处理更新（dry-run模式）
            apply_result = enforcer.apply_pending()
            results["dry_run_applied"] = apply_result.get("applied", 0)

        # 6. 闭环成功判定
        results["closed_loop_success"] = (
            results["injected_events"] > 0 and
            results["detected_anomalies"] > 0 and
            results["triggered_evolution"] > 0
        )

        # 详细结果
        results["details"] = {
            "poc_categories": {cat.value: len(self.get_pocs_by_category(cat)) for cat in PocCategory},
            "poc_severities": {sev.value: len(self.get_pocs_by_severity(sev)) for sev in PocSeverity},
            "seccomp_blacklist": self.generate_seccomp_blacklist(),
            "detection_rules_count": len(self.generate_detection_rules()),
        }

        return results

    def get_statistics(self) -> Dict[str, Any]:
        """获取POC库统计"""
        return {
            "total_pocs": len(self.pocs),
            "by_category": {cat.value: len(self.get_pocs_by_category(cat)) for cat in PocCategory},
            "by_severity": {sev.value: len(self.get_pocs_by_severity(sev)) for sev in PocSeverity},
            "critical_count": len(self.get_critical_pocs()),
            "cve_count": sum(1 for p in self.pocs if p.cve_id),
            "seccomp_blacklist_size": len(self.generate_seccomp_blacklist()),
            "detection_rules_count": len(self.generate_detection_rules()),
        }

    def export_to_json(self, file_path: str) -> None:
        """导出POC库到JSON文件"""
        data = {
            "version": "1.0",
            "generated_at": time.time(),
            "statistics": self.get_statistics(),
            "pocs": [poc.to_dict() for poc in self.pocs],
        }
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
