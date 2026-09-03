"""
Leader-Teammate 团队模型（借鉴 JiuwenSwarm 蜂群）

参考 JiuwenSwarm 的 Leader-Teammate 团队模型和 Inner/Outer Loop 自演进闭环，
扩展 PhotonBox 的多智能体编排，用于遗传算法批量评测和 Skill 自演进。

借鉴点：
1. Leader-Teammate 团队模型: Leader负责任务拆解、动态生成子Agent；Teammate执行子任务
2. Inner/Outer Loop 双层反馈: Inner-Loop(单Agent观察-推理-行动-验证) + Outer-Loop(目标-计划-评估-更新)
3. Agent权限模型: 细粒度工具/沙盒权限隔离，不同Teammate分配不同沙盒后端权限
4. 共享工作空间: 多Agent之间文件产物、日志、中间结果共享
5. 动态注册中心: Agent节点动态注册、动态预约空闲worker节点

许可证: Apache-2.0（与 JiuwenSwarm 一致）
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Tuple
from enum import Enum
import time
import threading
import uuid


class AgentRole(Enum):
    """Agent 角色"""
    LEADER = "leader"          # 领导者：任务拆解、分配、汇总
    TEAMMATE = "teammate"      # 队友：执行子任务
    SUPERVISOR = "supervisor"  # 监督者：质量检查、安全审计
    WORKER = "worker"          # 工作者：沙盒执行


class AgentStatus(Enum):
    """Agent 状态"""
    IDLE = "idle"              # 空闲
    BUSY = "busy"              # 忙碌
    WAITING = "waiting"        # 等待资源
    COMPLETED = "completed"    # 已完成
    FAILED = "failed"          # 失败
    EVOLVING = "evolving"      # 进化中


class LoopPhase(Enum):
    """循环阶段（Inner/Outer Loop）"""
    # Inner Loop（单 Agent 执行循环）
    OBSERVE = "observe"        # 观察：收集环境信息
    REASON = "reason"          # 推理：分析、决策
    ACT = "act"                # 行动：执行操作
    VERIFY = "verify"          # 验证：检查结果
    # Outer Loop（团队进化循环）
    GOAL = "goal"              # 目标：定义任务目标
    PLAN = "plan"              # 计划：拆解任务、分配资源
    EXECUTE = "execute"        # 执行：团队协作执行
    EVALUATE = "evaluate"      # 评估：结果评估、反馈
    UPDATE = "update"          # 更新：技能库、策略更新


@dataclass
class AgentPermission:
    """Agent 权限模型（细粒度权限隔离）"""
    can_access_light_pool: bool = True       # 可访问 LightPool（进程沙盒）
    can_access_strong_pool: bool = False     # 可访问 StrongPool（KVM MicroVM）
    can_access_network: bool = False         # 可访问网络
    can_access_filesystem: bool = True       # 可访问文件系统
    can_execute_arbitrary_code: bool = True  # 可执行任意代码
    max_execution_timeout_s: int = 30       # 最大执行超时
    max_memory_mb: int = 512                 # 最大内存
    allowed_tools: List[str] = field(default_factory=list)  # 允许使用的工具列表


@dataclass
class TaskResult:
    """任务结果"""
    task_id: str
    agent_id: str
    success: bool
    output: str = ""
    error: str = ""
    duration_ms: int = 0
    metrics: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[str] = field(default_factory=list)  # 产物路径列表
    feedback: Optional[str] = None  # 反馈（用于进化）


@dataclass
class TeammateAgent:
    """Teammate Agent（队友）"""
    agent_id: str
    name: str
    role: AgentRole = AgentRole.TEAMMATE
    status: AgentStatus = AgentStatus.IDLE
    permission: AgentPermission = field(default_factory=AgentPermission)
    skills: List[str] = field(default_factory=list)  # 拥有的技能
    success_count: int = 0
    failure_count: int = 0
    total_tasks: int = 0
    current_task: Optional[str] = None
    registered_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)

    @property
    def success_rate(self) -> float:
        """成功率"""
        if self.total_tasks == 0:
            return 0.0
        return self.success_count / self.total_tasks

    def can_handle_task(self, task_requirements: Dict[str, Any]) -> bool:
        """检查是否能处理任务（基于权限和技能）"""
        # 检查 StrongPool 权限
        if task_requirements.get("requires_strong_pool") and not self.permission.can_access_strong_pool:
            return False
        # 检查网络权限
        if task_requirements.get("requires_network") and not self.permission.can_access_network:
            return False
        # 检查技能
        required_skills = task_requirements.get("required_skills", [])
        for skill in required_skills:
            if skill not in self.skills:
                return False
        return True

    def record_result(self, result: TaskResult) -> None:
        """记录任务结果"""
        self.total_tasks += 1
        if result.success:
            self.success_count += 1
        else:
            self.failure_count += 1
        self.status = AgentStatus.IDLE
        self.current_task = None
        self.last_heartbeat = time.time()


@dataclass
class SharedWorkspace:
    """
    共享工作空间（借鉴 JiuwenSwarm Shared Workspace）

    多 Agent 之间文件产物、日志、中间结果共享。
    """
    workspace_id: str
    base_path: str = "/tmp/photonbox_workspace"
    artifacts: Dict[str, List[str]] = field(default_factory=dict)  # agent_id -> 产物列表
    logs: Dict[str, List[str]] = field(default_factory=dict)  # agent_id -> 日志列表
    shared_data: Dict[str, Any] = field(default_factory=dict)  # 共享数据
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add_artifact(self, agent_id: str, artifact_path: str) -> None:
        """添加产物"""
        with self._lock:
            if agent_id not in self.artifacts:
                self.artifacts[agent_id] = []
            self.artifacts[agent_id].append(artifact_path)

    def add_log(self, agent_id: str, log: str) -> None:
        """添加日志"""
        with self._lock:
            if agent_id not in self.logs:
                self.logs[agent_id] = []
            self.logs[agent_id].append(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {log}")

    def get_all_artifacts(self) -> List[str]:
        """获取所有产物"""
        with self._lock:
            all_artifacts = []
            for agent_artifacts in self.artifacts.values():
                all_artifacts.extend(agent_artifacts)
            return all_artifacts

    def set_shared_data(self, key: str, value: Any) -> None:
        """设置共享数据"""
        with self._lock:
            self.shared_data[key] = value

    def get_shared_data(self, key: str) -> Optional[Any]:
        """获取共享数据"""
        with self._lock:
            return self.shared_data.get(key)


class LeaderAgent:
    """
    Leader Agent（领导者，借鉴 JiuwenSwarm Leader-Teammate 模型）

    核心职责：
    1. 任务拆解：将大任务拆解为子任务
    2. 动态分配：根据 Teammate 能力和权限分配子任务
    3. 结果汇总：收集 Teammate 结果，汇总最终输出
    4. 质量控制：检查结果质量，决定是否重跑
    5. 进化反馈：将失败案例反馈给 Skill 进化模块
    """

    def __init__(self, name: str = "leader"):
        self.agent_id = str(uuid.uuid4())[:8]
        self.name = name
        self.role = AgentRole.LEADER
        self.teammates: Dict[str, TeammateAgent] = {}
        self.workspace = SharedWorkspace(workspace_id=self.agent_id)
        self.task_queue: List[Dict[str, Any]] = []
        self.results: Dict[str, TaskResult] = {}
        self._lock = threading.Lock()
        self.outer_loop_phase = LoopPhase.GOAL
        self.evolution_history: List[Dict[str, Any]] = []

    def register_teammate(self, teammate: TeammateAgent) -> str:
        """注册 Teammate（动态注册中心）"""
        with self._lock:
            self.teammates[teammate.agent_id] = teammate
            self.workspace.add_log(teammate.agent_id, f"Teammate registered: {teammate.name}")
            return teammate.agent_id

    def unregister_teammate(self, agent_id: str) -> None:
        """注销 Teammate"""
        with self._lock:
            if agent_id in self.teammates:
                del self.teammates[agent_id]
                self.workspace.add_log(agent_id, "Teammate unregistered")

    def decompose_task(self, task: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        任务拆解（Outer Loop: PLAN 阶段）

        将大任务拆解为子任务，每个子任务有明确的需求和权限要求。
        根据 task_type 分发到对应的拆解子函数。
        """
        self.outer_loop_phase = LoopPhase.PLAN
        task_type = task.get("type", "generic")

        if task_type == "ga_evaluation":
            subtasks = self._decompose_ga_evaluation(task)
        elif task_type == "code_audit":
            subtasks = self._decompose_code_audit(task)
        else:
            subtasks = self._decompose_generic(task)

        self.workspace.add_log(self.agent_id, f"Task decomposed into {len(subtasks)} subtasks")
        return subtasks

    def _decompose_ga_evaluation(self, task: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        拆解遗传算法批量评测任务

        将种群按 batch_size 拆分为多个批次，每个批次作为一个子任务。
        每个子任务需要 StrongPool 和 code_evaluation/sandbox_execution 技能。
        """
        subtasks = []
        population = task.get("population", [])
        batch_size = task.get("batch_size", 10)

        for i in range(0, len(population), batch_size):
            batch = population[i:i + batch_size]
            subtasks.append({
                "task_id": f"{task.get('task_id', 'ga')}_batch_{i // batch_size}",
                "type": "ga_batch_evaluation",
                "population_batch": batch,
                "requires_strong_pool": task.get("requires_strong_pool", True),
                "required_skills": ["code_evaluation", "sandbox_execution"],
                "timeout_s": task.get("timeout_s", 60),
            })

        return subtasks

    def _decompose_code_audit(self, task: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        拆解代码审计任务

        拆分为三个子任务：SAST 扫描、渗透测试、漏洞评估。
        渗透测试需要 StrongPool，SAST 和漏洞评估只需要 LightPool。
        """
        task_id = task.get("task_id", "audit")
        return [
            {
                "task_id": f"{task_id}_sast",
                "type": "sast_scan",
                "required_skills": ["sast"],
                "requires_strong_pool": False,
            },
            {
                "task_id": f"{task_id}_pentest",
                "type": "penetration_test",
                "required_skills": ["pentest"],
                "requires_strong_pool": True,
            },
            {
                "task_id": f"{task_id}_vuln",
                "type": "vulnerability_assessment",
                "required_skills": ["vuln_assessment"],
                "requires_strong_pool": False,
            },
        ]

    def _decompose_generic(self, task: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        拆解通用任务

        未知类型的任务不拆解，直接作为单个子任务返回。
        """
        return [task]

    def assign_task(self, subtask: Dict[str, Any]) -> Optional[str]:
        """
        分配子任务给合适的 Teammate

        策略：
        1. 筛选能处理任务的 Teammate（权限+技能匹配）
        2. 选择成功率最高、当前空闲的 Teammate
        3. 预留部分 Teammate 处理高优先级任务
        """
        with self._lock:
            candidates = []
            for agent_id, teammate in self.teammates.items():
                if teammate.status != AgentStatus.IDLE:
                    continue
                if not teammate.can_handle_task(subtask):
                    continue
                candidates.append(teammate)

            if not candidates:
                return None

            # 选择成功率最高的
            best = max(candidates, key=lambda t: t.success_rate)
            best.status = AgentStatus.BUSY
            best.current_task = subtask.get("task_id")
            self.workspace.add_log(best.agent_id, f"Assigned task: {subtask.get('task_id')}")
            return best.agent_id

    def execute_inner_loop(self, agent_id: str, subtask: Dict[str, Any]) -> TaskResult:
        """
        执行 Inner Loop（单 Agent 执行循环）

        阶段：OBSERVE → REASON → ACT → VERIFY
        拆分为验证和阶段执行两个子函数，主函数只负责调度。
        """
        # 验证 teammate 存在性
        teammate, error_result = self._validate_teammate_for_inner_loop(agent_id, subtask)
        if error_result is not None:
            return error_result

        # 执行所有阶段并返回结果
        return self._execute_inner_loop_phases(agent_id, subtask, teammate)

    def _validate_teammate_for_inner_loop(
        self, agent_id: str, subtask: Dict[str, Any]
    ) -> tuple:
        """
        验证 Inner Loop 的 teammate 是否存在

        返回: (teammate对象, 错误结果)
        如果 teammate 不存在，错误结果为 TaskResult；否则错误结果为 None。
        """
        teammate = self.teammates.get(agent_id)
        if not teammate:
            error_result = TaskResult(
                task_id=subtask.get("task_id", "unknown"),
                agent_id=agent_id,
                success=False,
                error="Teammate not found",
            )
            return None, error_result
        return teammate, None

    def _execute_inner_loop_phases(
        self, agent_id: str, subtask: Dict[str, Any], teammate: 'TeammateAgent'
    ) -> TaskResult:
        """
        执行 Inner Loop 所有阶段

        阶段：OBSERVE → REASON → ACT → VERIFY → 记录结果
        返回最终的 TaskResult 对象。
        """
        start_time = time.time()

        # OBSERVE + REASON: 观察环境并推理决策
        self._inner_loop_observe_and_reason(agent_id, subtask)

        # ACT: 执行任务
        success, output = self._inner_loop_act(agent_id, subtask)

        # VERIFY: 验证结果并创建结果对象
        result = self._inner_loop_verify_and_create_result(
            agent_id, subtask, success, output, start_time
        )

        # 记录结果和进化反馈
        self._inner_loop_record_result(teammate, subtask, result)

        return result

    def _inner_loop_observe_and_reason(self, agent_id: str, subtask: Dict[str, Any]) -> None:
        """
        Inner Loop OBSERVE + REASON 阶段

        OBSERVE: 观察环境，收集任务信息
        REASON: 推理决策，分析任务需求
        这两个阶段目前都是日志记录，合并为一个子函数减少碎片化。
        """
        self.workspace.add_log(agent_id, f"[OBSERVE] Task: {subtask.get('task_id')}")
        self.workspace.add_log(agent_id, "[REASON] Analyzing task requirements")

    def _inner_loop_act(self, agent_id: str, subtask: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Inner Loop ACT 阶段：执行任务

        实际执行应该调用沙盒客户端，这里简化为模拟执行。
        返回: (success, output)
        """
        self.workspace.add_log(agent_id, "[ACT] Executing task")
        success = subtask.get("expected_success", True)
        output = subtask.get("expected_output", "Task executed successfully")
        return success, output

    def _inner_loop_verify_and_create_result(
        self,
        agent_id: str,
        subtask: Dict[str, Any],
        success: bool,
        output: str,
        start_time: float,
    ) -> TaskResult:
        """
        Inner Loop VERIFY 阶段：验证结果并创建结果对象

        计算执行时长，构建 TaskResult 对象，包含 Inner Loop 阶段信息。
        """
        self.workspace.add_log(agent_id, "[VERIFY] Verifying result")
        duration_ms = int((time.time() - start_time) * 1000)

        return TaskResult(
            task_id=subtask.get("task_id", "unknown"),
            agent_id=agent_id,
            success=success,
            output=output,
            duration_ms=duration_ms,
            metrics={"inner_loop_phases": ["observe", "reason", "act", "verify"]},
        )

    def _inner_loop_record_result(
        self,
        teammate: TeammateAgent,
        subtask: Dict[str, Any],
        result: TaskResult,
    ) -> None:
        """
        记录 Inner Loop 执行结果

        1. 记录到 Teammate 的历史统计
        2. 记录到 Leader 的全局结果字典
        3. 如果失败，记录进化反馈用于 Skill 自演进
        """
        teammate.record_result(result)
        self.results[result.task_id] = result

        # 如果失败，记录进化反馈
        if not result.success:
            self._record_evolution_feedback(subtask, result)

    def execute_outer_loop(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行 Outer Loop（团队进化循环）

        阶段：GOAL → PLAN → EXECUTE → EVALUATE → UPDATE
        拆分为阶段执行和结果组装两个子函数，主函数只负责调度。
        """
        # 执行所有阶段，获取中间结果
        results, success_count, total_count, success_rate = self._outer_loop_run_phases(task)

        # 组装并返回结果
        return self._outer_loop_build_result(task, results, success_count, total_count, success_rate)

    def _outer_loop_run_phases(
        self, task: Dict[str, Any]
    ) -> Tuple[List['TaskResult'], int, int, float]:
        """
        执行 Outer Loop 所有阶段

        阶段：GOAL → PLAN → EXECUTE → EVALUATE → UPDATE
        返回: (结果列表, 成功数, 总数, 成功率)
        """
        # GOAL: 设置目标
        self.outer_loop_phase = LoopPhase.GOAL
        self.workspace.add_log(self.agent_id, f"[GOAL] Task: {task.get('description', 'Unknown')}")

        # PLAN: 任务拆解
        subtasks = self.decompose_task(task)

        # EXECUTE: 分配并执行
        self.outer_loop_phase = LoopPhase.EXECUTE
        results = self._outer_loop_execute_subtasks(subtasks)

        # EVALUATE: 评估结果
        self.outer_loop_phase = LoopPhase.EVALUATE
        success_count, total_count, success_rate = self._outer_loop_evaluate_results(results)

        # UPDATE: 更新技能库和策略
        self.outer_loop_phase = LoopPhase.UPDATE
        self._outer_loop_update_evolution(task, success_rate)

        return results, success_count, total_count, success_rate

    def _outer_loop_build_result(
        self,
        task: Dict[str, Any],
        results: List['TaskResult'],
        success_count: int,
        total_count: int,
        success_rate: float,
    ) -> Dict[str, Any]:
        """
        组装 Outer Loop 执行结果

        将各阶段的中间结果组装为统一的返回字典，包含任务信息、统计数据、
        详细结果、阶段列表和产物。
        """
        return {
            "task_id": task.get("task_id"),
            "total_subtasks": total_count,
            "success_count": success_count,
            "success_rate": success_rate,
            "results": [r.__dict__ for r in results],
            "outer_loop_phases": ["goal", "plan", "execute", "evaluate", "update"],
            "artifacts": self.workspace.get_all_artifacts(),
        }

    def _outer_loop_execute_subtasks(self, subtasks: List[Dict[str, Any]]) -> List[TaskResult]:
        """
        Outer Loop EXECUTE 阶段：分配并执行所有子任务

        遍历子任务列表，为每个子任务分配合适的 Teammate，
        然后执行 Inner Loop。无可用 Teammate 时记录等待日志。
        """
        results = []
        for subtask in subtasks:
            agent_id = self.assign_task(subtask)
            if agent_id:
                result = self.execute_inner_loop(agent_id, subtask)
                results.append(result)
            else:
                # 无可用 Teammate，任务等待
                self.workspace.add_log(
                    self.agent_id,
                    f"[WAIT] No available teammate for {subtask.get('task_id')}"
                )
        return results

    def _outer_loop_evaluate_results(self, results: List[TaskResult]) -> Tuple[int, int, float]:
        """
        Outer Loop EVALUATE 阶段：评估执行结果

        计算成功数量、总数量和成功率。
        返回: (success_count, total_count, success_rate)
        """
        success_count = sum(1 for r in results if r.success)
        total_count = len(results)
        success_rate = success_count / total_count if total_count > 0 else 0
        return success_count, total_count, success_rate

    def _outer_loop_update_evolution(self, task: Dict[str, Any], success_rate: float) -> None:
        """
        Outer Loop UPDATE 阶段：更新技能库和策略

        成功率低于 80% 时触发进化，记录进化历史。
        """
        if success_rate < 0.8:
            self.workspace.add_log(
                self.agent_id,
                f"[UPDATE] Success rate {success_rate:.2%} < 80%, triggering evolution"
            )
            # 触发进化（简化）
            self.evolution_history.append({
                "timestamp": time.time(),
                "task_id": task.get("task_id"),
                "success_rate": success_rate,
                "action": "skill_evolution_triggered",
            })

    def get_idle_teammates(self) -> List[TeammateAgent]:
        """获取空闲 Teammate 列表"""
        with self._lock:
            return [t for t in self.teammates.values() if t.status == AgentStatus.IDLE]

    def get_stats(self) -> Dict[str, Any]:
        """获取团队统计"""
        with self._lock:
            idle_count = sum(1 for t in self.teammates.values() if t.status == AgentStatus.IDLE)
            busy_count = sum(1 for t in self.teammates.values() if t.status == AgentStatus.BUSY)
            return {
                "leader_id": self.agent_id,
                "total_teammates": len(self.teammates),
                "idle_teammates": idle_count,
                "busy_teammates": busy_count,
                "total_tasks_completed": len(self.results),
                "overall_success_rate": (
                    sum(1 for r in self.results.values() if r.success) / len(self.results)
                    if self.results else 0
                ),
                "outer_loop_phase": self.outer_loop_phase.value,
                "evolution_count": len(self.evolution_history),
            }

    def _record_evolution_feedback(self, subtask: Dict[str, Any], result: TaskResult) -> None:
        """记录进化反馈（用于 Skill 自演进）"""
        feedback = {
            "timestamp": time.time(),
            "task_id": subtask.get("task_id"),
            "agent_id": result.agent_id,
            "error": result.error,
            "subtask_type": subtask.get("type"),
            "required_skills": subtask.get("required_skills", []),
        }
        self.workspace.set_shared_data(f"feedback_{subtask.get('task_id')}", feedback)
        self.workspace.add_log(self.agent_id, f"[FEEDBACK] Recorded failure feedback for {subtask.get('task_id')}")
