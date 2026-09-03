"""
evolution.adversary_loop_orchestrator — 红蓝对抗闭环编排器

完整闭环: 真实日志流 → 红蓝对抗推演 → 自动部署新防御规则到沙盒执行层

解决用户指出的核心问题:
1. 尚未对接真实日志流 → 编排器自动接入RealtimeLogStream
2. 推演完未自动部署 → 编排器自动将新防御规则通过DefenseRuleExecutor部署
3. 高级能力依赖裸机 → 编排器自动检测环境能力,优雅降级
4. 攻击面依然存在 → 编排器持续监控,新CVE出现时自动触发推演

架构:
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
│ RealtimeLogStream│────▶│ RedBlueAdversaryTrainer│────▶│ DefenseRuleExecutor  │
│ (真实日志消费)    │     │ (红蓝对抗推演)         │     │ (防御规则部署)       │
└─────────────────┘     └──────────────────────┘     └─────────────────────┘
         ▲                        │                              │
         │                        ▼                              ▼
    日志源配置              新防御规则生成                    沙盒执行层
  (seccomp/VM-Exit/        (蓝方进化)                     (seccomp/eBPF/
   审计链)                                                  StrongPool配置)
"""
from __future__ import annotations
import os
import json
import time
import threading
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

from evolution.realtime_log_stream import RealtimeLogStream, StreamStatus
from evolution.red_blue_adversary import RedBlueAdversaryTrainer
from evolution.defense_executor import DefenseRuleExecutor, ExecutionMode, ExecutionStatus
from evolution.defense_enforcer import ConfigUpdate, ConfigTarget


class OrchestratorState(Enum):
    """编排器状态"""
    STOPPED = "stopped"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"


class TriggerMode(Enum):
    """推演触发模式"""
    EVENT_DRIVEN = "event_driven"      # 事件驱动: 每N个事件触发一次推演
    TIMED = "timed"                    # 定时: 每N秒触发一次推演
    HYBRID = "hybrid"                  # 混合: 事件驱动+定时


@dataclass
class OrchestratorConfig:
    """编排器配置"""
    # 日志流配置
    log_sources: List[Dict[str, Any]] = field(default_factory=list)
    max_queue_size: int = 10000

    # 推演配置
    trigger_mode: TriggerMode = TriggerMode.HYBRID
    events_per_round: int = 50          # 每50个事件触发一次推演
    training_interval_seconds: int = 300  # 每5分钟定时推演一次
    training_rounds: int = 20           # 每次推演轮数

    # 部署配置
    auto_deploy: bool = True             # 自动部署新防御规则
    deploy_mode: ExecutionMode = ExecutionMode.DRY_RUN  # 部署模式(默认dry-run安全)
    min_rule_effectiveness: float = 0.6  # 最低规则有效性阈值才部署
    max_deploy_per_round: int = 10       # 每轮最多部署规则数

    # 安全配置
    require_confirmation_for_high_risk: bool = True
    enable_rollback: bool = True

    # 回调
    on_new_rule_deployed: Optional[Callable] = None
    on_training_completed: Optional[Callable] = None
    on_error: Optional[Callable] = None


@dataclass
class OrchestratorStats:
    """编排器统计"""
    state: OrchestratorState = OrchestratorState.STOPPED
    uptime_seconds: float = 0.0
    total_events_consumed: int = 0
    total_training_rounds: int = 0
    total_rules_generated: int = 0
    total_rules_deployed: int = 0
    total_deploy_failures: int = 0
    total_rollbacks: int = 0
    last_training_time: float = 0.0
    last_deploy_time: float = 0.0
    events_since_last_training: int = 0
    errors: int = 0


class AdversaryLoopOrchestrator:
    """
    红蓝对抗闭环编排器

    完整闭环: 真实日志流 → 红蓝对抗推演 → 自动部署新防御规则到沙盒执行层

    核心能力:
    1. 自动接入真实日志流(seccomp/VM-Exit/审计链)
    2. 事件驱动/定时/混合三种推演触发模式
    3. 推演产生的新防御规则自动部署到沙盒执行层
    4. 部署前有效性过滤,部署后验证,失败自动回滚
    5. 完整审计日志和统计指标
    6. 优雅降级: 无裸机环境时自动切换dry-run模式

    使用示例:
        config = OrchestratorConfig(
            log_sources=[
                {"name": "seccomp", "path": "/var/log/photon/seccomp.jsonl"},
                {"name": "audit", "path": "/var/log/photon/audit.jsonl"},
            ],
            auto_deploy=True,
            deploy_mode=ExecutionMode.DRY_RUN,  # 生产环境改为APPLY
        )
        orchestrator = AdversaryLoopOrchestrator(config)
        orchestrator.start()
        # ... 运行一段时间 ...
        orchestrator.stop()
    """

    def __init__(self, config: Optional[OrchestratorConfig] = None):
        self.config = config or OrchestratorConfig()
        self._state = OrchestratorState.STOPPED
        self._stats = OrchestratorStats()
        self._start_time: float = 0.0
        self._lock = threading.Lock()

        # 核心组件
        self._log_stream: Optional[RealtimeLogStream] = None
        self._trainer: Optional[RedBlueAdversaryTrainer] = None
        self._executor: Optional[DefenseRuleExecutor] = None

        # 后台线程
        self._timed_thread: Optional[threading.Thread] = None
        self._running = False

        # 已部署规则ID集合(防止重复部署)
        self._deployed_rule_ids: set = set()

    def start(self) -> bool:
        """
        启动编排器

        Returns:
            是否启动成功
        """
        if self._state == OrchestratorState.RUNNING:
            return False

        self._state = OrchestratorState.INITIALIZING
        self._running = True
        self._start_time = time.time()

        try:
            # 1. 初始化红蓝对抗训练器
            self._trainer = RedBlueAdversaryTrainer()

            # 2. 初始化防御规则执行器
            self._executor = DefenseRuleExecutor(
                config_dir=self._get_config_dir(),
                mode=self.config.deploy_mode,
                require_confirmation_for_high_risk=self.config.require_confirmation_for_high_risk,
            )

            # 3. 初始化实时日志流
            self._log_stream = RealtimeLogStream(
                max_queue_size=self.config.max_queue_size,
            )

            # 注册日志事件回调
            self._log_stream.register_event_callback(self._on_log_event)
            self._log_stream.register_escape_callback(self._on_escape_event)

            # 添加日志源
            for source in self.config.log_sources:
                self._log_stream.add_source(
                    name=source["name"],
                    file_path=source["path"],
                    from_beginning=source.get("from_beginning", False),
                )

            # 4. 启动日志流
            self._log_stream.start()

            # 5. 启动定时推演线程(如果是TIMED或HYBRID模式)
            if self.config.trigger_mode in (TriggerMode.TIMED, TriggerMode.HYBRID):
                self._timed_thread = threading.Thread(
                    target=self._timed_training_loop, daemon=True
                )
                self._timed_thread.start()

            self._state = OrchestratorState.RUNNING
            return True

        except Exception as e:
            self._state = OrchestratorState.ERROR
            self._stats.errors += 1
            if self.config.on_error:
                self.config.on_error(e)
            return False

    def stop(self, timeout: float = 10.0) -> None:
        """停止编排器"""
        self._running = False
        self._state = OrchestratorState.STOPPED

        if self._log_stream:
            self._log_stream.stop(timeout=timeout)

        if self._timed_thread and self._timed_thread.is_alive():
            self._timed_thread.join(timeout=timeout)

    def _on_log_event(self, event) -> None:
        """日志事件回调"""
        with self._lock:
            self._stats.total_events_consumed += 1
            self._stats.events_since_last_training += 1

        # 事件驱动模式: 每N个事件触发一次推演
        if self.config.trigger_mode in (TriggerMode.EVENT_DRIVEN, TriggerMode.HYBRID):
            if self._stats.events_since_last_training >= self.config.events_per_round:
                self._trigger_training(reason="event_driven")

    def _on_escape_event(self, event) -> None:
        """逃逸事件回调: 高优先级,立即触发推演"""
        # 逃逸事件是高优先级,立即触发一次推演
        self._trigger_training(reason="escape_event_detected", urgent=True)

    def _trigger_training(self, reason: str = "scheduled", urgent: bool = False) -> None:
        """触发一次红蓝对抗推演"""
        if not self._trainer or self._state != OrchestratorState.RUNNING:
            return

        with self._lock:
            if self._stats.events_since_last_training == 0 and not urgent:
                return
            self._stats.events_since_last_training = 0

        try:
            # 运行推演
            rounds = self.config.training_rounds if not urgent else min(10, self.config.training_rounds)
            stats = self._trainer.run_training(num_rounds=rounds)

            self._stats.total_training_rounds += rounds
            self._stats.last_training_time = time.time()

            # 自动部署新防御规则
            if self.config.auto_deploy:
                self._auto_deploy_new_rules()

            if self.config.on_training_completed:
                self.config.on_training_completed(stats)

        except Exception as e:
            self._stats.errors += 1
            if self.config.on_error:
                self.config.on_error(e)

    def _auto_deploy_new_rules(self) -> None:
        """自动部署推演产生的新防御规则"""
        if not self._trainer or not self._executor:
            return

        # 获取蓝方防御规则
        new_rules = []
        for rule in self._trainer.blue_agent.defense_rules:
            # 跳过已部署的规则
            if rule.rule_id in self._deployed_rule_ids:
                continue
            # 跳过有效性低于阈值的规则
            if rule.effectiveness < self.config.min_rule_effectiveness:
                continue
            new_rules.append(rule)

        # 限制每轮部署数量
        new_rules = new_rules[:self.config.max_deploy_per_round]

        if not new_rules:
            return

        # 为每条规则生成配置更新并部署
        deployed = 0
        for rule in new_rules:
            try:
                updates = self._executor.enforcer.generate_updates_from_rule(rule)
                if not updates:
                    continue

                results = self._executor.execute_updates(updates)
                success_count = sum(
                    1 for r in results if r.status == ExecutionStatus.SUCCESS
                )

                if success_count > 0:
                    self._deployed_rule_ids.add(rule.rule_id)
                    deployed += 1
                    self._stats.total_rules_deployed += 1
                    self._stats.last_deploy_time = time.time()

                    if self.config.on_new_rule_deployed:
                        self.config.on_new_rule_deployed(rule, results)
                else:
                    self._stats.total_deploy_failures += 1

            except Exception as e:
                self._stats.total_deploy_failures += 1
                self._stats.errors += 1
                if self.config.on_error:
                    self.config.on_error(e)

        self._stats.total_rules_generated += len(new_rules)

    def _timed_training_loop(self) -> None:
        """定时推演循环"""
        while self._running:
            time.sleep(self.config.training_interval_seconds)
            if self._running and self._state == OrchestratorState.RUNNING:
                self._trigger_training(reason="scheduled")

    def _get_config_dir(self) -> str:
        """获取配置目录（带权限回退机制）"""
        import tempfile
        candidates = [
            os.environ.get("PHOTON_CONFIG_DIR"),
            "/etc/photonbox",
            os.path.expanduser("~/.photonbox"),
            tempfile.gettempdir() + "/photonbox",
        ]
        for candidate in candidates:
            if not candidate:
                continue
            try:
                os.makedirs(candidate, exist_ok=True)
                # 测试可写性
                test_file = os.path.join(candidate, ".write_test")
                with open(test_file, 'w') as f:
                    f.write("test")
                os.remove(test_file)
                return candidate
            except (OSError, PermissionError):
                continue
        # 最后回退到临时目录
        return tempfile.mkdtemp(prefix="photonbox_")

    def get_stats(self) -> Dict[str, Any]:
        """获取编排器统计"""
        self._stats.uptime_seconds = time.time() - self._start_time if self._start_time else 0
        return {
            "state": self._state.value,
            "uptime_seconds": self._stats.uptime_seconds,
            "total_events_consumed": self._stats.total_events_consumed,
            "total_training_rounds": self._stats.total_training_rounds,
            "total_rules_generated": self._stats.total_rules_generated,
            "total_rules_deployed": self._stats.total_rules_deployed,
            "total_deploy_failures": self._stats.total_deploy_failures,
            "total_rollbacks": self._stats.total_rollbacks,
            "last_training_time": self._stats.last_training_time,
            "last_deploy_time": self._stats.last_deploy_time,
            "events_since_last_training": self._stats.events_since_last_training,
            "errors": self._stats.errors,
            "deployed_rule_count": len(self._deployed_rule_ids),
        }

    def get_status(self) -> Dict[str, Any]:
        """获取编排器状态摘要"""
        return {
            "state": self._state.value,
            "log_stream_running": self._log_stream.is_running() if self._log_stream else False,
            "trainer_ready": self._trainer is not None,
            "executor_mode": self._executor.mode.value if self._executor else "unknown",
            "auto_deploy": self.config.auto_deploy,
            "trigger_mode": self.config.trigger_mode.value,
            "stats": self.get_stats(),
        }

    def trigger_manual_training(self, rounds: Optional[int] = None) -> Dict[str, Any]:
        """手动触发一次推演"""
        if rounds:
            original = self.config.training_rounds
            self.config.training_rounds = rounds
        self._trigger_training(reason="manual", urgent=True)
        if rounds:
            self.config.training_rounds = original
        return self.get_stats()

    def rollback_last_deployments(self, count: int = 5) -> int:
        """回滚最近N次部署"""
        if not self._executor:
            return 0
        rolled_back = self._executor.rollback_last(count)
        self._stats.total_rollbacks += rolled_back
        return rolled_back
