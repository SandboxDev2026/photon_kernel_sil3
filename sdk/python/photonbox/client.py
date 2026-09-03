"""
PhotonBox SDK - 客户端模块

统一的客户端接口，整合沙盒执行、安全监控、红蓝对抗。
"""
from __future__ import annotations
from typing import Optional, Dict, Any, List, ContextManager
from contextlib import contextmanager

from .config import SandboxConfig, SecurityLevel
from .sandbox import SandboxSession, ExecutionResult
from .security import SecurityMonitor, EscapeDetectionEngine, EscapeEvent
from .adversary import AdversaryTrainer, AdversaryTrainingResult


class PhotonBoxClient:
    """
    PhotonBox 统一客户端

    整合沙盒执行、安全监控、红蓝对抗的统一接口。
    简化用户上手，一行代码即可使用核心功能。

    快速开始:
        from photonbox import PhotonBoxClient

        # 创建客户端
        client = PhotonBoxClient()

        # 执行代码
        result = client.execute("print('Hello!')")
        print(result.output)

        # 查看安全状态
        print(client.get_security_status())
    """

    def __init__(
        self,
        default_config: Optional[SandboxConfig] = None,
        auto_escape_block: bool = True,
        auto_evolve_defense: bool = False,
    ):
        """
        初始化客户端

        Args:
            default_config: 默认沙盒配置
            auto_escape_block: 自动阻断逃逸尝试
            auto_evolve_defense: 自动进化防御规则
        """
        self.default_config = default_config or SandboxConfig.standard()
        self.security_monitor = SecurityMonitor(auto_escape_block=auto_escape_block)
        self.adversary_trainer = AdversaryTrainer(auto_evolve=auto_evolve_defense)
        self._sessions: Dict[str, SandboxSession] = {}
        self._config = {
            "auto_escape_block": auto_escape_block,
            "auto_evolve_defense": auto_evolve_defense,
            "version": "4.14.0",
        }

    def execute(
        self,
        code: str,
        language: str = "python",
        config: Optional[SandboxConfig] = None,
        **kwargs,
    ) -> ExecutionResult:
        """
        执行代码（一次性）

        Args:
            code: 要执行的代码
            language: 编程语言
            config: 沙盒配置（None使用默认配置）
            **kwargs: 其他执行参数

        Returns:
            执行结果
        """
        effective_config = config or self.default_config
        with self.create_session(effective_config) as session:
            return session.execute(code, language=language, **kwargs)

    @contextmanager
    def create_session(
        self,
        config: Optional[SandboxConfig] = None,
        session_id: Optional[str] = None,
    ) -> ContextManager[SandboxSession]:
        """
        创建沙盒会话（上下文管理器）

        用法:
            with client.create_session() as session:
                result1 = session.execute("x = 1")
                result2 = session.execute("print(x)")

        Args:
            config: 沙盒配置
            session_id: 会话ID

        Yields:
            沙盒会话
        """
        effective_config = config or self.default_config
        session = SandboxSession(effective_config, session_id)
        self._sessions[session.session_id] = session
        try:
            yield session
        finally:
            session.close()
            del self._sessions[session.session_id]

    def get_security_status(self) -> Dict[str, Any]:
        """获取安全状态摘要"""
        return {
            "escape_detection": self.security_monitor.escape_engine.get_stats(),
            "active_sessions": len(self._sessions),
            "adversary_training": self.adversary_trainer.get_stats(),
            "config": self._config,
        }

    def get_recent_escapes(self, limit: int = 10) -> List[Dict[str, Any]]:
        """获取最近的逃逸事件"""
        return [e.to_dict() for e in self.security_monitor.escape_engine.get_recent_events(limit)]

    def train_defense(self, rounds: int = 50) -> AdversaryTrainingResult:
        """运行红蓝对抗训练，进化防御规则"""
        return self.adversary_trainer.train(rounds)

    def ingest_security_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        摄入安全事件，自动触发逃逸检测和防御进化

        Args:
            events: 安全事件列表

        Returns:
            处理结果
        """
        escapes_detected = 0
        for event in events:
            self.security_monitor.ingest_security_event(event)

        evolved = self.adversary_trainer.ingest_real_events(events)

        return {
            "events_ingested": len(events),
            "escapes_detected": self.security_monitor.escape_engine._stats["detected"],
            "defense_evolved": evolved,
        }

    def get_evolved_defense_rules(self) -> List[Dict[str, Any]]:
        """获取进化后的防御规则"""
        return self.adversary_trainer.get_evolved_defense_rules()

    @classmethod
    def quick_start(cls, security_level: str = "standard") -> "PhotonBoxClient":
        """
        快速开始（一行代码创建客户端）

        Args:
            security_level: 安全级别 (light/standard/strong)

        Returns:
            PhotonBoxClient实例
        """
        level_map = {
            "light": SecurityLevel.LIGHT,
            "standard": SecurityLevel.STANDARD,
            "strong": SecurityLevel.STRONG,
        }
        config = SandboxConfig(security_level=level_map.get(security_level, SecurityLevel.STANDARD))
        return cls(default_config=config)
