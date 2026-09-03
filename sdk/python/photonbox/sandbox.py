"""
PhotonBox SDK - 沙盒执行模块

简化的沙盒执行接口，支持会话式执行。
"""
from __future__ import annotations
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from enum import Enum

from .config import SandboxConfig, SecurityLevel


class ExecutionStatus(Enum):
    """执行状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    KILLED = "killed"
    ESCAPE_DETECTED = "escape_detected"  # 检测到逃逸尝试


@dataclass
class ExecutionResult:
    """
    执行结果

    包含代码执行的输出、状态、安全事件等。
    """
    execution_id: str
    status: ExecutionStatus
    output: str = ""
    error: str = ""
    exit_code: int = -1
    duration_ms: float = 0.0
    memory_used_mb: float = 0.0
    cpu_used_percent: float = 0.0
    security_events: List[Dict[str, Any]] = field(default_factory=list)
    sandbox_id: str = ""
    backend: str = ""  # LightPool / StrongPool
    escape_attempted: bool = False
    escape_blocked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "execution_id": self.execution_id,
            "status": self.status.value,
            "output": self.output,
            "error": self.error,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "memory_used_mb": self.memory_used_mb,
            "cpu_used_percent": self.cpu_used_percent,
            "security_events_count": len(self.security_events),
            "sandbox_id": self.sandbox_id,
            "backend": self.backend,
            "escape_attempted": self.escape_attempted,
            "escape_blocked": self.escape_blocked,
        }


class SandboxSession:
    """
    沙盒会话

    支持在同一个沙盒实例中执行多次代码，
    保持文件系统和环境状态。
    """

    def __init__(
        self,
        config: Optional[SandboxConfig] = None,
        session_id: Optional[str] = None,
    ):
        self.config = config or SandboxConfig.standard()
        self.session_id = session_id or str(uuid.uuid4())[:8]
        self.sandbox_id = f"sbox-{self.session_id}"
        self.created_at = time.time()
        self.executions: List[ExecutionResult] = []
        self._active = False
        self._backend = self._select_backend()

    def _select_backend(self) -> str:
        """根据安全级别选择后端"""
        if self.config.security_level == SecurityLevel.STRONG:
            return "StrongPool"
        elif self.config.security_level == SecurityLevel.LIGHT:
            return "LightPool"
        return "LightPool"  # 默认使用LightPool

    def execute(
        self,
        code: str,
        language: str = "python",
        timeout: Optional[int] = None,
    ) -> ExecutionResult:
        """
        在沙盒中执行代码

        Args:
            code: 要执行的代码
            language: 编程语言 (python/javascript/shell)
            timeout: 超时时间(秒), None使用配置默认值

        Returns:
            执行结果
        """
        execution_id = str(uuid.uuid4())[:12]
        start_time = time.time()
        effective_timeout = timeout or self.config.timeout_seconds

        # 模拟执行（实际SDK会调用gRPC/HTTP API）
        result = ExecutionResult(
            execution_id=execution_id,
            status=ExecutionStatus.COMPLETED,
            output=f"[PhotonBox {self._backend}] Executed {len(code)} bytes of {language} code",
            exit_code=0,
            duration_ms=(time.time() - start_time) * 1000,
            sandbox_id=self.sandbox_id,
            backend=self._backend,
        )

        self.executions.append(result)
        return result

    def execute_file(self, file_path: str, **kwargs) -> ExecutionResult:
        """执行文件中的代码"""
        with open(file_path, 'r') as f:
            code = f.read()
        return self.execute(code, **kwargs)

    def get_security_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取会话中的安全事件"""
        all_events = []
        for exec_result in self.executions:
            all_events.extend(exec_result.security_events)
        return all_events[-limit:]

    def close(self) -> None:
        """关闭沙盒会话，释放资源"""
        self._active = False

    @property
    def is_active(self) -> bool:
        """会话是否活跃"""
        return self._active

    @property
    def total_executions(self) -> int:
        """总执行次数"""
        return len(self.executions)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
