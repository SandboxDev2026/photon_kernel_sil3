"""
PhotonBox SDK - 配置模块

简化的配置接口，支持预设安全级别。
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any


class SecurityLevel(Enum):
    """安全级别预设"""
    LIGHT = "light"           # 轻量隔离: fork+seccomp, 低延迟, 内网可信
    STANDARD = "standard"     # 标准隔离: namespace+seccomp+Landlock
    STRONG = "strong"         # 强隔离: Firecracker MicroVM, 公网不可信
    CUSTOM = "custom"         # 自定义配置


@dataclass
class SandboxConfig:
    """
    沙盒配置

    简化的配置接口，用户只需选择安全级别即可。
    高级用户可以自定义各项参数。
    """
    security_level: SecurityLevel = SecurityLevel.STANDARD
    timeout_seconds: int = 30
    memory_limit_mb: int = 256
    cpu_limit: float = 1.0
    enable_network: bool = False
    enable_audit: bool = True
    enable_evolved_defense: bool = False  # 启用自进化防御
    custom_config: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        """根据安全级别应用预设配置"""
        if self.security_level == SecurityLevel.LIGHT:
            self._apply_light_preset()
        elif self.security_level == SecurityLevel.STANDARD:
            self._apply_standard_preset()
        elif self.security_level == SecurityLevel.STRONG:
            self._apply_strong_preset()

    def _apply_light_preset(self):
        """轻量隔离预设"""
        self.timeout_seconds = min(self.timeout_seconds, 60)
        self.memory_limit_mb = min(self.memory_limit_mb, 512)
        self.enable_network = False

    def _apply_standard_preset(self):
        """标准隔离预设"""
        self.timeout_seconds = min(self.timeout_seconds, 120)
        self.memory_limit_mb = min(self.memory_limit_mb, 1024)

    def _apply_strong_preset(self):
        """强隔离预设 (Firecracker MicroVM)"""
        self.timeout_seconds = min(self.timeout_seconds, 300)
        self.memory_limit_mb = min(self.memory_limit_mb, 4096)
        self.enable_evolved_defense = True

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "security_level": self.security_level.value,
            "timeout_seconds": self.timeout_seconds,
            "memory_limit_mb": self.memory_limit_mb,
            "cpu_limit": self.cpu_limit,
            "enable_network": self.enable_network,
            "enable_audit": self.enable_audit,
            "enable_evolved_defense": self.enable_evolved_defense,
            "custom_config": self.custom_config,
        }

    @classmethod
    def light(cls, **kwargs) -> "SandboxConfig":
        """快速创建轻量隔离配置"""
        return cls(security_level=SecurityLevel.LIGHT, **kwargs)

    @classmethod
    def standard(cls, **kwargs) -> "SandboxConfig":
        """快速创建标准隔离配置"""
        return cls(security_level=SecurityLevel.STANDARD, **kwargs)

    @classmethod
    def strong(cls, **kwargs) -> "SandboxConfig":
        """快速创建强隔离配置"""
        return cls(security_level=SecurityLevel.STRONG, **kwargs)
