"""
PhotonBox Python SDK

简化的Python SDK，让用户快速上手使用PhotonBox沙盒的核心功能。

核心功能:
1. 沙盒执行: 在隔离环境中执行代码
2. 安全审计: 查看审计日志和异常事件
3. 红蓝对抗: 启动自进化安全训练
4. 配置管理: 管理沙盒安全策略

快速开始:
    from photonbox import PhotonBoxClient

    client = PhotonBoxClient()
    result = client.execute("print('Hello, PhotonBox!')")
    print(result.output)
"""
from .client import PhotonBoxClient
from .sandbox import SandboxSession, ExecutionResult
from .security import SecurityMonitor, EscapeDetectionEngine
from .adversary import AdversaryTrainer
from .config import SandboxConfig, SecurityLevel

__version__ = "4.14.0"
__all__ = [
    "PhotonBoxClient",
    "SandboxSession",
    "ExecutionResult",
    "SecurityMonitor",
    "EscapeDetectionEngine",
    "AdversaryTrainer",
    "SandboxConfig",
    "SecurityLevel",
]
