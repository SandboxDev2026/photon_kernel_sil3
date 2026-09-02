"""
evolution.sandbox_client — 沙盒客户端

所有代码执行必须通过此客户端调用 photon_kernel_sil3 的 HTTP API，
禁止本地 exec/eval 执行生成代码。
"""
from __future__ import annotations
import json
from urllib.parse import urlparse
import time
import urllib.request
import urllib.error
from typing import Optional, Dict, Any


class SandboxResult:
    """沙盒执行结果"""
    def __init__(self, success: bool, output: str = "", error: str = "",
                 execution_time_ms: int = 0, risk_score: int = 0,
                 backend: str = "", security_alert: bool = False):
        self.success = success
        self.output = output
        self.error = error
        self.execution_time_ms = execution_time_ms
        self.risk_score = risk_score
        self.backend = backend
        self.security_alert = security_alert

    def __repr__(self) -> str:
        return (f"SandboxResult(success={self.success}, time={self.execution_time_ms}ms, "
                f"risk={self.risk_score}, backend={self.backend})")


def _validate_url(url: str, allowed_schemes=("http", "https")) -> str:
    """校验URL scheme, 防止 file:// 等危险scheme和SSRF"""
    if not url:
        raise ValueError("URL cannot be empty")
    parsed = urlparse(url)
    if parsed.scheme not in allowed_schemes:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}, allowed: {allowed_schemes}")
    if parsed.hostname in ("169.254.169.254", "metadata.google.internal", "100.100.100.200"):
        raise ValueError(f"Blocked access to cloud metadata service: {parsed.hostname}")
    return url


class SandboxClient:
    """
    photon_kernel_sil3 沙盒 HTTP 客户端

    所有 GA 变异/交叉生成的代码必须通过此客户端执行，
    绝对禁止本地 exec/eval。
    """
    def __init__(self, base_url: str = "http://127.0.0.1:8080",
                 timeout: int = 30, max_retries: int = 2):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries

    def execute(self, code: str, language: str = "python",
                task_id: str = "") -> SandboxResult:
        """
        提交代码到沙盒执行

        Args:
            code: 要执行的代码
            language: 编程语言 (python/node/bash)
            task_id: 任务ID（用于审计追踪）

        Returns:
            SandboxResult: 执行结果
        """
        payload = {
            "code": code,
            "language": language,
            "task_id": task_id,
        }
        url = f"{self.base_url}/execute"
        start_time = time.time()

        for attempt in range(self.max_retries + 1):
            try:
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    elapsed_ms = int((time.time() - start_time) * 1000)
                    return SandboxResult(
                        success=data.get("status") == "ok",
                        output=data.get("output", ""),
                        error=data.get("error", ""),
                        execution_time_ms=elapsed_ms,
                        risk_score=data.get("risk_score", 0),
                        backend=data.get("backend", ""),
                        security_alert=data.get("security_alert", False),
                    )
            except urllib.error.HTTPError as e:
                if attempt < self.max_retries:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                elapsed_ms = int((time.time() - start_time) * 1000)
                return SandboxResult(
                    success=False,
                    error=f"HTTP {e.code}: {e.reason}",
                    execution_time_ms=elapsed_ms,
                )
            except Exception as e:
                if attempt < self.max_retries:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                elapsed_ms = int((time.time() - start_time) * 1000)
                return SandboxResult(
                    success=False,
                    error=f"Sandbox connection error: {str(e)}",
                    execution_time_ms=elapsed_ms,
                )

        return SandboxResult(success=False, error="Max retries exceeded")

    def health_check(self) -> bool:
        """检查沙盒服务是否可用"""
        try:
            req = urllib.request.Request(f"{self.base_url}/health")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("status") == "ok"
        except Exception:
            return False

    def get_capabilities(self) -> Dict[str, Any]:
        """获取沙盒能力矩阵"""
        try:
            req = urllib.request.Request(f"{self.base_url}/capabilities")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return {}
