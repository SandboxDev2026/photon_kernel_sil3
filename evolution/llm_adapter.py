"""
evolution.llm_adapter — LLM 模型适配器

不要抄硬编码 LLM 模型名称、API 密钥逻辑，做一层模型适配器。
支持 OpenAI / Anthropic / 本地模型 / 自定义模型。
"""
from __future__ import annotations
import json
import time
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any


class LLMResponse:
    """LLM 响应"""
    def __init__(self, text: str, model: str = "", usage: Dict[str, int] = None,
                 latency_ms: int = 0, error: str = ""):
        self.text = text
        self.model = model
        self.usage = usage or {}
        self.latency_ms = latency_ms
        self.error = error

    @property
    def success(self) -> bool:
        return not self.error and bool(self.text)


class BaseLLMAdapter(ABC):
    """LLM 适配器基类"""
    def __init__(self, model: str = "default", temperature: float = 0.7,
                 max_tokens: int = 2048, timeout: int = 60):
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.total_calls = 0
        self.total_tokens = 0
        self.total_latency_ms = 0

    @abstractmethod
    def _call_api(self, prompt: str, **kwargs) -> LLMResponse:
        """实际调用 LLM API（子类实现）"""
        pass

    def generate(self, prompt: str, temperature: Optional[float] = None,
                 max_tokens: Optional[int] = None, **kwargs) -> str:
        """
        生成文本

        Args:
            prompt: 提示词
            temperature: 温度（覆盖默认值）
            max_tokens: 最大 token 数（覆盖默认值）

        Returns:
            生成的文本（失败时返回空字符串）
        """
        start = time.time()
        try:
            resp = self._call_api(
                prompt,
                temperature=temperature if temperature is not None else self.temperature,
                max_tokens=max_tokens if max_tokens is not None else self.max_tokens,
                **kwargs
            )
            self.total_calls += 1
            self.total_tokens += resp.usage.get("total_tokens", 0)
            self.total_latency_ms += int((time.time() - start) * 1000)
            return resp.text
        except Exception as e:
            self.total_calls += 1
            return ""

    def get_stats(self) -> Dict[str, Any]:
        """获取调用统计"""
        return {
            "total_calls": self.total_calls,
            "total_tokens": self.total_tokens,
            "avg_latency_ms": self.total_latency_ms / max(1, self.total_calls),
            "model": self.model,
        }


class OpenAIAdapter(BaseLLMAdapter):
    """OpenAI 兼容 API 适配器"""
    def __init__(self, api_key: str = "", base_url: str = "https://api.openai.com/v1",
                 model: str = "gpt-4", **kwargs):
        super().__init__(model=model, **kwargs)
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    def _call_api(self, prompt: str, **kwargs) -> LLMResponse:
        import urllib.request
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": kwargs.get("temperature", self.temperature),
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
        }
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return LLMResponse(
                text=data["choices"][0]["message"]["content"],
                model=data.get("model", self.model),
                usage=data.get("usage", {}),
            )


class AnthropicAdapter(BaseLLMAdapter):
    """Anthropic Claude API 适配器"""
    def __init__(self, api_key: str = "", model: str = "claude-3-sonnet", **kwargs):
        super().__init__(model=model, **kwargs)
        self.api_key = api_key

    def _call_api(self, prompt: str, **kwargs) -> LLMResponse:
        import urllib.request
        payload = {
            "model": self.model,
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            "messages": [{"role": "user", "content": prompt}],
        }
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return LLMResponse(
                text=data["content"][0]["text"],
                model=data.get("model", self.model),
                usage={"total_tokens": data.get("usage", {}).get("input_tokens", 0) +
                       data.get("usage", {}).get("output_tokens", 0)},
            )


class MockLLMAdapter(BaseLLMAdapter):
    """
    Mock LLM 适配器 — 用于测试

    不调用真实 API，返回预设响应。
    """
    def __init__(self, responses: List[str] = None, **kwargs):
        super().__init__(model="mock", **kwargs)
        self.responses = responses or []
        self.response_index = 0

    def _call_api(self, prompt: str, **kwargs) -> LLMResponse:
        if self.response_index < len(self.responses):
            text = self.responses[self.response_index]
            self.response_index += 1
        else:
            # 默认响应：简单回显
            text = f"# Mock response for prompt of length {len(prompt)}\ndef solve(x):\n    return x"
        return LLMResponse(text=text, model="mock", usage={"total_tokens": 100})


class LLMAdapterFactory:
    """LLM 适配器工厂"""
    @staticmethod
    def create(adapter_type: str = "mock", **kwargs) -> BaseLLMAdapter:
        """
        创建 LLM 适配器

        Args:
            adapter_type: openai / anthropic / mock
            **kwargs: 传递给适配器的参数

        Returns:
            LLM 适配器实例
        """
        adapters = {
            "openai": OpenAIAdapter,
            "anthropic": AnthropicAdapter,
            "mock": MockLLMAdapter,
        }
        cls = adapters.get(adapter_type, MockLLMAdapter)
        return cls(**kwargs)
