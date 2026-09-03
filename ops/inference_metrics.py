"""
InferenceMetrics — 推理相关指标监控

除了基础的资源水位，重点监控推理相关的指标：
- QPS（每秒查询数）
- 首Token延迟（TTFT, Time To First Token）
- Token生成速度（Tokens/sec）
- 显存碎片率（控制在15%以下）
- 请求队列深度
- 错误率
- P50/P95/P99延迟

设计原则：
1. 轻量级，无外部依赖（纯Python实现）
2. 支持滑动窗口统计（最近1/5/15分钟）
3. 支持Prometheus格式导出
4. 支持告警阈值配置
5. 线程安全（多线程环境下可安全使用）
"""

import time
import threading
import math
from collections import deque
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Deque
from enum import Enum


class MetricType(Enum):
    """指标类型"""
    COUNTER = "counter"  # 计数器（只增不减）
    GAUGE = "gauge"  # 仪表盘（可增可减）
    HISTOGRAM = "histogram"  # 直方图（分布统计）
    SUMMARY = "summary"  # 摘要（分位数统计）


@dataclass
class RequestRecord:
    """请求记录"""
    timestamp: float
    latency_ms: float  # 总延迟
    ttft_ms: float  # 首Token延迟
    input_tokens: int
    output_tokens: int
    success: bool
    error_type: str = ""
    queue_depth: int = 0  # 请求时的队列深度


@dataclass
class MetricSnapshot:
    """指标快照"""
    timestamp: float
    qps: float = 0.0
    active_requests: int = 0
    queue_depth: int = 0
    error_rate: float = 0.0
    avg_latency_ms: float = 0.0
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    avg_ttft_ms: float = 0.0
    p95_ttft_ms: float = 0.0
    token_generation_speed: float = 0.0  # tokens/sec
    input_throughput: float = 0.0  # tokens/sec
    output_throughput: float = 0.0  # tokens/sec
    vram_usage_gb: float = 0.0
    vram_total_gb: float = 0.0
    vram_fragmentation_rate: float = 0.0  # 显存碎片率
    gpu_utilization: float = 0.0  # GPU利用率(0-100)
    success_count: int = 0
    error_count: int = 0
    total_requests: int = 0


class InferenceMetrics:
    """
    推理指标监控器

    使用示例：
        metrics = InferenceMetrics()

        # 记录请求
        metrics.record_request(
            latency_ms=120.5,
            ttft_ms=45.2,
            input_tokens=100,
            output_tokens=50,
            success=True,
        )

        # 更新GPU指标
        metrics.update_gpu(vram_usage_gb=12.5, vram_total_gb=24.0,
                           vram_fragmentation=8.5, gpu_util=75.0)

        # 获取快照
        snapshot = metrics.get_snapshot()
        print(f"QPS: {snapshot.qps}, P99延迟: {snapshot.p99_latency_ms}ms")

        # 导出Prometheus格式
        prom = metrics.export_prometheus()
    """

    def __init__(self, window_seconds: int = 300, max_records: int = 10000):
        """
        初始化指标监控器

        Args:
            window_seconds: 滑动窗口大小（秒），默认5分钟
            max_records: 最大记录数，防止内存溢出
        """
        self.window_seconds = window_seconds
        self.max_records = max_records
        self._lock = threading.Lock()

        # 请求记录（滑动窗口）
        self._requests: Deque[RequestRecord] = deque(maxlen=max_records)

        # 计数器
        self._total_requests = 0
        self._total_success = 0
        self._total_errors = 0
        self._total_input_tokens = 0
        self._total_output_tokens = 0

        # 实时指标
        self._active_requests = 0
        self._queue_depth = 0
        self._vram_usage_gb = 0.0
        self._vram_total_gb = 0.0
        self._vram_fragmentation = 0.0
        self._gpu_utilization = 0.0

        # 启动时间
        self._start_time = time.time()

    def record_request(self, latency_ms: float, ttft_ms: float,
                       input_tokens: int, output_tokens: int,
                       success: bool, error_type: str = "",
                       queue_depth: int = 0) -> None:
        """记录一个请求"""
        record = RequestRecord(
            timestamp=time.time(),
            latency_ms=latency_ms,
            ttft_ms=ttft_ms,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            success=success,
            error_type=error_type,
            queue_depth=queue_depth,
        )

        with self._lock:
            self._requests.append(record)
            self._total_requests += 1
            self._total_input_tokens += input_tokens
            self._total_output_tokens += output_tokens
            if success:
                self._total_success += 1
            else:
                self._total_errors += 1

    def start_request(self) -> None:
        """开始一个请求（增加活跃请求数）"""
        with self._lock:
            self._active_requests += 1

    def end_request(self) -> None:
        """结束一个请求（减少活跃请求数）"""
        with self._lock:
            if self._active_requests > 0:
                self._active_requests -= 1

    def update_queue_depth(self, depth: int) -> None:
        """更新请求队列深度"""
        with self._lock:
            self._queue_depth = max(0, depth)

    def update_gpu(self, vram_usage_gb: float, vram_total_gb: float,
                   vram_fragmentation: float, gpu_util: float) -> None:
        """更新GPU指标"""
        with self._lock:
            self._vram_usage_gb = max(0.0, vram_usage_gb)
            self._vram_total_gb = max(0.0, vram_total_gb)
            self._vram_fragmentation = max(0.0, min(100.0, vram_fragmentation))
            self._gpu_utilization = max(0.0, min(100.0, gpu_util))

    def _calculate_basic_stats(self, snapshot: MetricSnapshot, window_requests: list, elapsed: float):
        """计算基础统计（请求数、成功率、错误率、QPS）"""
        snapshot.total_requests = len(window_requests)
        snapshot.success_count = sum(1 for r in window_requests if r.success)
        snapshot.error_count = snapshot.total_requests - snapshot.success_count
        snapshot.error_rate = snapshot.error_count / snapshot.total_requests * 100

        # QPS
        if elapsed > 0:
            snapshot.qps = snapshot.total_requests / elapsed

    def _calculate_latency_stats(self, snapshot: MetricSnapshot, window_requests: list):
        """计算延迟统计（avg/p50/p95/p99 + 首Token延迟）"""
        # 延迟统计
        latencies = sorted([r.latency_ms for r in window_requests])
        snapshot.avg_latency_ms = sum(latencies) / len(latencies)
        snapshot.p50_latency_ms = self._percentile(latencies, 50)
        snapshot.p95_latency_ms = self._percentile(latencies, 95)
        snapshot.p99_latency_ms = self._percentile(latencies, 99)

        # 首Token延迟
        ttfts = sorted([r.ttft_ms for r in window_requests])
        snapshot.avg_ttft_ms = sum(ttfts) / len(ttfts)
        snapshot.p95_ttft_ms = self._percentile(ttfts, 95)

    def _calculate_token_stats(self, snapshot: MetricSnapshot, window_requests: list, elapsed: float):
        """计算Token吞吐量统计"""
        total_input = sum(r.input_tokens for r in window_requests)
        total_output = sum(r.output_tokens for r in window_requests)
        total_latency_sec = sum(r.latency_ms for r in window_requests) / 1000

        if total_latency_sec > 0:
            snapshot.token_generation_speed = total_output / total_latency_sec
            snapshot.input_throughput = total_input / elapsed if elapsed > 0 else 0
            snapshot.output_throughput = total_output / elapsed if elapsed > 0 else 0

    def _fill_realtime_metrics(self, snapshot: MetricSnapshot):
        """填充实时指标（活跃请求、队列深度、VRAM、GPU利用率）"""
        snapshot.active_requests = self._active_requests
        snapshot.queue_depth = self._queue_depth
        snapshot.vram_usage_gb = self._vram_usage_gb
        snapshot.vram_total_gb = self._vram_total_gb
        snapshot.vram_fragmentation_rate = self._vram_fragmentation
        snapshot.gpu_utilization = self._gpu_utilization

    def get_snapshot(self) -> MetricSnapshot:
        """获取指标快照（滑动窗口内的统计）（优化版：拆分为4个子函数）"""
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds

            # 过滤窗口内的请求
            window_requests = [r for r in self._requests if r.timestamp >= cutoff]

            snapshot = MetricSnapshot(timestamp=now)

            if not window_requests:
                self._fill_realtime_metrics(snapshot)
                return snapshot

            elapsed = min(self.window_seconds, now - window_requests[0].timestamp)

            # 1. 基础统计
            self._calculate_basic_stats(snapshot, window_requests, elapsed)

            # 2. 延迟统计
            self._calculate_latency_stats(snapshot, window_requests)

            # 3. Token吞吐量统计
            self._calculate_token_stats(snapshot, window_requests, elapsed)

            # 4. 实时指标
            self._fill_realtime_metrics(snapshot)

            return snapshot

    def record_request(self, latency_ms: float, ttft_ms: float,
                       input_tokens: int, output_tokens: int,
                       success: bool, error_type: str = "",
                       queue_depth: int = 0) -> None:
        """记录一个请求"""
        record = RequestRecord(
            timestamp=time.time(),
            latency_ms=latency_ms,
            ttft_ms=ttft_ms,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            success=success,
            error_type=error_type,
            queue_depth=queue_depth,
        )

        with self._lock:
            self._requests.append(record)
            self._total_requests += 1
            self._total_input_tokens += input_tokens
            self._total_output_tokens += output_tokens
            if success:
                self._total_success += 1
            else:
                self._total_errors += 1

    def start_request(self) -> None:
        """开始一个请求（增加活跃请求数）"""
        with self._lock:
            self._active_requests += 1

    def end_request(self) -> None:
        """结束一个请求（减少活跃请求数）"""
        with self._lock:
            if self._active_requests > 0:
                self._active_requests -= 1

    def update_queue_depth(self, depth: int) -> None:
        """更新请求队列深度"""
        with self._lock:
            self._queue_depth = max(0, depth)

    def update_gpu(self, vram_usage_gb: float, vram_total_gb: float,
                   vram_fragmentation: float, gpu_util: float) -> None:
        """更新GPU指标"""
        with self._lock:
            self._vram_usage_gb = max(0.0, vram_usage_gb)
            self._vram_total_gb = max(0.0, vram_total_gb)
            self._vram_fragmentation = max(0.0, min(100.0, vram_fragmentation))
            self._gpu_utilization = max(0.0, min(100.0, gpu_util))

    def get_snapshot(self) -> MetricSnapshot:
        """获取指标快照（滑动窗口内的统计）"""
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds

            # 过滤窗口内的请求
            window_requests = [r for r in self._requests if r.timestamp >= cutoff]

            snapshot = MetricSnapshot(timestamp=now)

            if not window_requests:
                snapshot.vram_usage_gb = self._vram_usage_gb
                snapshot.vram_total_gb = self._vram_total_gb
                snapshot.vram_fragmentation_rate = self._vram_fragmentation
                snapshot.gpu_utilization = self._gpu_utilization
                snapshot.active_requests = self._active_requests
                snapshot.queue_depth = self._queue_depth
                return snapshot

            # 基础统计
            snapshot.total_requests = len(window_requests)
            snapshot.success_count = sum(1 for r in window_requests if r.success)
            snapshot.error_count = snapshot.total_requests - snapshot.success_count
            snapshot.error_rate = snapshot.error_count / snapshot.total_requests * 100

            # QPS
            elapsed = min(self.window_seconds, now - window_requests[0].timestamp)
            if elapsed > 0:
                snapshot.qps = snapshot.total_requests / elapsed

            # 延迟统计
            latencies = sorted([r.latency_ms for r in window_requests])
            snapshot.avg_latency_ms = sum(latencies) / len(latencies)
            snapshot.p50_latency_ms = self._percentile(latencies, 50)
            snapshot.p95_latency_ms = self._percentile(latencies, 95)
            snapshot.p99_latency_ms = self._percentile(latencies, 99)

            # 首Token延迟
            ttfts = sorted([r.ttft_ms for r in window_requests])
            snapshot.avg_ttft_ms = sum(ttfts) / len(ttfts)
            snapshot.p95_ttft_ms = self._percentile(ttfts, 95)

            # Token吞吐量
            total_input = sum(r.input_tokens for r in window_requests)
            total_output = sum(r.output_tokens for r in window_requests)
            total_latency_sec = sum(r.latency_ms for r in window_requests) / 1000

            if total_latency_sec > 0:
                snapshot.token_generation_speed = total_output / total_latency_sec
                snapshot.input_throughput = total_input / elapsed if elapsed > 0 else 0
                snapshot.output_throughput = total_output / elapsed if elapsed > 0 else 0

            # 实时指标
            snapshot.active_requests = self._active_requests
            snapshot.queue_depth = self._queue_depth
            snapshot.vram_usage_gb = self._vram_usage_gb
            snapshot.vram_total_gb = self._vram_total_gb
            snapshot.vram_fragmentation_rate = self._vram_fragmentation
            snapshot.gpu_utilization = self._gpu_utilization

            return snapshot

    def _check_latency_alerts(self, snapshot, thresholds: Dict[str, float]) -> List[Dict[str, Any]]:
        """检查延迟相关告警"""
        alerts = []
        p99_threshold = thresholds.get("p99_latency_ms", 500)
        if snapshot.p99_latency_ms > p99_threshold:
            alerts.append({"level": "critical", "metric": "p99_latency_ms",
                "value": snapshot.p99_latency_ms, "threshold": p99_threshold,
                "message": f"P99延迟 {snapshot.p99_latency_ms:.1f}ms 超过阈值 {p99_threshold}ms"})
        return alerts

    def _check_error_rate_alerts(self, snapshot, thresholds: Dict[str, float]) -> List[Dict[str, Any]]:
        """检查错误率告警"""
        alerts = []
        error_threshold = thresholds.get("error_rate", 1.0)
        if snapshot.error_rate > error_threshold:
            alerts.append({"level": "critical", "metric": "error_rate",
                "value": snapshot.error_rate, "threshold": error_threshold,
                "message": f"错误率 {snapshot.error_rate:.2f}% 超过阈值 {error_threshold}%"})
        return alerts

    def _check_vram_alerts(self, snapshot, thresholds: Dict[str, float]) -> List[Dict[str, Any]]:
        """检查显存相关告警"""
        alerts = []
        frag_threshold = thresholds.get("vram_fragmentation_rate", 15)
        if snapshot.vram_fragmentation_rate > frag_threshold:
            alerts.append({"level": "warning", "metric": "vram_fragmentation_rate",
                "value": snapshot.vram_fragmentation_rate, "threshold": frag_threshold,
                "message": f"显存碎片率 {snapshot.vram_fragmentation_rate:.1f}% 超过阈值 {frag_threshold}%"})
        return alerts

    def _check_gpu_alerts(self, snapshot, thresholds: Dict[str, float]) -> List[Dict[str, Any]]:
        """检查GPU利用率告警"""
        alerts = []
        gpu_high = thresholds.get("gpu_utilization_high", 85)
        gpu_low = thresholds.get("gpu_utilization_low", 70)
        if snapshot.gpu_utilization > gpu_high:
            alerts.append({"level": "warning", "metric": "gpu_utilization",
                "value": snapshot.gpu_utilization, "threshold": gpu_high,
                "message": f"GPU利用率 {snapshot.gpu_utilization:.1f}% 超过阈值 {gpu_high}%，建议扩容"})
        elif snapshot.gpu_utilization > 0 and snapshot.gpu_utilization < gpu_low:
            alerts.append({"level": "info", "metric": "gpu_utilization_low",
                "value": snapshot.gpu_utilization, "threshold": gpu_low,
                "message": f"GPU利用率 {snapshot.gpu_utilization:.1f}% 低于阈值 {gpu_low}%，建议缩容"})
        return alerts

    def _check_queue_alerts(self, snapshot, thresholds: Dict[str, float]) -> List[Dict[str, Any]]:
        """检查队列深度告警"""
        alerts = []
        queue_threshold = thresholds.get("queue_depth", 100)
        if snapshot.queue_depth > queue_threshold:
            alerts.append({"level": "warning", "metric": "queue_depth",
                "value": snapshot.queue_depth, "threshold": queue_threshold,
                "message": f"请求队列深度 {snapshot.queue_depth} 超过阈值 {queue_threshold}"})
        return alerts

    def check_alerts(self, thresholds: Dict[str, float]) -> List[Dict[str, Any]]:
        """检查所有告警（优化版：拆分成多个子函数）"""
        snapshot = self.get_snapshot()
        alerts = []
        alerts.extend(self._check_latency_alerts(snapshot, thresholds))
        alerts.extend(self._check_error_rate_alerts(snapshot, thresholds))
        alerts.extend(self._check_vram_alerts(snapshot, thresholds))
        alerts.extend(self._check_gpu_alerts(snapshot, thresholds))
        alerts.extend(self._check_queue_alerts(snapshot, thresholds))
        return alerts

    def export_prometheus(self) -> str:
        """导出Prometheus格式指标"""
        snapshot = self.get_snapshot()
        lines = [
            "# HELP photon_inference_qps Queries per second",
            "# TYPE photon_inference_qps gauge",
            f"photon_inference_qps {snapshot.qps}",
            "",
            "# HELP photon_inference_active_requests Active requests",
            "# TYPE photon_inference_active_requests gauge",
            f"photon_inference_active_requests {snapshot.active_requests}",
            "",
            "# HELP photon_inference_queue_depth Request queue depth",
            "# TYPE photon_inference_queue_depth gauge",
            f"photon_inference_queue_depth {snapshot.queue_depth}",
            "",
            "# HELP photon_inference_error_rate Error rate percentage",
            "# TYPE photon_inference_error_rate gauge",
            f"photon_inference_error_rate {snapshot.error_rate}",
            "",
            "# HELP photon_inference_latency_ms Latency in milliseconds",
            "# TYPE photon_inference_latency_ms summary",
            f"photon_inference_latency_ms{{quantile=\"0.5\"}} {snapshot.p50_latency_ms}",
            f"photon_inference_latency_ms{{quantile=\"0.95\"}} {snapshot.p95_latency_ms}",
            f"photon_inference_latency_ms{{quantile=\"0.99\"}} {snapshot.p99_latency_ms}",
            f"photon_inference_latency_ms_sum {snapshot.avg_latency_ms * snapshot.total_requests}",
            f"photon_inference_latency_ms_count {snapshot.total_requests}",
            "",
            "# HELP photon_inference_ttft_ms Time to first token in milliseconds",
            "# TYPE photon_inference_ttft_ms summary",
            f"photon_inference_ttft_ms{{quantile=\"0.95\"}} {snapshot.p95_ttft_ms}",
            "",
            "# HELP photon_inference_token_speed Token generation speed tokens/sec",
            "# TYPE photon_inference_token_speed gauge",
            f"photon_inference_token_speed {snapshot.token_generation_speed}",
            "",
            "# HELP photon_vram_usage_gb VRAM usage in GB",
            "# TYPE photon_vram_usage_gb gauge",
            f"photon_vram_usage_gb {snapshot.vram_usage_gb}",
            "",
            "# HELP photon_vram_total_gb VRAM total in GB",
            "# TYPE photon_vram_total_gb gauge",
            f"photon_vram_total_gb {snapshot.vram_total_gb}",
            "",
            "# HELP photon_vram_fragmentation_rate VRAM fragmentation rate percentage",
            "# TYPE photon_vram_fragmentation_rate gauge",
            f"photon_vram_fragmentation_rate {snapshot.vram_fragmentation_rate}",
            "",
            "# HELP photon_gpu_utilization GPU utilization percentage",
            "# TYPE photon_gpu_utilization gauge",
            f"photon_gpu_utilization {snapshot.gpu_utilization}",
            "",
        ]
        return "\n".join(lines)

    def get_counters(self) -> Dict[str, Any]:
        """获取累计计数器"""
        with self._lock:
            return {
                "total_requests": self._total_requests,
                "total_success": self._total_success,
                "total_errors": self._total_errors,
                "total_input_tokens": self._total_input_tokens,
                "total_output_tokens": self._total_output_tokens,
                "uptime_seconds": time.time() - self._start_time,
            }

    def reset(self) -> None:
        """重置所有指标"""
        with self._lock:
            self._requests.clear()
            self._total_requests = 0
            self._total_success = 0
            self._total_errors = 0
            self._total_input_tokens = 0
            self._total_output_tokens = 0
            self._active_requests = 0
            self._queue_depth = 0
            self._start_time = time.time()

    @staticmethod
    def _percentile(sorted_data: List[float], p: float) -> float:
        """计算百分位数"""
        if not sorted_data:
            return 0.0
        k = (len(sorted_data) - 1) * p / 100
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_data[int(k)]
        return sorted_data[int(f)] * (c - k) + sorted_data[int(c)] * (k - f)
