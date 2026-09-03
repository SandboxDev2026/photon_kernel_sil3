"""
evolution.realtime_log_stream — 生产实时日志流对接

将真实数据适配器从仿真测试样本升级为生产实时日志流:
1. 实时tail审计日志文件，新行实时解析
2. 事件回调机制，支持逃逸检测、防御进化等下游处理
3. 流控与背压，防止事件堆积
4. 多源汇聚，支持同时消费多个日志文件
5. 生产级特性: 断线重连、文件轮转、位置持久化、健康检查

与v26仿真输入的区别:
- v26: 一次性加载生成的测试数据文件
- v28: 持续监听生产日志文件，实时事件驱动
"""
from __future__ import annotations
import os
import json
import time
import threading
import queue
from typing import List, Dict, Any, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum

from evolution.real_data_adapter import (
    RealDataAdapter, SecurityEvent, EventSource
)
from evolution.log_consumer import FileTailConsumer


class StreamStatus(Enum):
    """流状态"""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"
    RECONNECTING = "reconnecting"


@dataclass
class StreamSource:
    """流源配置"""
    name: str
    file_path: str
    source_type: EventSource
    enabled: bool = True
    position_file: Optional[str] = None
    poll_interval: float = 0.1
    from_beginning: bool = False


@dataclass
class StreamStats:
    """流统计"""
    status: StreamStatus = StreamStatus.STOPPED
    total_events: int = 0
    total_anomalies: int = 0
    total_escapes: int = 0
    events_per_second: float = 0.0
    queue_size: int = 0
    uptime_seconds: float = 0.0
    last_event_time: float = 0.0
    errors: int = 0
    sources: Dict[str, Dict[str, Any]] = field(default_factory=dict)


class RealtimeLogStream:
    """
    生产实时日志流

    持续监听生产审计日志文件，实时解析事件，
    驱动逃逸检测、防御进化等下游处理。

    核心特性:
    - 多源汇聚: 同时消费seccomp/VM-Exit/审计链等多个日志
    - 事件回调: 支持注册多个下游处理器
    - 流控背压: 队列满时丢弃最旧事件，防止内存溢出
    - 生产级: 文件轮转检测、位置持久化、健康检查、断线重连
    """

    def __init__(
        self,
        adapter: Optional[RealDataAdapter] = None,
        max_queue_size: int = 10000,
        event_batch_size: int = 100,
        batch_interval_ms: float = 100.0,
    ):
        self.adapter = adapter or RealDataAdapter()
        self.max_queue_size = max_queue_size
        self.event_batch_size = event_batch_size
        self.batch_interval = batch_interval_ms / 1000.0

        self.sources: Dict[str, StreamSource] = {}
        self.consumers: Dict[str, FileTailConsumer] = {}
        self.event_queue: queue.Queue = queue.Queue(maxsize=max_queue_size)

        self._running = False
        self._processor_thread: Optional[threading.Thread] = None
        self._stats = StreamStats()
        self._start_time: float = 0.0
        self._event_count_window: List[float] = []

        # 事件回调
        self._callbacks: List[Callable[[SecurityEvent], None]] = []
        self._anomaly_callbacks: List[Callable[[SecurityEvent], None]] = []
        self._escape_callbacks: List[Callable[[SecurityEvent], None]] = []

    def add_source(
        self,
        name: str,
        file_path: str,
        source_type: EventSource = EventSource.SECCOMP_VIOLATION,
        from_beginning: bool = False,
        poll_interval: float = 0.1,
    ) -> bool:
        """
        添加日志源

        Args:
            name: 源名称
            file_path: 日志文件路径
            source_type: 事件来源类型
            from_beginning: 是否从文件开头开始读取
            poll_interval: 轮询间隔(秒)

        Returns:
            是否添加成功
        """
        if name in self.sources:
            return False

        source = StreamSource(
            name=name,
            file_path=file_path,
            source_type=source_type,
            from_beginning=from_beginning,
            poll_interval=poll_interval,
            position_file=f"{file_path}.offset",
        )
        self.sources[name] = source
        return True

    def remove_source(self, name: str) -> bool:
        """移除日志源"""
        if name not in self.sources:
            return False

        if name in self.consumers:
            self.consumers[name].stop()
            del self.consumers[name]

        del self.sources[name]
        return True

    def register_event_callback(self, callback: Callable[[SecurityEvent], None]) -> None:
        """注册事件回调（所有事件）"""
        self._callbacks.append(callback)

    def register_anomaly_callback(self, callback: Callable[[SecurityEvent], None]) -> None:
        """注册异常事件回调"""
        self._anomaly_callbacks.append(callback)

    def register_escape_callback(self, callback: Callable[[SecurityEvent], None]) -> None:
        """注册逃逸事件回调"""
        self._escape_callbacks.append(callback)

    def start(self) -> bool:
        """
        启动实时日志流

        Returns:
            是否启动成功
        """
        if self._running:
            return False

        self._running = True
        self._stats.status = StreamStatus.STARTING
        self._start_time = time.time()

        # 启动所有源的消费者
        for name, source in self.sources.items():
            if not source.enabled:
                continue
            self._start_consumer(source)

        # 启动事件处理线程
        self._processor_thread = threading.Thread(target=self._process_loop, daemon=True)
        self._processor_thread.start()

        self._stats.status = StreamStatus.RUNNING
        return True

    def _start_consumer(self, source: StreamSource) -> None:
        """启动单个源的消费者"""
        consumer = FileTailConsumer(
            file_path=source.file_path,
            adapter=self.adapter,
            source_type=source.source_type,
            position_file=source.position_file,
            poll_interval=source.poll_interval,
            max_queue_size=self.max_queue_size,
            from_beginning=source.from_beginning,
        )

        # 设置事件回调，将事件放入统一队列
        def on_event(event: SecurityEvent):
            try:
                self.event_queue.put(event, block=False)
            except queue.Full:
                # 队列满，丢弃最旧事件
                try:
                    self.event_queue.get_nowait()
                    self.event_queue.put(event, block=False)
                except Exception:
                    pass

        consumer.on_event = on_event
        consumer.start()
        self.consumers[source.name] = consumer

    def stop(self, timeout: float = 5.0) -> None:
        """停止实时日志流"""
        self._running = False
        self._stats.status = StreamStatus.STOPPED

        # 停止所有消费者
        for consumer in self.consumers.values():
            consumer.stop(timeout=timeout)
        self.consumers.clear()

        # 等待处理线程结束
        if self._processor_thread and self._processor_thread.is_alive():
            self._processor_thread.join(timeout=timeout)

    def _process_loop(self) -> None:
        """事件处理主循环"""
        batch: List[SecurityEvent] = []
        last_batch_time = time.time()

        while self._running:
            try:
                # 批量获取事件
                try:
                    event = self.event_queue.get(timeout=self.batch_interval)
                    batch.append(event)
                except queue.Empty:
                    pass

                # 批量处理条件: 达到批量大小 或 超过批量间隔
                now = time.time()
                if (len(batch) >= self.event_batch_size or
                    (batch and now - last_batch_time >= self.batch_interval)):
                    self._process_batch(batch)
                    batch = []
                    last_batch_time = now

                # 更新统计
                self._update_stats()

            except Exception as e:
                self._stats.errors += 1
                time.sleep(0.1)

    def _process_batch(self, events: List[SecurityEvent]) -> None:
        """处理一批事件"""
        for event in events:
            self._stats.total_events += 1
            self._stats.last_event_time = event.timestamp
            self._event_count_window.append(time.time())

            # 异常事件
            if event.anomaly_type is not None:
                self._stats.total_anomalies += 1
                for cb in self._anomaly_callbacks:
                    try:
                        cb(event)
                    except Exception:
                        pass

            # 高严重度事件视为逃逸尝试
            if event.severity in ["high", "critical"]:
                self._stats.total_escapes += 1
                for cb in self._escape_callbacks:
                    try:
                        cb(event)
                    except Exception:
                        pass

            # 通用事件回调
            for cb in self._callbacks:
                try:
                    cb(event)
                except Exception:
                    pass

    def _update_stats(self) -> None:
        """更新统计信息"""
        now = time.time()
        self._stats.uptime_seconds = now - self._start_time
        self._stats.queue_size = self.event_queue.qsize()

        # 计算每秒事件数（最近10秒窗口）
        cutoff = now - 10.0
        self._event_count_window = [t for t in self._event_count_window if t >= cutoff]
        if self._event_count_window:
            self._stats.events_per_second = len(self._event_count_window) / 10.0
        else:
            self._stats.events_per_second = 0.0

        # 更新各源状态
        for name, consumer in self.consumers.items():
            cs = consumer.get_stats()
            self._stats.sources[name] = {
                "total_consumed": cs.total_consumed,
                "total_events": cs.total_events,
                "total_anomalies": cs.total_anomalies,
                "errors": cs.errors,
                "running": consumer.is_running(),
                "last_position": cs.last_position,
            }

    def get_stats(self) -> StreamStats:
        """获取流统计"""
        return self._stats

    def get_status(self) -> Dict[str, Any]:
        """获取状态摘要"""
        return {
            "status": self._stats.status.value,
            "uptime_seconds": self._stats.uptime_seconds,
            "total_events": self._stats.total_events,
            "total_anomalies": self._stats.total_anomalies,
            "total_escapes": self._stats.total_escapes,
            "events_per_second": self._stats.events_per_second,
            "queue_size": self._stats.queue_size,
            "active_sources": len(self.consumers),
            "errors": self._stats.errors,
        }

    def is_running(self) -> bool:
        """是否正在运行"""
        return self._running

    def health_check(self) -> Dict[str, Any]:
        """健康检查"""
        healthy = self._running and self._stats.status == StreamStatus.RUNNING
        issues = []

        if not self._running:
            issues.append("stream not running")

        if self._stats.errors > 100:
            issues.append(f"high error count: {self._stats.errors}")

        if self._stats.queue_size > self.max_queue_size * 0.8:
            issues.append(f"queue near full: {self._stats.queue_size}/{self.max_queue_size}")

        for name, source in self.sources.items():
            if source.enabled and name not in self.consumers:
                issues.append(f"source {name} enabled but consumer not running")

        return {
            "healthy": healthy and len(issues) == 0,
            "issues": issues,
            "status": self.get_status(),
        }
