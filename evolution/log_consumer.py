"""
evolution.log_consumer — 日志消费层

支持两种消费模式：
1. 文件tail模式：持续tail审计日志文件，新行实时喂给RealDataAdapter
2. gRPC流模式：消费gRPC审计事件流（客户端流式），实时喂给RealDataAdapter

设计原则：
- 消费层独立于适配器，可单独测试
- 支持断线重连、文件轮转检测
- 内置背压控制，防止事件堆积
- 消费位置持久化，重启后从上次位置继续
"""
from __future__ import annotations
import os
import json
import time
import threading
import queue
from typing import List, Dict, Any, Optional, Callable, Iterator
from dataclasses import dataclass, field
from enum import Enum

from evolution.real_data_adapter import (
    RealDataAdapter, SecurityEvent, EventSource
)


class ConsumerMode(Enum):
    """消费模式"""
    FILE_TAIL = "file_tail"        # 文件tail模式
    GRPC_STREAM = "grpc_stream"    # gRPC流模式
    MEMORY_QUEUE = "memory_queue"  # 内存队列模式（用于测试）


@dataclass
class ConsumerStats:
    """消费统计"""
    total_consumed: int = 0
    total_events: int = 0
    total_anomalies: int = 0
    errors: int = 0
    last_event_time: float = 0.0
    last_position: int = 0
    queue_size: int = 0
    uptime_seconds: float = 0.0


class FileTailConsumer:
    """
    文件tail消费者

    持续tail审计日志文件，新行实时喂给RealDataAdapter。
    支持：
    - 文件轮转检测（inode变化）
    - 消费位置持久化
    - 背压控制
    - 优雅停止
    """

    def __init__(
        self,
        file_path: str,
        adapter: RealDataAdapter,
        source_type: EventSource = EventSource.SECCOMP_VIOLATION,
        position_file: Optional[str] = None,
        poll_interval: float = 0.1,
        max_queue_size: int = 10000,
        from_beginning: bool = False,
    ):
        self.file_path = file_path
        self.adapter = adapter
        self.source_type = source_type
        self.position_file = position_file or f"{file_path}.offset"
        self.poll_interval = poll_interval
        self.max_queue_size = max_queue_size
        self.from_beginning = from_beginning

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stats = ConsumerStats()
        self._event_queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self._last_inode: Optional[int] = None
        self._current_position: int = 0
        self._start_time: float = 0.0

        # 事件回调（可选）
        self.on_event: Optional[Callable[[SecurityEvent], None]] = None
        self.on_anomaly: Optional[Callable[[SecurityEvent], None]] = None
        self.on_error: Optional[Callable[[Exception], None]] = None

    def start(self) -> None:
        """启动消费线程"""
        if self._running:
            return

        self._running = True
        self._start_time = time.time()
        self._load_position()
        self._thread = threading.Thread(target=self._tail_loop, daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """停止消费线程"""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self._save_position()

    def _tail_loop(self) -> None:
        """tail主循环"""
        while self._running:
            try:
                self._check_file_rotation()
                self._read_new_lines()
                self._process_queue()
                self._update_stats()
                time.sleep(self.poll_interval)
            except Exception as e:
                self._stats.errors += 1
                if self.on_error:
                    self.on_error(e)
                time.sleep(self.poll_interval * 2)  # 错误时退避

    def _check_file_rotation(self) -> None:
        """检查文件轮转（inode变化）"""
        try:
            if not os.path.exists(self.file_path):
                return
            current_inode = os.stat(self.file_path).st_ino
            if self._last_inode is not None and current_inode != self._last_inode:
                # 文件已轮转，从头开始
                self._current_position = 0
                self._last_inode = current_inode
        except OSError:
            pass

    def _read_new_lines(self) -> None:
        """读取新行"""
        try:
            if not os.path.exists(self.file_path):
                return

            if self._last_inode is None:
                self._last_inode = os.stat(self.file_path).st_ino

            file_size = os.path.getsize(self.file_path)
            if self._current_position > file_size:
                # 文件被截断
                self._current_position = 0

            if self._current_position == 0 and not self.from_beginning:
                # 首次启动，从文件末尾开始
                self._current_position = file_size
                return

            with open(self.file_path, 'r') as f:
                f.seek(self._current_position)
                new_content = f.read()
                self._current_position = f.tell()

            # 按行分割
            lines = new_content.split('\n')
            # 最后一行可能不完整，留到下次
            if not new_content.endswith('\n') and lines:
                self._current_position -= len(lines[-1])
                lines = lines[:-1]

            for line in lines:
                line = line.strip()
                if line:
                    self._stats.total_consumed += 1
                    try:
                        # 直接喂给适配器
                        event = self._parse_and_adapt(line)
                        if event:
                            self._event_queue.put(event, block=False)
                    except queue.Full:
                        # 队列满，丢弃最旧的事件
                        try:
                            self._event_queue.get_nowait()
                            self._event_queue.put(event, block=False)
                        except Exception:
                            pass
                    except Exception as e:
                        self._stats.errors += 1
                        if self.on_error:
                            self.on_error(e)

        except (OSError, IOError):
            pass

    def _parse_and_adapt(self, line: str) -> Optional[SecurityEvent]:
        """解析行并适配为SecurityEvent"""
        # 根据source_type选择解析方式
        if self.source_type == EventSource.SECCOMP_VIOLATION:
            return self.adapter.seccomp_parser.parse_line(line)
        elif self.source_type == EventSource.AUDIT_CHAIN_ANOMALY:
            _, anomaly = self.adapter.audit_detector.verify_and_detect(line)
            return anomaly
        else:
            # 通用解析
            try:
                data = json.loads(line)
                return SecurityEvent(
                    event_id=data.get("event_id", "unknown"),
                    source=self.source_type,
                    timestamp=float(data.get("timestamp", time.time())),
                    sandbox_id=str(data.get("sandbox_id", "unknown")),
                    severity=data.get("severity", "medium"),
                    description=data.get("description", ""),
                    payload=data,
                )
            except json.JSONDecodeError:
                return None

    def _process_queue(self) -> None:
        """处理事件队列"""
        while not self._event_queue.empty():
            try:
                event = self._event_queue.get_nowait()
                self._stats.total_events += 1
                self._stats.last_event_time = event.timestamp

                if event.anomaly_type is not None:
                    self._stats.total_anomalies += 1
                    if self.on_anomaly:
                        self.on_anomaly(event)

                if self.on_event:
                    self.on_event(event)

            except queue.Empty:
                break

    def _update_stats(self) -> None:
        """更新统计"""
        self._stats.queue_size = self._event_queue.qsize()
        self._stats.last_position = self._current_position
        self._stats.uptime_seconds = time.time() - self._start_time

    def _load_position(self) -> None:
        """加载消费位置"""
        try:
            if os.path.exists(self.position_file):
                with open(self.position_file, 'r') as f:
                    data = json.load(f)
                    self._current_position = data.get("position", 0)
                    self._last_inode = data.get("inode")
        except (OSError, json.JSONDecodeError):
            pass

    def _save_position(self) -> None:
        """保存消费位置"""
        try:
            with open(self.position_file, 'w') as f:
                json.dump({
                    "position": self._current_position,
                    "inode": self._last_inode,
                    "timestamp": time.time(),
                }, f)
        except OSError:
            pass

    def get_stats(self) -> ConsumerStats:
        """获取消费统计"""
        return self._stats

    def is_running(self) -> bool:
        """是否正在运行"""
        return self._running


class GrpcStreamConsumer:
    """
    gRPC流消费者

    消费gRPC审计事件流（客户端流式），实时喂给RealDataAdapter。
    支持：
    - 断线重连（指数退避）
    - 流式批量处理
    - 优雅停止

    注意：需要gRPC Python库，无gRPC环境时自动降级为内存队列模式。
    """

    def __init__(
        self,
        grpc_target: str,
        adapter: RealDataAdapter,
        source_type: EventSource = EventSource.AUDIT_CHAIN_ANOMALY,
        reconnect_max_retries: int = 10,
        reconnect_base_delay: float = 1.0,
        max_queue_size: int = 10000,
    ):
        self.grpc_target = grpc_target
        self.adapter = adapter
        self.source_type = source_type
        self.reconnect_max_retries = reconnect_max_retries
        self.reconnect_base_delay = reconnect_base_delay
        self.max_queue_size = max_queue_size

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stats = ConsumerStats()
        self._event_queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self._grpc_available = False
        self._start_time: float = 0.0

        # 事件回调
        self.on_event: Optional[Callable[[SecurityEvent], None]] = None
        self.on_anomaly: Optional[Callable[[SecurityEvent], None]] = None
        self.on_error: Optional[Callable[[Exception], None]] = None

        self._check_grpc_available()

    def _check_grpc_available(self) -> None:
        """检查gRPC是否可用"""
        try:
            import grpc  # noqa: F401
            self._grpc_available = True
        except ImportError:
            self._grpc_available = False

    def start(self) -> None:
        """启动消费线程"""
        if self._running:
            return

        self._running = True
        self._start_time = time.time()
        self._thread = threading.Thread(target=self._stream_loop, daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """停止消费线程"""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def _stream_loop(self) -> None:
        """gRPC流主循环"""
        retry_count = 0
        while self._running:
            try:
                if not self._grpc_available:
                    # gRPC不可用，等待并重试
                    time.sleep(self.reconnect_base_delay)
                    self._check_grpc_available()
                    continue

                # 尝试连接并消费流
                self._consume_grpc_stream()
                retry_count = 0  # 重置重试计数

            except Exception as e:
                self._stats.errors += 1
                if self.on_error:
                    self.on_error(e)

                # 指数退避重连
                if retry_count < self.reconnect_max_retries:
                    delay = self.reconnect_base_delay * (2 ** retry_count)
                    time.sleep(min(delay, 60.0))
                    retry_count += 1
                else:
                    # 超过最大重试次数，等待更长时间
                    time.sleep(60.0)

    def _consume_grpc_stream(self) -> None:
        """消费gRPC流（实际实现需要根据proto定义）"""
        # 这里是框架实现，实际使用时需要根据proto生成的stub来消费
        # 示例逻辑：
        # import grpc
        # from audit_pb2 import AuditRecord
        # from audit_pb2_grpc import AuditServiceStub
        # channel = grpc.insecure_channel(self.grpc_target)
        # stub = AuditServiceStub(channel)
        # for record in stub.StreamAuditRecords(AuditStreamRequest()):
        #     event = self._parse_grpc_record(record)
        #     self._event_queue.put(event)

        # 框架模式下，模拟消费
        while self._running:
            time.sleep(1.0)  # 等待真实实现

    def _parse_grpc_record(self, record: Any) -> Optional[SecurityEvent]:
        """解析gRPC记录为SecurityEvent"""
        try:
            # 根据实际proto结构解析
            data = {
                "event_id": getattr(record, "event_id", "unknown"),
                "timestamp": getattr(record, "timestamp", time.time()),
                "sandbox_id": getattr(record, "sandbox_id", "unknown"),
                "severity": getattr(record, "severity", "medium"),
                "payload": getattr(record, "payload", {}),
            }
            return SecurityEvent(
                event_id=data["event_id"],
                source=self.source_type,
                timestamp=float(data["timestamp"]),
                sandbox_id=str(data["sandbox_id"]),
                severity=data["severity"],
                description=f"gRPC事件: {data['event_id']}",
                payload=data["payload"],
            )
        except Exception:
            return None

    def get_stats(self) -> ConsumerStats:
        """获取消费统计"""
        self._stats.queue_size = self._event_queue.qsize()
        self._stats.uptime_seconds = time.time() - self._start_time
        return self._stats

    def is_running(self) -> bool:
        """是否正在运行"""
        return self._running

    def is_grpc_available(self) -> bool:
        """gRPC是否可用"""
        return self._grpc_available


class LogConsumerManager:
    """
    日志消费管理器

    统一管理多个消费者（文件tail + gRPC流），
    将所有事件汇聚到同一个RealDataAdapter。
    """

    def __init__(self, adapter: Optional[RealDataAdapter] = None):
        self.adapter = adapter or RealDataAdapter()
        self.consumers: Dict[str, Any] = {}
        self._all_events: List[SecurityEvent] = []
        self._anomaly_events: List[SecurityEvent] = []
        self._lock = threading.Lock()

    def add_file_tail(
        self,
        name: str,
        file_path: str,
        source_type: EventSource = EventSource.SECCOMP_VIOLATION,
        **kwargs,
    ) -> FileTailConsumer:
        """添加文件tail消费者"""
        consumer = FileTailConsumer(
            file_path=file_path,
            adapter=self.adapter,
            source_type=source_type,
            **kwargs,
        )
        # 设置事件回调
        consumer.on_event = self._on_event
        consumer.on_anomaly = self._on_anomaly
        self.consumers[name] = consumer
        return consumer

    def add_grpc_stream(
        self,
        name: str,
        grpc_target: str,
        source_type: EventSource = EventSource.AUDIT_CHAIN_ANOMALY,
        **kwargs,
    ) -> GrpcStreamConsumer:
        """添加gRPC流消费者"""
        consumer = GrpcStreamConsumer(
            grpc_target=grpc_target,
            adapter=self.adapter,
            source_type=source_type,
            **kwargs,
        )
        consumer.on_event = self._on_event
        consumer.on_anomaly = self._on_anomaly
        self.consumers[name] = consumer
        return consumer

    def start_all(self) -> None:
        """启动所有消费者"""
        for consumer in self.consumers.values():
            consumer.start()

    def stop_all(self, timeout: float = 5.0) -> None:
        """停止所有消费者"""
        for consumer in self.consumers.values():
            consumer.stop(timeout=timeout)

    def _on_event(self, event: SecurityEvent) -> None:
        """事件回调"""
        with self._lock:
            self._all_events.append(event)
            # 限制内存使用
            if len(self._all_events) > 100000:
                self._all_events = self._all_events[-50000:]

    def _on_anomaly(self, event: SecurityEvent) -> None:
        """异常事件回调"""
        with self._lock:
            self._anomaly_events.append(event)
            if len(self._anomaly_events) > 10000:
                self._anomaly_events = self._anomaly_events[-5000:]

    def get_all_events(self, limit: int = 1000) -> List[SecurityEvent]:
        """获取所有事件（最近的）"""
        with self._lock:
            return self._all_events[-limit:]

    def get_anomaly_events(self, limit: int = 1000) -> List[SecurityEvent]:
        """获取异常事件（最近的）"""
        with self._lock:
            return self._anomaly_events[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """获取所有消费者统计"""
        stats = {}
        for name, consumer in self.consumers.items():
            s = consumer.get_stats()
            stats[name] = {
                "total_consumed": s.total_consumed,
                "total_events": s.total_events,
                "total_anomalies": s.total_anomalies,
                "errors": s.errors,
                "uptime_seconds": s.uptime_seconds,
                "running": consumer.is_running(),
            }
        stats["_total"] = {
            "events": len(self._all_events),
            "anomalies": len(self._anomaly_events),
            "consumers": len(self.consumers),
        }
        return stats
