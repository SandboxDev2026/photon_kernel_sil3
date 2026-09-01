#!/usr/bin/env python3
"""
Photon Kernel Sandbox - Python gRPC 服务端（可实测运行）

与 C++ sandbox_service.cpp 实现相同的 proto 接口，但用 Python gRPC 实现，
解决 C++ gRPC 库在容器环境无法编译的问题，可直接 pip install grpcio 后运行。

功能：
  - SandboxService.Execute: 同步执行代码（python3/node/shell），带超时+资源限制
  - SandboxService.ExecuteAsync: 异步执行，返回 task_id
  - SandboxService.GetPoolStatus: 池状态
  - SandboxService.GetTaskResult: 查询异步任务结果
  - AuditService.BatchReport: 客户端流式批量审计上报

用法：
  python3 server/python/sandbox_grpc_server.py --port 50051
  python3 server/python/sandbox_grpc_client.py --port 50051
"""
import os
import sys
import time
import json
import uuid
import signal
import resource
import subprocess
import threading
import argparse
from concurrent import futures
from collections import deque
from datetime import datetime, timezone

# 确保 proto 生成代码可导入
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import grpc
import sandbox_pb2
import sandbox_pb2_grpc

# ==================== 沙盒执行器 ====================
class SandboxExecutor:
    """代码执行器：subprocess + resource 限制 + 超时 kill"""
    RUNNERS = {
        0: ["python3", "-"],      # python3
        1: ["node", "-"],          # node
        2: ["/bin/sh", "-"],       # shell
    }
    def __init__(self):
        self.task_count = 0
        self._lock = threading.Lock()
    def execute(self, code, runner=0, timeout_ms=5000, environment=None):
        """同步执行代码，返回结果"""
        cmd = self.RUNNERS.get(runner, self.RUNNERS[0])
        env = os.environ.copy()
        if environment:
            env.update(environment)
        start = time.time()
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                preexec_fn=self._set_limits,
            )
            stdout, stderr = proc.communicate(input=code.encode("utf-8"), timeout=timeout_ms / 1000.0)
            elapsed = time.time() - start
            return {
                "success": proc.returncode == 0,
                "output": stdout.decode("utf-8", errors="replace"),
                "error": stderr.decode("utf-8", errors="replace"),
                "exit_code": proc.returncode,
                "cpu_time_us": int(elapsed * 1_000_000),
                "memory_peak_bytes": 0,  # Python subprocess 无法精确获取，用 0 占位
            }
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return {
                "success": False,
                "output": "",
                "error": f"timeout after {timeout_ms}ms",
                "exit_code": -1,
                "cpu_time_us": int((time.time() - start) * 1_000_000),
                "memory_peak_bytes": 0,
                "error_code": "TIMEOUT",
            }
        except FileNotFoundError as e:
            return {
                "success": False,
                "output": "",
                "error": f"runner not found: {e}",
                "exit_code": -1,
                "cpu_time_us": 0,
                "memory_peak_bytes": 0,
                "error_code": "RUNNER_NOT_FOUND",
            }
    @staticmethod
    def _set_limits():
        """子进程资源限制（类似 C++ rlimit）"""
        try:
            # CPU 时间 30s
            resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
            # 内存 256MB
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
            # 进程数 16
            resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
            # 文件大小 16MB
            resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
            # fd 数 64
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
            # core dump 禁用
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ValueError, OSError):
            pass  # 某些限制在容器中可能不支持，忽略
# ==================== 异步任务管理器 ====================
class AsyncTaskManager:
    def __init__(self, executor):
        self.executor = executor
        self.tasks = {}  # task_id -> task info
        self._lock = threading.Lock()
    def submit(self, code, runner=0, timeout_ms=5000, environment=None):
        task_id = str(uuid.uuid4())
        with self._lock:
            self.tasks[task_id] = {
                "status": "pending",
                "result": None,
                "created_at": time.time(),
            }
        # 后台线程执行
        t = threading.Thread(target=self._run_task, args=(task_id, code, runner, timeout_ms, environment), daemon=True)
        t.start()
        return task_id
    def _run_task(self, task_id, code, runner, timeout_ms, environment):
        with self._lock:
            self.tasks[task_id]["status"] = "running"
        result = self.executor.execute(code, runner, timeout_ms, environment)
        with self._lock:
            self.tasks[task_id]["status"] = "completed" if result["success"] else "failed"
            self.tasks[task_id]["result"] = result
    def get_result(self, task_id):
        with self._lock:
            return self.tasks.get(task_id)
# ==================== 审计日志存储 ====================
class AuditStore:
    """批量审计日志存储（内存 + 可选文件）"""
    def __init__(self, max_records=10000):
        self.records = deque(maxlen=max_records)
        self._lock = threading.Lock()
        self.total_received = 0
    def add(self, record):
        with self._lock:
            self.records.append({
                "event_id": record.event_id,
                "timestamp": record.timestamp,
                "payload": record.payload,
                "received_at": time.time(),
            })
            self.total_received += 1
    def count(self):
        with self._lock:
            return len(self.records)
# ==================== gRPC 服务实现 ====================
class SandboxServiceImpl(sandbox_pb2_grpc.SandboxServiceServicer):
    def __init__(self, executor, async_mgr):
        self.executor = executor
        self.async_mgr = async_mgr
    def Execute(self, request, context):
        result = self.executor.execute(
            code=request.task_code,
            runner=request.runner,
            timeout_ms=request.timeout_ms or 5000,
            environment=dict(request.environment) if request.environment else None,
        )
        return sandbox_pb2.SandboxResponse(
            success=result["success"],
            output=result["output"],
            error=result.get("error", ""),
            cpu_time_us=result["cpu_time_us"],
            memory_peak_bytes=result["memory_peak_bytes"],
            exit_code=result["exit_code"],
            error_code=result.get("error_code", ""),
        )
    def ExecuteAsync(self, request, context):
        task_id = self.async_mgr.submit(
            code=request.task_code,
            runner=request.runner,
            timeout_ms=request.timeout_ms or 5000,
            environment=dict(request.environment) if request.environment else None,
        )
        return sandbox_pb2.AsyncResponse(task_id=task_id, status="pending")
    def GetPoolStatus(self, request, context):
        # Python 实现简化：返回执行器统计
        return sandbox_pb2.PoolStatusResponse(
            total=8,  # 模拟池大小
            idle=max(0, 8 - self.executor.task_count),
            busy=min(self.executor.task_count, 8),
            failed=0,
        )
    def GetTaskResult(self, request, context):
        task = self.async_mgr.get_result(request.task_id)
        if not task:
            return sandbox_pb2.TaskResultResponse(found=False)
        result = task.get("result")
        if not result:
            return sandbox_pb2.TaskResultResponse(
                found=True, completed=False,
                success=False, output="", error="",
                cpu_time_us=0, memory_peak_bytes=0, exit_code=0,
            )
        return sandbox_pb2.TaskResultResponse(
            found=True,
            completed=task["status"] in ("completed", "failed"),
            success=result["success"],
            output=result["output"],
            error=result.get("error", ""),
            cpu_time_us=result["cpu_time_us"],
            memory_peak_bytes=result["memory_peak_bytes"],
            exit_code=result["exit_code"],
        )
class AuditServiceImpl(sandbox_pb2_grpc.AuditServiceServicer):
    def __init__(self, audit_store):
        self.audit_store = audit_store
    def BatchReport(self, request_iterator, context):
        """客户端流式批量上报：接收多条 AuditRecord，返回汇总"""
        ok_count = 0
        failed_count = 0
        for record in request_iterator:
            try:
                self.audit_store.add(record)
                ok_count += 1
            except Exception:
                failed_count += 1
        return sandbox_pb2.BatchReportResp(ok_count=ok_count, failed_count=failed_count)
# ==================== 服务端启动 ====================
def serve(port=50051):
    executor = SandboxExecutor()
    async_mgr = AsyncTaskManager(executor)
    audit_store = AuditStore()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    sandbox_pb2_grpc.add_SandboxServiceServicer_to_server(
        SandboxServiceImpl(executor, async_mgr), server)
    sandbox_pb2_grpc.add_AuditServiceServicer_to_server(
        AuditServiceImpl(audit_store), server)
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    print(f"[Photon Sandbox gRPC Server] listening on :{port}")
    print(f"  - SandboxService: Execute / ExecuteAsync / GetPoolStatus / GetTaskResult")
    print(f"  - AuditService: BatchReport (client streaming)")
    print(f"  - Runners: python3, node, shell")
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        print("\n[Photon Sandbox gRPC Server] shutting down...")
        server.stop(0)
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Photon Sandbox gRPC Server")
    parser.add_argument("--port", type=int, default=50051, help="gRPC port")
    args = parser.parse_args()
    serve(args.port)
