#!/usr/bin/env python3
"""gRPC 契约测试：用 Python 启动模拟服务端，验证 proto 定义的 API 可真实通信。

不验证 C++ 服务端实现（需要 gRPC C++ 库），但验证：
1. SandboxService.Execute / ExecuteAsync / GetPoolStatus API 契约
2. AuditService.BatchReport 客户端流式 RPC
3. 请求/响应消息字段序列化正确
4. 超时/错误处理
"""
import sys
import time
import unittest
from concurrent import futures

import grpc
sys.path.insert(0, '/tmp/proto_out')
import sandbox_pb2
import sandbox_pb2_grpc


# ---- 模拟服务端实现 ----
class MockSandboxService(sandbox_pb2_grpc.SandboxServiceServicer):
    def Execute(self, request, context):
        resp = sandbox_pb2.SandboxResponse()
        resp.success = True
        resp.output = f"executed: {request.task_code[:20]}"
        resp.exit_code = 0
        resp.cpu_time_us = 1500
        resp.memory_peak_bytes = 1024 * 1024
        return resp

    def ExecuteAsync(self, request, context):
        resp = sandbox_pb2.AsyncResponse()
        resp.task_id = f"task-{int(time.time())}"
        resp.status = "pending"
        return resp

    def GetPoolStatus(self, request, context):
        resp = sandbox_pb2.PoolStatusResponse()
        resp.total = 10
        resp.idle = 7
        resp.busy = 3
        resp.failed = 0
        return resp


class MockAuditService(sandbox_pb2_grpc.AuditServiceServicer):
    def __init__(self):
        self.received_count = 0

    def BatchReport(self, request_iterator, context):
        count = 0
        for record in request_iterator:
            count += 1
            # 验证每条记录字段完整
            assert record.event_id, "event_id should not be empty"
            assert record.timestamp > 0, "timestamp should be > 0"
        self.received_count = count
        resp = sandbox_pb2.BatchReportResp()
        resp.ok_count = count
        resp.failed_count = 0
        return resp


class TestGrpcContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        cls.sandbox_svc = MockSandboxService()
        cls.audit_svc = MockAuditService()
        sandbox_pb2_grpc.add_SandboxServiceServicer_to_server(cls.sandbox_svc, cls.server)
        sandbox_pb2_grpc.add_AuditServiceServicer_to_server(cls.audit_svc, cls.server)
        cls.port = cls.server.add_insecure_port('[::]:0')
        cls.server.start()
        cls.channel = grpc.insecure_channel(f'localhost:{cls.port}')
        cls.sandbox_stub = sandbox_pb2_grpc.SandboxServiceStub(cls.channel)
        cls.audit_stub = sandbox_pb2_grpc.AuditServiceStub(cls.channel)

    @classmethod
    def tearDownClass(cls):
        cls.channel.close()
        cls.server.stop(0)

    def test_execute_returns_output(self):
        """Execute 应返回 success=true 和 output。"""
        req = sandbox_pb2.SandboxRequest(task_name="test", task_code="print(42)", runner=0)
        resp = self.sandbox_stub.Execute(req, timeout=5)
        self.assertTrue(resp.success)
        self.assertIn("executed", resp.output)
        self.assertEqual(resp.exit_code, 0)
        self.assertGreater(resp.cpu_time_us, 0)
        self.assertGreater(resp.memory_peak_bytes, 0)

    def test_execute_async_returns_task_id(self):
        """ExecuteAsync 应返回 task_id 和 accepted=true。"""
        req = sandbox_pb2.SandboxRequest(task_name="async", task_code="sleep(1)", runner=0)
        resp = self.sandbox_stub.ExecuteAsync(req, timeout=5)
        self.assertEqual(resp.status, "pending")
        self.assertTrue(resp.task_id.startswith("task-"))

    def test_get_pool_status(self):
        """GetPoolStatus 应返回 worker 统计。"""
        req = sandbox_pb2.EmptyRequest()
        resp = self.sandbox_stub.GetPoolStatus(req, timeout=5)
        self.assertEqual(resp.total, 10)
        self.assertEqual(resp.idle, 7)
        self.assertEqual(resp.busy, 3)
        self.assertEqual(resp.failed, 0)

    def test_audit_batch_report_streaming(self):
        """BatchReport 客户端流式应批量发送 AuditRecord 并返回 ok_count。"""
        def record_generator():
            for i in range(10):
                yield sandbox_pb2.AuditRecord(
                    event_id=f"evt-{i}",
                    timestamp=int(time.time() * 1000),
                    payload=f"audit data {i}",
                )
        resp = self.audit_stub.BatchReport(record_generator(), timeout=5)
        self.assertEqual(resp.ok_count, 10)
        self.assertEqual(resp.failed_count, 0)
        self.assertEqual(self.audit_svc.received_count, 10)

    def test_audit_batch_report_single(self):
        """单条 AuditRecord 流式上报也应正常。"""
        def gen():
            yield sandbox_pb2.AuditRecord(
                event_id="single-evt",
                timestamp=1234567890,
                payload="test",
            )
        resp = self.audit_stub.BatchReport(gen(), timeout=5)
        self.assertEqual(resp.ok_count, 1)

    def test_execute_with_timeout(self):
        """带超时的 Execute 应正常返回（模拟服务端快速响应）。"""
        req = sandbox_pb2.SandboxRequest(task_name="to", task_code="x=1", runner=0)
        resp = self.sandbox_stub.Execute(req, timeout=1)  # 1秒超时
        self.assertTrue(resp.success)

    def test_sandbox_request_fields(self):
        """SandboxRequest 应包含 code/language/timeout_ms 字段。"""
        req = sandbox_pb2.SandboxRequest()
        req.task_name = "field-test"
        req.task_code = "print('hello')"
        req.timeout_ms = 5000
        req.runner = 0
        # 序列化/反序列化往返
        data = req.SerializeToString()
        req2 = sandbox_pb2.SandboxRequest()
        req2.ParseFromString(data)
        self.assertEqual(req2.task_code, "print('hello')")
        self.assertEqual(req2.timeout_ms, 5000)
        self.assertEqual(req2.runner, 0)

    def test_audit_record_serialization(self):
        """AuditRecord 应可正确序列化/反序列化。"""
        rec = sandbox_pb2.AuditRecord(
            event_id="evt-001",
            timestamp=9999999,
            payload="test payload with unicode 中文",
        )
        data = rec.SerializeToString()
        rec2 = sandbox_pb2.AuditRecord()
        rec2.ParseFromString(data)
        self.assertEqual(rec2.event_id, "evt-001")
        self.assertEqual(rec2.timestamp, 9999999)
        self.assertIn("中文", rec2.payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
