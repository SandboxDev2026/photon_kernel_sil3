#!/usr/bin/env python3
"""
Photon Kernel Sandbox - Python gRPC 客户端（实测用）

用法：
  python3 sandbox_grpc_client.py --port 50051
  python3 sandbox_grpc_client.py --code "print(42)" --runner 0
"""
import os
import sys
import time
import argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import grpc
import sandbox_pb2
import sandbox_pb2_grpc
def test_execute(stub, code, runner=0, label=""):
    """测试同步执行"""
    print(f"\n--- Execute: {label} ---")
    req = sandbox_pb2.SandboxRequest(
        task_name=f"test-{label}",
        task_code=code,
        timeout_ms=5000,
        runner=runner,
    )
    resp = stub.Execute(req)
    print(f"  success: {resp.success}")
    print(f"  exit_code: {resp.exit_code}")
    print(f"  output: {resp.output.strip()[:200]}")
    if resp.error:
        print(f"  error: {resp.error.strip()[:200]}")
    print(f"  cpu_time_us: {resp.cpu_time_us}")
    return resp
def test_execute_async(stub, code):
    """测试异步执行 + GetTaskResult"""
    print("\n--- ExecuteAsync + GetTaskResult ---")
    req = sandbox_pb2.SandboxRequest(
        task_name="async-test",
        task_code=code,
        timeout_ms=5000,
    )
    resp = stub.ExecuteAsync(req)
    print(f"  task_id: {resp.task_id}")
    print(f"  status: {resp.status}")
    # 轮询结果
    for i in range(20):
        time.sleep(0.1)
        result_req = sandbox_pb2.TaskResultRequest(task_id=resp.task_id)
        result = stub.GetTaskResult(result_req)
        if result.completed:
            print(f"  completed: {result.completed}")
            print(f"  success: {result.success}")
            print(f"  output: {result.output.strip()[:200]}")
            return result
    print("  timeout waiting for async task")
    return None
def test_pool_status(stub):
    """测试池状态"""
    print("\n--- GetPoolStatus ---")
    resp = stub.GetPoolStatus(sandbox_pb2.EmptyRequest())
    print(f"  total: {resp.total}")
    print(f"  idle: {resp.idle}")
    print(f"  busy: {resp.busy}")
    print(f"  failed: {resp.failed}")
    return resp
def test_audit_batch_report(stub):
    """测试审计批量上报（Client Streaming）"""
    print("\n--- AuditService.BatchReport (Client Streaming) ---")
    def generate_records():
        for i in range(5):
            yield sandbox_pb2.AuditRecord(
                event_id=f"audit-{i:04d}",
                timestamp=int(time.time() * 1_000_000),
                payload=f'{{"action":"execute","seq":{i},"user":"test"}}',
            )
    resp = stub.BatchReport(generate_records())
    print(f"  ok_count: {resp.ok_count}")
    print(f"  failed_count: {resp.failed_count}")
    return resp
def test_timeout(stub):
    """测试超时 kill"""
    print("\n--- Timeout Test (infinite loop) ---")
    req = sandbox_pb2.SandboxRequest(
        task_name="timeout-test",
        task_code="while True:\n    pass\n",
        timeout_ms=1000,
        runner=0,
    )
    resp = stub.Execute(req)
    print(f"  success: {resp.success}")
    print(f"  error_code: {resp.error_code}")
    print(f"  error: {resp.error.strip()[:100]}")
    return resp
def main():
    parser = argparse.ArgumentParser(description="Photon Sandbox gRPC Client")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=50051)
    parser.add_argument("--code", default=None, help="custom code to execute")
    args = parser.parse_args()
    channel = grpc.insecure_channel(f"{args.host}:{args.port}")
    stub = sandbox_pb2_grpc.SandboxServiceStub(channel)
    audit_stub = sandbox_pb2_grpc.AuditServiceStub(channel)
    print("=" * 60)
    print("Photon Sandbox gRPC Client - End-to-End Test")
    print("=" * 60)
    try:
        # 1. 基础执行
        test_execute(stub, "print(42)", 0, "python print(42)")
        # 2. 复杂计算
        test_execute(stub, "print(sum(range(1000)))", 0, "python sum")
        # 3. Shell
        test_execute(stub, "echo 'hello from shell'", 2, "shell echo")
        # 4. 异步执行
        test_execute_async(stub, "import time; time.sleep(0.2); print('async done')")
        # 5. 池状态
        test_pool_status(stub)
        # 6. 审计批量上报
        test_audit_batch_report(audit_stub)
        # 7. 超时
        test_timeout(stub)
        # 8. 自定义代码
        if args.code:
            test_execute(stub, args.code, 0, "custom")
        print("\n" + "=" * 60)
        print("All tests completed!")
        print("=" * 60)
    except grpc.RpcError as e:
        print(f"\ngRPC Error: {e}")
        sys.exit(1)
    finally:
        channel.close()
if __name__ == "__main__":
    main()
