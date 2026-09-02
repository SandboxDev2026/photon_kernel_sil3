#!/usr/bin/env python3
"""
隔离网关服务测试
验证：内网拦截、DNS劫持、限流、审计日志
"""
import sys
import os
import time
import socket
import struct
import threading
import json

sys.path.insert(0, os.path.dirname(__file__))
from isolation_gateway import (
    GatewayConfig, is_internal_ip, domain_matches,
    TokenBucket, ConnectionTracker, AuditLogger, DnsProxy
)

def test_internal_ip_block():
    """测试内网IP拦截"""
    print("=== test_internal_ip_block ===")
    # RFC1918
    is_int, reason = is_internal_ip("10.0.0.1")
    assert is_int, f"10.0.0.1 should be internal, got {reason}"
    print(f"  10.0.0.1 -> BLOCK ({reason})")

    is_int, reason = is_internal_ip("172.16.0.1")
    assert is_int
    print(f"  172.16.0.1 -> BLOCK ({reason})")

    is_int, reason = is_internal_ip("192.168.1.1")
    assert is_int
    print(f"  192.168.1.1 -> BLOCK ({reason})")

    # 回环
    is_int, reason = is_internal_ip("127.0.0.1")
    assert is_int
    print(f"  127.0.0.1 -> BLOCK ({reason})")

    # 云元数据（高危）
    is_int, reason = is_internal_ip("169.254.169.254")
    assert is_int
    assert "metadata" in reason.lower()
    print(f"  169.254.169.254 -> BLOCK (HIGH RISK: {reason})")

    # 公网允许
    is_int, reason = is_internal_ip("8.8.8.8")
    assert not is_int
    print(f"  8.8.8.8 -> ALLOW ({reason})")

    is_int, reason = is_internal_ip("1.1.1.1")
    assert not is_int
    print(f"  1.1.1.1 -> ALLOW ({reason})")

    print("  PASSED\n")

def test_domain_matching():
    """测试域名匹配"""
    print("=== test_domain_matching ===")
    assert domain_matches("api.example.com", "*.example.com")
    assert domain_matches("example.com", "*.example.com")
    assert not domain_matches("evil.com", "*.example.com")
    assert domain_matches("www.evil.com", "*.evil.com")
    print("  *.example.com matches api.example.com: OK")
    print("  *.evil.com matches www.evil.com: OK")
    print("  PASSED\n")

def test_token_bucket():
    """测试令牌桶带宽限流"""
    print("=== test_token_bucket ===")
    bucket = TokenBucket(rate_bytes_per_sec=1000, max_bytes=2000)
    # 初始有2000令牌
    assert bucket.consume(1000)
    assert bucket.consume(1000)
    assert not bucket.consume(100)  # 令牌耗尽
    print(f"  consume 1000: OK")
    print(f"  consume 1000: OK")
    print(f"  consume 100 (empty): BLOCK")
    # 等待补充
    time.sleep(0.2)
    assert bucket.consume(100)  # 补充了约200
    print(f"  after 0.2s, consume 100: OK")
    print("  PASSED\n")

def test_connection_tracker():
    """测试连接数跟踪"""
    print("=== test_connection_tracker ===")
    tracker = ConnectionTracker(max_per_sandbox=2, max_new_per_sec=5)

    # 前2个连接应该成功
    ok1, _ = tracker.try_acquire("sandbox-1", "conn-1")
    ok2, _ = tracker.try_acquire("sandbox-1", "conn-2")
    assert ok1 and ok2
    print(f"  conn-1, conn-2 acquired: OK (active={tracker.active_count('sandbox-1')})")

    # 第3个应该被拒绝（超过max_per_sandbox）
    ok3, reason = tracker.try_acquire("sandbox-1", "conn-3")
    assert not ok3
    print(f"  conn-3 blocked: {reason}")

    # 释放一个后应该可以
    tracker.release("sandbox-1", "conn-1")
    ok4, _ = tracker.try_acquire("sandbox-1", "conn-4")
    assert ok4
    print(f"  after release, conn-4 acquired: OK")

    # 不同沙盒独立计数
    ok5, _ = tracker.try_acquire("sandbox-2", "conn-5")
    assert ok5
    print(f"  sandbox-2 independent counter: OK")

    print("  PASSED\n")

def test_audit_logger():
    """测试审计日志 HMAC 哈希链"""
    print("=== test_audit_logger ===")
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
        log_file = f.name

    audit = AuditLogger(hmac_key="test-key", log_file=log_file)

    from isolation_gateway import ConnectionInfo
    conn1 = ConnectionInfo(
        conn_id="test-1", sandbox_id="sb-1", tenant_id="t1", token_id="tok-1",
        src_addr=("10.0.99.1", 12345), dest_ip="8.8.8.8", dest_port=443,
        dest_domain="dns.google", protocol="tcp", start_time=time.time()
    )
    hash1 = audit.log(conn1, "test")

    conn2 = ConnectionInfo(
        conn_id="test-2", sandbox_id="sb-1", tenant_id="t1", token_id="tok-1",
        src_addr=("10.0.99.1", 12346), dest_ip="1.1.1.1", dest_port=443,
        dest_domain="cloudflare", protocol="tcp", start_time=time.time()
    )
    hash2 = audit.log(conn2, "test")

    # 哈希链：第二条的 prev_hash 应该等于第一条的 hash
    assert hash1 and hash2
    assert len(hash1) == 64 and len(hash2) == 64
    print(f"  hash1: {hash1[:16]}...")
    print(f"  hash2: {hash2[:16]}...")

    # 验证日志文件
    with open(log_file) as f:
        lines = f.readlines()
    assert len(lines) == 2
    entry1 = json.loads(lines[0])
    entry2 = json.loads(lines[1])
    assert entry1["hash"] == hash1
    assert entry2["prev_hash"] == hash1
    assert entry2["hash"] == hash2
    print(f"  hash chain verified: entry2.prev_hash == entry1.hash")
    print(f"  audit log file: {log_file} ({len(lines)} entries)")

    os.unlink(log_file)
    print("  PASSED\n")

def test_dns_proxy_parse():
    """测试 DNS 域名解析"""
    print("=== test_dns_proxy_parse ===")
    config = GatewayConfig()
    audit = AuditLogger("test", "/tmp/test_dns.log")
    dns = DnsProxy(config, audit)

    # 构造一个 DNS 查询：www.example.com
    # Header: ID(2) + flags(2) + qdcount(2) + ...
    # Question: length labels + 0 + qtype(2) + qclass(2)
    domain = "www.example.com"
    labels = domain.split(".")
    question = b""
    for label in labels:
        question += bytes([len(label)]) + label.encode()
    question += b"\x00"  # end
    question += struct.pack(">HH", 1, 1)  # A, IN

    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    packet = header + question

    parsed = dns._parse_domain(packet)
    assert parsed == "www.example.com", f"Expected www.example.com, got {parsed}"
    print(f"  DNS query parse: www.example.com -> {parsed}")

    # 测试空域名
    parsed_empty = dns._parse_domain(b"\x00" * 12)
    assert parsed_empty == ""
    print(f"  Empty domain parse: OK")

    print("  PASSED\n")

def test_gateway_config():
    """测试网关配置"""
    print("=== test_gateway_config ===")
    config = GatewayConfig()
    assert config.max_connections_per_sandbox == 64
    assert config.max_new_connections_per_second == 10
    assert config.block_internal_networks == True
    assert config.enable_dns_hijack == True
    assert "8.8.8.8" in config.authorized_dns_servers
    print(f"  Default config: max_conns={config.max_connections_per_sandbox}, "
          f"max_rate={config.max_new_connections_per_second}/s, "
          f"bandwidth={config.max_bandwidth_mbps}Mbps")
    print(f"  DNS hijack: {config.enable_dns_hijack}, "
          f"internal block: {config.block_internal_networks}")
    print("  PASSED\n")

def main():
    print("=" * 60)
    print("Isolation Gateway Service Tests")
    print("=" * 60 + "\n")

    tests = [
        test_internal_ip_block,
        test_domain_matching,
        test_token_bucket,
        test_connection_tracker,
        test_audit_logger,
        test_dns_proxy_parse,
        test_gateway_config,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  FAILED: {e}\n")
            import traceback
            traceback.print_exc()
            failed += 1

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
