"""
PhotonBox SDK 示例 03: 安全监控

逃逸检测、安全事件摄入、防御规则进化。
"""
import sys
sys.path.insert(0, '..')

from photonbox import PhotonBoxClient

client = PhotonBoxClient(auto_escape_block=True)

# 1. 注册逃逸事件回调
def on_escape(event):
    print(f"🚨 逃逸检测! [{event.severity.value}] {event.description}")
    print(f"   阻断: {event.blocked}, 动作: {event.action_taken}")

client.security_monitor.register_callback("escape", on_escape)

# 2. 摄入安全事件（模拟真实日志）
events = [
    {
        "event_id": "evt-001",
        "source": "seccomp",
        "timestamp": 1234567890.0,
        "sandbox_id": "sbox-test",
        "severity": "high",
        "description": "ptrace系统调用被阻止",
        "syscall": "ptrace",
    },
    {
        "event_id": "evt-002",
        "source": "network",
        "timestamp": 1234567891.0,
        "sandbox_id": "sbox-test",
        "severity": "medium",
        "description": "内网访问尝试",
        "dst_cidr": "10.0.0.0/8",
    },
]

result = client.ingest_security_events(events)
print(f"摄入事件: {result['events_ingested']}")
print(f"逃逸检测: {result['escapes_detected']}")
print(f"防御进化: {result['defense_evolved']}")

# 3. 查看最近逃逸事件
print(f"\n最近逃逸事件:")
for event in client.get_recent_escapes(5):
    print(f"  [{event['severity']}] {event['description'][:60]}")

# 4. 查看安全状态
status = client.get_security_status()
print(f"\n安全状态:")
print(f"  总检测次数: {status['escape_detection']['total_checks']}")
print(f"  检测到逃逸: {status['escape_detection']['detected']}")
print(f"  已阻断: {status['escape_detection']['blocked']}")
