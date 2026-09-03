"""
PhotonBox SDK 示例 01: 快速开始

一行代码创建客户端，执行代码，查看安全状态。
"""
import sys
sys.path.insert(0, '..')  # 添加SDK路径

from photonbox import PhotonBoxClient

# 1. 一行代码创建客户端
client = PhotonBoxClient.quick_start('standard')

# 2. 执行代码
result = client.execute("print('Hello, PhotonBox!')")
print(f"输出: {result.output}")
print(f"后端: {result.backend}")
print(f"耗时: {result.duration_ms:.2f}ms")

# 3. 查看安全状态
status = client.get_security_status()
print(f"\n安全状态:")
print(f"  逃逸检测规则: {status['escape_detection']['rules_count']}个")
print(f"  活跃会话: {status['active_sessions']}")
