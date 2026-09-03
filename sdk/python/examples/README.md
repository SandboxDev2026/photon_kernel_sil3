# PhotonBox Python SDK 示例

## 快速开始

```python
from photonbox import PhotonBoxClient

# 一行代码创建客户端
client = PhotonBoxClient.quick_start('standard')

# 执行代码
result = client.execute("print('Hello, PhotonBox!')")
print(result.output)
```

## 示例列表

| 示例 | 说明 |
|------|------|
| [01_quick_start.py](01_quick_start.py) | 快速开始：创建客户端、执行代码、查看安全状态 |
| [02_sandbox_session.py](02_sandbox_session.py) | 会话式执行：在同一沙盒中执行多次代码 |
| [03_security_monitoring.py](03_security_monitoring.py) | 安全监控：逃逸检测、事件摄入、回调 |
| [04_adversary_training.py](04_adversary_training.py) | 红蓝对抗：自进化安全训练、防御规则进化 |

## 运行示例

```bash
cd sdk/python/examples
python3 01_quick_start.py
```

## 安全级别

| 级别 | 隔离技术 | 适用场景 |
|------|---------|---------|
| `light` | fork + seccomp | 内网可信Agent，低延迟 |
| `standard` | namespace + seccomp + Landlock | 标准隔离，默认推荐 |
| `strong` | Firecracker MicroVM | 公网不可信代码 |
