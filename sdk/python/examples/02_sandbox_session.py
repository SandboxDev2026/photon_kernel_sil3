"""
PhotonBox SDK 示例 02: 会话式执行

在同一个沙盒实例中执行多次代码，保持状态。
"""
import sys
sys.path.insert(0, '..')

from photonbox import PhotonBoxClient, SandboxConfig

client = PhotonBoxClient()

# 使用上下文管理器创建会话
with client.create_session(SandboxConfig.standard()) as session:
    # 第一次执行：定义变量
    r1 = session.execute("x = 42")
    print(f"第一次执行: exit_code={r1.exit_code}")

    # 第二次执行：使用变量
    r2 = session.execute("print(x * 2)")
    print(f"第二次执行: output={r2.output}")

    # 第三次执行：更复杂的代码
    r3 = session.execute("""
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)

print([fibonacci(i) for i in range(10)])
""")
    print(f"第三次执行: output={r3.output}")

    print(f"\n会话总执行次数: {session.total_executions}")
    print(f"沙盒ID: {session.sandbox_id}")
