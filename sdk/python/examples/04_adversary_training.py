"""
PhotonBox SDK 示例 04: 红蓝对抗训练

自进化安全训练，从真实事件中学习并进化防御规则。
"""
import sys
sys.path.insert(0, '..')

from photonbox import PhotonBoxClient

client = PhotonBoxClient(auto_evolve_defense=True)

# 1. 摄入真实安全事件
print("1. 摄入真实安全事件...")
events = [
    {"event_id": f"evt-{i:03d}", "source": "seccomp", "timestamp": 1234567890 + i,
     "sandbox_id": f"sbox-{i}", "severity": "high", "description": f"违规事件{i}",
     "syscall": ["ptrace", "kexec_load", "socket", "connect"][i % 4]}
    for i in range(20)
]
evolved = client.adversary_trainer.ingest_real_events(events)
print(f"   摄入事件: {len(events)}, 触发达尔文进化: {evolved}")

# 2. 运行红蓝对抗训练
print("\n2. 运行红蓝对抗训练 (50轮)...")
result = client.train_defense(rounds=50)
print(f"   训练轮数: {result.rounds}")
print(f"   红方胜率: {result.red_win_rate:.1%}")
print(f"   蓝方胜率: {result.blue_win_rate:.1%}")
print(f"   新增攻击用例: {result.new_attack_cases}")
print(f"   新增防御规则: {result.new_defense_rules}")
print(f"   训练耗时: {result.duration_seconds:.2f}s")

# 3. 查看进化后的防御规则
print("\n3. 进化后的防御规则 (前5个):")
rules = client.get_evolved_defense_rules()
for rule in rules[:5]:
    print(f"   [{rule['type']}] {rule['description'][:50]} (有效性: {rule['effectiveness']:.2f})")

# 4. 查看训练建议
print(f"\n4. 安全改进建议:")
for rec in result.recommendations[:3]:
    print(f"   - {rec}")
