#!/bin/bash
# scripts/check_privileges.sh — Photon Sandbox 权限环境快速检查
# 用法: bash scripts/check_privileges.sh
set -euo pipefail
echo "=== Photon Sandbox 权限环境检查 ==="
echo ""
echo "[1] 内核版本: $(uname -r)"
echo "    要求: >= 5.8 (CAP_BPF), >= 5.9 (CAP_CHECKPOINT_RESTORE), >= 5.10 (Landlock)"
kernel_major=$(uname -r | cut -d. -f1)
kernel_minor=$(uname -r | cut -d. -f2)
if [ "$kernel_major" -ge 5 ] && [ "$kernel_minor" -ge 10 ]; then
    echo "    状态: ✅ 满足最低要求"
else
    echo "    状态: ⚠️  内核版本偏低，部分功能不可用"
fi
echo ""
echo "[2] KVM 检查 (StrongPool Firecracker):"
if [ -e /dev/kvm ]; then
    echo "    /dev/kvm 存在: ✅ YES"
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        echo "    当前用户可读写: ✅ YES"
    else
        echo "    当前用户可读写: ❌ NO (需要加入 kvm 组或 chmod)"
    fi
    vmx_count=$(egrep -c '(vmx|svm)' /proc/cpuinfo 2>/dev/null || echo 0)
    echo "    CPU 虚拟化标志: $vmx_count 个"
else
    echo "    /dev/kvm 存在: ❌ NO (StrongPool 不可用，高风险任务将被拒绝)"
    echo "    解决: 需要宿主机开启硬件虚拟化 (BIOS VT-x/AMD-V)"
fi
echo ""
echo "[3] CAP_BPF 检查 (eBPF 网络过滤):"
bpf_disabled=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo "unknown")
echo "    unprivileged_bpf_disabled: $bpf_disabled"
if [ "$bpf_disabled" = "1" ]; then
    echo "    状态: ❌ 非特权 eBPF 被禁用，需要 CAP_BPF 或 root"
elif [ "$bpf_disabled" = "0" ]; then
    echo "    状态: ✅ 非特权 eBPF 可用"
else
    echo "    状态: ⚠️  未知"
fi
capeff=$(grep CapEff /proc/self/status 2>/dev/null | awk '{print $2}' || echo "unknown")
echo "    当前进程 CapEff: $capeff"
echo ""
echo "[4] CRIU 检查 (进程快照/恢复):"
if command -v criu &> /dev/null; then
    criu_ver=$(criu --version 2>&1 | head -1 || echo "unknown")
    echo "    criu 已安装: ✅ $criu_ver"
    if [ "$(id -u)" = "0" ]; then
        echo "    当前用户: root (完整 CRIU 能力)"
    else
        echo "    当前用户: 非 root (CRIU 能力受限，复杂进程可能 dump 失败)"
    fi
else
    echo "    criu 未安装: ❌ (快照功能不可用)"
    echo "    安装: sudo apt install criu"
fi
echo ""
echo "[5] Namespace 能力 (基础 LightPool):"
if [ -f /proc/sys/user/max_user_namespaces ]; then
    max_userns=$(cat /proc/sys/user/max_user_namespaces)
    echo "    用户 namespace: ✅ supported"
    echo "    max_user_namespaces: $max_userns"
else
    echo "    用户 namespace: ❌ 不支持或不可读"
fi
# 检查是否能创建 namespace
if [ "$(id -u)" = "0" ]; then
    echo "    当前用户: root (可创建完整 namespace)"
else
    echo "    当前用户: 非 root (namespace 创建受限，需要 CAP_SYS_ADMIN)"
fi
echo ""
echo "[6] cgroup v2 (资源限制):"
if mount 2>/dev/null | grep -q "cgroup2"; then
    echo "    cgroup v2: ✅ 已挂载"
    if [ -w /sys/fs/cgroup ]; then
        echo "    可写: ✅ YES"
    else
        echo "    可写: ❌ NO (需要 root 或 cgroup 所有权)"
    fi
else
    echo "    cgroup v2: ❌ 未挂载 (使用 cgroup v1 或无 cgroup)"
fi
echo ""
echo "[7] Landlock (路径访问控制):"
if [ -f /sys/kernel/security/lsm ]; then
    lsms=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "")
    if echo "$lsms" | grep -q "landlock"; then
        echo "    Landlock LSM: ✅ 已启用"
    else
        echo "    Landlock LSM: ❌ 未启用 (需要内核配置 CONFIG_SECURITY_LANDLOCK)"
    fi
else
    echo "    Landlock LSM: ⚠️  无法检测"
fi
echo ""
echo "[8] 网络能力 (隔离网关/DNS劫持):"
if [ "$(id -u)" = "0" ] || capsh --print 2>/dev/null | grep -q "cap_net_admin"; then
    echo "    CAP_NET_ADMIN: ✅ 可用 (可创建 netns、iptables、DNS劫持)"
else
    echo "    CAP_NET_ADMIN: ❌ 不可用 (网络隔离功能受限)"
fi
echo ""
echo "=== 检查完成 ==="
echo ""
echo "环境分级结论:"
if [ -e /dev/kvm ] && [ "$(id -u)" = "0" ]; then
    echo "  ✅ 裸机/特权环境: 全部能力可完整跑通，可做端到端验证"
elif [ "$(id -u)" = "0" ]; then
    echo "  ⚠️  特权容器: LightPool 可用，StrongPool/eBPF/CRIU 受限"
else
    echo "  ❌ 普通容器/非root: 只能编译+单元测试，无法跑端到端隔离链路"
fi
echo ""
echo "参考文档: docs/privilege_requirements.md"
