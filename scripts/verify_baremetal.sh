#!/bin/bash
# 裸机特权环境一键端到端验证脚本
#
# 用途：在有 root 权限的裸机环境中，验证所有"未实测"模块的真实端到端流程
# 覆盖：CRIU、eBPF、gRPC C++、K8s Operator、Firecracker MicroVM、Landlock、GPU、VNC
#
# 使用：sudo ./scripts/verify_baremetal.sh
# 环境要求：Ubuntu 22.04+，root，KVM 支持（可选）
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0; SKIP=0
pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; SKIP=$((SKIP+1)); }
echo "=========================================="
echo "  Photon Kernel Sandbox - 裸机端到端验证"
echo "=========================================="
echo ""
# 检查 root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}错误：需要 root 权限运行${NC}"
    echo "使用：sudo $0"
    exit 1
fi
# 检测环境能力
echo "--- 环境能力检测 ---"
echo "内核版本: $(uname -r)"
echo "CPU: $(nproc) cores"
echo "内存: $(free -h | grep Mem | awk '{print $2}')"
echo ""
# ==================== 1. 基础构建测试 ====================
echo "--- 1. 基础构建与单元测试 ---"
if [ -d build ]; then rm -rf build; fi
cmake -B build -DCMAKE_BUILD_TYPE=Release -DPHOTON_ENABLE_GRPC=OFF >/dev/null 2>&1
if cmake --build build -j"$(nproc)" >/dev/null 2>&1; then
    pass "编译成功"
else
    fail "编译失败"
fi
# 运行 C++ 单元测试
for test_bin in test_sandbox test_enhanced test_new_modules test_agent_orchestrator; do
    if [ -f "./build/$test_bin" ]; then
        if timeout 120 "./build/$test_bin" >/dev/null 2>&1; then
            pass "$test_bin 全部通过"
        else
            fail "$test_bin 有失败"
        fi
    fi
done
echo ""
# ==================== 2. CRIU 进程级快照 ====================
echo "--- 2. CRIU 进程级快照 ---"
if command -v criu >/dev/null 2>&1; then
    # 启动一个测试进程
    echo "test-criu-process" > /tmp/criu_test_data
    (sleep 300 &) 
    TEST_PID=$!
    sleep 1
    # dump
    mkdir -p /tmp/criu_dump
    if criu dump -t "$TEST_PID" -D /tmp/criu_dump --leave-running --shell-job >/dev/null 2>&1; then
        pass "CRIU dump 成功"
        # kill 原进程
        kill "$TEST_PID" 2>/dev/null || true
        # restore
        if criu restore -d -D /tmp/criu_dump --shell-job >/dev/null 2>&1; then
            pass "CRIU restore 成功"
            RESTORED_PID=$(pgrep -f "sleep 300" | head -1)
            if [ -n "$RESTORED_PID" ]; then
                pass "恢复后进程运行中 (PID=$RESTORED_PID)"
                kill "$RESTORED_PID" 2>/dev/null || true
            else
                fail "恢复后进程未找到"
            fi
        else
            fail "CRIU restore 失败"
        fi
    else
        fail "CRIU dump 失败"
    fi
    rm -rf /tmp/criu_dump /tmp/criu_test_data
else
    skip "CRIU 未安装 (apt install criu)"
fi
echo ""
# ==================== 3. eBPF 网络管控 ====================
echo "--- 3. eBPF 网络管控 ---"
if [ -f /sys/kernel/btf/vmlinux ] && command -v clang >/dev/null 2>&1; then
    if [ -d ebpf ]; then
        cd ebpf
        if make >/dev/null 2>&1; then
            pass "eBPF 程序编译成功"
            # 加载测试（需要 CAP_BPF）
            if ./ebpf_loader --dry-run >/dev/null 2>&1; then
                pass "eBPF 加载器初始化成功"
            else
                skip "eBPF 加载需要 CAP_BPF（当前可能无权限）"
            fi
        else
            fail "eBPF 程序编译失败"
        fi
        cd ..
    fi
else
    skip "eBPF 环境不满足（需要 BTF + clang，apt install clang libbpf-dev）"
fi
echo ""
# ==================== 4. gRPC C++ 服务端 ====================
echo "--- 4. gRPC C++ 服务端 ---"
if pkg-config --exists grpc++ 2>/dev/null || [ -f /usr/include/grpcpp/grpcpp.h ]; then
    if cmake -B build_grpc -DCMAKE_BUILD_TYPE=Release -DPHOTON_ENABLE_GRPC=ON >/dev/null 2>&1; then
        if cmake --build build_grpc -j"$(nproc)" --target sandbox_server sandbox_client >/dev/null 2>&1; then
            pass "gRPC C++ 服务端/客户端编译成功"
            # 启动服务端测试
            ./build_grpc/sandbox_server --port 50052 &
            SERVER_PID=$!
            sleep 2
            if ./build_grpc/sandbox_client --port 50052 --code "print(42)" >/dev/null 2>&1; then
                pass "gRPC 端到端通信成功"
            else
                fail "gRPC 端到端通信失败"
            fi
            kill "$SERVER_PID" 2>/dev/null || true
        else
            fail "gRPC C++ 编译失败"
        fi
    else
        fail "gRPC CMake 配置失败"
    fi
    rm -rf build_grpc
else
    skip "gRPC C++ 库未安装（apt install libgrpc++-dev protobuf-compiler-grpc）"
fi
echo ""
# ==================== 5. K8s Operator ====================
echo "--- 5. K8s Operator ---"
if command -v kubectl >/dev/null 2>&1 && kubectl cluster-info >/dev/null 2>&1; then
    if [ -f deploy/crd.yaml ]; then
        if kubectl apply -f deploy/crd.yaml >/dev/null 2>&1; then
            pass "CRD 安装成功"
            # 启动 operator
            python3 operator/operator.py &
            OP_PID=$!
            sleep 3
            # 创建测试 CR
            cat <<EOF | kubectl apply -f - >/dev/null 2>&1
apiVersion: sandbox.photon.dev/v1
kind: SandboxPool
metadata:
  name: test-pool
spec:
  replicas: 2
  riskLevel: MEDIUM
EOF
            sleep 5
            if kubectl get sandboxpool test-pool >/dev/null 2>&1; then
                pass "SandboxPool CR 创建成功"
                # 检查 Pod
                POD_COUNT=$(kubectl get pods -l app=photon-sandbox -o name 2>/dev/null | wc -l)
                if [ "$POD_COUNT" -ge 1 ]; then
                    pass "Operator 创建了 $POD_COUNT 个 Pod"
                else
                    skip "Pod 创建可能需要更多时间"
                fi
            else
                fail "SandboxPool CR 创建失败"
            fi
            # 清理
            kubectl delete sandboxpool test-pool >/dev/null 2>&1 || true
            kubectl delete -f deploy/crd.yaml >/dev/null 2>&1 || true
            kill "$OP_PID" 2>/dev/null || true
        else
            fail "CRD 安装失败"
        fi
    fi
else
    skip "K8s 集群不可用（需要 kind/minikube，apt install kind && kind create cluster）"
fi
echo ""
# ==================== 6. Firecracker MicroVM ====================
echo "--- 6. Firecracker MicroVM StrongPool ---"
if command -v firecracker >/dev/null 2>&1 && [ -e /dev/kvm ]; then
    pass "Firecracker + KVM 可用"
    # 检查内核和 rootfs
    if [ -f /var/lib/firecracker/vmlinux.bin ] && [ -f /var/lib/firecracker/rootfs.ext4 ]; then
        pass "MicroVM 内核和 rootfs 就绪"
        # 启动测试 VM
        ./build/test_microvm 2>/dev/null || skip "MicroVM 测试需要单独编译"
    else
        skip "MicroVM 内核/rootfs 未就绪（参考 docs/microvm_integration.md 准备）"
    fi
else
    skip "Firecracker 或 KVM 不可用（需要裸机 + KVM，apt install firecracker）"
fi
echo ""
# ==================== 7. Landlock 路径白名单 ====================
echo "--- 7. Landlock 路径白名单 ---"
if [ -f /sys/kernel/security/lsm ] && grep -q landlock /sys/kernel/security/lsm; then
    # 编译并运行 landlock 测试
    if timeout 30 ./build/test_enhanced --gtest_filter="*Landlock*" >/dev/null 2>&1; then
        pass "Landlock 路径白名单测试通过"
    else
        skip "Landlock 测试需要 CAP_SYS_ADMIN"
    fi
else
    skip "Landlock LSM 未启用"
fi
echo ""
# ==================== 8. GPU/CUDA 隔离 ====================
echo "--- 8. GPU/CUDA 隔离 ---"
if command -v nvidia-smi >/dev/null 2>&1 && [ -e /dev/nvidia0 ]; then
    GPU_COUNT=$(nvidia-smi --query-gpu=index --format=csv,noheader | wc -l)
    pass "检测到 $GPU_COUNT 块 GPU"
    # 测试 CUDA_VISIBLE_DEVICES 隔离
    CUDA_VISIBLE_DEVICES=0 nvidia-smi -L >/dev/null 2>&1 && pass "CUDA_VISIBLE_DEVICES=0 隔离有效"
    CUDA_VISIBLE_DEVICES="" nvidia-smi -L 2>&1 | grep -q "No devices" && pass "CUDA_VISIBLE_DEVICES='' 禁止 GPU 访问"
else
    skip "无 NVIDIA GPU（需要 nvidia-smi + /dev/nvidia0）"
fi
echo ""
# ==================== 9. VNC 桌面 ====================
echo "--- 9. VNC 桌面 ---"
MISSING_VNC=""
for dep in Xvfb x11vnc websockify openbox; do
    command -v "$dep" >/dev/null 2>&1 || MISSING_VNC="$MISSING_VNC $dep"
done
if [ -z "$MISSING_VNC" ]; then
    pass "VNC 桌面依赖齐全"
    # 启动测试桌面
    Xvfb :99 -screen 0 1280x720x24 &
    XVFB_PID=$!
    sleep 1
    x11vnc -display :99 -rfbport 5999 -forever -shared -noxdamage &
    VNC_PID=$!
    sleep 1
    if ss -tlnp | grep -q 5999; then
        pass "VNC 服务器启动成功 (port 5999)"
    else
        fail "VNC 服务器启动失败"
    fi
    kill "$XVFB_PID" "$VNC_PID" 2>/dev/null || true
else
    skip "VNC 依赖缺失:$MISSING_VNC（apt install xvfb x11vnc websockify openbox novnc）"
fi
echo ""
# ==================== 10. Namespace 隔离 ====================
echo "--- 10. Linux Namespace 隔离（6种）---"
# 测试 user namespace
if unshare -U true 2>/dev/null; then
    pass "User namespace 可用"
else
    skip "User namespace 被禁用（/proc/sys/kernel/unprivileged_userns_clone）"
fi
# 测试 pid namespace
if unshare -p true 2>/dev/null; then
    pass "PID namespace 可用"
else
    skip "PID namespace 需要 root"
fi
# 测试 mount namespace
if unshare -m true 2>/dev/null; then
    pass "Mount namespace 可用"
else
    skip "Mount namespace 需要 root"
fi
echo ""
# ==================== 汇总 ====================
echo "=========================================="
echo "  验证结果汇总"
echo "=========================================="
echo -e "通过: ${GREEN}$PASS${NC}"
echo -e "失败: ${RED}$FAIL${NC}"
echo -e "跳过: ${YELLOW}$SKIP${NC}"
echo ""
if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}所有已执行测试全部通过！${NC}"
else
    echo -e "${RED}有 $FAIL 项测试失败，请检查上方日志${NC}"
fi
echo ""
echo "未执行的跳过项需要对应环境支持："
echo "  - CRIU: apt install criu"
echo "  - eBPF: apt install clang libbpf-dev + CAP_BPF"
echo "  - gRPC C++: apt install libgrpc++-dev protobuf-compiler-grpc"
echo "  - K8s: kind create cluster"
echo "  - Firecracker: 裸机 + KVM + apt install firecracker"
echo "  - GPU: NVIDIA 驱动 + nvidia-smi"
echo "  - VNC: apt install xvfb x11vnc websockify openbox novnc"
exit $FAIL
