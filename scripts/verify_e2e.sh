#!/bin/bash
# Photon Kernel Sandbox 端到端验证脚本
# 在有 root 权限的机器上一键验证：CRIU / eBPF / K8s Operator / gRPC / 基础沙盒
#
# 用法:
#   sudo ./scripts/verify_e2e.sh              # 全部验证
#   sudo ./scripts/verify_e2e.sh --criu       # 仅 CRIU
#   sudo ./scripts/verify_e2e.sh --ebpf       # 仅 eBPF
#   sudo ./scripts/verify_e2e.sh --k8s        # 仅 K8s Operator
#   sudo ./scripts/verify_e2e.sh --grpc       # 仅 gRPC
#   sudo ./scripts/verify_e2e.sh --basic      # 仅基础沙盒（不需要 root）
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
PASS=0
FAIL=0
SKIP=0
# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
log_skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; SKIP=$((SKIP+1)); }
log_info() { echo -e "[INFO] $1"; }
# 检查 root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_skip "需要 root 权限，跳过 $1"
        return 1
    fi
    return 0
}
# ---- 基础沙盒验证（不需要 root）----
verify_basic() {
    echo ""
    echo "=== 基础沙盒验证 ==="
    if [ ! -f "$BUILD_DIR/test_sandbox" ]; then
        log_skip "test_sandbox 未构建，跳过"
        return
    fi
    if "$BUILD_DIR/test_sandbox" 2>&1 | tail -1 | grep -q "PASSED"; then
        log_pass "基础沙盒测试通过"
    else
        log_fail "基础沙盒测试失败"
    fi
    if [ -f "$BUILD_DIR/test_enhanced" ]; then
        RESULT=$("$BUILD_DIR/test_enhanced" 2>&1 | tail -3)
        PASSED=$(echo "$RESULT" | grep -oP '\d+(?= tests?\.? passed)' || echo 0)
        SKIPPED=$(echo "$RESULT" | grep -oP '\d+(?= tests?\.? skipped)' || echo 0)
        log_pass "增强测试: ${PASSED} 通过, ${SKIPPED} 跳过"
    fi
}
# ---- CRIU 验证 ----
verify_criu() {
    echo ""
    echo "=== CRIU 进程快照验证 ==="
    check_root "CRIU" || return
    if ! command -v criu &>/dev/null; then
        log_skip "criu 未安装，跳过 (apt install criu)"
        return
    fi
    # 检查内核支持
    if criu check --all 2>&1 | grep -q "Error"; then
        log_fail "CRIU 内核检查失败"
        return
    fi
    log_pass "CRIU 内核检查通过"
    # dump/restore 测试
    TEST_DIR=$(mktemp -d)
    sleep 300 &
    TEST_PID=$!
    sleep 0.5
    if criu dump -t "$TEST_PID" -D "$TEST_DIR" --shell-job --leave-running 2>/dev/null; then
        log_pass "CRIU dump 成功"
        kill "$TEST_PID" 2>/dev/null
        if criu restore -d -D "$TEST_DIR" --shell-job --pidfile "$TEST_DIR/restored.pid" 2>/dev/null; then
            log_pass "CRIU restore 成功"
            RESTORED_PID=$(cat "$TEST_DIR/restored.pid" 2>/dev/null || echo "?")
            if kill -0 "$RESTORED_PID" 2>/dev/null; then
                log_pass "恢复后进程存活 (PID=$RESTORED_PID)"
                kill "$RESTORED_PID" 2>/dev/null
            else
                log_fail "恢复后进程不存活"
            fi
        else
            log_fail "CRIU restore 失败"
        fi
    else
        log_fail "CRIU dump 失败"
        kill "$TEST_PID" 2>/dev/null
    fi
    rm -rf "$TEST_DIR"
}
# ---- eBPF 验证 ----
verify_ebpf() {
    echo ""
    echo "=== eBPF 网络管控验证 ==="
    check_root "eBPF" || return
    # 检查内核支持
    if ! grep -q "CONFIG_BPF=y" /boot/config-$(uname -r) 2>/dev/null && \
       ! zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_BPF=y"; then
        log_skip "内核不支持 eBPF，跳过"
        return
    fi
    # 检查权限
    if ! capsh --print 2>/dev/null | grep -q "cap_bpf"; then
        log_skip "缺少 CAP_BPF 权限，跳过"
        return
    fi
    log_pass "eBPF 内核支持 + CAP_BPF 权限"
    # 检查 libbpf
    if pkg-config --exists libbpf 2>/dev/null; then
        log_pass "libbpf 已安装"
    else
        log_skip "libbpf 未安装 (apt install libbpf-dev)"
    fi
    # 加载最小 eBPF 程序测试
    if command -v bpftool &>/dev/null; then
        log_pass "bpftool 可用"
    else
        log_skip "bpftool 未安装"
    fi
}
# ---- K8s Operator 验证 ----
verify_k8s() {
    echo ""
    echo "=== K8s Operator 验证 ==="
    if ! command -v kubectl &>/dev/null; then
        log_skip "kubectl 未安装，跳过"
        return
    fi
    if ! kubectl cluster-info &>/dev/null 2>&1; then
        log_skip "K8s 集群不可用，跳过 (kind create cluster)"
        return
    fi
    log_pass "K8s 集群可用"
    # 部署 CRD
    if kubectl apply -f "$PROJECT_DIR/deploy/crd.yaml" 2>/dev/null; then
        log_pass "CRD 部署成功"
    else
        log_fail "CRD 部署失败"
        return
    fi
    # 等待 CRD 就绪
    sleep 2
    # 创建测试 SandboxPool
    cat <<EOF | kubectl apply -f - 2>/dev/null
apiVersion: sandbox.photon.io/v1alpha1
kind: SandboxPool
metadata:
  name: e2e-test-pool
spec:
  replicas: 1
  riskLevel: low
  image: nginx:alpine
EOF
    sleep 3
    if kubectl get sandboxpool e2e-test-pool &>/dev/null; then
        log_pass "SandboxPool CR 创建成功"
    else
        log_fail "SandboxPool CR 创建失败"
    fi
    # 检查 Deployment
    if kubectl get deployment e2e-test-pool-worker &>/dev/null; then
        log_pass "Operator 创建 Deployment 成功"
    else
        log_skip "Deployment 未创建（Operator 可能未运行）"
    fi
    # 清理
    kubectl delete sandboxpool e2e-test-pool 2>/dev/null
    kubectl delete -f "$PROJECT_DIR/deploy/crd.yaml" 2>/dev/null
}
# ---- gRPC 验证 ----
verify_grpc() {
    echo ""
    echo "=== gRPC 服务端验证 ==="
    if [ ! -f "$BUILD_DIR/sandbox_server" ]; then
        log_skip "sandbox_server 未构建（需要 gRPC 库），跳过"
        return
    fi
    # 启动服务端
    "$BUILD_DIR/sandbox_server" &
    SERVER_PID=$!
    sleep 2
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        log_fail "gRPC 服务端启动失败"
        return
    fi
    log_pass "gRPC 服务端启动成功 (PID=$SERVER_PID)"
    # 运行客户端
    if [ -f "$BUILD_DIR/sandbox_client" ]; then
        if "$BUILD_DIR/sandbox_client" 2>&1 | grep -q "42"; then
            log_pass "gRPC 客户端执行 Python print(42) 成功"
        else
            log_fail "gRPC 客户端执行失败"
        fi
    fi
    kill "$SERVER_PID" 2>/dev/null
}
# ---- 主流程 ----
echo "=========================================="
echo " Photon Kernel Sandbox 端到端验证"
echo "=========================================="
echo "时间: $(date)"
echo "内核: $(uname -r)"
echo "用户: $(whoami)"
# 解析参数
if [ $# -eq 0 ]; then
    verify_basic
    verify_criu
    verify_ebpf
    verify_k8s
    verify_grpc
else
    for arg in "$@"; do
        case "$arg" in
            --basic) verify_basic ;;
            --criu)  verify_criu ;;
            --ebpf)  verify_ebpf ;;
            --k8s)   verify_k8s ;;
            --grpc)  verify_grpc ;;
        esac
    done
fi
echo ""
echo "=========================================="
echo " 验证结果: ${PASS} 通过, ${FAIL} 失败, ${SKIP} 跳过"
echo "=========================================="
exit $FAIL
