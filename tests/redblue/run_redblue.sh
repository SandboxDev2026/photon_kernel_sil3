#!/bin/bash
# LightPool 红蓝对抗测试一键执行脚本
#
# 用法：./run_redblue.sh [--compile-only] [--poc <name>]
#   --compile-only: 只编译不执行
#   --poc <name>: 只执行指定 POC（如 ptrace, fd_leak, fork_bomb, seccomp_bypass, mount_escape）
#
# 预期：所有 POC 在沙盒内运行时被拦截，返回非零或被杀死
# 注意：POC 设计为在沙盒内运行，直接在宿主运行可能成功（这是正常的）

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
COMPILE_ONLY=false
SPECIFIC_POC=""

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --compile-only) COMPILE_ONLY=true; shift ;;
        --poc) SPECIFIC_POC="$2"; shift 2 ;;
        *) echo "未知参数: $1"; exit 1 ;;
    esac
done

mkdir -p "$BUILD_DIR"

# POC 列表
POCS=(
    "redteam_poc_ptrace:POC-001 ptrace注入:Critical"
    "redteam_poc_fd_leak:POC-002 fd泄露:High"
    "redteam_poc_fork_bomb:POC-003 fork炸弹:High"
    "redteam_poc_seccomp_bypass:POC-004 seccomp绕过:Critical"
    "redteam_poc_mount_escape:POC-005 mount逃逸:Critical"
)

echo "=========================================="
echo "  PhotonBox LightPool 红蓝对抗测试"
echo "=========================================="
echo "构建目录: $BUILD_DIR"
echo ""

# 编译所有 POC
echo "--- 编译红队 POC ---"
COMPILE_FAIL=0
for poc_entry in "${POCS[@]}"; do
    IFS=':' read -r poc_name poc_desc poc_risk <<< "$poc_entry"

    # 如果指定了 POC，跳过其他
    if [ -n "$SPECIFIC_POC" ] && [ "$poc_name" != "redteam_poc_$SPECIFIC_POC" ]; then
        continue
    fi

    src="$SCRIPT_DIR/${poc_name}.cpp"
    bin="$BUILD_DIR/${poc_name}"

    if [ ! -f "$src" ]; then
        echo -e "${YELLOW}[SKIP]${NC} $poc_name: 源文件不存在"
        continue
    fi

    if g++ -O2 -std=c++17 -o "$bin" "$src" 2>/dev/null; then
        echo -e "${GREEN}[OK]${NC} $poc_name 编译成功"
    else
        echo -e "${RED}[FAIL]${NC} $poc_name 编译失败"
        COMPILE_FAIL=$((COMPILE_FAIL+1))
    fi
done

if [ "$COMPILE_FAIL" -gt 0 ]; then
    echo -e "${RED}编译失败 $COMPILE_FAIL 个，退出${NC}"
    exit 1
fi

if [ "$COMPILE_ONLY" = true ]; then
    echo "编译完成（--compile-only）"
    exit 0
fi

echo ""
echo "--- 执行红队 POC ---"
echo "注意：POC 设计为在沙盒内运行，直接在宿主运行可能成功"
echo ""

TOTAL=0
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

for poc_entry in "${POCS[@]}"; do
    IFS=':' read -r poc_name poc_desc poc_risk <<< "$poc_entry"

    if [ -n "$SPECIFIC_POC" ] && [ "$poc_name" != "redteam_poc_$SPECIFIC_POC" ]; then
        continue
    fi

    bin="$BUILD_DIR/${poc_name}"
    if [ ! -f "$bin" ]; then
        echo -e "${YELLOW}[SKIP]${NC} $poc_desc: 未编译"
        SKIP_COUNT=$((SKIP_COUNT+1))
        continue
    fi

    TOTAL=$((TOTAL+1))
    echo "--- $poc_desc (风险: $poc_risk) ---"

    # fork 炸弹需要超时保护
    if [ "$poc_name" = "redteam_poc_fork_bomb" ]; then
        timeout 5 "$bin" 2>&1 | tail -5
        exit_code=${PIPESTATUS[0]}
    else
        timeout 10 "$bin" 2>&1
        exit_code=$?
    fi

    # 判断结果：
    # exit_code=0: POC 认为测试通过（被拦截）
    # exit_code=1: POC 发现漏洞
    # exit_code=137 (128+9): 被 SIGKILL（seccomp KILL_PROCESS）
    # exit_code=124: timeout
    if [ "$exit_code" -eq 0 ]; then
        echo -e "${GREEN}[PASS]${NC} POC 被正确拦截（exit=0）"
        PASS_COUNT=$((PASS_COUNT+1))
    elif [ "$exit_code" -eq 137 ]; then
        echo -e "${GREEN}[PASS]${NC} 进程被 SIGKILL（seccomp KILL_PROCESS 生效）"
        PASS_COUNT=$((PASS_COUNT+1))
    elif [ "$exit_code" -eq 124 ]; then
        echo -e "${YELLOW}[TIMEOUT]${NC} POC 超时（可能需要检查资源限制）"
        FAIL_COUNT=$((FAIL_COUNT+1))
    elif [ "$exit_code" -eq 1 ]; then
        echo -e "${RED}[FAIL]${NC} POC 发现安全漏洞！（exit=1）"
        FAIL_COUNT=$((FAIL_COUNT+1))
    else
        echo -e "${YELLOW}[UNKNOWN]${NC} 退出码: $exit_code"
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
    echo ""
done

echo "=========================================="
echo "  红蓝对抗测试结果汇总"
echo "=========================================="
echo -e "总数: $TOTAL"
echo -e "通过: ${GREEN}$PASS_COUNT${NC}"
echo -e "失败: ${RED}$FAIL_COUNT${NC}"
echo -e "跳过: ${YELLOW}$SKIP_COUNT${NC}"
echo ""

if [ "$FAIL_COUNT" -eq 0 ] && [ "$TOTAL" -gt 0 ]; then
    echo -e "${GREEN}✅ 全部红队 POC 被正确拦截${NC}"
    exit 0
else
    echo -e "${RED}❌ 有 $FAIL_COUNT 个 POC 未被正确拦截，请检查${NC}"
    exit 1
fi
