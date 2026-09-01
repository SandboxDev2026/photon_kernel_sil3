#!/bin/bash
# Photon Kernel Sandbox 统一构建脚本
# 自动检测环境、安装依赖、配置编译选项、构建
#
# 用法:
#   ./scripts/build.sh              # 默认构建（非 gRPC，适合无 gRPC 环境）
#   ./scripts/build.sh --grpc       # 启用 gRPC（需要 libgrpc++-dev）
#   ./scripts/build.sh --clean      # 清理后重新构建
#   ./scripts/build.sh --test       # 构建后运行测试
#   ./scripts/build.sh --all        # 全部（clean + grpc + test）
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
# 默认选项
ENABLE_GRPC=OFF
DO_CLEAN=0
DO_TEST=0
# 解析参数
for arg in "$@"; do
    case "$arg" in
        --grpc)   ENABLE_GRPC=ON ;;
        --clean)  DO_CLEAN=1 ;;
        --test)   DO_TEST=1 ;;
        --all)    DO_CLEAN=1; ENABLE_GRPC=ON; DO_TEST=1 ;;
        -h|--help)
            echo "用法: $0 [--grpc] [--clean] [--test] [--all]"
            echo "  --grpc   启用 gRPC（需要 libgrpc++-dev）"
            echo "  --clean  清理 build 目录"
            echo "  --test   构建后运行测试"
            echo "  --all    全部（clean + grpc + test）"
            exit 0
            ;;
        *)
            echo "未知参数: $arg" >&2
            exit 1
            ;;
    esac
done
echo "=== Photon Kernel Sandbox 构建 ==="
echo "项目目录: ${PROJECT_DIR}"
echo "构建目录: ${BUILD_DIR}"
echo "gRPC: ${ENABLE_GRPC}"
echo ""
# ---- 检测依赖 ----
echo "[1/4] 检测依赖..."
MISSING_PKGS=""
# 编译工具
for cmd in cmake g++ make; do
    if ! command -v "$cmd" &>/dev/null; then
        MISSING_PKGS="${MISSING_PKGS} ${cmd}"
    fi
done
# gRPC 依赖（如果启用）
if [ "$ENABLE_GRPC" = "ON" ]; then
    for pkg in libgrpc++-dev protobuf-compiler-grpc; do
        if ! dpkg -s "$pkg" &>/dev/null 2>&1; then
            MISSING_PKGS="${MISSING_PKGS} ${pkg}"
        fi
    done
fi
# OpenSSL（可选，有则用，无则用 fallback）
if pkg-config --exists openssl 2>/dev/null; then
    echo "  OpenSSL: 已找到（使用 OpenSSL HMAC）"
else
    echo "  OpenSSL: 未找到（使用内置 crypto_utils fallback）"
fi
if [ -n "$MISSING_PKGS" ]; then
    echo ""
    echo "缺少依赖:${MISSING_PKGS}"
    echo "尝试自动安装（需要 sudo）..."
    if command -v sudo &>/dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq cmake g++ make ${MISSING_PKGS}
    else
        echo "无 sudo 权限，请手动安装: apt-get install -y${MISSING_PKGS}" >&2
        exit 1
    fi
fi
echo "  依赖检测完成"
# ---- GTest 检测 ----
echo ""
echo "[2/4] 检测 GTest..."
GTEST_DIR=""
for candidate in \
    "/usr/lib/x86_64-linux-gnu/cmake/GTest" \
    "/usr/lib/cmake/GTest" \
    "/usr/local/lib/cmake/GTest"; do
    if [ -d "$candidate" ]; then
        GTEST_DIR="$candidate"
        break
    fi
done
if [ -n "$GTEST_DIR" ]; then
    echo "  GTest: ${GTEST_DIR}"
else
    echo "  GTest: 未找到，测试将跳过"
fi
# ---- 清理 ----
if [ "$DO_CLEAN" = "1" ]; then
    echo ""
    echo "[3/4] 清理构建目录..."
    rm -rf "$BUILD_DIR"
    echo "  已清理"
fi
# ---- 配置 ----
echo ""
echo "[3/4] CMake 配置..."
CMAKE_ARGS=(
    -B "$BUILD_DIR"
    -S "$PROJECT_DIR"
    -DCMAKE_BUILD_TYPE=Release
    -DPHOTON_ENABLE_GRPC="$ENABLE_GRPC"
)
if [ -n "$GTEST_DIR" ]; then
    CMAKE_ARGS+=(-DGTEST_DIR="$GTEST_DIR")
fi
cmake "${CMAKE_ARGS[@]}"
# ---- 构建 ----
echo ""
echo "[4/4] 编译..."
JOBS="$(nproc 2>/dev/null || echo 4)"
cmake --build "$BUILD_DIR" -j"$JOBS"
echo ""
echo "=== 构建完成 ==="
echo "可执行文件: ${BUILD_DIR}/"
ls -1 "$BUILD_DIR"/*_test "$BUILD_DIR"/metrics_server "$BUILD_DIR"/e2b_gateway 2>/dev/null || true
# ---- 测试 ----
if [ "$DO_TEST" = "1" ]; then
    echo ""
    echo "=== 运行测试 ==="
    if [ -f "$BUILD_DIR/test_sandbox" ]; then
        "$BUILD_DIR/test_sandbox"
    fi
    if [ -f "$BUILD_DIR/test_enhanced" ]; then
        "$BUILD_DIR/test_enhanced"
    fi
    # Python 测试
    if command -v python3 &>/dev/null; then
        echo ""
        echo "--- Python Operator 测试 ---"
        python3 "$PROJECT_DIR/tests/test_operator.py" 2>&1 | tail -3
        echo ""
        echo "--- Python gRPC 契约测试 ---"
        if python3 -c "import grpc" 2>/dev/null; then
            mkdir -p /tmp/proto_out
            python3 -m grpc_tools.protoc -I "$PROJECT_DIR/proto" \
                --python_out=/tmp/proto_out --grpc_python_out=/tmp/proto_out \
                "$PROJECT_DIR/proto/sandbox.proto" 2>/dev/null || true
            PYTHONPATH=/tmp/proto_out python3 "$PROJECT_DIR/tests/test_grpc_contract.py" 2>&1 | tail -3
        else
            echo "grpcio 未安装，跳过 gRPC 契约测试"
        fi
    fi
fi
echo ""
echo "=== 全部完成 ==="
