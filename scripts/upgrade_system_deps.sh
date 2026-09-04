#!/bin/bash
# ============================================================
# PhotonBox 系统级依赖升级脚本
# 修复 2 个 HIGH CVE：
#   - CVE-2022-3602 (OpenSSL X.509 证书验证缓冲区溢出)
#   - CVE-2023-44487 (gRPC/HTTP/2 快速重置 DoS)
#
# 用法：
#   sudo bash scripts/upgrade_system_deps.sh
#
# 要求：
#   - root/sudo 权限
#   - Ubuntu 22.04 / 24.04 或 Debian 12
#   - 网络连接
# ============================================================

set -euo pipefail

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 检查 root 权限
if [[ $EUID -ne 0 ]]; then
    log_error "此脚本需要 root/sudo 权限"
    log_error "请运行: sudo bash scripts/upgrade_system_deps.sh"
    exit 1
fi

# 检测发行版
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "${ID:-unknown}"
    else
        echo "unknown"
    fi
}

DISTRO=$(detect_distro)
log_info "检测到发行版: $DISTRO"

# ============================================================
# 步骤 1：升级 OpenSSL（修复 CVE-2022-3602）
# ============================================================
upgrade_openssl() {
    log_info "=== 步骤 1/4：升级 OpenSSL（修复 CVE-2022-3602）==="

    # 检查当前版本
    CURRENT_OPENSSL=$(openssl version 2>/dev/null | awk '{print $2}' || echo "unknown")
    log_info "当前 OpenSSL 版本: $CURRENT_OPENSSL"

    # 检查是否需要升级（需要 >= 3.0.7）
    NEED_UPGRADE=false
    if [[ "$CURRENT_OPENSSL" != "unknown" ]]; then
        # 比较版本号
        if dpkg --compare-versions "$CURRENT_OPENSSL" lt "3.0.7"; then
            NEED_UPGRADE=true
        fi
    else
        NEED_UPGRADE=true
    fi

    if [[ "$NEED_UPGRADE" == "false" ]]; then
        log_info "OpenSSL 版本 >= 3.0.7，无需升级"
        return 0
    fi

    log_warn "OpenSSL 版本 < 3.0.7，存在 CVE-2022-3602 漏洞，开始升级"

    case "$DISTRO" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq libssl-dev openssl
            ;;
        centos|rhel|rocky|almalinux)
            yum update -y openssl openssl-devel
            ;;
        *)
            log_warn "不支持的发行版: $DISTRO，请手动升级 OpenSSL 到 >= 3.0.7"
            return 1
            ;;
    esac

    # 验证升级
    NEW_OPENSSL=$(openssl version 2>/dev/null | awk '{print $2}' || echo "unknown")
    log_info "升级后 OpenSSL 版本: $NEW_OPENSSL"

    if dpkg --compare-versions "$NEW_OPENSSL" ge "3.0.7"; then
        log_info "✅ OpenSSL 升级成功，CVE-2022-3602 已修复"
    else
        log_error "❌ OpenSSL 升级失败，当前版本仍 < 3.0.7"
        log_error "请尝试从源码编译: https://www.openssl.org/source/"
        return 1
    fi
}

# ============================================================
# 步骤 2：升级 gRPC C++（修复 CVE-2023-44487）
# ============================================================
upgrade_grpc() {
    log_info "=== 步骤 2/4：升级 gRPC C++（修复 CVE-2023-44487）==="

    # 检查当前版本
    CURRENT_GRPC=$(pkg-config --modversion grpc++ 2>/dev/null || echo "not_installed")
    log_info "当前 gRPC C++ 版本: $CURRENT_GRPC"

    # 检查是否需要升级（需要 >= 1.56）
    NEED_UPGRADE=false
    if [[ "$CURRENT_GRPC" == "not_installed" ]]; then
        NEED_UPGRADE=true
    elif dpkg --compare-versions "$CURRENT_GRPC" lt "1.56" 2>/dev/null; then
        NEED_UPGRADE=true
    fi

    if [[ "$NEED_UPGRADE" == "false" ]]; then
        log_info "gRPC C++ 版本 >= 1.56，无需升级"
        return 0
    fi

    log_warn "gRPC C++ 版本 < 1.56 或未安装，存在 CVE-2023-44487 漏洞，开始升级"

    case "$DISTRO" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq libgrpc++-dev protobuf-compiler-grpc libgrpc-dev protobuf-compiler
            ;;
        centos|rhel|rocky|almalinux)
            # CentOS/RHEL 需要 EPEL 或从源码编译
            log_warn "CentOS/RHEL 官方源可能没有 gRPC，建议从源码编译"
            log_warn "参考: https://grpc.io/docs/languages/cpp/quickstart/"
            ;;
        *)
            log_warn "不支持的发行版: $DISTRO，请手动升级 gRPC 到 >= 1.56"
            return 1
            ;;
    esac

    # 验证升级
    NEW_GRPC=$(pkg-config --modversion grpc++ 2>/dev/null || echo "not_installed")
    log_info "升级后 gRPC C++ 版本: $NEW_GRPC"

    if [[ "$NEW_GRPC" != "not_installed" ]] && dpkg --compare-versions "$NEW_GRPC" ge "1.56" 2>/dev/null; then
        log_info "✅ gRPC C++ 升级成功，CVE-2023-44487 已修复"
    else
        log_warn "⚠️  gRPC C++ 版本可能仍 < 1.56 或 pkg-config 无法检测"
        log_warn "如果 apt 源版本过低，请从源码编译 gRPC >= 1.56"
        log_warn "参考: https://grpc.io/docs/languages/cpp/quickstart/"
    fi
}

# ============================================================
# 步骤 3：升级 Python gRPC（修复 CVE-2023-44487）
# ============================================================
upgrade_python_grpc() {
    log_info "=== 步骤 3/4：升级 Python gRPC（修复 CVE-2023-44487）==="

    # 检查当前版本
    CURRENT_PY_GRPC=$(python3 -c "import grpc; print(grpc.__version__)" 2>/dev/null || echo "not_installed")
    log_info "当前 Python gRPC 版本: $CURRENT_PY_GRPC"

    # 升级
    pip3 install --upgrade grpcio grpcio-tools protobuf 2>&1 | tail -3

    # 验证
    NEW_PY_GRPC=$(python3 -c "import grpc; print(grpc.__version__)" 2>/dev/null || echo "not_installed")
    log_info "升级后 Python gRPC 版本: $NEW_PY_GRPC"

    if [[ "$NEW_PY_GRPC" != "not_installed" ]]; then
        log_info "✅ Python gRPC 升级成功"
    else
        log_error "❌ Python gRPC 升级失败"
        return 1
    fi
}

# ============================================================
# 步骤 4：验证 + 重新扫描 CVE
# ============================================================
verify_and_rescan() {
    log_info "=== 步骤 4/4：验证升级结果 + 重新扫描 CVE ==="

    echo ""
    echo "--- 版本验证 ---"
    echo "OpenSSL:  $(openssl version 2>/dev/null || echo 'not found')"
    echo "gRPC C++: $(pkg-config --modversion grpc++ 2>/dev/null || echo 'not installed')"
    echo "Python gRPC: $(python3 -c "import grpc; print(grpc.__version__)" 2>/dev/null || echo 'not installed')"
    echo ""

    # 运行 CVE 监控脚本
    if [[ -f scripts/cve_monitor.py ]]; then
        log_info "运行 CVE 监控脚本重新扫描..."
        python3 scripts/cve_monitor.py 2>&1 | tail -20 || true
    else
        log_warn "未找到 scripts/cve_monitor.py，跳过自动扫描"
    fi

    echo ""
    log_info "=== 升级完成 ==="
    echo ""
    echo "下一步："
    echo "  1. 重新编译 PhotonBox: cmake -B build && cmake --build build -j\$(nproc)"
    echo "  2. 运行全量测试: ctest --test-dir build --output-on-failure"
    echo "  3. 确认 CMake 输出中无 VULNERABLE 警告"
    echo ""
}

# ============================================================
# 主流程
# ============================================================
main() {
    echo ""
    echo "============================================================"
    echo "  PhotonBox 系统级依赖升级脚本"
    echo "  修复 CVE-2022-3602 (OpenSSL) + CVE-2023-44487 (gRPC)"
    echo "============================================================"
    echo ""

    upgrade_openssl
    echo ""
    upgrade_grpc
    echo ""
    upgrade_python_grpc
    echo ""
    verify_and_rescan
}

main "$@"
