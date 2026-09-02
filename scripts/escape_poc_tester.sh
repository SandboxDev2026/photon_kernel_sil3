#!/bin/bash
# escape_poc_tester.sh — 沙盒逃逸 POC 对抗测试框架
#
# 用途：收集公开的 namespace/seccomp/Landlock 逃逸 POC，在沙盒内自动运行，
#       验证隔离是否有效，检测逃逸面。
#
# 覆盖：
#   1. namespace 逃逸测试（user/pid/mount/net/uts/ipc）
#   2. seccomp 逃逸测试（系统调用过滤绕过）
#   3. Landlock 逃逸测试（文件路径控制绕过）
#   4. cgroup 逃逸测试（资源限制绕过）
#   5. 内核漏洞利用检测（已知 CVE POC 框架）
#   6. 信息泄露测试（/proc、/sys 信息泄露）
#
# 使用：
#   sudo ./scripts/escape_poc_tester.sh           # 全部测试
#   sudo ./scripts/escape_poc_tester.sh --namespace  # 仅 namespace 测试
#   sudo ./scripts/escape_poc_tester.sh --seccomp    # 仅 seccomp 测试
#   sudo ./scripts/escape_poc_tester.sh --quick      # 快速模式（跳过耗时测试）
#
# 注意：部分测试需要 root 权限，普通容器环境会自动 skip
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS=0; FAIL=0; SKIP=0; ESCAPES=0
TEST_NAMESPACE=true; TEST_SECCOMP=true; TEST_LANDLOCK=true
TEST_CGROUP=true; TEST_INFO_LEAK=true; QUICK_MODE=false

# ==================== 环境检测 ====================
# 环境分级:
#   photon-sandbox: 真正的PhotonBox沙盒 (有seccomp过滤)
#   container: 容器环境 (有namespace/cgroup但无seccomp)
#   host: 宿主机环境 (无隔离)
ENV_TYPE="host"
HAS_SECCOMP=false
HAS_NAMESPACE=false
HAS_CGROUP=false

# 检测seccomp (沙盒核心特征)
if [ -f /proc/self/status ]; then
    if grep -q "Seccomp:[[:space:]]*[12]" /proc/self/status 2>/dev/null; then
        HAS_SECCOMP=true
    fi
fi

# 检测namespace (容器/沙盒特征)
MY_PID=$$
PROC_COUNT=$(ls /proc | grep -c "^[0-9]" 2>/dev/null || echo "999")
if [ "$MY_PID" = "1" ] || [ "$PROC_COUNT" -lt 100 ]; then
    HAS_NAMESPACE=true
fi

# 检测cgroup (容器特征)
if [ -f /sys/fs/cgroup/memory.max ]; then
    MEM_LIMIT=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo "max")
    if [ "$MEM_LIMIT" != "max" ] && [ "$MEM_LIMIT" != "" ] && [ "$MEM_LIMIT" -lt 1099511627776 ]; then
        HAS_CGROUP=true
    fi
fi

# 判断环境类型
if [ "$HAS_SECCOMP" = true ]; then
    ENV_TYPE="photon-sandbox"
elif [ "$HAS_NAMESPACE" = true ] || [ "$HAS_CGROUP" = true ]; then
    ENV_TYPE="container"
else
    ENV_TYPE="host"
fi

# 兼容旧变量: 只有真正的photon-sandbox才算IN_SANDBOX
IN_SANDBOX=false
if [ "$ENV_TYPE" = "photon-sandbox" ]; then
    IN_SANDBOX=true
fi

echo "=========================================="
echo "  环境检测"
echo "=========================================="
echo "  seccomp过滤: $([ "$HAS_SECCOMP" = true ] && echo '有' || echo '无')"
echo "  namespace隔离: $([ "$HAS_NAMESPACE" = true ] && echo '有' || echo '无')"
echo "  cgroup限制: $([ "$HAS_CGROUP" = true ] && echo '有' || echo '无')"
echo ""
case "$ENV_TYPE" in
    photon-sandbox)
        echo "  [INFO] 当前在 PhotonBox 沙盒内部运行 (有seccomp过滤)"
        echo "  [INFO] 逃逸测试结果有效, 检测到逃逸即为真实漏洞!"
        ;;
    container)
        echo "  [WARN] 当前在容器环境中运行 (有namespace/cgroup但无seccomp过滤)"
        echo "  [WARN] 非 PhotonBox 沙盒, ptrace/system调用等测试'被允许'是预期行为"
        echo "  [WARN] 正确用法: 将本脚本传入 PhotonBox 沙盒内部运行"
        ;;
    host)
        echo "  [WARN] 当前在宿主机/普通环境中运行 (无任何隔离)"
        echo "  [WARN] 所有测试结果反映的是宿主机环境, 非沙盒内部!"
        echo "  [WARN] ptrace/system调用等测试在宿主机必然'被允许', 非逃逸漏洞!"
        ;;
esac
echo ""
# 解析参数
for arg in "$@"; do
    case $arg in
        --namespace) TEST_SECCOMP=false; TEST_LANDLOCK=false; TEST_CGROUP=false; TEST_INFO_LEAK=false ;;
        --seccomp) TEST_NAMESPACE=false; TEST_LANDLOCK=false; TEST_CGROUP=false; TEST_INFO_LEAK=false ;;
        --landlock) TEST_NAMESPACE=false; TEST_SECCOMP=false; TEST_CGROUP=false; TEST_INFO_LEAK=false ;;
        --cgroup) TEST_NAMESPACE=false; TEST_SECCOMP=false; TEST_LANDLOCK=false; TEST_INFO_LEAK=false ;;
        --info) TEST_NAMESPACE=false; TEST_SECCOMP=false; TEST_LANDLOCK=false; TEST_CGROUP=false ;;
        --quick) QUICK_MODE=true ;;
        --help|-h)
            echo "Usage: $0 [--namespace|--seccomp|--landlock|--cgroup|--info] [--quick]"
            exit 0 ;;
    esac
done
pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; SKIP=$((SKIP+1)); }
escape() { echo -e "${RED}[ESCAPE DETECTED]${NC} $1"; ESCAPES=$((ESCAPES+1)); FAIL=$((FAIL+1)); }
section() { echo -e "\n${BLUE}=== $1 ===${NC}"; }
echo "=========================================="
echo "  Photon Kernel Sandbox - 逃逸 POC 对抗测试"
echo "=========================================="
echo "环境: $(uname -r), root=$( [ "$EUID" -eq 0 ] && echo yes || echo no )"
echo "快速模式: $QUICK_MODE"
echo ""
# 创建临时工作目录
WORK_DIR=$(mktemp -d /tmp/photon_escape_test.XXXXXX)
trap "rm -rf $WORK_DIR" EXIT
# ==================== 1. Namespace 逃逸测试 ====================
if [ "$TEST_NAMESPACE" = true ]; then
section "1. Namespace 逃逸测试"
# 1.1 user namespace 逃逸：尝试创建 user namespace 并映射 root
cat > "$WORK_DIR/test_userns.c" << 'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>
#include <fcntl.h>
int main() {
    // 尝试创建 user namespace
    if (unshare(CLONE_NEWUSER) == -1) {
        printf("user namespace blocked\n");
        return 1;
    }
    // 映射 uid 0（尝试获取 root）
    int fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd == -1) { printf("uid_map open failed\n"); return 1; }
    if (write(fd, "0 0 1\n", 6) != 6) { printf("uid_map write failed\n"); close(fd); return 1; }
    close(fd);
    // 检查是否获得了 root
    if (geteuid() == 0) {
        printf("ESCAPE: got root in user namespace\n");
        return 0;
    }
    printf("user namespace created but not root\n");
    return 1;
}
EOF
if gcc -o "$WORK_DIR/test_userns" "$WORK_DIR/test_userns.c" 2>/dev/null; then
    if "$WORK_DIR/test_userns" 2>/dev/null | grep -q "ESCAPE"; then
        escape "user namespace 逃逸成功（获得 root）"
    else
        pass "user namespace 逃逸被阻止"
    fi
else
    skip "user namespace 测试编译失败（gcc 不可用）"
fi
# 1.2 pid namespace 逃逸：尝试看到宿主机进程
if [ -f /proc/1/status ]; then
    HOST_PID_COUNT=$(ls /proc/ | grep -c '^[0-9]' || echo 0)
    if [ "$HOST_PID_COUNT" -gt 100 ]; then
        # 如果能看到大量进程，说明 pid namespace 可能没有隔离
        escape "pid namespace 隔离失效（可见 $HOST_PID_COUNT 个宿主进程）"
    else
        pass "pid namespace 隔离有效（仅可见 $HOST_PID_COUNT 个进程）"
    fi
else
    skip "pid namespace 测试无法执行"
fi
# 1.3 mount namespace 逃逸：尝试挂载宿主机文件系统
cat > "$WORK_DIR/test_mount.c" << 'EOF'
#include <stdio.h>
#include <sys/mount.h>
int main() {
    // 尝试挂载 proc（常见逃逸第一步）
    if (mount("proc", "/tmp/proc_test", "proc", 0, NULL) == 0) {
        printf("ESCAPE: mount succeeded\n");
        umount("/tmp/proc_test");
        return 0;
    }
    printf("mount blocked\n");
    return 1;
}
EOF
mkdir -p /tmp/proc_test
if gcc -o "$WORK_DIR/test_mount" "$WORK_DIR/test_mount.c" 2>/dev/null; then
    if "$WORK_DIR/test_mount" 2>/dev/null | grep -q "ESCAPE"; then
        escape "mount namespace 逃逸成功（可挂载文件系统）"
    else
        pass "mount namespace 逃逸被阻止"
    fi
else
    skip "mount namespace 测试编译失败"
fi
# 1.4 network namespace 逃逸：尝试访问宿主机网络接口
if command -v ip >/dev/null 2>&1; then
    IFACE_COUNT=$(ip link show 2>/dev/null | grep -c "^[0-9]" || echo 0)
    if [ "$IFACE_COUNT" -gt 3 ]; then
        escape "network namespace 隔离失效（可见 $IFACE_COUNT 个网络接口）"
    else
        pass "network namespace 隔离有效（仅 $IFACE_COUNT 个接口）"
    fi
else
    skip "network namespace 测试需要 ip 命令"
fi
fi
# ==================== 2. seccomp 逃逸测试 ====================
if [ "$TEST_SECCOMP" = true ]; then
section "2. seccomp 逃逸测试"
# 2.1 尝试调用被禁止的系统调用（ptrace）
cat > "$WORK_DIR/test_ptrace.c" << 'EOF'
#include <stdio.h>
#include <sys/ptrace.h>
int main() {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0) {
        printf("ESCAPE: ptrace allowed\n");
        return 0;
    }
    printf("ptrace blocked\n");
    return 1;
}
EOF
if gcc -o "$WORK_DIR/test_ptrace" "$WORK_DIR/test_ptrace.c" 2>/dev/null; then
    if "$WORK_DIR/test_ptrace" 2>/dev/null | grep -q "ESCAPE"; then
        if [ "$IN_SANDBOX" = true ]; then
            escape "seccomp 逃逸：ptrace 被允许（高危 syscall）- 沙盒内部检测到, 真实漏洞!"
        else
            echo "  [SKIP] ptrace 在宿主机环境被允许(预期行为), 非沙盒内部, 不计为逃逸"
            SKIP=$((SKIP+1))
        fi
    else
        pass "seccomp 有效：ptrace 被阻止"
    fi
else
    skip "ptrace 测试编译失败"
fi
# 2.2 尝试 kexec_load（内核加载，极高危）
cat > "$WORK_DIR/test_kexec.c" << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
int main() {
    // kexec_load syscall number (x86_64: 246)
    long ret = syscall(246, 0, 0, 0, 0, 0);
    if (ret == 0 || (ret == -1 && errno != 0)) {
        // 如果没有被 SIGKILL，说明 seccomp 可能没有阻止
        printf("kexec not killed (errno check needed)\n");
    }
    printf("kexec test done\n");
    return 0;
}
EOF
# 这个测试可能导致进程被 kill，用 timeout 保护
if gcc -o "$WORK_DIR/test_kexec" "$WORK_DIR/test_kexec.c" 2>/dev/null; then
    if timeout 2 "$WORK_DIR/test_kexec" 2>/dev/null; then
        # 进程正常退出，说明 kexec 没有被 SIGKILL
        # 但可能返回了错误，需要检查
        escape "seccomp 风险：kexec_load 未被 SIGKILL（应检查是否被阻止）"
    else
        pass "seccomp 有效：kexec_load 被阻止（进程被杀或超时）"
    fi
else
    skip "kexec 测试编译失败"
fi
# 2.3 seccomp 绕过：尝试通过 syscall 号直接调用
cat > "$WORK_DIR/test_raw_syscall.c" << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
int main() {
    // 尝试调用 getpid（应该允许）
    long pid = syscall(SYS_getpid);
    printf("getpid via raw syscall: %ld\n", pid);
    // 尝试调用 open_by_handle_at（通常被禁止，需要 CAP_DAC_READ_SEARCH）
    long ret = syscall(304, 0, NULL, 0);  // open_by_handle_at
    printf("open_by_handle_at returned: %ld\n", ret);
    return 0;
}
EOF
if gcc -o "$WORK_DIR/test_raw" "$WORK_DIR/test_raw_syscall.c" 2>/dev/null; then
    OUTPUT=$(timeout 2 "$WORK_DIR/test_raw" 2>/dev/null || echo "killed")
    if echo "$OUTPUT" | grep -q "killed"; then
        pass "seccomp 有效：raw syscall 高危调用被阻止"
    else
        pass "seccomp raw syscall 测试完成（需人工审查输出）"
    fi
else
    skip "raw syscall 测试编译失败"
fi
fi
# ==================== 3. Landlock 逃逸测试 ====================
if [ "$TEST_LANDLOCK" = true ]; then
section "3. Landlock 逃逸测试"
# 3.1 检查 Landlock 是否启用
if [ -f /sys/kernel/security/lsm ]; then
    LSM=$(cat /sys/kernel/security/lsm)
    if echo "$LSM" | grep -q "landlock"; then
        pass "Landlock LSM 已启用"
    else
        skip "Landlock 未在内核中启用（LSM: $LSM）"
    fi
else
    skip "无法检查 Landlock 状态"
fi
# 3.2 尝试访问敏感文件
SENSITIVE_FILES=(
    "/etc/shadow"
    "/etc/sudoers"
    "/root/.ssh/id_rsa"
    "/proc/kallsyms"
    "/sys/kernel/debug"
)
for f in "${SENSITIVE_FILES[@]}"; do
    if [ -f "$f" ] || [ -d "$f" ]; then
        if cat "$f" >/dev/null 2>&1; then
            if [ "$IN_SANDBOX" = true ]; then
                escape "文件权限：可读取敏感文件 $f (沙盒内部检测到)"
            else
                echo "  [INFO] 宿主机环境可读取 $f (非沙盒内部, 预期行为)"
            fi
        else
            pass "敏感文件 $f 不可读"
        fi
    else
        echo "  [SKIP] 敏感文件 $f 不存在, 跳过"
        SKIP=$((SKIP+1))
    fi
done
fi
# ==================== 4. cgroup 逃逸测试 ====================
if [ "$TEST_CGROUP" = true ]; then
section "4. cgroup 逃逸测试"
# 4.1 检查 cgroup v2 是否挂载
if mount | grep -q "cgroup2"; then
    pass "cgroup v2 已挂载"
else
    skip "cgroup v2 未挂载（系统使用 cgroup v1 或无 cgroup）"
fi
# 4.2 尝试修改 cgroup 限制
if [ -d /sys/fs/cgroup ]; then
    if echo "max" > /sys/fs/cgroup/photon_test/memory.max 2>/dev/null; then
        escape "cgroup 逃逸：可修改 cgroup 限制（memory.max）"
        rmdir /sys/fs/cgroup/photon_test 2>/dev/null || true
    else
        pass "cgroup 限制不可修改（受保护）"
    fi
fi
# 4.3 资源耗尽测试（fork bomb 检测）
if [ "$QUICK_MODE" = false ]; then
    echo "  运行 fork bomb 检测（5秒超时）..."
    FORK_COUNT=0
    for i in $(seq 1 100); do
        (sleep 10 &) 2>/dev/null && FORK_COUNT=$((FORK_COUNT+1)) || break
    done
    # 清理
    pkill -f "sleep 10" 2>/dev/null || true
    if [ "$FORK_COUNT" -lt 100 ]; then
        pass "cgroup/rlimit 有效：fork 被限制在 $FORK_COUNT 个"
    else
        escape "cgroup/rlimit 风险：可 fork $FORK_COUNT 个进程（可能耗尽资源）"
    fi
fi
fi
# ==================== 5. 信息泄露测试 ====================
if [ "$TEST_INFO_LEAK" = true ]; then
section "5. 信息泄露测试"
# 5.1 /proc 信息泄露
if [ -f /proc/kallsyms ]; then
    KALLSYMS_COUNT=$(wc -l < /proc/kallsyms 2>/dev/null || echo 0)
    if [ "$KALLSYMS_COUNT" -gt 0 ]; then
        # 检查是否全是 0（kptr_restrict 保护）
        ZERO_COUNT=$(grep -c "0000000000000000" /proc/kallsyms 2>/dev/null || echo 0)
        if [ "$ZERO_COUNT" -gt 0 ] && [ "$ZERO_COUNT" -eq "$KALLSYMS_COUNT" ]; then
            pass "/proc/kallsyms 受 kptr_restrict 保护（全零）"
        else
            escape "信息泄露：/proc/kallsyms 可读且包含真实内核符号地址"
        fi
    fi
fi
# 5.2 内核版本信息泄露
if [ -f /proc/version ]; then
    KERNEL_VER=$(cat /proc/version)
    echo "  内核版本: $KERNEL_VER"
    # 内核版本是公开信息，不算泄露，但记录
    pass "/proc/version 可读（预期行为，用于兼容性检查）"
fi
# 5.3 云元数据服务访问
echo "  测试云元数据服务访问（169.254.169.254）..."
if command -v curl >/dev/null 2>&1; then
    if timeout 2 curl -s http://169.254.169.254/latest/meta-data/ 2>/dev/null | grep -q .; then
        escape "严重：可访问云元数据服务 169.254.169.254（可能窃取 IAM 凭证）"
    else
        pass "云元数据服务不可访问（网络隔离有效）"
    fi
else
    skip "云元数据测试需要 curl"
fi
# 5.4 宿主机 hostname 泄露
if [ -f /etc/hostname ]; then
    HOSTNAME_VAL=$(cat /etc/hostname)
    echo "  沙盒 hostname: $HOSTNAME_VAL"
    # hostname 应该是沙盒独立的，不应该是宿主机的
    pass "hostname 可读（应为沙盒独立 hostname）"
fi
fi
# ==================== 汇总 ====================
echo ""
echo "=========================================="
echo "  逃逸测试结果汇总"
echo "=========================================="
echo -e "通过: ${GREEN}$PASS${NC}"
echo -e "失败: ${RED}$FAIL${NC}"
echo -e "跳过: ${YELLOW}$SKIP${NC}"
echo -e "逃逸检测: ${RED}$ESCAPES${NC}"
echo ""
if [ "$ESCAPES" -gt 0 ]; then
    if [ "$IN_SANDBOX" = true ]; then
        echo -e "${RED}⚠️  在沙盒内部检测到 $ESCAPES 个逃逸点！请立即修复后再上线。${NC}"
        echo "建议："
        echo "  1. 检查 seccomp 白名单是否包含多余 syscall"
        echo "  2. 确认 namespace 隔离是否完整（user/pid/mount/net）"
        echo "  3. 验证网络隔离是否阻止内网/元数据访问"
        echo "  4. 运行 libFuzzer 对 TaskSpec 解析做模糊测试"
    else
        echo -e "${YELLOW}⚠️  在宿主机环境检测到 $ESCAPES 个'逃逸点'，但这是预期行为（宿主机无隔离）。${NC}"
        echo -e "${YELLOW}    请将本脚本传入沙盒内部重新运行以获得有效结果。${NC}"
    fi
    exit 1
elif [ "$FAIL" -gt 0 ]; then
    echo -e "${YELLOW}⚠️  有 $FAIL 项测试失败，$ESCAPES 个逃逸点。建议审查后上线。${NC}"
    exit 1
else
    if [ "$IN_SANDBOX" = true ]; then
        echo -e "${GREEN}✅ 在沙盒内部所有已执行测试通过，未检测到逃逸点。${NC}"
    else
        echo -e "${YELLOW}ℹ️  在宿主机环境所有已执行测试通过（但宿主机本就无隔离，结果仅供参考）。${NC}"
    fi
    echo "注意：跳过的 $SKIP 项需要对应环境支持才能完整验证。"
    exit 0
fi
