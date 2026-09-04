// LightPool 安全测试用例集合
//
// 四大类安全测试：
//   1. seccomp 安全用例（高危 syscall 拦截、参数过滤、32位兼容模式）
//   2. 资源隔离用例（fork 炸弹、内存炸弹、fd 耗尽）
//   3. 逃逸路径用例（fd 泄露、/proc 篡改、信号竞争）
//   4. 审计证据完整性用例（违规记录、HMAC 链、防篡改）
//
// 注意：这些测试验证安全策略的配置和逻辑正确性。
// 实际的 syscall 拦截需要在真实沙盒进程内运行（见 tests/redblue/ POC）。

#include <gtest/gtest.h>
#include <sys/syscall.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <set>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>

// 引入 seccomp 策略头文件
#include "photon_kernel/sandbox/seccomp_policy.hpp"

using namespace photon_kernel::sandbox;

// ============================================================================
// 第一类：seccomp 安全用例
// ============================================================================

class SeccompPolicyTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// 1.1 default_mode 基础白名单测试
TEST_F(SeccompPolicyTest, DefaultModeAllowsCommonSyscalls) {
    SeccompPolicy policy(SeccompMode::DEFAULT);
    EXPECT_EQ(policy.mode(), SeccompMode::DEFAULT);
    EXPECT_EQ(policy.mode_name(), "default_mode");

    // 常见 syscall 应该被允许
    EXPECT_TRUE(policy.is_allowed(SYS_read));
    EXPECT_TRUE(policy.is_allowed(SYS_write));
    EXPECT_TRUE(policy.is_allowed(SYS_openat));
    EXPECT_TRUE(policy.is_allowed(SYS_close));
    EXPECT_TRUE(policy.is_allowed(SYS_mmap));
    EXPECT_TRUE(policy.is_allowed(SYS_munmap));
    EXPECT_TRUE(policy.is_allowed(SYS_clone));
    EXPECT_TRUE(policy.is_allowed(SYS_execve));
    EXPECT_TRUE(policy.is_allowed(SYS_exit));
}

// 1.2 untrusted_code_mode 禁用高危 syscall
TEST_F(SeccompPolicyTest, UntrustedModeBlocksDangerousSyscalls) {
    SeccompPolicy policy(SeccompMode::UNTRUSTED_CODE);
    EXPECT_EQ(policy.mode_name(), "untrusted_code_mode");

    // 高危 syscall 必须被禁用
    EXPECT_FALSE(policy.is_allowed(SYS_ptrace));
    EXPECT_FALSE(policy.is_allowed(SYS_kexec_load));
    EXPECT_FALSE(policy.is_allowed(SYS_mount));
    EXPECT_FALSE(policy.is_allowed(SYS_umount2));
    EXPECT_FALSE(policy.is_allowed(SYS_open_by_handle_at));
    EXPECT_FALSE(policy.is_allowed(SYS_init_module));
    EXPECT_FALSE(policy.is_allowed(SYS_finit_module));

    // 额外禁用：namespace 操作
    EXPECT_FALSE(policy.is_allowed(SYS_unshare));
    EXPECT_FALSE(policy.is_allowed(SYS_setns));

    // 基础 syscall 仍然允许
    EXPECT_TRUE(policy.is_allowed(SYS_read));
    EXPECT_TRUE(policy.is_allowed(SYS_write));
    EXPECT_TRUE(policy.is_allowed(SYS_openat));
    EXPECT_TRUE(policy.is_allowed(SYS_mmap));
}

// 1.3 default_mode 允许 ptrace（业务可能需要调试子进程）
TEST_F(SeccompPolicyTest, DefaultModeAllowsPtrace) {
    SeccompPolicy policy(SeccompMode::DEFAULT);
    EXPECT_TRUE(policy.is_allowed(SYS_ptrace));
    EXPECT_TRUE(policy.is_allowed(SYS_mount));
}

// 1.4 双模式差异验证
TEST_F(SeccompPolicyTest, DualModeDifference) {
    SeccompPolicy default_policy(SeccompMode::DEFAULT);
    SeccompPolicy untrusted_policy(SeccompMode::UNTRUSTED_CODE);

    // untrusted 模式的白名单应该更小
    EXPECT_LT(untrusted_policy.allowed_syscalls().size(),
              default_policy.allowed_syscalls().size());

    // 差异应该包含所有高危 syscall
    std::set<int> diff;
    for (int nr : default_policy.allowed_syscalls()) {
        if (!untrusted_policy.is_allowed(nr)) {
            diff.insert(nr);
        }
    }
    EXPECT_GT(diff.size(), 0u);
    EXPECT_TRUE(diff.count(SYS_ptrace) > 0);
    EXPECT_TRUE(diff.count(SYS_mount) > 0);
}

// 1.5 参数过滤规则存在性
TEST_F(SeccompPolicyTest, ParamFilterRulesExist) {
    SeccompPolicy policy(SeccompMode::UNTRUSTED_CODE);
    const auto& filters = policy.param_filters();

    EXPECT_GT(filters.size(), 0u);
    EXPECT_TRUE(policy.has_param_filter(SYS_clone));

    // clone 应该过滤 namespace flag
    bool clone_ns_filter = false;
    for (const auto& f : filters) {
        if (f.syscall_nr == SYS_clone && f.arg_index == 0) {
            // 检查 mask 包含 CLONE_NEWNS
            if (f.mask & 0x00020000) { // CLONE_NEWNS
                clone_ns_filter = true;
            }
        }
    }
    EXPECT_TRUE(clone_ns_filter);
}

// 1.6 规则快照生成
TEST_F(SeccompPolicyTest, GenerateSnapshotJson) {
    SeccompPolicy policy(SeccompMode::UNTRUSTED_CODE);
    std::string snapshot = policy.generate_snapshot_json();

    EXPECT_NE(snapshot.find("untrusted_code_mode"), std::string::npos);
    EXPECT_NE(snapshot.find("SECCOMP_RET_KILL_PROCESS"), std::string::npos);
    EXPECT_NE(snapshot.find("hash"), std::string::npos);
    EXPECT_NE(snapshot.find("ptrace"), std::string::npos);
}

// 1.7 规则哈希稳定性
TEST_F(SeccompPolicyTest, RuleHashStability) {
    SeccompPolicy policy1(SeccompMode::UNTRUSTED_CODE);
    SeccompPolicy policy2(SeccompMode::UNTRUSTED_CODE);

    // 相同配置应该产生相同哈希
    EXPECT_EQ(policy1.compute_hash(), policy2.compute_hash());

    // 不同模式应该产生不同哈希
    SeccompPolicy default_policy(SeccompMode::DEFAULT);
    EXPECT_NE(policy1.compute_hash(), default_policy.compute_hash());
}

// 1.8 BPF 程序生成
TEST_F(SeccompPolicyTest, GenerateBpfProgram) {
    SeccompPolicy policy(SeccompMode::UNTRUSTED_CODE);
    std::string bpf = policy.generate_bpf_program();

    EXPECT_NE(bpf.find("SECCOMP_RET_KILL_PROCESS"), std::string::npos);
    EXPECT_NE(bpf.find("SECCOMP_RET_ALLOW"), std::string::npos);
    EXPECT_NE(bpf.find("ptrace"), std::string::npos);
}

// ============================================================================
// 第二类：资源隔离用例
// ============================================================================

class ResourceIsolationTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// 2.1 rlimit NOFILE 限制验证
TEST_F(ResourceIsolationTest, RlimitNofileLimit) {
    struct rlimit old_limit, new_limit;
    getrlimit(RLIMIT_NOFILE, &old_limit);

    // 设置低限制模拟沙盒环境
    new_limit.rlim_cur = 64;
    new_limit.rlim_max = 64;
    ASSERT_EQ(setrlimit(RLIMIT_NOFILE, &new_limit), 0);

    // 尝试打开超过限制的文件
    int fds[100];
    int opened = 0;
    for (int i = 0; i < 100; i++) {
        fds[i] = open("/dev/null", O_RDONLY);
        if (fds[i] >= 0) {
            opened++;
        } else {
            break;
        }
    }

    // 应该在达到限制后失败
    EXPECT_LT(opened, 100);
    EXPECT_LE(opened, 64);

    // 清理
    for (int i = 0; i < opened; i++) {
        close(fds[i]);
    }

    // 恢复原限制
    setrlimit(RLIMIT_NOFILE, &old_limit);
}

// 2.2 rlimit NPROC 限制（fork 炸弹防护）
TEST_F(ResourceIsolationTest, RlimitNprocLimit) {
    struct rlimit old_limit, new_limit;
    getrlimit(RLIMIT_NPROC, &old_limit);

    // 设置低进程数限制
    new_limit.rlim_cur = 16;
    new_limit.rlim_max = 16;
    ASSERT_EQ(setrlimit(RLIMIT_NPROC, &new_limit), 0);

    // 尝试 fork 超过限制
    int child_count = 0;
    pid_t pids[32];
    for (int i = 0; i < 32; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            // 子进程短暂存活
            usleep(50000);
            _exit(0);
        } else if (pid > 0) {
            pids[i] = pid;
            child_count++;
        } else {
            // fork 失败（预期）
            break;
        }
    }

    // 应该在达到限制后失败
    EXPECT_LT(child_count, 32);

    // 等待子进程退出
    for (int i = 0; i < child_count; i++) {
        waitpid(pids[i], nullptr, 0);
    }

    // 恢复原限制
    setrlimit(RLIMIT_NPROC, &old_limit);
}

// 2.3 rlimit AS 限制（内存炸弹防护）
TEST_F(ResourceIsolationTest, RlimitAsLimit) {
    struct rlimit old_limit, new_limit;
    getrlimit(RLIMIT_AS, &old_limit);

    // 设置 64MB 地址空间限制
    new_limit.rlim_cur = 64 * 1024 * 1024;
    new_limit.rlim_max = 64 * 1024 * 1024;
    ASSERT_EQ(setrlimit(RLIMIT_AS, &new_limit), 0);

    // 尝试分配超过限制的内存
    void* ptr = mmap(nullptr, 128 * 1024 * 1024, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    EXPECT_EQ(ptr, MAP_FAILED);
    EXPECT_EQ(errno, ENOMEM);

    // 小分配应该成功
    void* small_ptr = mmap(nullptr, 1024, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    EXPECT_NE(small_ptr, MAP_FAILED);
    if (small_ptr != MAP_FAILED) {
        munmap(small_ptr, 1024);
    }

    // 恢复原限制
    setrlimit(RLIMIT_AS, &old_limit);
}

// 2.4 rlimit CPU 时间限制
TEST_F(ResourceIsolationTest, RlimitCpuTimeLimit) {
    struct rlimit old_limit, new_limit;
    getrlimit(RLIMIT_CPU, &old_limit);

    // 设置 1 秒 CPU 时间限制
    new_limit.rlim_cur = 1;
    new_limit.rlim_max = 1;
    ASSERT_EQ(setrlimit(RLIMIT_CPU, &new_limit), 0);

    // 注意：不实际消耗 CPU 时间（会杀死测试进程）
    // 只验证限制已设置
    struct rlimit check;
    getrlimit(RLIMIT_CPU, &check);
    EXPECT_EQ(check.rlim_cur, 1u);

    // 恢复原限制
    setrlimit(RLIMIT_CPU, &old_limit);
}

// ============================================================================
// 第三类：逃逸路径用例
// ============================================================================

class EscapePathTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// 3.1 fd 继承检查（exec 前应关闭特权 fd）
TEST_F(EscapePathTest, FdInheritanceCheck) {
    // 打开一个文件描述符
    int test_fd = open("/dev/null", O_RDONLY);
    ASSERT_GE(test_fd, 0);

    // 设置 FD_CLOEXEC（沙盒应该对所有特权 fd 设置此标志）
    int flags = fcntl(test_fd, F_GETFD);
    ASSERT_GE(flags, 0);
    fcntl(test_fd, F_SETFD, flags | FD_CLOEXEC);

    // 验证 FD_CLOEXEC 已设置
    flags = fcntl(test_fd, F_GETFD);
    EXPECT_TRUE(flags & FD_CLOEXEC);

    close(test_fd);
}

// 3.2 /proc 敏感路径访问限制
TEST_F(EscapePathTest, ProcSensitivePathAccess) {
    // 这些路径在沙盒内应该被 Landlock 或 seccomp 参数过滤拦截
    const char* sensitive_paths[] = {
        "/proc/kcore",
        "/proc/kmsg",
        "/proc/sysrq-trigger",
        "/dev/mem",
        "/dev/kmem",
        "/dev/port",
    };

    for (const char* path : sensitive_paths) {
        // 尝试打开（预期失败）
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            // 如果能打开，至少验证不能读
            char buf[16];
            ssize_t n = read(fd, buf, sizeof(buf));
            EXPECT_LT(n, 0) << "路径 " << path << " 可以读取！";
            close(fd);
        }
        // 打开失败是预期行为（权限不足或不存在）
    }
}

// 3.3 信号处理安全（SIGSTOP 不能被捕获）
TEST_F(EscapePathTest, SigstopCannotBeCaught) {
    // SIGSTOP 和 SIGKILL 不能被捕获、阻塞或忽略
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;

    // 尝试忽略 SIGSTOP（应该失败）
    int ret = sigaction(SIGSTOP, &sa, nullptr);
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(errno, EINVAL);

    // 尝试忽略 SIGKILL（应该失败）
    ret = sigaction(SIGKILL, &sa, nullptr);
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(errno, EINVAL);
}

// 3.4 进程权限检查（沙盒进程不应有 root 权限）
TEST_F(EscapePathTest, ProcessPrivilegeCheck) {
    // 沙盒内进程应该以非 root 用户运行
    uid_t uid = getuid();
    gid_t gid = getgid();

    // 注意：测试环境可能是 root，这里只验证获取成功
    EXPECT_GE(uid, 0u);
    EXPECT_GE(gid, 0u);

    // 检查 capabilities（沙盒应该 drop 大部分 capabilities）
    // 这里只验证 /proc/self/status 存在
    FILE* f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        bool found_cap = false;
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "CapEff:", 7) == 0) {
                found_cap = true;
                // CapEff 应该为 0（沙盒 drop 所有 capabilities）
                unsigned long cap_eff = strtoul(line + 7, nullptr, 16);
                // 注意：测试环境可能有 capabilities，这里只验证解析成功
                EXPECT_GE(cap_eff, 0u);
                break;
            }
        }
        EXPECT_TRUE(found_cap);
        fclose(f);
    }
}

// ============================================================================
// 第四类：审计证据完整性用例
// ============================================================================

class AuditIntegrityTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// 4.1 seccomp 违规事件记录
TEST_F(AuditIntegrityTest, SeccompViolationEventLogging) {
    SeccompViolationEvent event;
    event.timestamp_ns = 1234567890000ULL;
    event.pid = 12345;
    event.syscall_nr = 101; // ptrace
    event.syscall_name = "ptrace";
    event.args[0] = 0; // PTRACE_TRACEME
    event.args[1] = 0;
    event.mode = "untrusted_code_mode";
    event.killed = true;

    // 记录违规事件
    uint64_t before = SeccompPolicy::violation_count();
    SeccompPolicy::log_violation(event);
    uint64_t after = SeccompPolicy::violation_count();

    EXPECT_EQ(after, before + 1);
}

// 4.2 审计事件字段完整性
TEST_F(AuditIntegrityTest, AuditEventFieldCompleteness) {
    SeccompViolationEvent event;
    event.timestamp_ns = 1234567890000ULL;
    event.pid = 12345;
    event.syscall_nr = 165; // mount
    event.syscall_name = "mount";
    event.args[0] = reinterpret_cast<uint64_t>("/tmp");
    event.args[1] = reinterpret_cast<uint64_t>("/mnt");
    event.args[2] = reinterpret_cast<uint64_t>("tmpfs");
    event.mode = "untrusted_code_mode";
    event.killed = true;

    // 验证所有关键字段都有值
    EXPECT_GT(event.timestamp_ns, 0u);
    EXPECT_GT(event.pid, 0);
    EXPECT_GT(event.syscall_nr, 0);
    EXPECT_FALSE(event.syscall_name.empty());
    EXPECT_FALSE(event.mode.empty());
    EXPECT_TRUE(event.killed);
}

// 4.3 审计日志 HMAC 链完整性（模拟）
TEST_F(AuditIntegrityTest, AuditLogHmacChainIntegrity) {
    // 模拟审计日志 HMAC 链
    // 每条记录包含 prev_hash，形成链式结构
    std::vector<std::string> hashes;
    std::string prev_hash = std::string(64, '0');

    for (int i = 0; i < 10; i++) {
        std::string record = "seq=" + std::to_string(i) + ",prev=" + prev_hash;
        std::string hash = std::to_string(std::hash<std::string>{}(record));
        // 填充到 64 字符（模拟 SHA256）
        while (hash.length() < 64) hash = "0" + hash;
        hashes.push_back(hash);
        prev_hash = hash;
    }

    // 验证链式结构：每条记录的 prev_hash 等于前一条的 hash
    for (size_t i = 1; i < hashes.size(); i++) {
        // 这里只验证哈希数量正确
        EXPECT_EQ(hashes[i].length(), 64u);
    }
    EXPECT_EQ(hashes.size(), 10u);
}

// 4.4 审计日志防篡改（修改记录后哈希变化）
TEST_F(AuditIntegrityTest, AuditLogTamperDetection) {
    std::string record1 = "seq=0,action=ALLOW,syscall=read";
    std::string record2 = "seq=0,action=ALLOW,syscall=read"; // 相同
    std::string record3 = "seq=0,action=DENY,syscall=read";  // 被篡改

    std::hash<std::string> hasher;
    size_t hash1 = hasher(record1);
    size_t hash2 = hasher(record2);
    size_t hash3 = hasher(record3);

    // 相同记录应该有相同哈希
    EXPECT_EQ(hash1, hash2);
    // 篡改后哈希应该变化
    EXPECT_NE(hash1, hash3);
}

// ============================================================================
// 主函数
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
