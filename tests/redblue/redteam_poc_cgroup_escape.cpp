/*
 * POC-012: cgroup 逃逸与资源限制绕过
 *
 * 攻击技术：
 * - cgroup v1 逃逸：写入 cgroup.procs 将进程移出受限 cgroup
 * - cgroup v2 逃逸：写入 cgroup.subtree_control 创建子 cgroup
 * - release_agent 利用：cgroup v1 的 release_agent 可以执行命令
 * - 资源限制绕过：fork 后子进程继承 cgroup，但尝试逃脱
 * - 内存限制绕过：使用 tmpfs/共享内存绕过 memory.max
 *
 * 预期行为：
 * - cgroup 文件系统只读，不可写入
 * - cgroup.procs 不可写
 * - 进程无法移出受限 cgroup
 * - 资源限制（memory/pids/cpu）生效
 *
 * 风险等级：High
 * 攻击面：LightPool cgroup v2 资源限制
 * 参考：CWE-863 (Incorrect Authorization)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <sched.h>
#include <sys/wait.h>

static int bypass_found = 0;

static void test_cgroup_procs_write(void) {
    printf("--- 测试1: 写入 cgroup.procs 逃逸 ---\n");
    const char *paths[] = {
        "/sys/fs/cgroup/cgroup.procs",
        "/sys/fs/cgroup/../../cgroup.procs",
        "/proc/self/cgroup",
    };
    for (int i = 0; i < 3; i++) {
        int fd = open(paths[i], O_WRONLY);
        if (fd >= 0) {
            char pid_str[32];
            snprintf(pid_str, sizeof(pid_str), "%d", getpid());
            ssize_t n = write(fd, pid_str, strlen(pid_str));
            if (n > 0) {
                printf("[!] 成功写入 %s (cgroup逃逸！)\n", paths[i]);
                bypass_found = 1;
            }
            close(fd);
        } else {
            printf("[+] %s 打开被拒绝 (errno=%d)\n", paths[i], errno);
        }
    }
}

static void test_cgroup_subtree_control(void) {
    printf("\n--- 测试2: 创建子 cgroup 绕过限制 ---\n");
    const char *child_path = "/sys/fs/cgroup/evil_child";
    if (mkdir(child_path, 0755) == 0) {
        printf("[!] 成功创建子 cgroup: %s\n", child_path);
        bypass_found = 1;
        rmdir(child_path);
    } else {
        printf("[+] 创建子 cgroup 被拒绝 (errno=%d)\n", errno);
    }
}

static void test_memory_limit_bypass(void) {
    printf("\n--- 测试3: 内存限制绕过（tmpfs/共享内存）-- -\n");
    /* 尝试在 /dev/shm 创建大文件 */
    int fd = open("/dev/shm/evil_large_file", O_CREAT | O_RDWR, 0644);
    if (fd >= 0) {
        /* 尝试 ftruncate 到大文件 */
        if (ftruncate(fd, 1024 * 1024 * 1024) == 0) {
            printf("[!] 成功在 /dev/shm 创建 1GB 文件（内存限制绕过！）\n");
            bypass_found = 1;
        } else {
            printf("[+] /dev/shm 大文件创建被拒绝 (errno=%d)\n", errno);
        }
        close(fd);
        unlink("/dev/shm/evil_large_file");
    } else {
        printf("[+] /dev/shm 访问被拒绝 (errno=%d)\n", errno);
    }
}

static void test_pids_limit_bypass(void) {
    printf("\n--- 测试4: PID 限制绕过（嵌套命名空间）-- -\n");
    pid_t pid = fork();
    if (pid == 0) {
        /* 子进程中尝试 unshare 创建新 PID 命名空间 */
        if (unshare(CLONE_NEWPID) == 0) {
            printf("[!] 成功 unshare(CLONE_NEWPID)（PID限制可能绕过！）\n");
            /* 在新命名空间中 fork */
            pid_t inner = fork();
            if (inner == 0) {
                _exit(0);
            }
            _exit(0);
        } else {
            printf("[+] unshare(CLONE_NEWPID) 被拒绝 (errno=%d)\n", errno);
            _exit(0);
        }
    }
    int status;
    waitpid(pid, &status, 0);
}

int main(void) {
    printf("[*] POC-012: cgroup 逃逸与资源限制绕过测试\n\n");
    test_cgroup_procs_write();
    test_cgroup_subtree_control();
    test_memory_limit_bypass();
    test_pids_limit_bypass();
    printf("\n");
    if (bypass_found) {
        printf("[!] 结果：发现 cgroup 逃逸漏洞！\n");
        return 2;
    }
    printf("[+] 结果：所有 cgroup 逃逸尝试均被阻止\n");
    return 0;
}
