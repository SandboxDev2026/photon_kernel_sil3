/*
 * POC-011: Landlock 路径遍历与符号链接绕过
 *
 * 攻击技术：利用 Landlock 文件系统限制的绕过技术
 * - 路径遍历：../ 序列突破目录限制
 * - 符号链接：创建指向受限目录的符号链接
 * - /proc/self/fd/：通过已打开的文件描述符访问
 * - 重命名竞争：在 Landlock 规则应用前重命名文件
 * - bind mount：尝试挂载覆盖受限路径
 *
 * 预期行为：
 * - Landlock 限制所有路径访问，包括符号链接解析后的目标
 * - 路径遍历被规范化后拒绝
 * - /proc/self/fd/ 访问受 Landlock 限制
 * - 进程被杀死或操作被拒绝
 *
 * 风险等级：High
 * 攻击面：LightPool Landlock 文件系统隔离
 * 参考：CWE-22 (Path Traversal), CWE-59 (Link Following)
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
#include <dirent.h>

static int bypass_found = 0;

/* 测试1：路径遍历 */
static void test_path_traversal(void) {
    printf("--- 测试1: 路径遍历 (../) ---\n");
    const char *traversal_paths[] = {
        "/tmp/../../etc/shadow",
        "/tmp/./../etc/passwd",
        "/tmp/subdir/../../../etc/shadow",
        "....//....//etc/shadow",
        "/tmp/%2e%2e/%2e%2e/etc/shadow",
    };

    for (int i = 0; i < 5; i++) {
        int fd = open(traversal_paths[i], O_RDONLY);
        if (fd >= 0) {
            char buf[256];
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                if (strstr(buf, "root:") != NULL || strstr(buf, "x:") != NULL) {
                    printf("[!] 路径遍历成功: %s\n", traversal_paths[i]);
                    printf("[!] 读取内容: %.100s\n", buf);
                    bypass_found = 1;
                }
            }
            close(fd);
        } else {
            printf("[+] 路径遍历被拒绝: %s (errno=%d)\n", traversal_paths[i], errno);
        }
    }
}

/* 测试2：符号链接绕过 */
static void test_symlink_bypass(void) {
    printf("\n--- 测试2: 符号链接绕过 ---\n");

    /* 创建指向 /etc/shadow 的符号链接 */
    unlink("/tmp/evil_link");
    if (symlink("/etc/shadow", "/tmp/evil_link") == 0) {
        int fd = open("/tmp/evil_link", O_RDONLY);
        if (fd >= 0) {
            char buf[256];
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                printf("[!] 符号链接绕过成功: /tmp/evil_link -> /etc/shadow\n");
                printf("[!] 读取内容: %.100s\n", buf);
                bypass_found = 1;
            }
            close(fd);
        } else {
            printf("[+] 符号链接目标访问被拒绝 (errno=%d)\n", errno);
        }
    }
    unlink("/tmp/evil_link");

    /* 测试 O_NOFOLLOW */
    unlink("/tmp/evil_link2");
    symlink("/etc/passwd", "/tmp/evil_link2");
    int fd = open("/tmp/evil_link2", O_RDONLY | O_NOFOLLOW);
    if (fd >= 0) {
        printf("[!] O_NOFOLLOW 应该失败但成功了\n");
        close(fd);
    } else {
        printf("[+] O_NOFOLLOW 正确拒绝符号链接 (errno=%d)\n", errno);
    }
    unlink("/tmp/evil_link2");
}

/* 测试3：/proc/self/fd/ 绕过 */
static void test_proc_fd_bypass(void) {
    printf("\n--- 测试3: /proc/self/fd/ 绕过 ---\n");

    /* 先打开一个允许的文件 */
    int fd = open("/tmp/allowed_file.txt", O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        printf("[-] 无法创建测试文件: %s\n", strerror(errno));
        return;
    }
    write(fd, "allowed content", 15);

    /* 通过 /proc/self/fd/ 访问 */
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);

    int fd2 = open(fd_path, O_RDONLY);
    if (fd2 >= 0) {
        char buf[256];
        read(fd2, buf, sizeof(buf));
        printf("[*] /proc/self/fd/ 访问自己的fd正常: %.50s\n", buf);
        close(fd2);
    }

    /* 尝试通过 /proc/self/fd/ 访问其他进程的 fd */
    DIR *proc_dir = opendir("/proc");
    if (proc_dir) {
        struct dirent *entry;
        int found_other = 0;
        while ((entry = readdir(proc_dir)) != NULL && !found_other) {
            if (entry->d_name[0] >= '1' && entry->d_name[0] <= '9') {
                pid_t other_pid = atoi(entry->d_name);
                if (other_pid != getpid()) {
                    char other_fd_path[128];
                    snprintf(other_fd_path, sizeof(other_fd_path),
                             "/proc/%d/fd/0", other_pid);
                    int fd3 = open(other_fd_path, O_RDONLY);
                    if (fd3 >= 0) {
                        printf("[!] 成功访问其他进程的 fd: %s\n", other_fd_path);
                        bypass_found = 1;
                        close(fd3);
                        found_other = 1;
                    }
                }
            }
        }
        closedir(proc_dir);
        if (!found_other) {
            printf("[+] 其他进程的 fd 访问被拒绝\n");
        }
    }

    close(fd);
    unlink("/tmp/allowed_file.txt");
}

/* 测试4：相对路径绕过 */
static void test_relative_path(void) {
    printf("\n--- 测试4: 相对路径绕过 ---\n");

    /* 切换到 /tmp，用相对路径访问 /etc */
    if (chdir("/tmp") == 0) {
        int fd = open("../../etc/shadow", O_RDONLY);
        if (fd >= 0) {
            char buf[256];
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                printf("[!] 相对路径遍历成功: ../../etc/shadow\n");
                printf("[!] 内容: %.100s\n", buf);
                bypass_found = 1;
            }
            close(fd);
        } else {
            printf("[+] 相对路径遍历被拒绝 (errno=%d)\n", errno);
        }
    }
}

int main(void) {
    printf("[*] POC-011: Landlock 路径遍历与符号链接绕过测试\n");
    printf("[*] 目标：验证 Landlock 文件系统限制的完整性\n\n");

    test_path_traversal();
    test_symlink_bypass();
    test_proc_fd_bypass();
    test_relative_path();

    printf("\n");
    if (bypass_found) {
        printf("[!] 结果：发现 Landlock 绕过漏洞！\n");
        printf("[!] 修复建议：确保 Landlock 规则覆盖符号链接解析、路径规范化、/proc/self/fd/\n");
        return 2;
    }
    printf("[+] 结果：所有 Landlock 绕过尝试均被阻止\n");
    return 0;
}
