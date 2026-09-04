// POC-002: fd 泄露逃逸（红队对抗用例）
//
// 攻击技术：继承未关闭的特权文件描述符，尝试通过 fd 读写宿主文件
// 预期行为：特权 fd 在 exec 前已被关闭，访问返回 EBADF
// 风险等级：High
//
// 编译：g++ -o redteam_poc_fd_leak redteam_poc_fd_leak.cpp
// 在沙盒内运行：./redteam_poc_fd_leak
// 预期：所有高 fd 访问失败，无宿主文件泄露

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

int main() {
    printf("[POC-002] fd 泄露逃逸测试\n");
    printf("[POC-002] 扫描所有继承的文件描述符...\n");

    int leaked_count = 0;
    int max_fd = 1024;

    // 扫描 fd 3 到 max_fd（0/1/2 是标准输入输出）
    for (int fd = 3; fd < max_fd; fd++) {
        struct stat st;
        if (fstat(fd, &st) == 0) {
            // 这个 fd 是打开的，尝试读取
            char buf[256];
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                printf("[POC-002] ⚠️  fd=%d 可读取! mode=%o, size=%ld\n",
                       fd, st.st_mode, (long)st.st_size);
                printf("[POC-002]    内容前64字节: %.64s\n", buf);
                leaked_count++;
            } else if (n == 0) {
                printf("[POC-002] fd=%d 打开但为空 (mode=%o)\n", fd, st.st_mode);
            }
        }
    }

    // 尝试通过 /proc/self/fd 访问宿主文件
    printf("[POC-002] 尝试通过 /proc/self/fd 访问...\n");
    DIR* dir = opendir("/proc/self/fd");
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_name[0] == '.') continue;
            char linkpath[256];
            char target[1024];
            snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%s", entry->d_name);
            ssize_t len = readlink(linkpath, target, sizeof(target) - 1);
            if (len > 0) {
                target[len] = '\0';
                printf("[POC-002] fd=%s -> %s\n", entry->d_name, target);
            }
        }
        closedir(dir);
    } else {
        printf("[POC-002] /proc/self/fd 不可访问（Landlock 已拦截）\n");
    }

    if (leaked_count > 0) {
        printf("[POC-002] ❌ 安全漏洞：发现 %d 个可读取的泄露 fd\n", leaked_count);
        return 1;
    } else {
        printf("[POC-002] ✅ 未发现可读取的泄露 fd（fd 已在 exec 前关闭）\n");
    }

    printf("[POC-002] 测试完成\n");
    return 0;
}
