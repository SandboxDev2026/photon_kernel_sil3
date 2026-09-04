// POC-005: mount 逃逸（红队对抗用例）
//
// 攻击技术：尝试 mount 各种文件系统突破沙盒隔离
//   1. mount procfs 到可控目录，读取宿主进程信息
//   2. mount sysfs 读取宿主硬件信息
//   3. mount tmpfs 然后尝试 pivot_root
//   4. mount --bind 宿主敏感目录
// 预期行为：mount syscall 被 seccomp KILL，或 mount 权限不足失败
// 风险等级：Critical
//
// 编译：g++ -o redteam_poc_mount_escape redteam_poc_mount_escape.cpp
// 在沙盒内运行：./redteam_poc_mount_escape
// 预期：所有 mount 尝试失败，无文件系统逃逸

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#ifndef SYS_pivot_root
#define SYS_pivot_root 155
#endif
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>

#ifndef MS_PRIVATE
#define MS_PRIVATE (1 << 18)
#endif

int try_mount(const char* source, const char* target, const char* fstype,
               unsigned long flags, const void* data, const char* desc) {
    printf("[POC-005] 尝试: %s\n", desc);
    printf("         mount(\"%s\", \"%s\", \"%s\", 0x%lx, ...)\n",
           source, target, fstype, flags);

    int ret = mount(source, target, fstype, flags, data);
    if (ret == 0) {
        printf("         ❌ mount 成功！可能存在逃逸路径\n");
        return 1; // 成功（安全漏洞）
    } else {
        printf("         ✅ mount 失败: errno=%d (%s)\n", errno, strerror(errno));
        return 0; // 失败（预期行为）
    }
}

int main() {
    printf("[POC-005] mount 逃逸测试\n");
    printf("[POC-005] 预期：untrusted_code_mode 下 mount 被 seccomp KILL\n\n");

    int escape_count = 0;

    // 创建挂载点目录
    mkdir("/tmp/mount_test", 0755);
    mkdir("/tmp/mount_test/proc", 0755);
    mkdir("/tmp/mount_test/sys", 0755);
    mkdir("/tmp/mount_test/tmpfs", 0755);
    mkdir("/tmp/mount_test/bind", 0755);

    // === 尝试1: mount procfs ===
    escape_count += try_mount(
        "proc", "/tmp/mount_test/proc", "proc",
        MS_NOSUID | MS_NOEXEC | MS_NODEV, nullptr,
        "mount procfs（读取宿主进程信息）"
    );

    // === 尝试2: mount sysfs ===
    escape_count += try_mount(
        "sysfs", "/tmp/mount_test/sys", "sysfs",
        MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_RDONLY, nullptr,
        "mount sysfs（读取宿主硬件信息）"
    );

    // === 尝试3: mount tmpfs 然后尝试 pivot_root ===
    escape_count += try_mount(
        "tmpfs", "/tmp/mount_test/tmpfs", "tmpfs",
        0, "size=64k",
        "mount tmpfs（准备 pivot_root）"
    );

    // 如果 tmpfs mount 成功，尝试 pivot_root
    if (access("/tmp/mount_test/tmpfs", F_OK) == 0) {
        printf("[POC-005] 尝试 pivot_root 到 tmpfs...\n");
        if (chdir("/tmp/mount_test/tmpfs") == 0) {
            // pivot_root 需要 old root 目录
            mkdir("oldroot", 0755);
            int ret = syscall(SYS_pivot_root, ".", "oldroot");
            if (ret == 0) {
                printf("[POC-005] ❌ pivot_root 成功！根文件系统已切换\n");
                escape_count++;
            } else {
                printf("[POC-005] ✅ pivot_root 失败: errno=%d (%s)\n", errno, strerror(errno));
            }
        }
    }

    // === 尝试4: mount --bind 宿主 /etc 目录 ===
    escape_count += try_mount(
        "/etc", "/tmp/mount_test/bind", nullptr,
        MS_BIND | MS_RDONLY, nullptr,
        "mount --bind /etc（读取宿主配置）"
    );

    // === 尝试5: mount cgroup2 ===
    mkdir("/tmp/mount_test/cgroup", 0755);
    escape_count += try_mount(
        "cgroup2", "/tmp/mount_test/cgroup", "cgroup2",
        0, nullptr,
        "mount cgroup2（操作宿主 cgroup）"
    );

    // === 尝试6: umount2 卸载宿主挂载 ===
    printf("[POC-005] 尝试 umount2(\"/proc\", MNT_DETACH)...\n");
    int ret_umount = umount2("/proc", MNT_DETACH);
    if (ret_umount == 0) {
        printf("[POC-005] ❌ umount2 /proc 成功！可以破坏宿主命名空间\n");
        escape_count++;
    } else {
        printf("[POC-005] ✅ umount2 失败: errno=%d (%s)\n", errno, strerror(errno));
    }

    // 清理
    umount("/tmp/mount_test/proc");
    umount("/tmp/mount_test/sys");
    umount("/tmp/mount_test/tmpfs");
    umount("/tmp/mount_test/bind");
    umount("/tmp/mount_test/cgroup");

    printf("\n[POC-005] 统计: 成功逃逸 %d 次\n", escape_count);

    if (escape_count > 0) {
        printf("[POC-005] ❌ 发现 %d 个 mount 逃逸漏洞！\n", escape_count);
        return 1;
    } else {
        printf("[POC-005] ✅ 所有 mount 逃逸尝试均被拦截\n");
        return 0;
    }
}
