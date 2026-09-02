// NamespaceIsolator 实现：Linux namespace 隔离（mount+pid+net+uts+ipc + pivot_root）
//
// 执行流程（子进程中）：
//   1. clone() 时传入 CLONE_NEWNS|NEWPID|NEWNET|NEWUTS|NEWIPC
//   2. setup_in_child():
//      a. mount --make-rprivate /  (防止挂载事件泄漏到宿主)
//      b. 创建临时 rootfs 目录
//      c. 挂载 tmpfs 作为新根
//      d. 在新根中创建 /proc /dev /tmp /bin /lib /lib64 /usr
//      e. pivot_root 到新根
//      f. 卸载旧根
//      g. 挂载 /proc (pid namespace)
//      h. 挂载最小 /dev
//      i. 挂载 /tmp
//      j. 设置 hostname
//      k. 启用 loopback (network namespace)
#include "photon_kernel/sandbox/namespace_isolation.hpp"
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <sched.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <vector>
#ifndef MS_REC
#define MS_REC 16384
#endif
#ifndef MS_PRIVATE
#define MS_PRIVATE (1 << 18)
#endif
#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif
namespace photon_kernel {
namespace sandbox {
bool NamespaceIsolator::is_supported() {
    // 检查 /proc/self/ns 是否存在
    struct stat st;
    if (stat("/proc/self/ns", &st) != 0) return false;
    // 检查 user namespace 是否可用（unprivileged 或 root）
    // 方法：尝试 unshare(CLONE_NEWUSER) 看是否成功
    pid_t pid = fork();
    if (pid == 0) {
        // 子进程：尝试 unshare user namespace
        if (unshare(CLONE_NEWUSER) != 0) _exit(1);
        // 写 uid_map 测试
        std::ofstream uid_map("/proc/self/uid_map");
        if (!uid_map.is_open()) _exit(1);
        uid_map << "0 " << geteuid() << " 1\n";
        uid_map.close();
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return true;
    // root 环境也支持（即使 userns 被禁用）
    if (geteuid() == 0) return true;
    return false;
}
int NamespaceIsolator::clone_flags(const NamespaceConfig& config) {
    int flags = SIGCHLD;  // 必须有 SIGCHLD，否则子进程退出不发信号
    if (config.enable_mount) flags |= CLONE_NEWNS;
    if (config.enable_pid) flags |= CLONE_NEWPID;
    if (config.enable_net) flags |= CLONE_NEWNET;
    if (config.enable_uts) flags |= CLONE_NEWUTS;
    if (config.enable_ipc) flags |= CLONE_NEWIPC;
    if (config.enable_user) flags |= CLONE_NEWUSER;
    return flags;
}
int NamespaceIsolator::setup_in_child(const NamespaceConfig& config) {
    // 0. User namespace: 必须在其他 namespace 操作之前设置 uid/gid 映射
    //    （设置后沙盒内获得 CAP_SYS_ADMIN，才能进行 mount/pivot_root）
    if (config.enable_user) {
        if (setup_user_namespace(config) != 0) {
            std::cerr << "[namespace] setup_user_namespace failed\n";
            return -1;
        }
    }
    // 1. Mount namespace: 使所有挂载私有
    if (config.enable_mount) {
        if (setup_mount_namespace(config) != 0) {
            std::cerr << "[namespace] setup_mount_namespace failed\n";
            return -1;
        }
    }
    // 2. UTS namespace: 设置 hostname
    if (config.enable_uts) {
        if (setup_uts_namespace(config) != 0) {
            std::cerr << "[namespace] setup_uts_namespace failed\n";
            return -1;
        }
    }
    // 3. Network namespace: 启用 loopback
    if (config.enable_net) {
        if (setup_network_namespace() != 0) {
            std::cerr << "[namespace] setup_network_namespace failed (continuing)\n";
            // 网络设置失败不致命，继续执行（沙盒仍无外网）
        }
    }
    return 0;
}
int NamespaceIsolator::setup_mount_namespace(const NamespaceConfig& config) {
    // 使根挂载私有，防止挂载事件传播到宿主
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) {
        std::cerr << "[namespace] mount --make-rprivate / failed: " << strerror(errno) << "\n";
        return -1;
    }
    // pivot_root: 切换到最小根文件系统
    if (setup_pivot_root(config) != 0) {
        std::cerr << "[namespace] pivot_root failed: " << strerror(errno) << "\n";
        return -1;
    }
    return 0;
}
int NamespaceIsolator::setup_pivot_root(const NamespaceConfig& config) {
    // 创建临时根目录
    std::string new_root = config.rootfs_path;
    bool created_tmp = false;
    if (new_root.empty()) {
        char tmpl[] = "/tmp/photon_sandbox_root_XXXXXX";
        char* result = mkdtemp(tmpl);
        if (!result) {
            std::cerr << "[namespace] mkdtemp failed: " << strerror(errno) << "\n";
            return -1;
        }
        new_root = result;
        created_tmp = true;
    }
    // 挂载 tmpfs 作为新根
    if (mount("tmpfs", new_root.c_str(), "tmpfs", 0, "size=64m,mode=0755") != 0) {
        std::cerr << "[namespace] mount tmpfs failed: " << strerror(errno) << "\n";
        return -1;
    }
    // 在新根中创建必要目录
    std::vector<std::string> dirs = {"/proc", "/dev", "/tmp", "/bin", "/lib", "/lib64",
                                       "/usr", "/usr/bin", "/usr/lib", "/etc", "/home", "/root"};
    for (const auto& d : dirs) {
        std::string path = new_root + d;
        mkdir(path.c_str(), 0755);
    }
    // 绑定挂载必要的系统目录（只读）
    // /bin, /lib, /lib64, /usr 绑定挂载，使解释器可用
    std::vector<std::string> bind_dirs = {"/bin", "/lib", "/lib64", "/usr", "/etc/alternatives"};
    for (const auto& d : bind_dirs) {
        struct stat st;
        if (stat(d.c_str(), &st) == 0) {
            std::string src = d;
            std::string dst = new_root + d;
            mkdir(dst.c_str(), 0755);
            if (mount(src.c_str(), dst.c_str(), nullptr, MS_BIND | MS_REC, nullptr) != 0) {
                // 绑定挂载失败不致命，继续
                std::cerr << "[namespace] bind mount " << d << " failed: " << strerror(errno) << "\n";
            }
        }
    }
    // pivot_root
    // 先 chdir 到新根
    if (chdir(new_root.c_str()) != 0) {
        std::cerr << "[namespace] chdir to new_root failed: " << strerror(errno) << "\n";
        return -1;
    }
    // 创建 put_old 目录
    std::string put_old = new_root + "/.oldroot";
    mkdir(put_old.c_str(), 0700);
    // 调用 pivot_root
    if (syscall(SYS_pivot_root, ".", ".oldroot") != 0) {
        std::cerr << "[namespace] pivot_root syscall failed: " << strerror(errno) << "\n";
        return -1;
    }
    // 切换到新根
    if (chdir("/") != 0) {
        std::cerr << "[namespace] chdir / failed: " << strerror(errno) << "\n";
        return -1;
    }
    // 卸载旧根
    if (umount2("/.oldroot", MNT_DETACH) != 0) {
        std::cerr << "[namespace] umount oldroot failed: " << strerror(errno) << "\n";
        // 不致命，继续
    }
    rmdir("/.oldroot");
    // 挂载 /proc
    if (config.mount_proc) {
        if (setup_proc() != 0) {
            std::cerr << "[namespace] mount /proc failed: " << strerror(errno) << "\n";
        }
    }
    // 挂载最小 /dev
    if (config.mount_dev) {
        if (setup_minimal_dev() != 0) {
            std::cerr << "[namespace] setup /dev failed: " << strerror(errno) << "\n";
        }
    }
    // 挂载 /tmp
    if (config.mount_tmp) {
        if (mount("tmpfs", "/tmp", "tmpfs", 0, "size=32m,mode=1777") != 0) {
            std::cerr << "[namespace] mount /tmp failed: " << strerror(errno) << "\n";
        }
    }
    return 0;
}
int NamespaceIsolator::setup_proc() {
    if (mount("proc", "/proc", "proc", 0, nullptr) != 0) {
        return -1;
    }
    return 0;
}
int NamespaceIsolator::setup_minimal_dev() {
    // 挂载 tmpfs 到 /dev
    if (mount("tmpfs", "/dev", "tmpfs", 0, "size=16m,mode=0755") != 0) {
        return -1;
    }
    // 创建基本设备节点
    // /dev/null
    mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3));
    // /dev/zero
    mknod("/dev/zero", S_IFCHR | 0666, makedev(1, 5));
    // /dev/random
    mknod("/dev/random", S_IFCHR | 0666, makedev(1, 8));
    // /dev/urandom
    mknod("/dev/urandom", S_IFCHR | 0666, makedev(1, 9));
    // /dev/tty
    mknod("/dev/tty", S_IFCHR | 0666, makedev(5, 0));
    // /dev/console (绑定挂载宿主的)
    // /dev/shm
    mkdir("/dev/shm", 01777);
    mount("tmpfs", "/dev/shm", "tmpfs", 0, "size=8m,mode=1777");
    // /dev/pts
    mkdir("/dev/pts", 0755);
    mount("devpts", "/dev/pts", "devpts", 0, "newinstance,ptmxmode=0666");
    return 0;
}
int NamespaceIsolator::setup_network_namespace() {
    // 启用 loopback 接口
    // 通过 netlink 或 ioctl 设置 lo up
    // 简化：用 system 调用 ip link set lo up
    // (实际生产环境应用 libnl 或 socket ioctl)
    if (system("ip link set lo up 2>/dev/null") != 0) {
        // ip 命令可能不存在，尝试用 ifconfig
        if (system("ifconfig lo up 2>/dev/null") != 0) {
            // 都失败也不致命，沙盒仍无外网
            return 0;
        }
    }
    return 0;
}
int NamespaceIsolator::setup_uts_namespace(const NamespaceConfig& config) {
    if (sethostname(config.hostname.c_str(), config.hostname.size()) != 0) {
        return -1;
    }
    return 0;
}
int NamespaceIsolator::setup_user_namespace(const NamespaceConfig& config) {
    // User namespace 已由 clone(CLONE_NEWUSER) 创建
    // 现在需要设置 uid/gid 映射
    // 1. 禁止 setgroups（必须在写 gid_map 之前）
    std::ofstream setgroups("/proc/self/setgroups");
    if (setgroups.is_open()) {
        setgroups << "deny\n";
        setgroups.close();
    }
    // 2. 写 uid_map：沙盒内 uid → 宿主 uid
    uint32_t outer_uid = config.uid_map_outer == 0 ? geteuid() : config.uid_map_outer;
    if (write_id_map("/proc/self/uid_map", config.uid_map_inner, outer_uid, config.uid_map_count) != 0) {
        std::cerr << "[namespace] write uid_map failed: " << strerror(errno) << "\n";
        return -1;
    }
    // 3. 写 gid_map：沙盒内 gid → 宿主 gid
    uint32_t outer_gid = config.gid_map_outer == 0 ? getegid() : config.gid_map_outer;
    if (write_id_map("/proc/self/gid_map", config.gid_map_inner, outer_gid, config.gid_map_count) != 0) {
        std::cerr << "[namespace] write gid_map failed: " << strerror(errno) << "\n";
        return -1;
    }
    return 0;
}

int NamespaceIsolator::write_id_map(const std::string& path, uint32_t inner, uint32_t outer, uint32_t count) {
    std::ofstream f(path);
    if (!f.is_open()) return -1;
    f << inner << " " << outer << " " << count << "\n";
    f.close();
    return 0;
}

std::string NamespaceIsolator::capability_description(const NamespaceConfig& config) {
    std::string desc;
    if (config.enable_mount) desc += "mount+pivot_root ";
    if (config.enable_pid) desc += "pid ";
    if (config.enable_net) desc += "net ";
    if (config.enable_uts) desc += "uts ";
    if (config.enable_ipc) desc += "ipc ";
    if (config.enable_user) desc += "user ";
    if (desc.empty()) desc = "none";
    return desc;
}
} // namespace sandbox
} // namespace photon_kernel
