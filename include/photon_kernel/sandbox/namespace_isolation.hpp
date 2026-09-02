#ifndef PHOTON_KERNEL_SANDBOX_NAMESPACE_ISOLATION_HPP
#define PHOTON_KERNEL_SANDBOX_NAMESPACE_ISOLATION_HPP
// NamespaceIsolator —— Linux namespace 隔离（进程沙盒标准地基）
//
// 实现 5 种 namespace 隔离：
//   1. Mount namespace (CLONE_NEWNS) + pivot_root：文件系统隔离，沙盒看不到宿主文件系统
//   2. PID namespace (CLONE_NEWPID)：进程隔离，沙盒内首进程 PID=1，看不到宿主进程
//   3. Network namespace (CLONE_NEWNET)：网络隔离，沙盒内只有 loopback，无外网
//   4. UTS namespace (CLONE_NEWUTS)：hostname 隔离
//   5. IPC namespace (CLONE_NEWIPC)：System V IPC / POSIX 消息队列隔离
//
// 注意：namespace 隔离需要 CAP_SYS_ADMIN（root）。
// 当前容器无 root 时，is_supported() 返回 false，自动降级为仅 seccomp+rlimit。
// 在裸机/有 root 的环境运行时，namespace 隔离完整生效。
#include <string>
#include <csignal>
namespace photon_kernel {
namespace sandbox {
struct NamespaceConfig {
    bool enable_mount = true;     // Mount namespace + pivot_root
    bool enable_pid = true;       // PID namespace
    bool enable_net = true;       // Network namespace（无外网）
    bool enable_uts = true;       // UTS namespace（hostname）
    bool enable_ipc = true;       // IPC namespace
    std::string hostname = "photon-sandbox";
    std::string rootfs_path = ""; // pivot_root 目标目录，空则自动创建临时目录
    bool mount_proc = true;       // 挂载 /proc
    bool mount_dev = true;        // 挂载 /dev (tmpfs + null/zero/random/urandom)
    bool mount_tmp = true;        // 挂载 /tmp (tmpfs)
};
class NamespaceIsolator {
public:
    // 检测当前环境是否支持 namespace 隔离
    // 需要：root (EUID=0) 或 CAP_SYS_ADMIN
    static bool is_supported();
    // 获取 clone() 所需的 flags（根据配置决定启用哪些 namespace）
    static int clone_flags(const NamespaceConfig& config);
    // 在子进程中设置 namespace 环境（在 clone 后、exec 前调用）
    // 返回 0 成功，-1 失败（失败时应 _exit）
    static int setup_in_child(const NamespaceConfig& config);
    // 获取能力描述（用于日志/状态输出）
    static std::string capability_description(const NamespaceConfig& config);
private:
    // Mount namespace: 使所有挂载私有，然后 pivot_root
    static int setup_mount_namespace(const NamespaceConfig& config);
    // pivot_root: 切换根文件系统
    static int setup_pivot_root(const NamespaceConfig& config);
    // Network namespace: 启用 loopback
    static int setup_network_namespace();
    // UTS namespace: 设置 hostname
    static int setup_uts_namespace(const NamespaceConfig& config);
    // 挂载最小 /dev
    static int setup_minimal_dev();
    // 挂载 /proc
    static int setup_proc();
};
} // namespace sandbox
} // namespace photon_kernel
#endif
