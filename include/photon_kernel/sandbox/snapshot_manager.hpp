#ifndef PHOTON_KERNEL_SANDBOX_SNAPSHOT_MANAGER_HPP
#define PHOTON_KERNEL_SANDBOX_SNAPSHOT_MANAGER_HPP
// 快照克隆管理器（生产级优化一）：
// 预 fork N 个"母沙盒"进程，每个母进程一次性完成 seccomp + rlimit 安装并长驻。
// clone_sandbox() 时向母进程发 fork 指令，母进程直接 fork 出已就绪的子进程，
// 跳过 seccomp 安装和 rlimit 设置，目标克隆延迟 <1ms。
//
// 与 PrewarmedWorker 的区别：
//   - PrewarmedWorker：完整 worker 池，内部 fork+exec 解释器并返回完整执行结果
//   - SnapshotManager：底层快照克隆 API，只负责 fork 已就绪进程并返回 PID，
//     调用方自行管理子进程（适用于自定义执行逻辑、极致延迟场景）
#include <sys/types.h>
#include <vector>
#include <mutex>
#include <atomic>
#include <chrono>
#include <string>
namespace photon_kernel {
namespace sandbox {
struct SnapshotState {
    pid_t parent_pid = -1;     // 母进程 PID
    int cmd_fd = -1;            // 父进程写 → 母进程读（fork 指令管道）
    int res_fd = -1;            // 母进程写 → 父进程读（子进程 PID 管道）
    std::chrono::steady_clock::time_point created_at;
    bool is_ready = false;
};
class SnapshotManager {
public:
    static SnapshotManager& instance();
    // 初始化：启动 pool_size 个预热母进程（装好 seccomp + rlimit）
    // level：风险等级，决定 seccomp 白名单和 rlimit 配置
    void init(size_t pool_size = 10, int risk_level = 1);
    // 从快照克隆一个新沙盒（向母进程发 fork 指令，返回子进程 PID）
    // 目标延迟 <1ms；失败返回 -1
    pid_t clone_sandbox();
    // 回收沙盒子进程（waitpid）
    void recycle(pid_t child_pid);
    // 关闭所有母进程
    void shutdown();
    [[nodiscard]] size_t snapshot_count() const;
    [[nodiscard]] bool initialized() const { return initialized_.load(); }
    // 统计：累计克隆次数
    [[nodiscard]] uint64_t clone_count() const { return clone_count_.load(); }
private:
    SnapshotManager() = default;
    ~SnapshotManager();
    SnapshotManager(const SnapshotManager&) = delete;
    SnapshotManager& operator=(const SnapshotManager&) = delete;
    std::vector<SnapshotState> snapshots_;
    mutable std::mutex mutex_;
    std::atomic<bool> initialized_{false};
    std::atomic<uint64_t> clone_count_{0};
    size_t round_robin_ = 0;
};
} // namespace sandbox
} // namespace photon_kernel
#endif
