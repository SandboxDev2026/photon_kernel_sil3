#ifndef PHOTON_KERNEL_SANDBOX_SNAPSHOT_HPP
#define PHOTON_KERNEL_SANDBOX_SNAPSHOT_HPP

#include <string>
#include <vector>
#include <sys/types.h>

#include "sandbox_config.hpp"

namespace photon_kernel {
namespace sandbox {

// ---- 快照（任务3）----
// 分两层：
//  1) SandboxSnapshot：沙盒“配置级”快照 —— 保存风险等级/资源限制/syscall 白名单，
//     用于从快照重建沙盒（跳过手工重新配置），保存/加载往返可验证。
//  2) CRIU 集成：进程级快照（dump/restore），需要在 root + 安装 criu 的环境使用；
//     本机无特权环境无法实测，提供完整接口与命令封装。
struct SandboxSnapshot {
    static constexpr const char* FORMAT_VERSION = "1.0";

    std::string format_version = FORMAT_VERSION;
    std::string created_at;
    std::string label;             // 快照名称/用途
    SandboxConfig config;
    std::vector<int> whitelist;    // 已生成的白名单 syscall 编号（恢复时直接复用）

    // 保存为文本快照文件（key=value，自解释）
    bool save(const std::string& path) const;
    // 从快照文件加载；失败返回 false
    static bool load(const std::string& path, SandboxSnapshot& out);

    // 从已保存的快照重建一份配置（等价于跳过重新配置）
    SandboxConfig to_config() const { return config; }
};

// ---- CRIU 进程级快照集成 ----
// 需要 root 权限且系统安装 criu。命令封装：
//   dump:    criu dump -t <pid> -D <dir> --shell-job
//   restore: criu restore -D <dir> --shell-job
[[nodiscard]] bool criu_available();
// dump 指定 pid 的进程状态到 image_dir
bool criu_dump_process(pid_t pid, const std::string& image_dir, std::string& err);
// 从 image_dir 恢复进程，返回恢复后的 pid
bool criu_restore_process(const std::string& image_dir, pid_t& out_pid, std::string& err);

} // namespace sandbox
} // namespace photon_kernel

#endif
