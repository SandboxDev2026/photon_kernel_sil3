#ifndef PHOTON_KERNEL_SANDBOX_LANDLOCK_HPP
#define PHOTON_KERNEL_SANDBOX_LANDLOCK_HPP
// Landlock 路径白名单（生产级优化五）：
// Linux 5.13+ 内核安全模块，限制进程可访问的文件系统路径。
// 与 seccomp（syscall 级）互补：seccomp 限制能调用哪些 syscall，
// Landlock 限制能访问哪些路径（即使 syscall 在白名单内）。
//
// 运行时检测内核支持；不支持时返回 false 并标注 unavailable，不影响功能。
// 条件编译：检测 <linux/landlock.h> 头文件可用性。
#include <string>
#include <vector>
namespace photon_kernel {
namespace sandbox {
struct LandlockResult {
    bool applied = false;
    bool available = false;   // 内核是否支持 Landlock
    std::string message;
};
class LandlockEnforcer {
public:
    // 检测内核是否支持 Landlock
    [[nodiscard]] static bool is_supported();
    // 应用路径白名单：只允许读取 allowed_paths 下的文件/目录
    // 成功返回 true；内核不支持或应用失败返回 false
    [[nodiscard]] static LandlockResult apply_read_only(const std::vector<std::string>& allowed_paths);
private:
    LandlockEnforcer() = default;
};
} // namespace sandbox
} // namespace photon_kernel
#endif
