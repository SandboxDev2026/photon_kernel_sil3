#ifndef PHOTON_KERNEL_SANDBOX_CODE_RUNNER_HPP
#define PHOTON_KERNEL_SANDBOX_CODE_RUNNER_HPP

#include <string>
#include <chrono>
#include <cstdint>

namespace photon_kernel {
namespace sandbox {

// ---- 支持的代码运行器 ----
enum class CodeRunner : int {
    PYTHON3 = 0,
    NODE = 1,
    SHELL = 2
};

std::string code_runner_to_string(CodeRunner r);

struct CodeRunRequest {
    CodeRunner runner = CodeRunner::PYTHON3;
    std::string code;                 // 传给解释器 stdin 的用户代码
    std::chrono::milliseconds timeout{5000};
    size_t max_output_bytes = 64 * 1024;  // 输出捕获上限（防止内存膨胀）
};

struct CodeRunResult {
    bool success = false;
    std::string output;               // 捕获的 stdout
    std::string error;                // 失败原因 / stderr（有限）
    int exit_code = 0;
    int exit_signal = 0;
    int64_t cpu_time_us = 0;
    int64_t memory_peak_bytes = 0;
    int64_t elapsed_us = 0;
};

// 解释器路径白名单（硬编码）。
// 说明：seccomp-bpf 只能按 syscall 过滤，无法按“路径”过滤（不能解引用用户内存指针），
// 因此“解释器路径白名单”在源头实现：只允许 exec 这几个预置解释器，杜绝任意路径执行。
[[nodiscard]] const char* interpreter_path(CodeRunner r);

// 在“已初始化沙箱（rlimit + seccomp 已就绪）”的进程内执行用户代码：
//   1. fork 任务进程（继承 seccomp/rlimit）
//   2. 任务进程 exec 预置解释器，stdin 接收用户代码，stdout/stderr 捕获到临时文件
//   3. 看门狗超时 kill，wait4 收集资源统计
// process_limit：在任务进程内单独设置 RLIMIT_NPROC（防 fork 炸弹），
//   不影响调用方（worker）持续 fork 新任务的能力。
// 该函数可被预 fork 沙盒 worker 重复调用（一次初始化、多次执行）。
[[nodiscard]] CodeRunResult run_user_code(const CodeRunRequest& req,
                                          size_t process_limit = 64);

} // namespace sandbox
} // namespace photon_kernel

#endif
