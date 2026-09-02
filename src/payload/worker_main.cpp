// worker_main.cpp - Worker进程入口
// 从共享内存读取任务, 执行, 将结果写回共享内存
// 用法: ./payload_worker --shm <shared_memory_name> [--loop] [--max-tasks N]
#include "photon_kernel/payload/shm_channel.hpp"
#include "photon_kernel/payload/payload_executor.hpp"
#include "photon_kernel/payload/strong_pool_config.hpp"

#include <iostream>
#include <string>
#include <csignal>
#include <unistd.h>
#include <optional>

using namespace photon_kernel::payload;

static volatile bool g_running = true;

void signal_handler(int sig) {
    (void)sig;
    g_running = false;
}

int main(int argc, char* argv[]) {
    std::string shm_name;
    bool loop_mode = false;
    int max_tasks = 0;  // 0=无限

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--shm" && i + 1 < argc) {
            shm_name = argv[++i];
        } else if (arg == "--loop") {
            loop_mode = true;
        } else if (arg == "--max-tasks" && i + 1 < argc) {
            max_tasks = std::atoi(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0] << " --shm <name> [--loop] [--max-tasks N]\n";
            return 0;
        }
    }

    if (shm_name.empty()) {
        std::cerr << "Error: --shm is required\n";
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 加载StrongPool配置
    StrongPoolConfig config = evolution_task_config();
    if (!config.validate()) {
        std::cerr << "Warning: Invalid StrongPool config, using defaults\n";
    }

    // 打开共享内存
    std::optional<ShmChannel> channel;
    try {
        channel = ShmChannel::open(shm_name);
    } catch (const std::exception& e) {
        std::cerr << "Failed to open shared memory: " << e.what() << "\n";
        return 1;
    }

    // 创建执行器
    PayloadExecutor executor;
    executor.set_memory_limit(config.memory_limit_bytes);
    executor.set_cpu_limit(config.cpu_count);
    executor.set_default_timeout(config.timeout_ms);

    std::cout << "[Worker] PID=" << getpid() << " shm=" << shm_name
              << " mem=" << config.memory_limit_bytes / 1024 / 1024 << "M"
              << " cpu=" << config.cpu_count
              << " timeout=" << config.timeout_ms << "ms\n";

    int tasks_executed = 0;
    while (g_running) {
        if (max_tasks > 0 && tasks_executed >= max_tasks) break;

        // 等待任务就绪
        if (!channel->wait_for_status(TaskStatus::READY, 1000)) {
            if (!loop_mode) break;
            continue;
        }

        // 执行任务
        try {
            ExecutionResult result = executor.execute(*channel);
            tasks_executed++;
            std::cout << "[Worker] Task " << tasks_executed
                      << " exit=" << result.exit_code
                      << " time=" << result.duration_ns / 1000000 << "ms"
                      << (result.timed_out ? " TIMEOUT" : "")
                      << (result.killed ? " KILLED" : "") << "\n";
        } catch (const std::exception& e) {
            std::cerr << "[Worker] Execution error: " << e.what() << "\n";
            channel->set_status(TaskStatus::ERROR);
        }

        if (!loop_mode) break;
    }

    std::cout << "[Worker] Done, executed " << tasks_executed << " tasks\n";
    return 0;
}
