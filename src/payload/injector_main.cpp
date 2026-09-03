// injector_main.cpp - 宿主机侧注入器入口
// 编译用户代码, 通过共享内存注入Worker执行, 读取结果
// 用法: ./payload_injector --shm <name> --file <code_file> --lang <python|js|shell|cpp>
#include "photon_kernel/payload/shm_channel.hpp"
#include "photon_kernel/payload/code_compiler.hpp"
#include "photon_kernel/payload/strong_pool_config.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <optional>

using namespace photon_kernel::payload;

int main(int argc, char* argv[]) {
    std::string shm_name = "/photon_payload_" + std::to_string(getpid());
    std::string code_file;
    std::string language = "auto";
    uint32_t timeout_ms = 10000;
    bool create_channel = true;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--shm" && i + 1 < argc) {
            shm_name = argv[++i];
        } else if (arg == "--file" && i + 1 < argc) {
            code_file = argv[++i];
        } else if (arg == "--lang" && i + 1 < argc) {
            language = argv[++i];
        } else if (arg == "--timeout" && i + 1 < argc) {
            timeout_ms = static_cast<uint32_t>(std::atoi(argv[++i]));
        } else if (arg == "--connect") {
            create_channel = false;  // 连接已存在的通道
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [options]\n"
                      << "  --shm <name>     Shared memory name (default: auto)\n"
                      << "  --file <path>    Code file to execute\n"
                      << "  --lang <lang>    Language: python|js|shell|cpp|auto\n"
                      << "  --timeout <ms>   Execution timeout (default: 10000)\n"
                      << "  --connect        Connect to existing channel (don't create)\n";
            return 0;
        }
    }

    // 读取代码
    std::string code;
    if (!code_file.empty()) {
        std::ifstream f(code_file);
        if (!f) {
            std::cerr << "Error: Cannot open file: " << code_file << "\n";
            return 1;
        }
        std::stringstream ss;
        ss << f.rdbuf();
        code = ss.str();
    } else {
        // 从stdin读取
        std::stringstream ss;
        ss << std::cin.rdbuf();
        code = ss.str();
    }

    if (code.empty()) {
        std::cerr << "Error: No code provided (use --file or stdin)\n";
        return 1;
    }

    // 加载StrongPool配置(进化任务强制StrongPool)
    StrongPoolConfig config = evolution_task_config();
    std::cout << "[Injector] StrongPool config: mem=" << config.memory_limit_bytes / 1024 / 1024
              << "M cpu=" << config.cpu_count << " timeout=" << config.timeout_ms << "ms\n";
    std::cout << "[Injector] force_strong_for_evolution=" << config.force_strong_for_evolution
              << " allow_light_pool=" << config.allow_light_pool << "\n";

    // 编译代码
    CodeCompiler compiler;
    CompiledPayload compiled = compiler.compile_auto(code, language);
    if (!compiled.success) {
        std::cerr << "[Injector] Compile failed: " << compiled.error << "\n";
        return 1;
    }
    if (!compiled.error.empty()) {
        std::cout << "[Injector] Compile warning: " << compiled.error << "\n";
    }
    std::cout << "[Injector] Compiled: type=" << static_cast<int>(compiled.type)
              << " size=" << compiled.bytecode.size() << " bytes\n";

    // 创建/打开共享内存通道
    std::optional<ShmChannel> channel;
    try {
        if (create_channel) {
            channel = ShmChannel::create(shm_name);
            std::cout << "[Injector] Created shm: " << shm_name << "\n";
            std::cout << "[Injector] Start worker with: ./payload_worker --shm " << shm_name << "\n";
        } else {
            channel = ShmChannel::open(shm_name);
            std::cout << "[Injector] Connected to shm: " << shm_name << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "[Injector] Shm error: " << e.what() << "\n";
        return 1;
    }

    // 注入任务
    uint64_t task_id = static_cast<uint64_t>(getpid()) * 1000 + time(nullptr) % 1000;
    compiler.inject_to_channel(*channel, compiled, task_id, timeout_ms);
    std::cout << "[Injector] Task injected: id=" << task_id << "\n";

    // 等待结果
    std::cout << "[Injector] Waiting for result...\n";
    if (!channel->wait_for_status(TaskStatus::DONE, timeout_ms + 5000)) {
        TaskStatus st = channel->get_status();
        std::cerr << "[Injector] Timeout waiting for result, status=" << static_cast<int>(st) << "\n";
        return 1;
    }

    // 读取结果
    size_t result_size;
    int exit_code = 0;
    const uint8_t* result = channel->read_result(result_size, exit_code);
    std::string result_str(reinterpret_cast<const char*>(result), result_size);

    std::cout << "========== Result ==========\n";
    std::cout << result_str;
    if (!result_str.empty() && result_str.back() != '\n') std::cout << "\n";
    std::cout << "============================\n";
    std::cout << "[Injector] Exit code: " << exit_code << "\n";

    return exit_code;
}
