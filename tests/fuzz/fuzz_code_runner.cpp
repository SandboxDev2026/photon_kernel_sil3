// Fuzz target: 代码执行器（输入任意字节作为代码）
#include <cstdint>
#include <cstddef>
#include <string>
#include "photon_kernel/sandbox/code_runner.hpp"
#include "photon_kernel/sandbox/sandbox_config.hpp"
using namespace photon_kernel::sandbox;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    std::string code(reinterpret_cast<const char*>(data), size);
    CodeRunner runners[] = {CodeRunner::PYTHON3, CodeRunner::NODE, CodeRunner::SHELL};
    for (auto runner : runners) {
        CodeRunRequest req;
        req.code = code;
        req.runner = runner;
        req.timeout = std::chrono::milliseconds(1000);
        SandboxConfig cfg = SandboxConfig::for_code_runner();
        try {
            CodeRunResult result = run_user_code(req, cfg.process_limit);
            (void)result;
        } catch (...) {}
    }
    return 0;
}
