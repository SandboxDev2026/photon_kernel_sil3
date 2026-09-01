#include <grpcpp/grpcpp.h>
#include <iostream>
#include <chrono>
#include <memory>
#include "sandbox.grpc.pb.h"
using namespace photon::sandbox;
int main(int argc, char** argv) {
    std::string target_str(argc > 1 ? argv[1] : "localhost:50051");
    auto channel = grpc::CreateChannel(target_str, grpc::InsecureChannelCredentials());
    std::unique_ptr<SandboxService::Stub> stub = SandboxService::NewStub(channel);
    // ---- 测试 1: 同步执行（真实代码，经预 fork 预热池 Fast-Path）----
    SandboxRequest request;
    request.set_task_name("py_hello");
    request.set_runner(0);  // 0=python3
    request.set_task_code("print('Hello from sandbox')\nimport sys\nprint('py', sys.version_info.major)");
    request.set_timeout_ms(3000);
    request.set_risk_level(MEDIUM);
    SandboxResponse response;
    grpc::ClientContext context;
    auto start = std::chrono::steady_clock::now();
    auto status = stub->Execute(&context, request, &response);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    if (status.ok()) {
        std::cout << "[Execute] success=" << response.success() << "\n";
        std::cout << "[Execute] output:\n" << response.output();
        if (!response.error().empty()) std::cout << "[Execute] error: " << response.error() << "\n";
        std::cout << "[Execute] cpu=" << response.cpu_time_us() << "us"
                  << " mem=" << response.memory_peak_bytes() << "B"
                  << " rtt=" << elapsed.count() << "us\n";
    } else {
        std::cerr << "RPC failed: " << status.error_message() << "\n";
    }
    // ---- 测试 2: shell 快速任务（预热池命中延迟）----
    {
        SandboxRequest req;
        req.set_task_name("sh_fast");
        req.set_runner(2);  // 2=shell
        req.set_task_code("exit 0");
        req.set_timeout_ms(2000);
        SandboxResponse resp;
        grpc::ClientContext ctx;
        auto s2 = std::chrono::steady_clock::now();
        auto st = stub->Execute(&ctx, req, &resp);
        auto e2 = std::chrono::steady_clock::now();
        long rtt = std::chrono::duration_cast<std::chrono::microseconds>(e2 - s2).count();
        std::cout << "[Fast-Path shell] success=" << (st.ok() && resp.success())
                  << " rtt=" << rtt << "us\n";
    }
    // ---- 测试 3: 获取池状态 ----
    EmptyRequest empty;
    PoolStatusResponse status_resp;
    grpc::ClientContext ctx2;
    stub->GetPoolStatus(&ctx2, empty, &status_resp);
    std::cout << "\n[Pool Status]\n";
    std::cout << " Total: " << status_resp.total() << "\n";
    std::cout << " Idle: " << status_resp.idle() << "\n";
    std::cout << " Busy: " << status_resp.busy() << "\n";
    std::cout << " Failed: " << status_resp.failed() << "\n";
    return 0;
}
