#include <grpcpp/grpcpp.h>
#include <iostream>
#include <memory>
#include <signal.h>
#include "photon_kernel/sandbox/sandbox_service.hpp"
#include "photon_kernel/sandbox/sandbox_pool_v2.hpp"
#include "photon_kernel/sandbox/code_runner.hpp"
using namespace photon_kernel::sandbox;
static std::unique_ptr<grpc::Server> server_ptr;
static std::shared_ptr<SandboxPoolV2> pool_ptr;
void signal_handler(int sig) {
    std::cout << "\n[Server] Shutting down...\n";
    if (pool_ptr) pool_ptr->shutdown();
    if (server_ptr) server_ptr->Shutdown();
    exit(0);
}
int main(int argc, char** argv) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    // ---- 预 fork 预热池配置（真·预 fork：启动即 fork min_size 个子进程并装好 seccomp）----
    PoolV2Config pool_config;
    pool_config.min_size = 10;   // 启动预 fork 的 worker 数
    pool_config.max_size = 50;
    pool_config.risk_level = RiskLevel::MEDIUM;
    pool_config.task_timeout = std::chrono::milliseconds(5000);
    // ---- 初始化预 fork 预热池 ----
    pool_ptr = std::make_shared<SandboxPoolV2>(pool_config);
    pool_ptr->initialize();
    // ---- 启动 gRPC 服务 ----
    std::string server_address("0.0.0.0:50051");
    SandboxServiceImpl service(pool_ptr);
    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    server_ptr = builder.BuildAndStart();
    std::cout << "[Server] gRPC server listening on " << server_address << "\n";
    std::cout << "[Server] Pre-fork pool: " << pool_config.min_size
              << " seccomp-ready workers (Fast-Path)\n";
    server_ptr->Wait();
    return 0;
}
