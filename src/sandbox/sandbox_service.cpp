#include "photon_kernel/sandbox/sandbox_service.hpp"
#include "photon_kernel/sandbox/sandbox_exception.hpp"
#include <atomic>
#include <thread>
#include <iostream>
namespace photon_kernel {
namespace sandbox {
// 将 gRPC 请求解析为代码执行请求
CodeRunRequest SandboxServiceImpl::make_run_request(
    const photon::sandbox::SandboxRequest& request) {
    CodeRunRequest req;
    // runner: 0=python3 1=node 2=shell（默认 python3）
    int runner = request.runner();
    if (runner >= static_cast<int>(CodeRunner::PYTHON3) &&
        runner <= static_cast<int>(CodeRunner::SHELL)) {
        req.runner = static_cast<CodeRunner>(runner);
    } else {
        req.runner = CodeRunner::PYTHON3;
    }
    req.code = request.task_code();
    req.timeout = std::chrono::milliseconds(
        request.timeout_ms() > 0 ? request.timeout_ms() : 5000);
    return req;
}

grpc::Status SandboxServiceImpl::Execute(grpc::ServerContext* context,
                                         const photon::sandbox::SandboxRequest* request,
                                         photon::sandbox::SandboxResponse* response) {
    try {
        // 1. 解析请求 -> 代码执行请求（真实执行：Python/Node/Shell，经预 fork worker）
        CodeRunRequest req = make_run_request(*request);
        // 2. Fast-Path：从预 fork 预热池取已就绪 worker 执行
        auto result = pool_->execute(req);
        // 3. 填充响应（含真实输出/资源统计）
        response->set_success(result.success);
        response->set_output(result.output);
        if (!result.error.empty()) {
            response->set_error(result.error);
        }
        response->set_cpu_time_us(result.cpu_time_us);
        response->set_memory_peak_bytes(result.memory_peak_bytes);
        response->set_exit_code(result.exit_code);
        if (!result.success) {
            response->set_error_code(std::to_string(result.exit_signal) +
                                     (result.error.empty() ? "" : ":" + result.error));
        }
        return grpc::Status::OK;
    } catch (const SandboxException& e) {
        response->set_success(false);
        response->set_error(e.what());
        response->set_error_code(std::to_string(static_cast<int>(e.code())));
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    } catch (const std::exception& e) {
        response->set_success(false);
        response->set_error(e.what());
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
}

grpc::Status SandboxServiceImpl::ExecuteAsync(grpc::ServerContext* context,
                                              const photon::sandbox::SandboxRequest* request,
                                              photon::sandbox::AsyncResponse* response) {
    // 生成任务 ID
    static std::atomic<int> task_counter{0};
    std::string task_id = "async-" + std::to_string(++task_counter);
    response->set_task_id(task_id);
    response->set_status("accepted");
    // 异步执行：后台线程从预热池取 worker 真实执行
    std::thread([this, request, task_id]() {
        try {
            CodeRunRequest req = make_run_request(*request);
            auto result = pool_->execute(req);
            std::cout << "[Sandbox] Async task " << task_id
                      << " completed: " << (result.success ? "success" : "failed")
                      << " cpu_us=" << result.cpu_time_us << "\n";
        } catch (const std::exception& e) {
            std::cerr << "[Sandbox] Async task " << task_id << " error: " << e.what() << "\n";
        }
    }).detach();
    return grpc::Status::OK;
}

grpc::Status SandboxServiceImpl::GetPoolStatus(grpc::ServerContext* context,
                                               const photon::sandbox::EmptyRequest* request,
                                               photon::sandbox::PoolStatusResponse* response) {
    auto status = pool_->get_status();
    response->set_total(static_cast<int32_t>(status.total));
    response->set_idle(static_cast<int32_t>(status.idle));
    response->set_busy(static_cast<int32_t>(status.busy));
    response->set_failed(static_cast<int32_t>(status.failed));
    return grpc::Status::OK;
}
} // namespace sandbox
} // namespace photon_kernel
