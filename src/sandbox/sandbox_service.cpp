#include "photon_kernel/sandbox/sandbox_service.hpp"
#include "photon_kernel/sandbox/sandbox_exception.hpp"
#include "photon_kernel/sandbox/metrics.hpp"
#include <atomic>
#include <thread>
#include <iostream>
#include <sstream>
#include <chrono>
namespace photon_kernel {
namespace sandbox {
std::atomic<uint64_t> SandboxServiceImpl::task_counter_{0};
// RAII 并发计数守卫：构造时 +1（已在外部 fetch_add），析构时 -1
class ConcurrentGuard {
public:
    explicit ConcurrentGuard(std::atomic<int>& counter) : counter_(counter) {}
    ~ConcurrentGuard() { counter_.fetch_sub(1); }
    ConcurrentGuard(const ConcurrentGuard&) = delete;
    ConcurrentGuard& operator=(const ConcurrentGuard&) = delete;
private:
    std::atomic<int>& counter_;
};
// ---- 请求验证 ----
std::string SandboxServiceImpl::validate_request(
    const photon::sandbox::SandboxRequest& req) {
    if (req.task_code().empty()) {
        return "task_code must not be empty";
    }
    if (static_cast<int>(req.task_code().size()) > kMaxCodeSizeBytes) {
        return "task_code exceeds max size (1MB)";
    }
    if (req.timeout_ms() < 0) {
        return "timeout_ms must be non-negative";
    }
    if (req.timeout_ms() > kMaxTimeoutMs) {
        return "timeout_ms exceeds max (60s)";
    }
    int runner = req.runner();
    if (runner < 0 || runner > static_cast<int>(CodeRunner::SHELL)) {
        return "invalid runner value";
    }
    return "";
}
// ---- 请求解析 ----
CodeRunRequest SandboxServiceImpl::make_run_request(
    const photon::sandbox::SandboxRequest& request) {
    CodeRunRequest req;
    int runner = request.runner();
    if (runner >= static_cast<int>(CodeRunner::PYTHON3) &&
        runner <= static_cast<int>(CodeRunner::SHELL)) {
        req.runner = static_cast<CodeRunner>(runner);
    } else {
        req.runner = CodeRunner::PYTHON3;
    }
    req.code = request.task_code();
    int timeout_ms = request.timeout_ms();
    if (timeout_ms <= 0) timeout_ms = 5000;
    if (timeout_ms > kMaxTimeoutMs) timeout_ms = kMaxTimeoutMs;
    req.timeout = std::chrono::milliseconds(timeout_ms);
    return req;
}
// ---- 填充响应 ----
void SandboxServiceImpl::fill_response(const CodeRunResult& result,
                                        photon::sandbox::SandboxResponse* response) {
    response->set_success(result.success);
    response->set_output(result.output);
    if (!result.error.empty()) {
        response->set_error(result.error);
    }
    response->set_cpu_time_us(result.cpu_time_us);
    response->set_memory_peak_bytes(result.memory_peak_bytes);
    response->set_exit_code(result.exit_code);
    if (!result.success) {
        std::ostringstream oss;
        oss << result.exit_signal;
        if (!result.error.empty()) oss << ":" << result.error;
        response->set_error_code(oss.str());
    }
}
// ---- 审计日志（结构化 JSON，生产环境应接入 AuditLogger）----
void SandboxServiceImpl::log_audit(const std::string& action,
                                    const std::string& task_id,
                                    const photon::sandbox::SandboxRequest& req,
                                    bool success,
                                    int64_t cpu_us) {
    std::ostringstream oss;
    oss << "{\"event\":\"sandbox." << action << "\""
        << ",\"task_id\":\"" << task_id << "\""
        << ",\"runner\":" << req.runner()
        << ",\"code_size\":" << req.task_code().size()
        << ",\"timeout_ms\":" << req.timeout_ms()
        << ",\"success\":" << (success ? "true" : "false")
        << ",\"cpu_us\":" << cpu_us
        << "}";
    std::cerr << "[AUDIT] " << oss.str() << "\n";
}
// ---- Execute：同步执行 ----
grpc::Status SandboxServiceImpl::Execute(
    grpc::ServerContext* context,
    const photon::sandbox::SandboxRequest* request,
    photon::sandbox::SandboxResponse* response) {
    // 1. 请求验证
    std::string err = validate_request(*request);
    if (!err.empty()) {
        response->set_success(false);
        response->set_error(err);
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, err);
    }
    // 2. 并发控制
    if (concurrent_tasks_.fetch_add(1) >= kMaxConcurrentTasks) {
        concurrent_tasks_.fetch_sub(1);
        response->set_success(false);
        response->set_error("server overloaded: max concurrent tasks reached");
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "overloaded");
    }
    ConcurrentGuard guard(concurrent_tasks_);  // 析构时自动 -1
    auto start = std::chrono::steady_clock::now();
    try {
        CodeRunRequest req = make_run_request(*request);
        auto result = pool_->execute(req);
        fill_response(result, response);
        // metrics
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start).count();
        Metrics::instance().record_task(result.success,
            std::chrono::microseconds(elapsed),
            std::chrono::microseconds(result.cpu_time_us));
        // audit
        log_audit("execute", "sync", *request, result.success, result.cpu_time_us);
        return grpc::Status::OK;
    } catch (const SandboxException& e) {
        response->set_success(false);
        response->set_error(e.what());
        response->set_error_code(std::to_string(static_cast<int>(e.code())));
        log_audit("execute", "sync", *request, false, 0);
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    } catch (const std::exception& e) {
        response->set_success(false);
        response->set_error(e.what());
        log_audit("execute", "sync", *request, false, 0);
        return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
    }
    concurrent_tasks_.fetch_sub(1);
}
// ---- ExecuteAsync：异步执行（修复 use-after-free：先拷贝 request）----
grpc::Status SandboxServiceImpl::ExecuteAsync(
    grpc::ServerContext* context,
    const photon::sandbox::SandboxRequest* request,
    photon::sandbox::AsyncResponse* response) {
    // 1. 请求验证
    std::string err = validate_request(*request);
    if (!err.empty()) {
        response->set_task_id("");
        response->set_status("rejected: " + err);
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, err);
    }
    // 2. 并发控制
    if (concurrent_tasks_.fetch_add(1) >= kMaxConcurrentTasks) {
        concurrent_tasks_.fetch_sub(1);
        response->set_task_id("");
        response->set_status("rejected: overloaded");
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "overloaded");
    }
    // 3. 生成任务 ID
    std::string task_id = "async-" + std::to_string(++task_counter_);
    response->set_task_id(task_id);
    response->set_status("accepted");
    // 4. 关键修复：在创建线程前拷贝 request（CodeRunRequest 是值类型，不依赖 gRPC request 指针）
    CodeRunRequest req = make_run_request(*request);
    // 5. 注册任务状态
    {
        std::lock_guard<std::mutex> lock(tasks_mutex_);
        async_tasks_[task_id] = AsyncTaskState{};
    }
    // 6. 异步执行（捕获 req 值拷贝，不捕获 request 指针）
    std::thread([this, task_id, req]() {
        CodeRunResult result;
        try {
            result = pool_->execute(req);
        } catch (const std::exception& e) {
            result.success = false;
            result.error = e.what();
            result.exit_code = -1;
        }
        // 存储结果
        {
            std::lock_guard<std::mutex> lock(tasks_mutex_);
            auto it = async_tasks_.find(task_id);
            if (it != async_tasks_.end()) {
                it->second.completed = true;
                it->second.result = result;
            }
        }
        concurrent_tasks_.fetch_sub(1);
    }).detach();
    return grpc::Status::OK;
}
// ---- GetTaskResult：查询异步任务结果 ----
grpc::Status SandboxServiceImpl::GetTaskResult(
    grpc::ServerContext* context,
    const photon::sandbox::TaskResultRequest* request,
    photon::sandbox::TaskResultResponse* response) {
    std::string task_id = request->task_id();
    if (task_id.empty()) {
        response->set_found(false);
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "task_id must not be empty");
    }
    std::lock_guard<std::mutex> lock(tasks_mutex_);
    auto it = async_tasks_.find(task_id);
    if (it == async_tasks_.end()) {
        response->set_found(false);
        response->set_completed(false);
        return grpc::Status::OK;
    }
    response->set_found(true);
    response->set_completed(it->second.completed);
    if (it->second.completed) {
        const auto& r = it->second.result;
        response->set_success(r.success);
        response->set_output(r.output);
        response->set_error(r.error);
        response->set_cpu_time_us(r.cpu_time_us);
        response->set_memory_peak_bytes(r.memory_peak_bytes);
        response->set_exit_code(r.exit_code);
    }
    return grpc::Status::OK;
}
// ---- GetPoolStatus ----
grpc::Status SandboxServiceImpl::GetPoolStatus(
    grpc::ServerContext* context,
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
