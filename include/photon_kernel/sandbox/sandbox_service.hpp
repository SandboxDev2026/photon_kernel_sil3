#ifndef PHOTON_KERNEL_SANDBOX_SERVICE_HPP
#define PHOTON_KERNEL_SANDBOX_SERVICE_HPP
#include <memory>
#include <mutex>
#include <map>
#include <string>
#include <atomic>
#include <thread>
#include <chrono>
#include <grpcpp/grpcpp.h>
#include "sandbox.grpc.pb.h"
#include "sandbox_pool_v2.hpp"
#include "code_runner.hpp"
namespace photon_kernel {
namespace sandbox {
// 异步任务状态
struct AsyncTaskState {
    bool completed = false;
    CodeRunResult result;
};
// gRPC 沙盒服务实现（补齐版）：
//   - Execute：同步执行，含请求验证 + 审计 + metrics + 并发控制
//   - ExecuteAsync：异步执行，修复 use-after-free（先拷贝 request），结果存入任务表
//   - GetTaskResult：查询异步任务结果
//   - GetPoolStatus：池状态
class SandboxServiceImpl final : public photon::sandbox::SandboxService::Service {
public:
    static constexpr int kMaxConcurrentTasks = 128;
    static constexpr int kMaxCodeSizeBytes = 1024 * 1024;  // 1MB
    static constexpr int kMaxTimeoutMs = 60000;              // 60s
    explicit SandboxServiceImpl(std::shared_ptr<SandboxPoolV2> pool)
        : pool_(std::move(pool)), concurrent_tasks_(0) {}
    ~SandboxServiceImpl() {
        for (int i = 0; i < 50 && concurrent_tasks_.load() > 0; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    grpc::Status Execute(grpc::ServerContext* context,
                         const photon::sandbox::SandboxRequest* request,
                         photon::sandbox::SandboxResponse* response) override;
    grpc::Status ExecuteAsync(grpc::ServerContext* context,
                              const photon::sandbox::SandboxRequest* request,
                              photon::sandbox::AsyncResponse* response) override;
    grpc::Status GetTaskResult(grpc::ServerContext* context,
                                const photon::sandbox::TaskResultRequest* request,
                                photon::sandbox::TaskResultResponse* response) override;
    grpc::Status GetPoolStatus(grpc::ServerContext* context,
                               const photon::sandbox::EmptyRequest* request,
                               photon::sandbox::PoolStatusResponse* response) override;
private:
    static std::string validate_request(const photon::sandbox::SandboxRequest& req);
    static CodeRunRequest make_run_request(const photon::sandbox::SandboxRequest& request);
    static void fill_response(const CodeRunResult& result,
                              photon::sandbox::SandboxResponse* response);
    static void log_audit(const std::string& action,
                          const std::string& task_id,
                          const photon::sandbox::SandboxRequest& req,
                          bool success,
                          int64_t cpu_us);
    std::shared_ptr<SandboxPoolV2> pool_;
    std::atomic<int> concurrent_tasks_;
    std::mutex tasks_mutex_;
    std::map<std::string, AsyncTaskState> async_tasks_;
    static std::atomic<uint64_t> task_counter_;
};
} // namespace sandbox
} // namespace photon_kernel
#endif
