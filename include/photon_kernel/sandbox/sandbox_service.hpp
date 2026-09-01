#ifndef PHOTON_KERNEL_SANDBOX_SERVICE_HPP
#define PHOTON_KERNEL_SANDBOX_SERVICE_HPP

#include <memory>

#include <grpcpp/grpcpp.h>

#include "sandbox.grpc.pb.h"
#include "sandbox_pool_v2.hpp"

namespace photon_kernel {
namespace sandbox {

// proto 包 photon.sandbox 生成的 C++ 命名空间为 photon::sandbox
class SandboxServiceImpl final : public photon::sandbox::SandboxService::Service {
public:
    // 基于预 fork 预热池（SandboxPoolV2）：任务经 Fast-Path 从池取已就绪 worker 执行
    explicit SandboxServiceImpl(std::shared_ptr<SandboxPoolV2> pool) : pool_(pool) {}

    // ---- gRPC 方法实现 ----
    grpc::Status Execute(grpc::ServerContext* context,
                         const photon::sandbox::SandboxRequest* request,
                         photon::sandbox::SandboxResponse* response) override;

    grpc::Status ExecuteAsync(grpc::ServerContext* context,
                              const photon::sandbox::SandboxRequest* request,
                              photon::sandbox::AsyncResponse* response) override;

    grpc::Status GetPoolStatus(grpc::ServerContext* context,
                               const photon::sandbox::EmptyRequest* request,
                               photon::sandbox::PoolStatusResponse* response) override;

private:
    // 将 gRPC 请求解析为代码执行请求（runner 映射 + 超时）
    static CodeRunRequest make_run_request(const photon::sandbox::SandboxRequest& request);
    std::shared_ptr<SandboxPoolV2> pool_;
};

} // namespace sandbox
} // namespace photon_kernel

#endif
