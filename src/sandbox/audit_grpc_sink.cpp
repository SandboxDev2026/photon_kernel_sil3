#include "photon_kernel/sandbox/audit_grpc_sink.hpp"

#include <fstream>
#include <iostream>

// 启用 gRPC 时引入真实上报实现
#if __has_include(<grpcpp/grpcpp.h>)
#define PHOTON_AUDIT_GRPC_AVAILABLE 1
#endif

#ifdef PHOTON_AUDIT_GRPC_AVAILABLE
// ===== 在启用 gRPC 的环境中，此处填充真实 stub 调用 =====
// 参考（需与扩展后的 proto 匹配）：
//   #include <grpcpp/grpcpp.h>
//   #include "sandbox.grpc.pb.h"   // 扩展后的审计 RPC 生成代码
//   static std::unique_ptr<AuditService::Stub> g_stub;
#endif

namespace photon_kernel {
namespace sandbox {

GrpcAuditSink::~GrpcAuditSink() {
    stop();
}

GrpcAuditSink& GrpcAuditSink::instance() {
    static GrpcAuditSink sink;
    return sink;
}

void GrpcAuditSink::init(const std::string& endpoint,
                         size_t batch_max,
                         std::chrono::milliseconds flush_interval,
                         std::chrono::milliseconds rpc_timeout,
                         const std::string& spool_path) {
    std::lock_guard<std::mutex> lock(mtx_);
    endpoint_ = endpoint;
    batch_max_ = batch_max;
    flush_interval_ = flush_interval;
    rpc_timeout_ = rpc_timeout;
    spool_path_ = spool_path;
#ifdef PHOTON_AUDIT_GRPC_AVAILABLE
    // auto channel = grpc::CreateChannel(endpoint, grpc::InsecureChannelCredentials());
    // g_stub = AuditService::NewStub(channel);
    enabled_ = true;
#else
    enabled_ = false;
    std::cerr << "[AuditGrpcSink] gRPC not available at build time; async upload "
                 "will spool to local file and retry (file audit still active)\n";
#endif
}

void GrpcAuditSink::start() {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) return;
    worker_ = std::thread(&GrpcAuditSink::worker_loop, this);
}

void GrpcAuditSink::stop() {
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false)) return;
    cv_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
}

void GrpcAuditSink::report(const std::string& json_line) {
    std::lock_guard<std::mutex> lock(mtx_);
    queue_.push(json_line);
    cv_.notify_one();
}

// ---- 批量发送 ----
// gRPC 环境：以 rpc_timeout 超时逐条/批量调用 stub；当前骨架（无 gRPC）返回 false，
// 使调用方走“失败落盘 + 定期重试”路径。
bool GrpcAuditSink::send_batch(const std::vector<std::string>& records) {
    if (records.empty()) return true;
#ifdef PHOTON_AUDIT_GRPC_AVAILABLE
    // bool all_ok = true;
    // for (const auto& rec : records) {
    //     AuditRecord req; req.set_json(rec);
    //     AuditAck ack; grpc::ClientContext ctx;
    //     ctx.set_deadline(std::chrono::system_clock::now() + rpc_timeout_);  // 100ms 超时
    //     if (!g_stub->ReportAudit(&ctx, req, &ack).ok()) all_ok = false;
    // }
    // return all_ok;
    (void)records;
    return false;  // 骨架：待填充 stub 后改为真实返回值
#else
    (void)records;
    (void)rpc_timeout_;
    return false;  // 无 gRPC：模拟发送失败，驱动本地 spool + 重试
#endif
}

// ---- spool 持久化 ----
void GrpcAuditSink::persist_to_spool(const std::vector<std::string>& records) {
    if (records.empty() || spool_path_.empty()) return;
    std::ofstream f(spool_path_, std::ios::app);
    if (!f.is_open()) return;
    for (const auto& r : records) {
        f << r << "\n";
    }
    f.flush();
}

size_t GrpcAuditSink::load_spool(std::vector<std::string>& out) {
    out.clear();
    std::ifstream f(spool_path_);
    if (!f.is_open()) return 0;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty()) out.push_back(line);
    }
    return out.size();
}

void GrpcAuditSink::rewrite_spool(const std::vector<std::string>& records) {
    // 原子重写：先写临时文件再 rename
    const std::string tmp = spool_path_ + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f.is_open()) return;
        for (const auto& r : records) {
            f << r << "\n";
        }
        f.flush();
    }
    std::rename(tmp.c_str(), spool_path_.c_str());
}

// ---- 后台线程 ----
void GrpcAuditSink::worker_loop() {
    while (running_.load()) {
        // 1) 先重试历史失败（spool 文件）
        retry_spool();

        // 2) 取一批新记录
        std::vector<std::string> batch;
        {
            std::unique_lock<std::mutex> lock(mtx_);
            cv_.wait_for(lock, flush_interval_, [&] {
                return !running_.load() || !queue_.empty();
            });
            while (!queue_.empty() && batch.size() < batch_max_) {
                batch.push_back(std::move(queue_.front()));
                queue_.pop();
            }
        }

        // 3) 批量发送；失败落盘待重试
        if (!batch.empty()) {
            if (send_batch(batch)) {
                sent_.fetch_add(batch.size());
            } else {
                failed_.fetch_add(batch.size());
                persist_to_spool(batch);
            }
        }
    }

    // stop 后 drain 剩余队列
    std::vector<std::string> remain;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        while (!queue_.empty()) {
            remain.push_back(std::move(queue_.front()));
            queue_.pop();
        }
    }
    if (!remain.empty()) {
        if (send_batch(remain)) {
            sent_.fetch_add(remain.size());
        } else {
            failed_.fetch_add(remain.size());
            persist_to_spool(remain);
        }
    }
}

void GrpcAuditSink::retry_spool() {
    std::vector<std::string> spooled;
    if (load_spool(spooled) == 0) return;

    std::vector<std::string> remain;
    for (const auto& rec : spooled) {
        if (send_batch({rec})) {
            sent_.fetch_add(1);
        } else {
            remain.push_back(rec);
        }
    }
    // 成功的从 spool 移除；失败的保留等待下轮重试
    if (remain.size() != spooled.size()) {
        rewrite_spool(remain);
    }
}

bool GrpcAuditSink::enabled() const {
    return enabled_;
}

size_t GrpcAuditSink::queue_size() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return queue_.size();
}

size_t GrpcAuditSink::spool_size() const {
    // 直接统计 spool 文件行数（const 安全）
    std::ifstream f(spool_path_);
    if (!f.is_open()) return 0;
    size_t n = 0;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty()) ++n;
    }
    return n;
}

size_t GrpcAuditSink::sent_count() const {
    return sent_.load();
}

size_t GrpcAuditSink::failed_count() const {
    return failed_.load();
}

} // namespace sandbox
} // namespace photon_kernel
