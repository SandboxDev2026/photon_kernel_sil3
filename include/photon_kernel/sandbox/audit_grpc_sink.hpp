#ifndef PHOTON_KERNEL_SANDBOX_AUDIT_GRPC_SINK_HPP
#define PHOTON_KERNEL_SANDBOX_AUDIT_GRPC_SINK_HPP

#include <string>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <thread>
#include <vector>
#include <chrono>

namespace photon_kernel {
namespace sandbox {

// 集中式审计上报（异步批量 + 失败重试，参考 fluent-bit 的队列/批量设计）。
//
// 设计：
//   - report() 仅入队（非阻塞），不阻塞主流程；
//   - 后台线程周期性批量取出并发送（批量上限 batch_max、刷新间隔 flush_interval）；
//   - 每次 gRPC 调用带 rpc_timeout 超时（默认 100ms），避免长时间阻塞；
//   - 发送失败（或当前环境无 gRPC）的记录持久化到本地 spool 文件，
//     后台线程每轮先重试 spool，成功后从文件移除。
//
// 本类核心（队列/后台线程/重试）不依赖 gRPC，无 gRPC 环境也能编译并测试；
// 发送动作 send_batch() 在检测到 gRPC 头文件时填充真实 stub 调用，否则返回 false
// （驱动“失败落盘 + 重试”路径，保证审计不丢）。
class GrpcAuditSink {
public:
    static GrpcAuditSink& instance();

    // 配置上报端点与批量参数
    //  - flush_interval：后台线程刷新周期
    //  - rpc_timeout：单次 gRPC 调用超时（默认 100ms）
    void init(const std::string& endpoint,
              size_t batch_max = 16,
              std::chrono::milliseconds flush_interval = std::chrono::milliseconds(100),
              std::chrono::milliseconds rpc_timeout = std::chrono::milliseconds(100),
              const std::string& spool_path = "audit_spool.jsonl");

    // 异步上报：入队后立即返回
    void report(const std::string& json_line);

    // 启动/停止后台上报线程
    void start();
    void stop();

    [[nodiscard]] bool enabled() const;

    // 统计与状态
    [[nodiscard]] size_t queue_size() const;
    [[nodiscard]] size_t spool_size() const;
    [[nodiscard]] size_t sent_count() const;
    [[nodiscard]] size_t failed_count() const;

    // 批量发送（gRPC 环境实现；无 gRPC 返回 false 以驱动失败重试路径）
    // 供单元测试直接调用验证。
    bool send_batch(const std::vector<std::string>& records);

private:
    GrpcAuditSink() = default;
    GrpcAuditSink(const GrpcAuditSink&) = delete;
    GrpcAuditSink& operator=(const GrpcAuditSink&) = delete;
    ~GrpcAuditSink();

    void worker_loop();
    void retry_spool();

    void persist_to_spool(const std::vector<std::string>& records);
    size_t load_spool(std::vector<std::string>& out);
    void rewrite_spool(const std::vector<std::string>& records);

    std::string endpoint_;
    std::string spool_path_;
    size_t batch_max_ = 16;
    std::chrono::milliseconds flush_interval_{100};
    std::chrono::milliseconds rpc_timeout_{100};

    mutable std::mutex mtx_;
    std::condition_variable cv_;
    std::queue<std::string> queue_;
    std::atomic<bool> running_{false};
    std::thread worker_;

    std::atomic<size_t> sent_{0};
    std::atomic<size_t> failed_{0};
    bool enabled_ = false;
};

} // namespace sandbox
} // namespace photon_kernel

#endif
