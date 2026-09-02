// shm_channel.hpp - 共享内存通信通道
// 宿主机侧(Injector)与Worker进程通过共享内存传递任务载荷和执行结果
// 布局: [Header控制区][Payload代码区][Result结果区]
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <stdexcept>
#include <atomic>

namespace photon_kernel::payload {

// 载荷类型
enum class PayloadType : uint32_t {
    NATIVE = 0,      // C++ 原生函数指针(已编译的机器码)
    WASM = 1,        // WASM 模块
    PYTHON_BC = 2,   // Python 字节码(pyc)
    JS_BC = 3,       // QuickJS 字节码
    SHELL = 4,       // Shell 命令
    UNKNOWN = 0xFF
};

// 任务状态
enum class TaskStatus : uint32_t {
    IDLE = 0,        // 空闲, 等待任务
    READY = 1,       // 任务已写入, 等待Worker取走
    RUNNING = 2,     // Worker正在执行
    DONE = 3,        // 执行完成, 结果已写回
    ERROR = 4,       // 执行出错
    TIMEOUT = 5,     // 超时
    CANCELLED = 6    // 已取消
};

// 共享内存头部(固定大小, 64字节对齐)
struct __attribute__((packed, aligned(64))) ShmHeader {
    uint32_t magic;               // 魔数 0x50425845 ('PBXE')
    uint32_t version;             // 版本
    std::atomic<uint32_t> status; // TaskStatus
    uint64_t task_id;             // 任务ID
    uint32_t payload_type;        // PayloadType
    uint32_t payload_size;        // 载荷大小(字节)
    uint32_t result_size;         // 结果大小(字节)
    int32_t  exit_code;           // 退出码
    uint32_t timeout_ms;          // 超时(毫秒)
    uint64_t start_ns;            // 开始时间(纳秒)
    uint64_t end_ns;              // 结束时间(纳秒)
    uint32_t worker_pid;          // Worker PID
    uint32_t reserved[8];         // 保留
};

static_assert(sizeof(ShmHeader) == 128, "ShmHeader must be 128 bytes");

// 共享内存通道
class ShmChannel {
public:
    static constexpr uint32_t MAGIC = 0x50425845;
    static constexpr uint32_t VERSION = 1;
    static constexpr size_t   DEFAULT_PAYLOAD_SIZE = 1 * 1024 * 1024;  // 1MB 载荷区
    static constexpr size_t   DEFAULT_RESULT_SIZE  = 256 * 1024;         // 256KB 结果区

    // 创建新的共享内存(宿主机侧调用)
    static ShmChannel create(const std::string& name,
                             size_t payload_size = DEFAULT_PAYLOAD_SIZE,
                             size_t result_size = DEFAULT_RESULT_SIZE);

    // 打开已存在的共享内存(Worker侧调用)
    static ShmChannel open(const std::string& name);

    ~ShmChannel();

    // 禁止拷贝
    ShmChannel(const ShmChannel&) = delete;
    ShmChannel& operator=(const ShmChannel&) = delete;

    // 移动
    ShmChannel(ShmChannel&& other) noexcept;
    ShmChannel& operator=(ShmChannel&& other) noexcept;

    // 写入任务载荷(宿主机侧)
    void write_payload(const void* data, size_t size, PayloadType type,
                       uint64_t task_id, uint32_t timeout_ms = 10000);

    // 读取任务载荷(Worker侧)
    const uint8_t* read_payload(size_t& out_size, PayloadType& out_type,
                                 uint64_t& out_task_id, uint32_t& out_timeout) const;

    // 写入执行结果(Worker侧)
    void write_result(const void* data, size_t size, int exit_code);

    // 读取执行结果(宿主机侧)
    const uint8_t* read_result(size_t& out_size, int& out_exit_code) const;

    // 状态操作
    TaskStatus get_status() const;
    void set_status(TaskStatus status);
    bool wait_for_status(TaskStatus expected, uint32_t timeout_ms = 5000) const;

    // 获取头部指针
    ShmHeader* header() { return header_; }
    const ShmHeader* header() const { return header_; }

    // 获取载荷/结果区指针
    uint8_t* payload_area() { return payload_area_; }
    const uint8_t* payload_area() const { return payload_area_; }
    uint8_t* result_area() { return result_area_; }
    const uint8_t* result_area() const { return result_area_; }

    size_t total_size() const { return total_size_; }
    size_t payload_size() const { return payload_size_; }
    size_t result_size() const { return result_size_; }
    const std::string& name() const { return name_; }

    // 取消链接(删除共享内存对象)
    static void unlink(const std::string& name);

private:
    ShmChannel() = default;

    std::string name_;
    int fd_ = -1;
    void* mapped_ = nullptr;
    ShmHeader* header_ = nullptr;
    uint8_t* payload_area_ = nullptr;
    uint8_t* result_area_ = nullptr;
    size_t total_size_ = 0;
    size_t payload_size_ = 0;
    size_t result_size_ = 0;
    bool owner_ = false;  // 是否为创建者(负责unlink)
};

} // namespace photon_kernel::payload
