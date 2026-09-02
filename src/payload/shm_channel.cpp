// shm_channel.cpp - 共享内存通信通道实现
#include "photon_kernel/payload/shm_channel.hpp"

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <chrono>
#include <thread>

namespace photon_kernel::payload {

ShmChannel ShmChannel::create(const std::string& name, size_t payload_size, size_t result_size) {
    ShmChannel ch;
    ch.name_ = name;
    ch.payload_size_ = payload_size;
    ch.result_size_ = result_size;
    ch.total_size_ = sizeof(ShmHeader) + payload_size + result_size;
    ch.owner_ = true;

    // 创建共享内存对象
    ch.fd_ = shm_open(name.c_str(), O_CREAT | O_RDWR | O_EXCL, 0600);
    if (ch.fd_ < 0) {
        // 如果已存在, 先删除再创建
        shm_unlink(name.c_str());
        ch.fd_ = shm_open(name.c_str(), O_CREAT | O_RDWR | O_EXCL, 0600);
        if (ch.fd_ < 0) {
            throw std::runtime_error("shm_open failed: " + std::string(strerror(errno)));
        }
    }

    // 设置大小
    if (ftruncate(ch.fd_, ch.total_size_) < 0) {
        close(ch.fd_);
        shm_unlink(name.c_str());
        throw std::runtime_error("ftruncate failed: " + std::string(strerror(errno)));
    }

    // 映射
    ch.mapped_ = mmap(nullptr, ch.total_size_, PROT_READ | PROT_WRITE,
                       MAP_SHARED, ch.fd_, 0);
    if (ch.mapped_ == MAP_FAILED) {
        close(ch.fd_);
        shm_unlink(name.c_str());
        throw std::runtime_error("mmap failed: " + std::string(strerror(errno)));
    }

    // 初始化头部
    ch.header_ = static_cast<ShmHeader*>(ch.mapped_);
    std::memset(ch.header_, 0, sizeof(ShmHeader));
    ch.header_->magic = MAGIC;
    ch.header_->version = VERSION;
    ch.header_->status.store(static_cast<uint32_t>(TaskStatus::IDLE));
    ch.header_->worker_pid = static_cast<uint32_t>(getpid());

    ch.payload_area_ = static_cast<uint8_t*>(ch.mapped_) + sizeof(ShmHeader);
    ch.result_area_ = ch.payload_area_ + payload_size;

    return ch;
}

ShmChannel ShmChannel::open(const std::string& name) {
    ShmChannel ch;
    ch.name_ = name;
    ch.owner_ = false;

    ch.fd_ = shm_open(name.c_str(), O_RDWR, 0600);
    if (ch.fd_ < 0) {
        throw std::runtime_error("shm_open failed: " + std::string(strerror(errno)));
    }

    // 获取大小
    struct stat st;
    if (fstat(ch.fd_, &st) < 0) {
        close(ch.fd_);
        throw std::runtime_error("fstat failed: " + std::string(strerror(errno)));
    }
    ch.total_size_ = static_cast<size_t>(st.st_size);

    // 映射
    ch.mapped_ = mmap(nullptr, ch.total_size_, PROT_READ | PROT_WRITE,
                       MAP_SHARED, ch.fd_, 0);
    if (ch.mapped_ == MAP_FAILED) {
        close(ch.fd_);
        throw std::runtime_error("mmap failed: " + std::string(strerror(errno)));
    }

    ch.header_ = static_cast<ShmHeader*>(ch.mapped_);

    // 验证魔数
    if (ch.header_->magic != MAGIC) {
        munmap(ch.mapped_, ch.total_size_);
        close(ch.fd_);
        throw std::runtime_error("Invalid magic number in shared memory");
    }

    // 计算区域大小(从头部推断)
    ch.payload_size_ = DEFAULT_PAYLOAD_SIZE;
    ch.result_size_ = DEFAULT_RESULT_SIZE;
    if (ch.total_size_ > sizeof(ShmHeader)) {
        size_t remaining = ch.total_size_ - sizeof(ShmHeader);
        ch.payload_size_ = remaining * 3 / 4;  // 载荷区占3/4
        ch.result_size_ = remaining - ch.payload_size_;
    }

    ch.payload_area_ = static_cast<uint8_t*>(ch.mapped_) + sizeof(ShmHeader);
    ch.result_area_ = ch.payload_area_ + ch.payload_size_;

    return ch;
}

ShmChannel::~ShmChannel() {
    if (mapped_ && mapped_ != MAP_FAILED) {
        munmap(mapped_, total_size_);
    }
    if (fd_ >= 0) {
        close(fd_);
    }
    if (owner_) {
        shm_unlink(name_.c_str());
    }
}

ShmChannel::ShmChannel(ShmChannel&& other) noexcept
    : name_(std::move(other.name_)), fd_(other.fd_), mapped_(other.mapped_),
      header_(other.header_), payload_area_(other.payload_area_),
      result_area_(other.result_area_), total_size_(other.total_size_),
      payload_size_(other.payload_size_), result_size_(other.result_size_),
      owner_(other.owner_) {
    other.fd_ = -1;
    other.mapped_ = nullptr;
    other.header_ = nullptr;
    other.payload_area_ = nullptr;
    other.result_area_ = nullptr;
    other.owner_ = false;
}

ShmChannel& ShmChannel::operator=(ShmChannel&& other) noexcept {
    if (this != &other) {
        this->~ShmChannel();
        new (this) ShmChannel(std::move(other));
    }
    return *this;
}

void ShmChannel::write_payload(const void* data, size_t size, PayloadType type,
                                uint64_t task_id, uint32_t timeout_ms) {
    if (size > payload_size_) {
        throw std::runtime_error("Payload too large: " + std::to_string(size) +
                                 " > " + std::to_string(payload_size_));
    }
    if (get_status() != TaskStatus::IDLE && get_status() != TaskStatus::DONE &&
        get_status() != TaskStatus::ERROR && get_status() != TaskStatus::TIMEOUT) {
        throw std::runtime_error("Channel not ready for new task");
    }

    std::memcpy(payload_area_, data, size);
    header_->payload_type = static_cast<uint32_t>(type);
    header_->payload_size = static_cast<uint32_t>(size);
    header_->task_id = task_id;
    header_->timeout_ms = timeout_ms;
    header_->result_size = 0;
    header_->exit_code = 0;
    set_status(TaskStatus::READY);
}

const uint8_t* ShmChannel::read_payload(size_t& out_size, PayloadType& out_type,
                                          uint64_t& out_task_id, uint32_t& out_timeout) const {
    if (get_status() != TaskStatus::READY) {
        throw std::runtime_error("No ready task in channel");
    }
    out_size = header_->payload_size;
    out_type = static_cast<PayloadType>(header_->payload_type);
    out_task_id = header_->task_id;
    out_timeout = header_->timeout_ms;
    return payload_area_;
}

void ShmChannel::write_result(const void* data, size_t size, int exit_code) {
    if (size > result_size_) {
        // 截断
        size = result_size_;
    }
    std::memcpy(result_area_, data, size);
    header_->result_size = static_cast<uint32_t>(size);
    header_->exit_code = exit_code;
    set_status(TaskStatus::DONE);
}

const uint8_t* ShmChannel::read_result(size_t& out_size, int& out_exit_code) const {
    out_size = header_->result_size;
    out_exit_code = header_->exit_code;
    return result_area_;
}

TaskStatus ShmChannel::get_status() const {
    return static_cast<TaskStatus>(header_->status.load(std::memory_order_acquire));
}

void ShmChannel::set_status(TaskStatus status) {
    header_->status.store(static_cast<uint32_t>(status), std::memory_order_release);
}

bool ShmChannel::wait_for_status(TaskStatus expected, uint32_t timeout_ms) const {
    auto start = std::chrono::steady_clock::now();
    while (get_status() != expected) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed >= static_cast<int64_t>(timeout_ms)) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    return true;
}

void ShmChannel::unlink(const std::string& name) {
    shm_unlink(name.c_str());
}

} // namespace photon_kernel::payload
