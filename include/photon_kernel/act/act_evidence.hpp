#ifndef PHOTON_KERNEL_ACT_EVIDENCE_HPP
#define PHOTON_KERNEL_ACT_EVIDENCE_HPP

// 可追溯性证据链（V4.14 第十六条可追溯性 / 第十条开发阶段提交可追溯）
// 建立 需求 → 代码 → 测试 → 部署 的双向可追溯链，每条证据绑定 Git commit SHA
// （审查补强项 4：证据链与具体代码提交绑定）。

#include <cstdint>
#include <string>
#include <vector>

namespace photon_kernel {
namespace act {

enum class EvidenceStage {
    REQUIREMENT,  // 需求
    DEVELOPMENT,  // 开发（代码）
    TESTING,      // 测试
    DEPLOYMENT    // 部署/运维
};

const char* evidence_stage_name(EvidenceStage s);

struct EvidenceRecord {
    std::string id;           // 证据编号（如 REQ-001）
    EvidenceStage stage;
    std::string artifact;     // 需求/代码/测试引用（如 PRD §3.2 / src/sandbox.cpp / tests/eh_*.cpp）
    std::string git_commit;   // Git commit SHA（证据绑定提交）
    std::string note;
};

// 需求 ↔ 代码 ↔ 测试 双向链
struct TraceLink {
    std::string from_id;   // 如需求 REQ-001
    std::string to_id;     // 如代码/tests 证据编号
};

class EvidenceLogger {
public:
    // 追加一条证据记录（自动生成递增编号）
    void add(EvidenceStage stage, const std::string& artifact,
             const std::string& note, const std::string& id = "");

    // 设置/自动获取 Git commit SHA（优先显式设置；否则读 GIT_COMMIT 环境变量）
    void set_git_commit(const std::string& sha);
    // 从环境变量 GIT_COMMIT 读取
    void read_git_commit_from_env(const std::string& env_var = "GIT_COMMIT");

    // 双向链：需求→代码→测试
    bool link(const std::string& from_id, const std::string& to_id);

    [[nodiscard]] std::vector<EvidenceRecord> records() const;
    [[nodiscard]] std::vector<EvidenceRecord> records_of(EvidenceStage s) const;
    [[nodiscard]] std::vector<TraceLink> trace_links() const;

    // 可追溯性合规自检：三阶段（需求/开发/测试）均有证据且绑定 commit
    [[nodiscard]] bool self_check_pass() const;

    // 证据链是否绑定 Git commit
    [[nodiscard]] bool has_git_commit() const;
    [[nodiscard]] std::string git_commit() const;

private:
    std::vector<EvidenceRecord> records_;
    std::vector<TraceLink> links_;
    std::string git_commit_;
    uint64_t seq_ = 0;
};

} // namespace act
} // namespace photon_kernel

#endif
