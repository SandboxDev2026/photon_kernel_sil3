# 项目治理修复说明

**日期**: 2026-09-03
**修复类型**: 项目治理（许可证、命名、诚实标注）
**触发原因**: 社区反馈指出品牌支柱未验证、扩张速度超过验证速度、安全评估自证、命名痕迹未清理、许可证非标

---

## 修复清单

### 1. 许可证：Modified MIT → Apache-2.0 ✅

**问题**: 原 Modified MIT 许可证包含"月活过亿须署名"等非标条款，企业法务审非标许可证会比审 Apache-2.0 苛刻得多，可能反而拖慢采纳。0 star 仓库套超前条款不匹配。

**修复**: 替换为标准 Apache-2.0 许可证（201 行）。

**理由**:
- Apache-2.0 是企业最广泛接受的开源许可证之一
- 包含专利授权条款，对贡献者和使用者都有保护
- 企业法务审查流程成熟，采纳阻力小
- 与 K8s、Firecracker、gVisor 等云原生基础设施项目许可证一致

**文件**: `LICENSE`

---

### 2. 诚实标注：README 开头添加生产就绪状态警告 ✅

**问题**: README 强调 KVM 硬件虚拟化作为核心卖点，但验证矩阵里 StrongPool 写着"代码完整，待 KVM 验证"。卖点和欠账是同一处，容易误导用户。

**修复**: 在 README 标题之后、架构介绍之前，添加醒目的生产就绪状态警告：

```
⚠️ 生产就绪状态：🟡 内网受限可用，公网部署待验证

本项目核心卖点是 KVM 硬件虚拟化（StrongPool），但 StrongPool 尚未在真实 /dev/kvm 裸机环境完成端到端验证。

未验证模块清单：
- StrongPool (KVM MicroVM): 无 /dev/kvm + firecracker
- eBPF 网络管控: 无 CAP_BPF + libbpf
- CRIU 快照: 无 criu 二进制 + root
- gRPC (C++): 无 libgrpc++-dev
- K8s Operator: 无 K8s 集群
- namespace 隔离: 无 CAP_SYS_ADMIN

当前仅适用于内网可信/半可信 Agent 场景，禁止直接对公网暴露不可信用户代码。
```

**理由**:
- 让用户在第一时间了解项目真实状态，不被营销话术误导
- 明确列出未验证模块和缺失条件
- 给出明确的使用边界（内网可信场景）
- 列出生产部署前必须完成的 3 项前置条件

**文件**: `README.md`

---

### 3. 命名痕迹检查 ✅

**问题**: 仓库名还叫 photon_kernel_sil3，GitHub About 简介可能还挂着 "SIL-3 compliance engine"。

**检查结果**:
- ✅ CMakeLists.txt 项目名已是 `PhotonBox`
- ✅ README 标题已是 `PhotonBox`
- ✅ 源码 C++ namespace 保持 `photon_kernel::sandbox`（技术命名，不影响品牌）
- ⚠️ GitHub 仓库名仍是 `photon_kernel_sil3`（需用户在 GitHub 网页操作改名）
- ⚠️ GitHub About 简介（需用户在 GitHub 网页修改）

**用户需手动操作**:
1. GitHub 仓库改名：Settings → General → Repository name → `PhotonBox`
2. GitHub About 简介修改：点击 About 齿轮 → Description → "基于 KVM 硬件虚拟化的安全隔离沙盒"
3. 改名后更新本地 remote：`git remote set-url origin https://github.com/SandboxDev2026/PhotonBox.git`

---

### 4. 安全评估自证问题说明 ✅

**问题**: 安全评估 v5 到 v17 一天刷了十多轮，"低风险"结论在独立第三方做对抗性审计之前，只能算自证。

**说明**:
- 所有安全评估报告（v5-v17）均为**内部自评估**，不代表第三方认证
- 评估方法：SAST 静态扫描 + 内部逃逸 POC 测试 + fuzz 测试 + CVE 扫描
- 局限性：
  - 无独立第三方对抗性审计
  - 无裸机特权环境端到端验证（KVM/eBPF/CRIU/K8s）
  - 无红队渗透测试
  - 无大规模生产环境验证
- 正确解读："低风险" = "内部自评估未发现高危问题"，≠ "生产安全"

**已采取措施**:
- README 开头明确标注生产就绪状态
- `docs/third_party_audit_checklist.md` 已准备第三方审计待办清单（37 项测试）
- `docs/audit_test_cases.md` 已准备第三方审计测试用例集（15 个详细用例含 POC）
- 第十七条（第三方安全审计）前置材料已就绪，待选择审计机构执行

---

### 5. 扩张速度 vs 验证速度说明 ✅

**问题**: 一天之内叠加了大量模块（ops 六大产品化模块、遗传算法、多智能体 benchmark），测试从 102 涨到 393，但 K8s 集群实测、eBPF 特权验证这些旧账还没还，验证债绝对值还在涨。

**现状**:
- 代码模块：17+ 个主要模块
- 单元测试：393 个（C++ 180 + Python 213）
- 未验证特权模块：6 个（StrongPool/eBPF/CRIU/gRPC-C++/K8s/namespace）
- 验证债：需要裸机 + root + KVM + CAP_BPF + CRIU + K8s 集群

**后续优先级调整**:
1. **P0（最高优先级）**: 裸机 KVM 环境跑通 StrongPool 端到端验证
2. **P0**: 完成独立第三方安全审计
3. **P1**: eBPF 特权环境验证
4. **P1**: K8s Operator 集群验证
5. **P2**: 暂停新增功能模块，优先偿还验证债
6. **P2**: CRIU 快照特权环境验证

---

## 修复验证

| 验证项 | 结果 |
|--------|------|
| 许可证改为 Apache-2.0 | ✅ 201 行标准许可证 |
| README 添加生产就绪警告 | ✅ 标题后第一屏可见 |
| 未验证模块清单完整 | ✅ 6 个模块列出缺失条件 |
| 使用边界明确 | ✅ 内网可信/半可信场景 |
| 全量单元测试 | ✅ 393 通过（C++ 180 + Python 213） |
| SAST 静态扫描 | ✅ 0 HIGH |
| 渗透测试（内部 POC） | ✅ 0 逃逸 |
| 漏洞评估 | ⚠️ 2 HIGH CVE（OpenSSL/gRPC，有 fallback） |

---

## 仍需用户手动操作

1. **GitHub 仓库改名**: Settings → General → Repository name → `PhotonBox`
2. **GitHub About 简介修改**: "基于 KVM 硬件虚拟化的安全隔离沙盒"
3. **本地 remote 更新**: `git remote set-url origin https://github.com/SandboxDev2026/PhotonBox.git`
4. **选择第三方审计机构**: 使用 `docs/third_party_audit_checklist.md` 和 `docs/audit_test_cases.md` 启动审计
5. **准备裸机 KVM 环境**: 跑通 `scripts/verify_baremetal.sh` 完成 StrongPool 端到端验证

---

## 诚实声明

本项目目前是**设计原型 + 内部自评估**状态，不是生产就绪产品。核心卖点（KVM 硬件虚拟化）尚未在真实环境验证。所有"低风险"结论均为内部自评估，不代表第三方认证。

禁止在以下场景使用：
- 公网直接暴露不可信用户代码
- 生产环境多租户部署
- 处理敏感数据（支付、医疗、个人隐私）

推荐使用场景：
- 内网可信/半可信 Agent 代码执行
- 学习和研究沙盒隔离技术
- 二次开发基础（需自行完成安全审计和特权环境验证）
