# PhotonBox 第三方安全审计证据收集模板

**版本**: v1.0
**日期**: 2026-09-03
**用途**: 第三方安全审计机构进行审计时的证据收集标准模板
**前置条件**: 审计必须在 x86_64 真实裸金属环境执行，`RUNNING_IN_NESTED_VM=FALSE`

---

## 一、证据收集总览

### 1.1 证据分类

| 证据类别 | 说明 | 收集方式 | 保留期限 |
|---------|------|---------|---------|
| 环境证据 | 审计环境的硬件、软件、权限配置 | 命令输出截图/日志 | 永久 |
| 代码证据 | 源代码、构建产物、依赖清单 | 代码仓库快照/SBOM | 永久 |
| 测试证据 | 测试用例执行结果、日志、截图 | 测试报告/日志文件 | 永久 |
| 漏洞证据 | 发现的漏洞详情、PoC、复现步骤 | 漏洞报告/PoC代码 | 永久 |
| 配置证据 | 安全配置、权限设置、网络策略 | 配置文件导出 | 永久 |
| 审计师证据 | 审计师资质、签名、时间戳 | 资质证书/签名报告 | 永久 |

### 1.2 证据完整性要求

1. **不可篡改**：所有证据必须记录 SHA256 哈希值
2. **时间戳**：所有证据必须记录收集时间（UTC）
3. **审计师签名**：关键证据必须由审计师电子签名
4. **链完整性**：证据之间必须有明确的关联关系（测试用例→测试结果→漏洞报告）
5. **原始性**：优先收集原始命令输出，不经过人工编辑

---

## 二、环境证据收集模板

### 2.1 硬件环境证据

```
【硬件环境证据】
证据ID: ENV-HW-001
收集时间: YYYY-MM-DD HH:MM:SS UTC
审计师: [姓名/资质编号]

1. CPU 信息
   命令: cat /proc/cpuinfo | head -30
   输出:
   [粘贴命令输出]
   SHA256: [哈希值]

2. 内存信息
   命令: free -h
   输出:
   [粘贴命令输出]
   SHA256: [哈希值]

3. 磁盘信息
   命令: df -h && lsblk
   输出:
   [粘贴命令输出]
   SHA256: [哈希值]

4. KVM 支持
   命令: grep -E 'vmx|svm' /proc/cpuinfo | head -5 && ls -la /dev/kvm
   输出:
   [粘贴命令输出]
   SHA256: [哈希值]

5. 嵌套虚拟化检测（必须为 FALSE）
   命令: cpuid -1 | grep hypervisor
   输出:
   [应为空，表示非嵌套环境]
   RUNNING_IN_NESTED_VM: FALSE
   SHA256: [哈希值]

审计师确认: [签名]
```

### 2.2 软件环境证据

```
【软件环境证据】
证据ID: ENV-SW-001
收集时间: YYYY-MM-DD HH:MM:SS UTC
审计师: [姓名/资质编号]

1. 操作系统
   命令: lsb_release -a && uname -a
   输出:
   [粘贴命令输出]
   SHA256: [哈希值]

2. 内核版本（必须 >= 5.15，推荐 6.x）
   命令: uname -r
   输出:
   [粘贴命令输出]
   SHA256: [哈希值]

3. cgroup v2 确认
   命令: mount | grep cgroup2
   输出:
   [粘贴命令输出]
   SHA256: [哈希值]

4. 编译器版本
   命令: gcc --version && cmake --version
   输出:
   [粘贴命令输出]
   SHA256: [哈希值]

5. OpenSSL 版本（必须 >= 3.0.7）
   命令: openssl version
   输出:
   [粘贴命令输出]
   CVE-2022-3602 状态: [已修复/未修复]
   SHA256: [哈希值]

6. gRPC C++ 版本（必须 >= 1.56）
   命令: pkg-config --modversion grpc++
   输出:
   [粘贴命令输出]
   CVE-2023-44487 状态: [已修复/未修复]
   SHA256: [哈希值]

7. gRPC Python 版本（必须 >= 1.62）
   命令: pip3 show grpcio | grep Version
   输出:
   [粘贴命令输出]
   SHA256: [哈希值]

8. Firecracker 版本（如使用 StrongPool，必须 >= 1.5）
   命令: firecracker --version
   输出:
   [粘贴命令输出]
   SHA256: [哈希值]

9. CRIU 版本（如使用快照功能）
   命令: criu --version
   输出:
   [粘贴命令输出]
   SHA256: [哈希值]

10. eBPF 工具
    命令: bpftool version && dpkg -l libbpf-dev | grep libbpf
    输出:
    [粘贴命令输出]
    SHA256: [哈希值]

审计师确认: [签名]
```

### 2.3 权限环境证据

```
【权限环境证据】
证据ID: ENV-PERM-001
收集时间: YYYY-MM-DD HH:MM:SS UTC
审计师: [姓名/资质编号]

1. 当前用户
   命令: id && whoami
   输出:
   [粘贴命令输出]
   SHA256: [哈希值]

2. Capabilities 列表
   命令: capsh --print
   输出:
   [粘贴命令输出]
   必须包含: CAP_SYS_ADMIN, CAP_BPF, CAP_NET_ADMIN, CAP_KVM, CAP_SYS_PTRACE
   SHA256: [哈希值]

3. KVM 设备权限
   命令: ls -la /dev/kvm && groups | grep kvm
   输出:
   [粘贴命令输出]
   SHA256: [哈希值]

4. cgroup 写权限
   命令: ls -la /sys/fs/cgroup/ && touch /sys/fs/cgroup/photon_test 2>&1
   输出:
   [粘贴命令输出]
   SHA256: [哈希值]

5. namespace 创建权限
   命令: unshare --user --mount --pid --net echo "namespace OK"
   输出:
   [粘贴命令输出]
   SHA256: [哈希值]

审计师确认: [签名]
```

---

## 三、代码证据收集模板

### 3.1 源代码快照

```
【源代码快照证据】
证据ID: CODE-SRC-001
收集时间: YYYY-MM-DD HH:MM:SS UTC
审计师: [姓名/资质编号]

1. 仓库信息
   仓库URL: https://github.com/SandboxDev2026/photon_kernel_sil3
   分支: main
   Commit: [commit hash]
   Commit 时间: [commit time]
   Tag/版本: [如 v4.14.0]

2. 代码快照
   命令: git archive --format=tar.gz --output=photon_audit_YYYYMMDD.tar.gz HEAD
   文件: photon_audit_YYYYMMDD.tar.gz
   SHA256: [文件哈希值]
   大小: [文件大小]

3. 代码统计
   命令: cloc . --exclude-dir=build,build2,.git
   输出:
   [粘贴 cloc 输出]
   SHA256: [哈希值]

4. 依赖清单 (SBOM)
   命令: python3 scripts/cve_monitor.py --sbom
   输出:
   [粘贴 SBOM JSON]
   SHA256: [哈希值]

审计师确认: [签名]
```

### 3.2 构建产物证据

```
【构建产物证据】
证据ID: CODE-BUILD-001
收集时间: YYYY-MM-DD HH:MM:SS UTC
审计师: [姓名/资质编号]

1. 构建配置
   命令: cmake -B build_audit -DCMAKE_BUILD_TYPE=Release -DPHOTON_ENABLE_GRPC=ON -DPHOTON_ENABLE_EBPF=ON -DPHOTON_ENABLE_STRONGPOOL_FIRECRACKER=ON -DPHOTON_ENABLE_CRIU=ON -DPHOTON_ENABLE_LANDLOCK=ON
   输出:
   [粘贴 cmake 输出]
   关键检查:
   - OpenSSL 版本检查: [>= 3.0.7 / WARNING]
   - gRPC 版本检查: [>= 1.56 / WARNING]
   SHA256: [哈希值]

2. 编译过程
   命令: cmake --build build_audit -j$(nproc) 2>&1 | tee build_log.txt
   输出:
   [粘贴编译输出]
   编译状态: [成功/失败]
   警告数量: [数量]
   错误数量: [数量]
   SHA256: [哈希值]

3. 构建产物清单
   命令: ls -la build_audit/*.so build_audit/sandbox_* build_audit/test_* 2>/dev/null
   输出:
   [粘贴产物列表]
   SHA256: [每个产物的哈希值]

审计师确认: [签名]
```

---

## 四、测试证据收集模板

### 4.1 单元测试证据

```
【单元测试证据】
证据ID: TEST-UNIT-001
收集时间: YYYY-MM-DD HH:MM:SS UTC
审计师: [姓名/资质编号]

1. C++ 单元测试
   命令: ctest --test-dir build_audit --output-on-failure 2>&1 | tee ctest_log.txt
   输出:
   [粘贴 ctest 输出]
   测试总数: [数量]
   通过: [数量]
   失败: [数量]
   跳过: [数量]
   执行时间: [时间]
   SHA256: [哈希值]

2. Python 单元测试
   命令: python3 -m unittest discover -s evolution/tests -v 2>&1 | tee pytest_log.txt
   输出:
   [粘贴 pytest 输出]
   测试总数: [数量]
   通过: [数量]
   失败: [数量]
   错误: [数量]
   执行时间: [时间]
   SHA256: [哈希值]

3. 测试覆盖率（如启用）
   命令: lcov --directory build_audit --capture --output-file coverage.info && genhtml coverage.info --output-directory coverage_report
   输出:
   [粘贴覆盖率摘要]
   行覆盖率: [百分比]
   函数覆盖率: [百分比]
   分支覆盖率: [百分比]
   SHA256: [哈希值]

审计师确认: [签名]
```

### 4.2 集成测试证据

```
【集成测试证据】
证据ID: TEST-INT-001
收集时间: YYYY-MM-DD HH:MM:SS UTC
审计师: [姓名/资质编号]

1. 裸机端到端验证
   命令: sudo ./scripts/verify_baremetal.sh 2>&1 | tee verify_baremetal_log.txt
   输出:
   [粘贴脚本输出]
   模块验证结果:
   - namespace 隔离: [PASS/FAIL/SKIP]
   - cgroup v2 资源限制: [PASS/FAIL/SKIP]
   - seccomp 系统调用过滤: [PASS/FAIL/SKIP]
   - Landlock 路径白名单: [PASS/FAIL/SKIP]
   - eBPF 网络管控: [PASS/FAIL/SKIP]
   - StrongPool Firecracker MicroVM: [PASS/FAIL/SKIP]
   - CRIU 快照恢复: [PASS/FAIL/SKIP]
   - gRPC 服务端通信: [PASS/FAIL/SKIP]
   - 审计 HMAC 哈希链: [PASS/FAIL/SKIP]
   - 逃逸 POC 拦截: [PASS/FAIL/SKIP]
   嵌套环境标记: RUNNING_IN_NESTED_VM=[TRUE/FALSE]
   SHA256: [哈希值]

2. 逃逸 POC 测试
   命令: sudo ./scripts/escape_poc_tester.sh --full 2>&1 | tee escape_poc_log.txt
   输出:
   [粘贴脚本输出]
   POC 总数: [数量]
   成功拦截: [数量]
   逃逸成功: [数量]（必须为 0）
   SHA256: [哈希值]

3. 压力测试
   命令: [压测命令]
   输出:
   [粘贴压测输出]
   并发数: [数量]
   持续时间: [时间]
   成功率: [百分比]
   P99 延迟: [毫秒]
   内存泄漏: [有/无]
   fd 泄漏: [有/无]
   僵尸进程: [有/无]
   SHA256: [哈希值]

审计师确认: [签名]
```

---

## 五、漏洞证据收集模板

### 5.1 漏洞发现报告

```
【漏洞发现报告】
证据ID: VULN-XXXX
发现时间: YYYY-MM-DD HH:MM:SS UTC
审计师: [姓名/资质编号]

1. 漏洞基本信息
   漏洞编号: PHOTON-YYYY-NNN
   漏洞名称: [简短描述]
   严重等级: CRITICAL / HIGH / MEDIUM / LOW
   漏洞类型: [注入/溢出/权限绕过/信息泄露/拒绝服务/其他]
   发现方法: SAST / 渗透测试 / 配置审计 / 人工审计 / 模糊测试

2. 漏洞位置
   模块: [模块名称]
   文件: [文件路径]
   行号: [起始行-结束行]
   函数: [函数名]
   代码片段:
   ```
   [粘贴相关代码]
   ```

3. 漏洞描述
   [详细描述漏洞的成因、原理、影响]

4. 影响范围
   受影响版本: [版本范围]
   影响组件: [组件列表]
   攻击前提: [需要的前提条件]
   攻击后果: [可能造成的后果]
   CVSS 评分: [0.0-10.0]
   CVSS 向量: [CVSS:3.1/...]

5. 复现步骤
   环境要求: [复现需要的环境]
   复现命令:
   ```
   [粘贴复现命令]
   ```
   预期结果: [描述预期的异常行为]
   实际结果: [描述实际观察到的结果]

6. PoC 代码
   ```python
   [粘贴 PoC 代码]
   ```
   PoC 文件: [PoC 文件路径]
   PoC SHA256: [文件哈希值]

7. 修复建议
   修复方案: [详细的修复方案]
   修复代码:
   ```
   [粘贴修复后的代码]
   ```
   修复优先级: [立即/7天内/30天内/90天内]
   相关 CWE: [CWE 编号]

8. 审计师确认
   审计师签名: [电子签名]
   确认时间: YYYY-MM-DD HH:MM:SS UTC
   漏洞状态: 待修复 / 修复中 / 已修复 / 已复测 / 接受风险
```

### 5.2 漏洞复测报告

```
【漏洞复测报告】
证据ID: VULN-XXXX-RETEST
复测时间: YYYY-MM-DD HH:MM:SS UTC
审计师: [姓名/资质编号]

1. 原漏洞信息
   原漏洞编号: PHOTON-YYYY-NNN
   原漏洞名称: [名称]
   原严重等级: [等级]
   修复 commit: [commit hash]
   修复时间: [时间]

2. 复测结果
   复测方法: [重新执行 PoC / 重新扫描 / 代码审查]
   复测命令:
   ```
   [粘贴复测命令]
   ```
   复测输出:
   [粘贴复测输出]

3. 复测结论
   漏洞状态: ✅ 已修复 / ⚠️ 部分修复 / ❌ 未修复 / ⚠️ 引入新问题
   修复有效性: [有效/部分有效/无效]
   回归测试: [通过/失败]
   新引入问题: [描述，如无则写"无"]

4. 审计师确认
   审计师签名: [电子签名]
   确认时间: YYYY-MM-DD HH:MM:SS UTC
```

---

## 六、配置证据收集模板

### 6.1 安全配置审计

```
【安全配置证据】
证据ID: CONFIG-SEC-001
收集时间: YYYY-MM-DD HH:MM:SS UTC
审计师: [姓名/资质编号]

1. seccomp 白名单审计
   命令: [导出 seccomp 规则的命令]
   输出:
   [粘贴 seccomp 规则列表]
   审计结果:
   - 总 syscall 数: [数量]
   - 必要 syscall: [数量]
   - 不必要 syscall: [数量]（建议删除）
   - 高危 syscall (ptrace/kexec/...): [有/无]
   SHA256: [哈希值]

2. capabilities 配置
   命令: [导出 capabilities 配置的命令]
   输出:
   [粘贴配置]
   审计结果:
   - 保留的 capabilities: [列表]
   - 可删除的 capabilities: [列表]
   - 高危 capabilities (CAP_SYS_ADMIN/...): [有/无，说明必要性]
   SHA256: [哈希值]

3. cgroup 资源限制
   命令: cat /sys/fs/cgroup/photon_pool/*/memory.max /sys/fs/cgroup/photon_pool/*/cpu.max
   输出:
   [粘贴配置]
   审计结果:
   - CPU 限制: [值，是否合理]
   - 内存限制: [值，是否合理]
   - PID 限制: [值，是否合理]
   - IO 限制: [值，是否合理]
   SHA256: [哈希值]

4. 网络策略配置
   命令: [导出网络策略的命令]
   输出:
   [粘贴配置]
   审计结果:
   - 内网黑名单 (RFC1918): [已配置/未配置]
   - 元数据地址 (169.254.169.254): [已拦截/未拦截]
   - DNS 劫持: [已配置/未配置]
   - 连接数限制: [已配置/未配置]
   - 带宽限制: [已配置/未配置]
   SHA256: [哈希值]

5. 审计日志配置
   命令: [导出审计配置的命令]
   输出:
   [粘贴配置]
   审计结果:
   - HMAC 哈希链: [已启用/未启用]
   - 日志持久化: [WORM/本地文件/远程上报]
   - 日志轮转: [已配置/未配置]
   - 磁盘水位告警: [已配置/未配置]
   - 密钥管理: [外部注入/硬编码，支持轮换/不支持]
   SHA256: [哈希值]

审计师确认: [签名]
```

---

## 七、审计师资质与签名

### 7.1 审计师资质证明

```
【审计师资质证明】
证据ID: AUDITOR-QUAL-001

主审计师:
  姓名: [姓名]
  资质: [OSCP / CISSP / CEH / CISP / 其他]
  证书编号: [编号]
  有效期: [起止日期]
  工作单位: [机构名称]
  工作年限: [年]
  相关项目经验: [简述]

助理审计师:
  姓名: [姓名]
  资质: [资质]
  证书编号: [编号]
  工作单位: [机构名称]

审计机构:
  名称: [机构全称]
  资质: [信息安全服务资质 / 其他]
  证书编号: [编号]
  有效期: [起止日期]
  地址: [地址]
  联系方式: [电话/邮箱]

附件:
  - 主审计师资质证书扫描件
  - 助理审计师资质证书扫描件
  - 审计机构资质证书扫描件
```

### 7.2 审计报告签名页

```
【审计报告签名页】

项目名称: PhotonBox 安全隔离沙盒
审计版本: [版本号/commit hash]
审计类型: 第三方独立安全审计
审计范围: [简述审计范围]
审计周期: YYYY-MM-DD 至 YYYY-MM-DD

审计结论:
  整体安全等级: [优秀/良好/一般/较差]
  CRITICAL 漏洞数: [数量]
  HIGH 漏洞数: [数量]
  MEDIUM 漏洞数: [数量]
  LOW 漏洞数: [数量]
  是否通过审计: [通过/有条件通过/不通过]
  生产部署建议: [可部署/修复后可部署/不建议部署]

主审计师签名: ____________________  日期: __________
助理审计师签名: ____________________  日期: __________
审计机构盖章: ____________________  日期: __________

本报告仅对审计时的代码版本和环境负责，不代表未来版本的安全性。
本报告不构成法律担保，仅代表审计机构的专业判断。
```

---

## 八、证据清单与索引

### 8.1 证据总清单

| 证据ID | 证据名称 | 类别 | 收集人 | 收集时间 | SHA256 | 存储位置 |
|--------|---------|------|--------|---------|--------|---------|
| ENV-HW-001 | 硬件环境证据 | 环境 | [姓名] | [时间] | [哈希] | [路径] |
| ENV-SW-001 | 软件环境证据 | 环境 | [姓名] | [时间] | [哈希] | [路径] |
| ENV-PERM-001 | 权限环境证据 | 环境 | [姓名] | [时间] | [哈希] | [路径] |
| CODE-SRC-001 | 源代码快照 | 代码 | [姓名] | [时间] | [哈希] | [路径] |
| CODE-BUILD-001 | 构建产物证据 | 代码 | [姓名] | [时间] | [哈希] | [路径] |
| TEST-UNIT-001 | 单元测试证据 | 测试 | [姓名] | [时间] | [哈希] | [路径] |
| TEST-INT-001 | 集成测试证据 | 测试 | [姓名] | [时间] | [哈希] | [路径] |
| VULN-XXXX | 漏洞发现报告 | 漏洞 | [姓名] | [时间] | [哈希] | [路径] |
| CONFIG-SEC-001 | 安全配置证据 | 配置 | [姓名] | [时间] | [哈希] | [路径] |
| AUDITOR-QUAL-001 | 审计师资质证明 | 审计师 | [姓名] | [时间] | [哈希] | [路径] |

### 8.2 证据存储要求

1. **存储格式**：原始文件 + PDF 导出 + SHA256 校验文件
2. **存储位置**：加密存储，仅授权人员可访问
3. **备份策略**：异地备份，至少保留 3 份
4. **保留期限**：永久保留（安全审计证据）
5. **访问控制**：记录所有访问日志，防止证据被篡改

---

**模板版本**: v1.0
**最后更新**: 2026-09-03
**适用项目**: PhotonBox (原 photon_kernel_sil3)
**配套文档**: 
- docs/security/THIRD_PARTY_AUDIT_EXECUTION_PLAN.md (审计执行计划)
- docs/security/third_party_audit_checklist.md (审计检查清单)
- docs/security/audit_test_cases.md (审计测试用例集)
