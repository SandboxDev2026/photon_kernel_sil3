# PhotonBox 安全边界声明

**版本**: v27
**更新日期**: 2026-09-03
**状态**: ⚠️ 生产未就绪 — 完整第三方安全审计前禁止对公网暴露不可信代码

---

## 一、核心安全边界（必须遵守）

### 1.1 绝对禁止事项

| 禁止事项 | 原因 | 替代方案 |
|---------|------|---------|
| 对公网暴露不可信用户代码 | LightPool共享宿主内核，内核0day可逃逸 | 仅内网可信Agent场景使用 |
| 在普通Docker容器运行完整沙盒 | 无CAP_SYS_ADMIN/CAP_BPF/KVM，隔离能力失效 | 裸机/开启虚拟化的虚拟机 |
| 关闭审计模块 | 攻击无法追溯，证据链断裂 | HMAC审计链必须开启 |
| 高风险任务降级到LightPool | 安全策略失效，内核逃逸风险 | KVM缺失时直接拒绝任务 |
| 生产环境使用dry-run配置下发 | 防御规则不会实际生效 | 生产环境设dry_run=False |

### 1.2 隔离能力边界

| 隔离层级 | 技术 | 隔离强度 | 适用场景 |
|---------|------|---------|---------|
| LightPool | fork + namespace + seccomp + Landlock + cgroup v2 | ⭐⭐ 中 | 内网可信/半可信Agent |
| StrongPool | Firecracker MicroVM + KVM硬件虚拟化 | ⭐⭐⭐⭐ 高 | 公网不可信代码（需裸机KVM） |
| 审计层 | HMAC-SHA256哈希链 + 批量gRPC上报 | ⭐⭐⭐ 中高 | 所有场景必须开启 |

**关键限制**: LightPool共享宿主内核，即使全套隔离拉满，遇到内核UAF、eBPF漏洞依旧可以逃逸。

---

## 二、未验证模块清单（生产部署前必须完成）

### 2.1 6个关键模块未端到端验证

| 模块 | 缺失条件 | 风险等级 | 验证方式 |
|------|---------|---------|---------|
| StrongPool Firecracker | 无 /dev/kvm + firecracker二进制 | 🔴 P0 | 裸机KVM环境跑通创建→执行→销毁 |
| eBPF网络管控 | 无 CAP_BPF + libbpf-dev | 🔴 P0 | 加载eBPF程序，验证内网IP拦截 |
| CRIU进程快照 | 无 criu二进制 + root | 🟡 P2 | criu dump/restore验证进程状态 |
| gRPC C++服务端 | 无 libgrpc++-dev | 🟠 P1 | 编译启动sandbox_server，客户端通信 |
| K8s Operator | 无 K8s集群 | 🟠 P1 | kind create cluster，验证Reconcile |
| namespace隔离 | 无 CAP_SYS_ADMIN | 🔴 P0 | 验证mount/pid/net/user namespace完整隔离 |

### 2.2 生产部署前三件事（官方要求）

1. **裸机KVM环境跑通 `scripts/verify_baremetal.sh`** — 验证StrongPool+eBPF+namespace完整链路
2. **完成独立第三方安全审计** — 当前仅内部自评估，无第三方认证
3. **升级OpenSSL/gRPC依赖** — 修复2个HIGH CVE（系统侧OpenSSL 3.0.2待升级）

---

## 三、已知安全风险

### 3.1 设计固有风险

1. **LightPool内核逃逸风险**: 共享宿主内核，内核漏洞可逃逸
2. **StrongPool并非绝对安全**: 攻击面包含Firecracker二进制、KVM模块、virtio驱动
3. **MicroVM高并发内存成本**: 每VM 5-15MB基础开销，单机并发受限
4. **RiskScorer可被混淆绕过**: 静态扫描只能识别明显危险模式

### 3.2 代码待验证风险

1. **seccomp白名单未逐行审计**: 多余syscall可能存在逃逸利用点
2. **TaskSpec解析未fuzz测试**: 恶意构造可能绕过资源限制
3. **Release-Gate与沙盒同权限**: 管理器被攻破可篡改审计证据
4. **CapabilityToken密钥硬编码**: 生产环境必须外部注入+密钥轮换
5. **解释器白名单应用层判断**: 非内核强制，存在绕过面

### 3.3 运维部署风险

1. **特权依赖**: 完整沙盒需要root/CAP_SYS_ADMIN/CAP_BPF/CAP_KVM
2. **容器环境能力失效**: 普通Docker容器大部分隔离能力直接失效
3. **KVM硬件兼容性**: 部分云实例CPU不支持虚拟化
4. **单人维护**: 无大规模线上实战，无第三方安全审计

---

## 四、红蓝对抗框架安全边界

### 4.1 v25-v27 实现状态

| 组件 | 状态 | 说明 |
|------|------|------|
| RedBlueAdversaryTrainer | ✅ 框架完整 | 红方/蓝方/自博弈/制度性红队测试 |
| RealDataAdapter | ✅ 三种真实信号 | seccomp违规/VM-Exit事件/审计链异常 |
| LogConsumer | ✅ 文件tail+gRPC流 | 持续消费日志，断线重连，位置持久化 |
| DefenseRuleEnforcer | ⚠️ dry-run默认 | 配置更新指令生成，默认不实际修改 |
| PocEventLibrary | ✅ 11个POC样本 | 含CVE-2022-0185、CVE-2021-4034等 |

### 4.2 关键限制

1. **攻击检测为基于规则的模拟实现**: 尚未对接真实的沙箱逃逸检测引擎
2. **防御规则下发默认dry-run**: 生产环境需手动设dry_run=False并验证
3. **真实数据源来自生成的测试数据**: 符合C++ AuditLogger格式，但未对接生产日志流
4. **gRPC流消费为框架实现**: 需根据实际proto定义补充消费逻辑
5. **POC样本仅记录事件特征**: 不包含可执行的利用代码，仅用于检测规则生成

### 4.3 闭环测试验证结果

```
完整链路:
  真实日志(seccomp/VM-Exit/审计链)
    → 日志消费层(FileTail/GrpcStream) ✅
    → RealDataAdapter(解析+异常检测) ✅
    → POC事件样本库(真实漏洞样本) ✅
    → RedBlueAdversaryTrainer(红蓝对抗+自进化) ✅
    → DefenseRuleEnforcer(防御规则下发, dry-run) ✅
    → LightPool/seccomp + StrongPool配置 ⚠️ 待实际生效
```

---

## 五、独立第三方安全审计状态

### 5.1 当前状态

- ❌ **未完成独立第三方安全审计**
- ✅ 已准备7份审计前置材料（约2200+行）
- ✅ 内部SAST/渗透/漏洞评估持续进行
- ⚠️ 所有安全结论为自评估，不代表第三方认证

### 5.2 审计前置材料清单

| 材料 | 行数 | 说明 |
|------|------|------|
| third_party_audit_checklist.md | 218 | 37项审计测试清单 |
| audit_test_cases.md | 655 | 15个详细测试用例含POC |
| THIRD_PARTY_AUDIT_EXECUTION_PLAN.md | 268 | 审计执行计划模板 |
| AUDIT_EVIDENCE_COLLECTION_TEMPLATE.md | 643 | 6类证据收集标准模板 |
| third_party_audit_statement.md | ~250 | 第三方审计声明 |
| escape_security_audit.md | ~13KB | 逃逸风险审计清单 |
| seccomp_audit_report.md | ~5KB | seccomp白名单审计 |

### 5.3 审计完成前的强制限制

1. 禁止对公网暴露不可信用户代码
2. 禁止在生产环境使用完整沙盒功能
3. 禁止关闭审计模块
4. 禁止高风险任务降级到LightPool
5. 配置下发必须保持dry-run模式

---

## 六、生产就绪检查清单（P0项）

| 检查项 | 状态 | 说明 |
|--------|------|------|
| StrongPool+eBPF裸机完整验证 | ❌ 待验证 | 需/dev/kvm+CAP_BPF |
| seccomp白名单逐行审计 | ❌ 待完成 | 需安全专家复核 |
| TaskSpec fuzz测试 | ❌ 待运行 | 需clang+libFuzzer |
| 内网拦截对抗测试 | ❌ 待验证 | 需模拟逃逸场景 |
| Release-Gate独立进程隔离 | ❌ 待改造 | 当前与沙盒同权限 |
| CapabilityToken密钥外部注入 | ❌ 待改造 | 当前硬编码 |
| 独立第三方安全审计 | ❌ 未完成 | 前置材料已就绪 |
| OpenSSL/gRPC系统依赖升级 | ❌ 待升级 | 需sudo权限 |

**P0项全部完成前，项目绝对不能对公接收不可信用户代码。**

---

## 七、联系与报告

- **安全问题报告**: 参见 `SECURITY.md`
- **漏洞披露**: 负责任披露，48小时内响应
- **审计咨询**: 第三方机构可使用上述7份前置材料
- **代码仓库**: https://github.com/SandboxDev2026/photon_kernel_sil3

---

**最后更新**: 2026-09-03 (v27)
**下次审核**: 完成P0项后重新评估
