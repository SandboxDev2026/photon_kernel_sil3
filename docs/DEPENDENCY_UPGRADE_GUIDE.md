# PhotonBox 依赖升级指南

**版本**: v1.0
**日期**: 2026-09-03
**用途**: 修复已知 HIGH CVE，升级关键依赖到安全版本

---

## 一、必须升级的依赖（HIGH CVE）

### 1.1 OpenSSL（修复 CVE-2022-3602）

| 项目 | 详情 |
|------|------|
| CVE 编号 | CVE-2022-3602 |
| 严重等级 | HIGH |
| 漏洞描述 | OpenSSL 3.0 X.509 证书验证缓冲区溢出 |
| 受影响版本 | 3.0.0 - 3.0.6 |
| 修复版本 | >= 3.0.7 |
| 影响组件 | 审计模块 HMAC-SHA256（可选，有纯C++ fallback） |

**升级命令**：
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y libssl-dev
openssl version  # 确认 >= 3.0.7

# 验证
python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"
```

**CMake 版本检查**：
- 已在 `CMakeLists.txt` 中添加 OpenSSL >= 3.0.7 版本检查
- 如检测到易受攻击版本，编译时输出 WARNING

### 1.2 gRPC C++（修复 CVE-2023-44487）

| 项目 | 详情 |
|------|------|
| CVE 编号 | CVE-2023-44487 |
| 严重等级 | HIGH |
| 漏洞描述 | HTTP/2 快速重置攻击（Rapid Reset），可导致 DoS |
| 受影响版本 | gRPC < 1.56.0（实际修复 1.59.0） |
| 修复版本 | >= 1.56.0（推荐 >= 1.59.0） |
| 影响组件 | gRPC 沙盒服务端/客户端、审计上报 |

**升级命令**：
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y libgrpc++-dev protobuf-compiler-grpc
pkg-config --modversion grpc++  # 确认 >= 1.56

# 从源码编译（推荐最新版）
git clone https://github.com/grpc/grpc
cd grpc
git submodule update --init
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
sudo cmake --install build
```

**CMake 版本检查**：
- 已在 `CMakeLists.txt` 中添加 gRPC >= 1.56 版本检查
- 如检测到易受攻击版本，编译时输出 WARNING

### 1.3 gRPC Python（修复 CVE-2023-44487 + CVE-2024-24762）

| 项目 | 详情 |
|------|------|
| CVE 编号 | CVE-2023-44487 (HIGH), CVE-2024-24762 (MEDIUM) |
| 受影响版本 | < 1.62.0 |
| 修复版本 | >= 1.62.0（推荐最新版） |
| 影响组件 | Python gRPC 服务端/客户端、审计上报网关 |

**升级命令**：
```bash
pip3 install --upgrade grpcio grpcio-tools protobuf
pip3 show grpcio | grep Version  # 确认 >= 1.62.0
```

**当前状态**：
- ✅ 已升级到 grpcio 1.83.1（2026-09-03）
- ✅ CVE-2023-44487 已修复
- ✅ CVE-2024-24762 已修复

### 1.4 Firecracker（修复 CVE-2023-41051）

| 项目 | 详情 |
|------|------|
| CVE 编号 | CVE-2023-41051 |
| 严重等级 | MEDIUM |
| 漏洞描述 | Firecracker virtio-vsock 信息泄露 |
| 受影响版本 | < 1.5.0 |
| 修复版本 | >= 1.5.0（推荐最新版） |
| 影响组件 | StrongPool MicroVM 后端 |

**升级命令**：
```bash
# 从官方 release 下载
FIRECRACKER_VERSION="v1.7.0"  # 使用最新版
curl -L "https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-x86_64.tgz" -o firecracker.tgz
tar xzf firecracker.tgz
sudo mv release-v*/firecracker /usr/local/bin/
firecracker --version  # 确认 >= 1.5.0
```

---

## 二、升级后验证

### 2.1 版本检测脚本

项目已集成自动版本检测功能（v22 新增）：

```bash
python3 scripts/cve_monitor.py
```

输出包含：
- 实际安装的各组件版本
- HIGH CVE 修复状态（✅ 已修复 / ⚠️ 未修复）
- 升级建议

### 2.2 手动验证

```bash
# OpenSSL
openssl version
python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"

# gRPC Python
pip3 show grpcio grpcio-tools protobuf

# gRPC C++
pkg-config --modversion grpc++

# Firecracker
firecracker --version
```

### 2.3 重新编译

```bash
# 清理旧构建
rm -rf build2

# 重新配置（CMake 会自动检测版本并输出 WARNING）
cmake -B build2 \
  -DGTest_DIR=/home/user/.super_doubao/super-doubao-runtime/workspace/_gtest_deps/install/lib/cmake/GTest \
  -DCMAKE_BUILD_TYPE=Release \
  -DPHOTON_ENABLE_GRPC=ON \
  -DBUILD_TESTING=ON

# 编译
cmake --build build2 -j$(nproc)

# 运行测试
ctest --test-dir build2 --output-on-failure
```

### 2.4 CVE 重扫

```bash
python3 scripts/cve_monitor.py --report
# 预期：HIGH CVE 数量 = 0（所有已安装组件均已升级）
```

---

## 三、当前环境升级状态（2026-09-03）

| 组件 | 当前版本 | 要求版本 | CVE 状态 | 说明 |
|------|---------|---------|---------|------|
| OpenSSL (系统) | 3.0.2 | >= 3.0.7 | ⚠️ 未修复 | 无 sudo 无法 apt 升级，生产环境必须升级 |
| OpenSSL (Python) | 3.0.16 | >= 3.0.7 | ✅ 已修复 | Python ssl 模块使用独立 OpenSSL |
| gRPC (Python) | 1.83.1 | >= 1.62.0 | ✅ 已修复 | 已升级到最新版 |
| gRPC (C++) | 未安装 | >= 1.56.0 | ⚠️ 未安装 | 无 libgrpc++-dev，生产环境必须安装 |
| Firecracker | 未安装 | >= 1.5.0 | ⚠️ 未安装 | 无 KVM 环境，StrongPool 不可用 |
| Protobuf | 7.36.1 | >= 4.0 | ✅ 正常 | 已升级到最新版 |

**HIGH CVE 总结**：
- CVE-2022-3602 (OpenSSL)：Python 侧已修复，系统侧待升级（需 sudo）
- CVE-2023-44487 (gRPC)：Python 侧已修复，C++ 侧待安装（需 sudo）

---

## 四、生产部署检查清单

升级完成后，生产部署前必须确认：

- [ ] OpenSSL 系统版本 >= 3.0.7（`openssl version` 确认）
- [ ] gRPC C++ 版本 >= 1.56.0（`pkg-config --modversion grpc++` 确认）
- [ ] gRPC Python 版本 >= 1.62.0（`pip3 show grpcio` 确认）
- [ ] Firecracker 版本 >= 1.5.0（如使用 StrongPool）
- [ ] CMake 编译无 HIGH CVE WARNING
- [ ] `python3 scripts/cve_monitor.py` 输出 HIGH CVE = 0
- [ ] 全量测试通过（C++ 180 + Python 248）
- [ ] 裸机 KVM 环境跑通 `scripts/verify_baremetal.sh`
- [ ] 完成独立第三方安全审计

---

## 五、持续维护

1. **定期扫描**：每月运行 `python3 scripts/cve_monitor.py --report`
2. **依赖更新**：每季度检查并升级关键依赖
3. **CVE 订阅**：订阅 OpenSSL、gRPC、Firecracker 的安全公告
4. **自动化**：在 CI/CD 流水线中集成 CVE 扫描，发现 HIGH CVE 阻断部署

---

**文档版本**: v1.0
**最后更新**: 2026-09-03
**适用项目**: PhotonBox (原 photon_kernel_sil3)
