# PhotonBox 依赖升级与 CVE 修复报告

**日期**: 2026-09-04
**版本**: PhotonBox (原 photon_kernel_sil3)
**状态**: 部分完成（系统级升级需 sudo 环境）

---

## 一、待修复 HIGH CVE 清单

| CVE ID | 组件 | 漏洞描述 | 影响版本 | 修复版本 | 状态 |
|--------|------|----------|----------|----------|------|
| CVE-2022-3602 | OpenSSL | X.509 证书验证缓冲区溢出（RCE 风险） | < 3.0.7 | >= 3.0.7 | 🔄 源码编译中 |
| CVE-2023-44487 | gRPC / HTTP/2 | 快速重置 DoS 攻击（Rapid Reset） | < 1.56 (C++) / < 1.60 (Python) | >= 1.56 / >= 1.60 | ✅ Python 已修复 |

---

## 二、当前环境版本检测

### 2.1 系统级组件（容器环境，无 sudo）

```
OpenSSL:  3.0.2 (VULNERABLE - 需 >= 3.0.7)
gRPC C++: 未安装 (pkg-config 无法找到)
Python:    3.12.9
内核:      6.6.95
发行版:    Ubuntu 22.04 (容器)
```

### 2.2 Python 侧组件（已升级）

```
grpcio:       1.83.1 (>= 1.60, CVE-2023-44487 已修复)
grpcio-tools: 1.83.1
protobuf:     最新版
```

---

## 三、升级执行情况

### 3.1 Python gRPC 升级（已完成 ✅）

**执行命令**:
```bash
pip3 install --upgrade grpcio grpcio-tools protobuf
```

**验证结果**:
```
grpcio 1.83.1 >= 1.60: CVE-2023-44487 已修复
```

**影响范围**:
- `server/python/sandbox_grpc_client.py`
- `evolution/` 模块中所有 gRPC 调用
- Python SDK 层

### 3.2 OpenSSL 系统级升级（源码编译进行中 🔄）

**方案**: 从源码编译 OpenSSL 3.0.15 到用户目录（无需 sudo）

**执行步骤**:
```bash
# 1. 下载源码
curl -sL https://www.openssl.org/source/openssl-3.0.15.tar.gz -o openssl-3.0.15.tar.gz

# 2. 解压并配置
tar xzf openssl-3.0.15.tar.gz
cd openssl-3.0.15
./config --prefix=/path/to/openssl_install \
         --openssldir=/path/to/openssl_install/ssl \
         no-tests

# 3. 编译安装
make -j$(nproc)
make install

# 4. 验证
/path/to/openssl_install/bin/openssl version
# 预期输出: OpenSSL 3.0.15
```

**当前进度**: 编译进行中（已编译 500+ 个 .o 文件，预计还需 10-20 分钟）

**注意**: 源码编译的 OpenSSL 需要设置 `LD_LIBRARY_PATH` 和 `PKG_CONFIG_PATH` 才能被 CMake 找到：
```bash
export LD_LIBRARY_PATH=/path/to/openssl_install/lib64:$LD_LIBRARY_PATH
export PKG_CONFIG_PATH=/path/to/openssl_install/lib64/pkgconfig:$PKG_CONFIG_PATH
cmake -B build -DOPENSSL_ROOT_DIR=/path/to/openssl_install
```

### 3.3 gRPC C++ 系统级升级（建议在 sudo 环境执行）

**方案 A（推荐，有 sudo）**: 使用系统包管理器
```bash
sudo bash scripts/upgrade_system_deps.sh
```

**方案 B（无 sudo，源码编译）**: 使用 cmake FetchContent
```cmake
# CMakeLists.txt 中添加
include(FetchContent)
FetchContent_Declare(
    gRPC
    GIT_REPOSITORY https://github.com/grpc/grpc.git
    GIT_TAG        v1.62.0  # >= 1.56
)
FetchContent_MakeAvailable(gRPC)
```

**注意**: gRPC C++ 源码编译需要 protobuf、abseil-cpp、zlib、c-ares、re2 等大量依赖，编译时间 30-60 分钟。

---

## 四、CMake 版本安全检查（已实现 ✅）

### 4.1 OpenSSL 版本检查（CMakeLists.txt 第 34-40 行）

```cmake
if(OPENSSL_VERSION VERSION_LESS "3.0.7")
    message(WARNING "OpenSSL version ${OPENSSL_VERSION} is VULNERABLE (CVE-2022-3602)")
    message(WARNING "Upgrade OpenSSL: sudo apt install -y libssl-dev (>= 3.0.7)")
    message(WARNING "Continuing with VULNERABLE OpenSSL - NOT for production use!")
else()
    message(STATUS "OpenSSL version ${OPENSSL_VERSION} - security patch level OK")
endif()
```

### 4.2 gRPC 版本检查（CMakeLists.txt 第 309-315 行）

```cmake
if(gRPC_VERSION VERSION_LESS "1.56")
    message(WARNING "gRPC version ${gRPC_VERSION} is VULNERABLE (CVE-2023-44487)")
    message(WARNING "Upgrade gRPC: sudo apt install -y libgrpc++-dev (>= 1.56)")
    message(WARNING "Continuing with VULNERABLE gRPC - NOT for production use!")
else()
    message(STATUS "gRPC version ${gRPC_VERSION} - security patch level OK")
endif()
```

---

## 五、系统级升级脚本（已创建 ✅）

**文件**: `scripts/upgrade_system_deps.sh`

**功能**:
1. 自动检测发行版（Ubuntu/Debian/CentOS/RHEL）
2. 升级 OpenSSL 到 >= 3.0.7（修复 CVE-2022-3602）
3. 升级 gRPC C++ 到 >= 1.56（修复 CVE-2023-44487）
4. 升级 Python gRPC 到 >= 1.60
5. 验证升级结果
6. 重新运行 CVE 监控脚本

**用法**:
```bash
sudo bash scripts/upgrade_system_deps.sh
```

---

## 六、CVE 监控脚本（已存在 ✅）

**文件**: `scripts/cve_monitor.py`

**功能**:
- 检测实际安装的 OpenSSL/gRPC 版本
- 对比已知 CVE 影响版本
- 输出 HIGH/MEDIUM/LOW 风险等级
- 生成修复建议

**用法**:
```bash
python3 scripts/cve_monitor.py
```

---

## 七、生产部署前必须完成

### 7.1 系统级依赖升级（P0）

```bash
# 在有 sudo 权限的裸机/虚拟机环境执行
sudo bash scripts/upgrade_system_deps.sh

# 验证
openssl version          # 预期 >= 3.0.7
pkg-config --modversion grpc++  # 预期 >= 1.56
python3 -c "import grpc; print(grpc.__version__)"  # 预期 >= 1.60
```

### 7.2 重新编译验证

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# 确认 CMake 输出中无 VULNERABLE 警告
ctest --test-dir build --output-on-failure
```

### 7.3 重新扫描 CVE

```bash
python3 scripts/cve_monitor.py
# 预期: HIGH CVE 数量 = 0
```

---

## 八、环境限制说明

### 8.1 当前容器环境限制

- ❌ 无 sudo 权限（`no new privileges` flag 阻止 sudo）
- ❌ 无法使用 `apt-get install` 升级系统包
- ❌ 无法修改系统级 OpenSSL（/usr/lib/x86_64-linux-gnu/libssl.so）
- ✅ 可以从源码编译到用户目录
- ✅ 可以升级 Python 包（pip install）

### 8.2 生产环境要求

- ✅ 裸机或开启嵌套虚拟化的虚拟机
- ✅ root/sudo 权限
- ✅ KVM 硬件虚拟化（/dev/kvm）
- ✅ CAP_BPF 能力（eBPF 网络过滤）
- ✅ CRIU 二进制（进程快照）
- ✅ libgrpc++-dev >= 1.56
- ✅ OpenSSL >= 3.0.7

---

## 九、总结

| 组件 | CVE | 当前状态 | 修复方式 |
|------|-----|----------|----------|
| Python gRPC | CVE-2023-44487 | ✅ 已修复 (1.83.1) | `pip install --upgrade grpcio` |
| OpenSSL (系统) | CVE-2022-3602 | 🔄 源码编译中 (3.0.15) | `sudo apt install libssl-dev` 或源码编译 |
| gRPC C++ | CVE-2023-44487 | ⚠️ 未安装 | `sudo apt install libgrpc++-dev` 或源码编译 |

**下一步**:
1. 等待 OpenSSL 源码编译完成，验证 3.0.15 安装成功
2. 在有 sudo 权限的环境执行 `scripts/upgrade_system_deps.sh` 完成系统级升级
3. 重新编译 PhotonBox，确认 CMake 无 VULNERABLE 警告
4. 运行全量测试 + CVE 扫描，确认 HIGH CVE = 0
