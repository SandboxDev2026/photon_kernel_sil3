# 太空沙盒开源项目可抄模块清单

**日期**: 2026-09-04
**状态**: 技术调研参考
**纠正说明**: SpaceEngine 不是开源的（专有软件，0.990 后 shader 加密），以下是真正能打开仓库、直接读代码、按模块抄的项目。

---

## 一、完整项目（抄架构）

### 1. Pioneer — 最适合抄的太空沙盒游戏

| 项目 | 详情 |
|------|------|
| 仓库 | pioneerspacesim/pioneer |
| 许可证 | GPL-3.0（注意开源传染性） |
| 技术栈 | C++ + OpenGL + Lua |

**可抄模块**:
- **ECS 实体系统**：轻量级 Entity-Component，管理上千天体不卡
- **星系/扇区生成**：`src/Galaxy.cpp`、`src/SectorView.cpp` — 真实恒星库 + 程序生成混合
- **轨道物理**：`src/Orbit.cpp` — 开普勒轨道计算（解析解，比每帧 N 体计算省性能）
- **超空间/星图跳转**：`src/HyperspaceCloud.cpp`
- **飞船操控**：`src/Ship.cpp` + Lua 脚本驱动

**代码入口**: `src/Game.cpp` → `src/Space.cpp` → 各 Body 子类

**适合抄**: 想做一个能飞、能降落、能交易的完整太空游戏

---

### 2. OpenSpace — 科研级架构范本

| 项目 | 详情 |
|------|------|
| 仓库 | OpenSpace/OpenSpace |
| 许可证 | BSD-3-Clause（商用友好） |
| 技术栈 | C++ + OpenGL 4.6 + Qt |

**四层架构**（官方文档明确分层，非常好抄）:
- `openspace-core`：场景图、脚本、渲染、交互、导航
- `modules/`：可插拔功能模块（天体、漫游者、卫星等）
- `Ghoul`：通用工具库（纹理加载、字体、网络）
- `SGCT`：集群同步与多窗口

**可抄模块**:
- **场景图设计**：`src/openspace/scene/` — 天体层级管理
- **真实数据接入**：NASA SPICE 内核、小行星中心数据
- **时间系统**：多尺度时间（从实时到亿年）
- **模块插件机制**：每个功能独立 module，松耦合

**代码入口**: `src/openspace/engine/` → `src/openspace/scene/`

**适合抄**: 做天文可视化、科普软件、数据驱动的宇宙浏览器

---

### 3. Celestia — 老牌但代码干净

| 项目 | 详情 |
|------|------|
| 仓库 | CelestiaProject/Celestia |
| 许可证 | GPL-2.0 |
| 技术栈 | C++ + OpenGL |

**可抄模块**:
- **恒星数据库处理**：依巴谷星表解析、恒星渲染
- **天体分类系统**：恒星/行星/卫星/小行星统一基类
- **星表加载**：`.stc`、`.ssc` 配置文件格式

**适合抄**: 纯天体浏览、星图渲染，不需要游戏玩法

---

## 二、新兴项目（代码新、好读、现代技术栈）

### 4. OpenVerse — 纯引力沙盒

| 项目 | 详情 |
|------|------|
| 仓库 | ortanaV2/OpenVerse |
| 许可证 | 待确认（开源早期） |
| 定位 | 不是游戏，是"好奇心沙盒"，多恒星系统、行星、卫星、小行星带、环，真实引力物理驱动 |

**可抄**: N 体引力模拟、天体系统生成、渲染管线

**优势**: 代码量小，早期项目，读起来不费劲

---

### 5. AION — Zig + WASM 现代架构

| 项目 | 详情 |
|------|------|
| 仓库 | azillion/aion |
| 技术栈 | Zig（核心仿真）+ TypeScript（浏览器客户端）+ WASM |

**Monorepo 结构**:
- `packages/game-sim/`：Zig 自包含仿真库，可编译为 WASM 和原生
- `packages/client/`：TypeScript 浏览器端

**可抄**: 核心逻辑与渲染分离、WASM 移植方案、跨端架构

**适合抄**: 想做网页版宇宙沙盒，核心用系统语言编译到 WASM

---

## 三、按模块抄（不用整个项目，抠出来用）

### 行星程序生成

| 项目 | 技术栈 | 许可证 | 抄什么 |
|------|--------|--------|--------|
| Procedural Planet - Chunked LOD | Godot 纯 GDScript + GLSL | MIT | 四叉树分块 LOD、立方体→球体投影、5 层噪声地形、海拔着色。零依赖，打开即跑 |
| Godot 3D Planet Generator | Godot 4.5 Shader | MIT | 行星本体 + 云层 + 大气散射三个 shader，7 种预设星球（类地/冰/熔岩/沙/气态/恒星） |
| ProceduralTerrains | Three.js | MIT | 星球模式 + 体积云 + 真实水面 + GLB 导出，支持无限世界和瓦片 |
| PlanetTechJS | Three.js | — | 大规模行星创建/编辑库，噪声生成、大气散射、水力侵蚀 |

### 引力/物理模拟

| 项目 | 技术栈 | 抄什么 |
|------|--------|--------|
| SimVerse25 | React + Canvas | 自定义欧拉积分引力循环、时间缩放、实时多人（Socket.io） |
| Pioneer `src/Orbit.cpp` | C++ | 开普勒轨道解析解，比每帧 N 体计算省性能 |

### 网页端轻量方案

| 项目 | 技术栈 | 特点 |
|------|--------|------|
| universe-sim | Unity + OpenXR VR | 宇宙模拟器，项目结构标准，可参考 Unity 下的目录组织 |
| threejs-procedural-planets | Three.js | 参数化星球生成，大气+云层，适合快速出 demo |

---

## 四、抄的策略建议

| 目标 | 推荐方案 | 注意事项 |
|------|----------|----------|
| 快速出 demo | Godot + "Procedural Planet - Chunked LOD" | MIT，纯 GDScript，零依赖，一周内能跑起来一个可降落的星球 |
| 完整游戏 | fork Pioneer | ECS + 星系生成 + 飞船操控已全，GPL-3.0 注意开源传染性 |
| 科研/可视化 | 参考 OpenSpace 四层架构 + 模块插件机制 | BSD 协议商用友好 |
| 网页版 | AION 的 Zig→WASM 核心 + TS 前端架构，或 Three.js + ProceduralTerrains | 核心逻辑与渲染分离 |
| 只缺某个模块 | 直接抠 Godot 3D Planet Generator 的 shader | 大气散射那个最值钱，MIT 可商用 |

---

## 五、可借鉴到 PhotonBox 沙盒项目的架构思想

虽然太空游戏和安全沙盒是不同领域，但以下架构设计思想可以跨领域借鉴：

### 5.1 ECS 实体系统（Pioneer）→ 沙盒实例管理

**借鉴点**: 用 Entity-Component-System 模式管理沙盒实例，替代传统的继承层级。

**应用到 PhotonBox**:
- Entity = 沙盒实例 ID
- Component = 资源配置（CPU/内存/网络）、安全等级、状态、后端类型（LightPool/StrongPool）
- System = 调度器、资源监控、安全审计、生命周期管理

**优势**: 管理上万个沙盒实例不卡，新增功能只需添加 Component/System，不修改现有类。

### 5.2 四层架构（OpenSpace）→ PhotonBox 分层

**借鉴点**: 核心层 + 可插拔模块层 + 通用工具层 + 集群同步层。

**应用到 PhotonBox**:
- `photon-core`：沙盒执行核心（namespace/seccomp/cgroup/MicroVM）
- `modules/`：可插拔功能模块（审计、网络过滤、GA进化、红蓝对抗、RAG等）
- `photon-utils`：通用工具库（HMAC、日志、配置、序列化）
- `photon-cluster`：集群调度与多节点同步

**优势**: 每个功能独立 module，松耦合，可单独测试和替换。

### 5.3 模块插件机制（OpenSpace）→ 安全模块插件化

**借鉴点**: 每个功能独立 module，通过统一接口注册，运行时动态加载。

**应用到 PhotonBox**:
- 安全检测模块（eBPF/seccomp/Landlock）统一接口，可插拔
- 审计输出模块（文件/gRPC/HTTP）统一接口，可插拔
- 进化算法模块（GA/岛屿GA/Skill自演进）统一接口，可插拔

**优势**: 新增安全检测方式不需要修改核心代码，只需实现接口并注册。

### 5.4 核心逻辑与渲染分离 + WASM 移植（AION）→ PhotonBox 架构

**借鉴点**: 核心仿真逻辑用系统语言编写，可编译为原生和 WASM，前端用高级语言。

**应用到 PhotonBox**:
- 沙盒执行核心用 C++ 编写（已有）
- 控制面/管理面用 Python/TypeScript 编写（已有 Python SDK）
- 核心逻辑可编译为 WASM，用于浏览器端沙盒配置/模拟器

**优势**: 核心逻辑与控制面分离，可跨端部署，核心可复用。

### 5.5 开普勒轨道解析解（Pioneer）→ 资源调度优化

**借鉴点**: 用解析解替代每帧数值计算，大幅降低计算开销。

**应用到 PhotonBox**:
- 沙盒资源预测：用解析模型预测资源使用趋势，替代实时轮询
- 调度决策：用排队论解析解计算最优调度，替代启发式规则
- 并发控制：用 Little's Law 解析计算最优并发数，替代经验值

**优势**: 降低调度器 CPU 开销，提高大规模集群下的调度效率。

---

## 六、许可证注意事项

| 项目 | 许可证 | 商用友好 | 传染性 |
|------|--------|----------|--------|
| Pioneer | GPL-3.0 | ❌ | 强传染性，衍生作品必须开源 |
| OpenSpace | BSD-3-Clause | ✅ | 无传染性 |
| Celestia | GPL-2.0 | ❌ | 强传染性 |
| OpenVerse | 待确认 | — | — |
| AION | 待确认 | — | — |
| Godot Planet Shader | MIT | ✅ | 无传染性 |
| ProceduralTerrains | MIT | ✅ | 无传染性 |

**重要**: GPL 协议的代码不能直接复制到 Apache-2.0 的 PhotonBox 项目中，只能参考算法思想，重新实现。MIT/BSD 协议的代码可以直接复制，保留版权声明即可。

---

## 七、参考链接

- Pioneer: https://github.com/pioneerspacesim/pioneer
- OpenSpace: https://github.com/OpenSpace/OpenSpace
- Celestia: https://github.com/CelestiaProject/Celestia
- OpenVerse: https://github.com/ortanaV2/OpenVerse
- AION: https://github.com/azillion/aion
