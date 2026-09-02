#ifndef PHOTON_KERNEL_SANDBOX_VNC_DESKTOP_HPP
#define PHOTON_KERNEL_SANDBOX_VNC_DESKTOP_HPP
// VNC 桌面模块
//
// 目标：为沙盒提供图形化桌面环境，支持：
//   1. Xvfb 虚拟显示（无硬件 GPU 也能运行 GUI 应用）
//   2. x11vnc VNC 服务器（远程桌面）
//   3. noVNC + websockify（浏览器访问，无需 VNC 客户端）
//   4. 窗口管理器（openbox 或 fluxbox）
//   5. 桌面应用启动（浏览器、终端、IDE 等）
//
// 架构：
//   沙盒内: Xvfb(:99) → x11vnc(5900) → websockify(6080) → 浏览器(noVNC)
//
// 注意：完整的 GPU 加速桌面需要 VirGL 或 GPU 透传，本模块提供软件渲染框架。
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <memory>
namespace photon_kernel {
namespace sandbox {
struct VncDesktopConfig {
    // 显示分辨率
    int width = 1280;
    int height = 720;
    int depth = 24;
    // Xvfb 显示号
    int display = 99;
    // VNC 端口
    int vnc_port = 5900;
    // websockify 端口（noVNC 访问端口）
    int websockify_port = 6080;
    // VNC 密码（空=无密码）
    std::string vnc_password = "";
    // 窗口管理器
    std::string window_manager = "openbox";
    // 是否启用 noVNC（浏览器访问）
    bool enable_novnc = true;
    // noVNC 静态文件目录
    std::string novnc_path = "/usr/share/novnc";
    // 桌面环境（xfce/lxde/openbox）
    std::string desktop_env = "openbox";
    // 自动启动的应用
    std::vector<std::string> autostart_apps;
};
struct VncDesktopSession {
    std::string session_id;
    std::string sandbox_id;
    VncDesktopConfig config;
    bool running = false;
    pid_t xvfb_pid = -1;
    pid_t x11vnc_pid = -1;
    pid_t websockify_pid = -1;
    pid_t wm_pid = -1;
    std::string vnc_url;       // vnc://host:port
    std::string novnc_url;     // http://host:port/vnc.html
};
class VncDesktopManager {
public:
    static VncDesktopManager& instance();
    // 为沙盒启动 VNC 桌面
    std::shared_ptr<VncDesktopSession> start_session(
        const std::string& sandbox_id, const VncDesktopConfig& config);
    // 停止 VNC 桌面会话
    void stop_session(const std::string& session_id);
    // 获取会话
    std::shared_ptr<VncDesktopSession> get_session(const std::string& session_id) const;
    // 在沙盒桌面中启动应用
    bool launch_app(const std::string& session_id, const std::string& app_cmd);
    // 截图（通过 xwd 或 import）
    std::string screenshot(const std::string& session_id, const std::string& output_path);
    // 检查依赖是否安装（Xvfb/x11vnc/websockify/openbox）
    std::vector<std::string> check_dependencies() const;
    bool dependencies_available() const;
    // 获取所有会话
    std::vector<std::shared_ptr<VncDesktopSession>> all_sessions() const;
    // 停止所有会话
    void stop_all();
    // 重置（测试用）
    void reset();
private:
    VncDesktopManager() = default;
    VncDesktopManager(const VncDesktopManager&) = delete;
    VncDesktopManager& operator=(const VncDesktopManager&) = delete;
    mutable std::mutex mtx_;
    std::unordered_map<std::string, std::shared_ptr<VncDesktopSession>> sessions_;
    // 启动 Xvfb
    bool start_xvfb(VncDesktopSession& session);
    // 启动 x11vnc
    bool start_x11vnc(VncDesktopSession& session);
    // 启动 websockify + noVNC
    bool start_websockify(VncDesktopSession& session);
    // 启动窗口管理器
    bool start_window_manager(VncDesktopSession& session);
    // 生成会话 ID
    std::string generate_session_id() const;
};
} // namespace sandbox
} // namespace photon_kernel
#endif
