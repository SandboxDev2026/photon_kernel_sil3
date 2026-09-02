// VNC 桌面实现
#include "photon_kernel/sandbox/vnc_desktop.hpp"
#include <sstream>
#include <cstdlib>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
namespace photon_kernel {
namespace sandbox {
VncDesktopManager& VncDesktopManager::instance() {
    static VncDesktopManager mgr;
    return mgr;
}
std::string VncDesktopManager::generate_session_id() const {
    static uint64_t counter = 0;
    return "vnc-" + std::to_string(++counter);
}
std::vector<std::string> VncDesktopManager::check_dependencies() const {
    std::vector<std::string> missing;
    const char* deps[] = {"Xvfb", "x11vnc", "websockify", "openbox"};
    for (const char* dep : deps) {
        std::string cmd = "command -v " + std::string(dep) + " >/dev/null 2>&1";
        if (system(cmd.c_str()) != 0) {
            missing.push_back(dep);
        }
    }
    return missing;
}
bool VncDesktopManager::dependencies_available() const {
    return check_dependencies().empty();
}
bool VncDesktopManager::start_xvfb(VncDesktopSession& session) {
    std::ostringstream cmd;
    cmd << "Xvfb :" << session.config.display
        << " -screen 0 " << session.config.width
        << "x" << session.config.height
        << "x" << session.config.depth
        << " >/dev/null 2>&1 &";
    if (system(cmd.str().c_str()) != 0) return false;
    // 等待 Xvfb 启动
    for (int i = 0; i < 50; ++i) {
        std::string check = "xdpyinfo -display :" + std::to_string(session.config.display) +
            " >/dev/null 2>&1";
        if (system(check.c_str()) == 0) break;
        usleep(100000);
    }
    session.xvfb_pid = 0;  // 用 pgrep 查找
    return true;
}
bool VncDesktopManager::start_x11vnc(VncDesktopSession& session) {
    std::ostringstream cmd;
    cmd << "x11vnc -display :" << session.config.display
        << " -rfbport " << session.config.vnc_port
        << " -forever -shared -noxdamage"
        << " >/dev/null 2>&1 &";
    if (!session.config.vnc_password.empty()) {
        cmd << " -passwd " << session.config.vnc_password;
    }
    if (system(cmd.str().c_str()) != 0) return false;
    usleep(500000);  // 等待 x11vnc 启动
    session.x11vnc_pid = 0;
    return true;
}
bool VncDesktopManager::start_websockify(VncDesktopSession& session) {
    if (!session.config.enable_novnc) return true;
    std::ostringstream cmd;
    cmd << "websockify --web=" << session.config.novnc_path
        << " " << session.config.websockify_port
        << " localhost:" << session.config.vnc_port
        << " >/dev/null 2>&1 &";
    if (system(cmd.str().c_str()) != 0) return false;
    usleep(500000);
    session.websockify_pid = 0;
    session.novnc_url = "http://localhost:" + std::to_string(session.config.websockify_port) + "/vnc.html";
    return true;
}
bool VncDesktopManager::start_window_manager(VncDesktopSession& session) {
    std::ostringstream cmd;
    cmd << "DISPLAY=:" << session.config.display
        << " " << session.config.window_manager
        << " >/dev/null 2>&1 &";
    if (system(cmd.str().c_str()) != 0) return false;
    usleep(300000);
    session.wm_pid = 0;
    return true;
}
std::shared_ptr<VncDesktopSession> VncDesktopManager::start_session(
    const std::string& sandbox_id, const VncDesktopConfig& config) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto session = std::make_shared<VncDesktopSession>();
    session->session_id = generate_session_id();
    session->sandbox_id = sandbox_id;
    session->config = config;
    // 启动组件
    if (!start_xvfb(*session)) {
        session->running = false;
        return session;
    }
    if (!start_window_manager(*session)) {
        // WM 启动失败不影响桌面
    }
    if (!start_x11vnc(*session)) {
        session->running = false;
        return session;
    }
    if (!start_websockify(*session)) {
        // noVNC 启动失败不影响 VNC
    }
    // 启动自动应用
    for (const auto& app : config.autostart_apps) {
        std::string cmd = "DISPLAY=:" + std::to_string(config.display) + " " + app + " >/dev/null 2>&1 &";
        (void)system(cmd.c_str());
    }
    session->running = true;
    session->vnc_url = "vnc://localhost:" + std::to_string(config.vnc_port);
    sessions_[session->session_id] = session;
    return session;
}
void VncDesktopManager::stop_session(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return;
    auto& session = it->second;
    session->running = false;
    // kill 所有相关进程
    std::string kill_cmd =
        "pkill -f 'Xvfb :" + std::to_string(session->config.display) + "' 2>/dev/null; "
        "pkill -f 'x11vnc.*" + std::to_string(session->config.vnc_port) + "' 2>/dev/null; "
        "pkill -f 'websockify.*" + std::to_string(session->config.websockify_port) + "' 2>/dev/null; "
        "pkill -f '" + session->config.window_manager + "' 2>/dev/null";
    (void)system(kill_cmd.c_str());
    sessions_.erase(it);
}
std::shared_ptr<VncDesktopSession> VncDesktopManager::get_session(
    const std::string& session_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = sessions_.find(session_id);
    return it == sessions_.end() ? nullptr : it->second;
}
bool VncDesktopManager::launch_app(const std::string& session_id, const std::string& app_cmd) {
    auto session = get_session(session_id);
    if (!session || !session->running) return false;
    std::string cmd = "DISPLAY=:" + std::to_string(session->config.display) +
        " " + app_cmd + " >/dev/null 2>&1 &";
    return system(cmd.c_str()) == 0;
}
std::string VncDesktopManager::screenshot(const std::string& session_id,
                                            const std::string& output_path) {
    auto session = get_session(session_id);
    if (!session || !session->running) return "";
    std::string cmd = "DISPLAY=:" + std::to_string(session->config.display) +
        " import -window root " + output_path + " 2>/dev/null";
    if (system(cmd.c_str()) != 0) {
        // 用 xwd 备选
        cmd = "DISPLAY=:" + std::to_string(session->config.display) +
            " xwd -root -out " + output_path + ".xwd 2>/dev/null";
        (void)system(cmd.c_str());
        return output_path + ".xwd";
    }
    return output_path;
}
std::vector<std::shared_ptr<VncDesktopSession>> VncDesktopManager::all_sessions() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<std::shared_ptr<VncDesktopSession>> result;
    for (const auto& [id, session] : sessions_) {
        result.push_back(session);
    }
    return result;
}
void VncDesktopManager::stop_all() {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto& [id, session] : sessions_) {
        session->running = false;
        std::string kill_cmd =
            "pkill -f 'Xvfb' 2>/dev/null; "
            "pkill -f x11vnc 2>/dev/null; "
            "pkill -f websockify 2>/dev/null";
        (void)system(kill_cmd.c_str());
    }
    sessions_.clear();
}
void VncDesktopManager::reset() {
    stop_all();
}
} // namespace sandbox
} // namespace photon_kernel
