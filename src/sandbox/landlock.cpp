#include "photon_kernel/sandbox/landlock.hpp"
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cerrno>
#include <iostream>
#if __has_include(<linux/landlock.h>)
#include <linux/landlock.h>
#define PHOTON_LANDLOCK_AVAILABLE 1
#endif
namespace photon_kernel {
namespace sandbox {
bool LandlockEnforcer::is_supported() {
#ifdef PHOTON_LANDLOCK_AVAILABLE
    struct landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    long _rc = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
    int fd = static_cast<int>(_rc);
    if (fd >= 0) {
        close(fd);
        return true;
    }
    return errno != ENOSYS && errno != EOPNOTSUPP;
#else
    return false;
#endif
}
LandlockResult LandlockEnforcer::apply_read_only(const std::vector<std::string>& allowed_paths) {
    LandlockResult result;
#ifdef PHOTON_LANDLOCK_AVAILABLE
    if (!is_supported()) {
        result.available = false;
        result.applied = false;
        result.message = "Landlock not supported by kernel (requires Linux 5.13+)";
        return result;
    }
    result.available = true;
    struct landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    long _rc2 = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
    int ruleset_fd = static_cast<int>(_rc2);
    if (ruleset_fd < 0) {
        result.message = "landlock_create_ruleset failed: " + std::string(std::strerror(errno));
        return result;
    }
    for (const auto& path : allowed_paths) {
        int dir_fd = open(path.c_str(), O_PATH | O_CLOEXEC);
        if (dir_fd < 0) {
            std::cerr << "[Landlock] open(" << path << ") failed: " << std::strerror(errno) << "\n";
            continue;
        }
        struct landlock_path_beneath_attr path_attr = {};
        path_attr.parent_fd = dir_fd;
        path_attr.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
        if (syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0) != 0) {
            std::cerr << "[Landlock] landlock_add_rule failed for " << path << ": "
                      << std::strerror(errno) << "\n";
        }
        close(dir_fd);
    }
    if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) != 0) {
        result.message = "landlock_restrict_self failed: " + std::string(std::strerror(errno));
        close(ruleset_fd);
        return result;
    }
    close(ruleset_fd);
    result.applied = true;
    result.message = "Landlock read-only whitelist applied (" + std::to_string(allowed_paths.size()) + " paths)";
    return result;
#else
    result.available = false;
    result.applied = false;
    result.message = "Landlock headers not available at build time";
    return result;
#endif
}
} // namespace sandbox
} // namespace photon_kernel
