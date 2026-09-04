// POC-001: ptrace 注入父进程（红队对抗用例）
//
// 攻击技术：沙盒内进程尝试 ptrace 附加父进程，注入恶意代码
// 预期行为：seccomp 拦截 ptrace，进程被 SECCOMP_RET_KILL_PROCESS 杀死
// 风险等级：Critical
//
// 编译：g++ -o redteam_poc_ptrace redteam_poc_ptrace.cpp
// 在沙盒内运行：./redteam_poc_ptrace
// 预期：进程被杀死，退出码非0，审计日志记录 ptrace 违规

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>

int main() {
    printf("[POC-001] ptrace 注入父进程测试\n");
    printf("[POC-001] 当前 PID: %d, 父 PID: %d\n", getpid(), getppid());
    printf("[POC-001] 尝试 ptrace(PTRACE_ATTACH, 父进程)...\n");

    // 尝试 ptrace 附加父进程
    // 在 untrusted_code_mode 下，ptrace 在 seccomp 白名单之外，应被 KILL
    long result = ptrace(PTRACE_ATTACH, getppid(), nullptr, nullptr);

    // 如果走到这里，说明 ptrace 没有被 seccomp 拦截（安全漏洞！）
    if (result == 0) {
        printf("[POC-001] ❌ 安全漏洞：ptrace 附加成功！可以注入父进程\n");
        ptrace(PTRACE_DETACH, getppid(), nullptr, nullptr);
        return 1; // 返回非零表示测试失败（有漏洞）
    } else {
        printf("[POC-001] ptrace 返回错误（可能被 seccomp 拦截或权限不足）: %m\n");
    }

    printf("[POC-001] 测试完成\n");
    return 0;
}
