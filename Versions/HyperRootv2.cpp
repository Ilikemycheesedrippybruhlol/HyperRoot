#include <iostream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <syscall.h>
#include <unistd.h>
#include <cstring>

// Utility to write data into child process memory
void poke_data(pid_t child, long addr, const std::string& data) {
    size_t len = data.length() + 1; // include null terminator
    const char* buf = data.c_str();
    for (size_t i = 0; i < len; i += sizeof(long)) {
        long word = 0;
        memcpy(&word, buf + i, std::min(sizeof(long), len - i));
        ptrace(PTRACE_POKEDATA, child, addr + i, word);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) return 1;

    pid_t child = fork();
    if (child == 0) {
        // 1. Request Trace
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);

        // 2. Load Seccomp filter to trap ONLY specific syscalls (performance boost)
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SYS_getuid, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE), // Trap getuid
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW), // Allow others
        };
        struct sock_fprog prog = { .len = 4, .filter = filter };
        
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);

        raise(SIGSTOP);
        execvp(argv[1], &argv[1]);
        return 0;
    }

    int status;
    waitpid(child, &status, 0);
    // Enable advanced options: trace new threads and Seccomp events
    ptrace(PTRACE_SETOPTIONS, child, NULL, 
           PTRACE_O_TRACESECCOMP | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK);

    while (true) {
        ptrace(PTRACE_CONT, child, NULL, NULL);
        waitpid(child, &status, 0);

        if (WIFEXITED(status)) break;

        // Handle Seccomp event (This is triggered BEFORE the syscall executes)
        if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child, NULL, &regs);

            if (regs.orig_rax == SYS_getuid) {
                // To spoof getuid, we let it finish and then change RAX
                ptrace(PTRACE_SYSCALL, child, NULL, NULL);
                waitpid(child, &status, 0);
                
                ptrace(PTRACE_GETREGS, child, NULL, &regs);
                regs.rax = 0; // Spoof to root
                ptrace(PTRACE_SETREGS, child, NULL, &regs);
                std::cout << "[PRoot+] Spoofed getuid -> 0\n";
            }
        }
    }
    return 0;
}
