#include <iostream>
#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <syscall.h>
#include <unistd.h>
#include <cstring>

// Helper to read a string from the child's memory space
std::string peek_string(pid_t child, long addr) {
    std::string res;
    long word;
    while (true) {
        word = ptrace(PTRACE_PEEKDATA, child, addr + res.size(), NULL);
        if (word == -1) break;
        char *ptr = (char *)&word;
        for (int i = 0; i < sizeof(long); ++i) {
            if (ptr[i] == '\0') return res;
            res += ptr[i];
        }
    }
    return res;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <command>\n";
        return 1;
    }

    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP); // Stop until the parent is ready
        execvp(argv[1], argv + 1);
        return 0;
    }

    int status;
    waitpid(child, &status, 0);
    // Set option to distinguish syscall traps from other signals
    ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_O_TRACESYSGOOD);

    bool is_entry = true;
    while (true) {
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        waitpid(child, &status, 0);

        if (WIFEXITED(status)) break;

        // Check if the stop was specifically for a syscall
        if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child, NULL, &regs);

            if (is_entry) {
                // --- SYSCALL ENTRY ---
                if (regs.orig_rax == SYS_openat || regs.orig_rax == SYS_open) {
                    // Example: Intercept file opens
                    long path_addr = (regs.orig_rax == SYS_openat) ? regs.rsi : regs.rdi;
                    std::string path = peek_string(child, path_addr);
                    std::cout << "[Emulator] Child trying to open: " << path << "\n";
                }
            } else {
                // --- SYSCALL EXIT ---
                if (regs.orig_rax == SYS_getuid || regs.orig_rax == SYS_geteuid) {
                    // Modify return value (RAX) to 0 (root) on exit
                    regs.rax = 0;
                    ptrace(PTRACE_SETREGS, child, NULL, &regs);
                    std::cout << "[Emulator] Spoofed UID to 0 (root)\n";
                }
            }
            is_entry = !is_entry; // Toggle between entry and exit
        }
    }
    return 0;
}
