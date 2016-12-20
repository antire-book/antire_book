#include "ptrace_funcs.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

bool attach_to_pid(int p_pid)
{
    if (ptrace(PTRACE_ATTACH, p_pid, NULL, NULL) < 0)
    {
        return false;
    }

    int status = 0;
    return waitpid(p_pid, &status, 0) != -1;
}

bool detach_from_pid(int p_pid)
{
    return ptrace(PTRACE_DETACH, p_pid, NULL, NULL) == 0;
}

bool remote_read(int p_pid, const char* p_from, char* p_data, int p_length)
{
    for (int loops = (p_length / sizeof(long));
         loops > 0; --loops, p_from += sizeof(long), p_data += sizeof(long))
    {
        long word = ptrace(PTRACE_PEEKTEXT, p_pid, p_from, NULL);
        if (word == -1 && errno)
        {
            return false;
        }
        *(long *)p_data = word;
    }
    return true;
}

bool remote_write(int p_pid, const char* p_to, const char* p_data, int p_length)
{
    for (int loops = (p_length / sizeof(long));
         loops > 0; --loops, p_data += sizeof(long), p_to += sizeof(long))
    {
        if (ptrace(PTRACE_POKETEXT, p_pid, p_to, *(void **)p_data) == -1)
        {
            return false;
        }
    }

    int remainder = p_length % sizeof(p_length);
    if (remainder == 0)
    {
        return true;
    }

    remainder = sizeof(long) - remainder;
    long peeked = ptrace(PTRACE_PEEKTEXT, p_pid, p_to, NULL);
    memcpy(&peeked, p_data, remainder);
    if (ptrace(PTRACE_POKETEXT, p_pid, p_to, peeked) == -1)
    {
        return false;
    }

    return true;
}

bool remote_zero_mem(int p_pid, const char* p_to, int p_length)
{
    long zero = 0;
    for (int loops = (p_length / (sizeof(long)));
         loops > 0; loops--, p_to += sizeof(long))
    {
        if (ptrace(PTRACE_POKETEXT, p_pid, p_to, zero) == -1)
        {
            return false;
        }
    }
    return true;
}

bool remote_execute(int p_pid, uint64_t p_address, const char* p_shell_code,
                    int p_code_size, char** p_argv, int p_argc, uint64_t* p_retval)
{
    struct user_regs_struct registers = {};
    if (!backup_registers(p_pid, &registers))
    {
        return false;
    }

    // when reason fails, a nop sled helps
    const char nop_sled[8] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    if (!remote_write(p_pid, (char*)p_address, nop_sled, sizeof(nop_sled)))
    {
        return false;
    }
    p_address += sizeof(nop_sled);

    if (!remote_write(p_pid, (char*)p_address, p_shell_code, p_code_size))
    {
        return false;
    }

    switch (p_argc)
    {
        case 2:
            registers.rsi = (uintptr_t)p_argv[1];
        case 1:
            registers.rdi = (uintptr_t)p_argv[0];
        default:
            break;
    }

    registers.rip = p_address;
    if (!restore_registers(p_pid, &registers))
    {
        return false;
    }

    if (ptrace(PTRACE_CONT, p_pid, NULL, NULL) < 0)
    {
        return false;
    }

    int status = 0;
    waitpid(p_pid, &status, 0);
    if (ptrace(PTRACE_GETREGS, p_pid, NULL, &registers) < 0)
    {
        return false;
    }

    if (WSTOPSIG(status) != SIGTRAP)
    {
        printf("[!] No SIGTRAP received, something went wrong. Signal: %d\n", WSTOPSIG(status));
        return false;
    }

    (*p_retval) = registers.rax;
    return true;
}

bool backup_registers(int p_pid, struct user_regs_struct* p_backup_registers)
{
    if (ptrace(PTRACE_GETREGS, p_pid, NULL, p_backup_registers) < 0)
    {
        return false;
    }
    return true;
}

bool restore_registers(int p_pid, struct user_regs_struct* p_backup_registers)
{
    if (ptrace(PTRACE_SETREGS, p_pid, NULL, p_backup_registers) < 0)
    {
        return false;
    }
    return true;
}
