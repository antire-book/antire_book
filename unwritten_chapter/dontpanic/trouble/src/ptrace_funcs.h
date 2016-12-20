#ifndef PTRACE_FUNCS_H
#define PTRACE_FUNCS_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/user.h>

bool attach_to_pid(int p_pid);

bool detach_from_pid(int p_pid);

bool remote_read(int p_pid, const char* p_from, char* p_data, int p_length);

bool remote_write(int p_pid, const char* p_to, const char* p_data, int p_length);

bool remote_zero_mem(int p_pid, const char* p_to, int p_length);

bool remote_execute(int p_pid, uint64_t p_address, const char* p_shell_code,
                    int p_code_size, char** p_argv, int p_argc, uint64_t* p_retval);

bool backup_registers(int p_pid, struct user_regs_struct* p_backup_registers);

bool restore_registers(int p_pid, struct user_regs_struct* p_backup_registers);

#endif
