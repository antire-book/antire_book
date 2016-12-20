#include "load_binary.h"
#include "generated/the_binary.h"
#include "ptrace_funcs.h"

#include <stddef.h>
#include <sys/mman.h>

void __attribute__((aligned(8), optimize("O0"), section(".mmap_space")))
    mmap_space()
{
    //mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    asm("xor %%rdi, %%rdi\n"
        "mov %0, %%rsi\n"
        "mov %1, %%rdx\n"
        "mov %2, %%r10\n"
        "mov %3, %%r8\n"
        "xor %%r9, %%r9\n"
        "mov $9, %%rax\n"
        "syscall\n"
        "int3"
        :
        : "g"((sizeof(the_binary) & ~(PAGE_SIZE - 1))),
          "g"(PROT_READ|PROT_WRITE|PROT_EXEC),
          "g"(MAP_PRIVATE|MAP_ANONYMOUS), "g"(-1));
}

void __attribute__((aligned(8), optimize("O0"), section(".start_thread")))
    start_thread(int (*thread_create)(int*, int*, void *(*), void*), void (*thread_start)(void *))
{
    int thread_id = 0;
    thread_create(&thread_id, NULL, (void**)thread_start, NULL);
    asm("int3");
}

bool write_binary(int p_pid, const char* p_to)
{
    if (!remote_write(p_pid, p_to, (const char*)&the_binary[0], sizeof(the_binary)))
    {
        return false;
    }
    return true;
}

uint64_t get_thread_start()
{
    return s_thread_start;
}
