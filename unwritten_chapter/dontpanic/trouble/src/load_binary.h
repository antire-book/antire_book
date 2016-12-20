#ifndef CREATE_REMOTE_THREAD_ASM_H
#define CREATE_REMOTE_THREAD_ASM_H

#include <stdint.h>
#include <stdbool.h>

void __attribute__((aligned(8), optimize("O0"), section(".mmap_space"))) mmap_space();

void __attribute__((aligned(8), optimize("O0"), section(".start_thread")))
    start_thread(int (*thread_create)(int*, int*, void *(*), void*), void (*thread_start)(void *));

bool write_binary(int p_pid, const char* p_to);

uint64_t get_thread_start();

#endif
