#include "maps_parsing.h"

#include "ptrace_funcs.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>

FILE* open_proc_maps(int p_pid)
{
    char proc_maps[255] = { 0 };
    if (snprintf(proc_maps, sizeof(proc_maps) - 1, "/proc/%d/maps", p_pid) <= 0)
    {
        return 0;
    }

    FILE* maps_file = fopen(proc_maps, "r");
    if (maps_file == NULL)
    {
        return 0;
    }

    return maps_file;
}

uint64_t find_lib_base(int p_pid, const char* const p_lib, char* p_lib_path)
{
    FILE* maps_file = open_proc_maps(p_pid);
    if (maps_file == 0)
    {
        return 0;
    }

    char maps_line[512] = { 0 };
    while (fgets(maps_line, sizeof(maps_line) - 1, maps_file))
    {
        if (strstr(maps_line, p_lib) && strstr(maps_line, ".so"))
        {
            char* address_separator = strchr(maps_line, '-');
            if (address_separator == NULL)
            {
                continue;
            }

            *address_separator = 0;
            uint64_t base = strtoul(maps_line, NULL, 16);

            ++address_separator;
            while (*address_separator != 0 && *address_separator != '/')
            {
                ++address_separator;
            }

            if (strchr(address_separator, '\n') == NULL)
            {
                return 0;
            }

            int copy_length = strchr(address_separator, '\n') - address_separator;
            memcpy(p_lib_path, address_separator, copy_length);
            fclose(maps_file);
            return base;
        }
    }

    fclose(maps_file);
    return 0;
}

uint64_t find_free_space(int p_pid)
{
    FILE* maps_file = open_proc_maps(p_pid);
    if (maps_file == 0)
    {
        return 0;
    }

    char maps_line[512] = { 0 };
    while (fgets(maps_line, sizeof(maps_line) - 1, maps_file))
    {
        if (strstr(maps_line, "r-xp"))
        {
            char* address_separator = strchr(maps_line, '-');
            if (address_separator == NULL)
            {
                continue;
            }
            address_separator++;
            uint64_t align_region = strtoul(address_separator, NULL, 16);

            if (!attach_to_pid(p_pid))
            {
                fclose(maps_file);
                return 0;
            }

            bool clean = true;
            uint64_t free_start = align_region - 0x100;
            for (uint64_t i = free_start; i < align_region; i += sizeof(long))
            {
                long space = ptrace(PTRACE_PEEKTEXT, p_pid, (char*)i, NULL);
                if (space != 0)
                {
                    clean = false;
                }
            }

            if (!detach_from_pid(p_pid))
            {
                fclose(maps_file);
                return 0;
            }

            if (clean)
            {
                fclose(maps_file);
                return free_start;
            }
        }
    }

    fclose(maps_file);
    return 0;
}

uint64_t get_file_executable_mapping(int p_pid, const char* p_file_path)
{
    FILE* maps_file = open_proc_maps(p_pid);
    if (maps_file == 0)
    {
        return 0;
    }

    char maps_line[512] = { 0 };
    while (fgets(maps_line, sizeof(maps_line) - 1, maps_file))
    {
        if (strstr(maps_line, p_file_path) && strstr(maps_line, "r-xp"))
        {
            fclose(maps_file);
            return strtoul(maps_line, NULL, 16);
        }
    }
    fclose(maps_file);
    return 0;
}
