#ifndef MAPS_PARSING_H
#define MAPS_PARSING_H

#include <stdint.h>
#include <stdbool.h>

uint64_t find_lib_base(int p_pid, const char* const p_lib, char* p_lib_path);

uint64_t find_free_space(int p_pid);

uint64_t get_file_executable_mapping(int p_pid, const char* p_entry_point);

#endif
