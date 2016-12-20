#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

/**
 * This program, when used with LD_PRELOAD, will print the values passed into
 * memcmp and then pass the values to to the real memcmp. Usage:
 *
 * LD_PRELOAD=./catch_memcmp.so ../../trouble/build/trouble
 */
int memcmp(const void *s1, const void *s2, size_t n)
{
    char* new_s1 = calloc(n + 1, 1);
    char* new_s2 = calloc(n + 1, 1);

    memcpy(new_s1, s1, n);
    memcpy(new_s2, s2, n);

    printf("memcmp(%s, %s, %u)\n", new_s1, new_s2, (int)n);

    free(new_s1);
    free(new_s2);

    // pass the params to the real memcmp and return the result
    int (*original_memcmp)(const void *s1, const void *s2, size_t n);
    original_memcmp = dlsym(RTLD_NEXT, "memcmp");
    return original_memcmp(s1, s2, n);
}
