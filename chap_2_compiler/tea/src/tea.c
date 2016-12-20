#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/**
 * This is an implementation of Corrected Block Tiny Encryption Algorithm (aka
 * XXTEA). XXTEA is a simple block cipher designed by David Wheeler and Roger
 * Needham that addressed issues in the original BTEA implementation. The
 * algorithm was first published in 1998.
 *
 * The code is based off of the reference code which you can easily find on
 * wikipedia: https://en.wikipedia.org/wiki/XXTEA
 *
 * Note: Do not try to secure your data with this algorithm. This is just a
 * toy to illustrate the affects of optimization on code.
 */

#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))

void btea_encrypt(uint32_t *v, int n, uint32_t const key[4])
{
    uint32_t sum = 0;
    for (unsigned rounds = 6 + 52/n; rounds > 0; --rounds)
    {
        uint32_t z = v[n-1];
        uint32_t y = 0;
        unsigned p = 0;

        sum += 0x9e3779b9;
        unsigned e = (sum >> 2) & 3;

        for ( ; (int)p < n - 1; p++)
        {
            y = v[p+1];
            v[p] += MX;
            z = v[p];
        }

        y = v[0];
        v[n - 1] += MX;
        z = v[n - 1];
    }
}

void btea_decrypt(uint32_t *v, int n, uint32_t const key[4])
{
    unsigned rounds = 6 + 52/n;
    uint32_t sum = rounds * DELTA;
    uint32_t y = v[0];
    uint32_t z = 0;
    do
    {
        unsigned e = (sum >> 2) & 3;
        unsigned p = n - 1;
        for ( ; p > 0; p--)
        {
            z = v[p-1];
            y = v[p] -= MX;
        }
        z = v[n-1];
        y = v[0] -= MX;
        sum -= DELTA;
    }
    while (--rounds);
}

int main()
{
    char data[] = "abcfefghilmno123";
    uint32_t orig_len = strlen(data);
    printf("plaintext: ");
    if ((orig_len % sizeof(uint32_t)) != 0)
    {
        printf("Bad size: %lu\n", (orig_len % sizeof(uint32_t)));
        return EXIT_FAILURE;
    }

    for (size_t i = 0; i < orig_len; i++)
    {
        printf("0x%02x ", (data[i] & 0xff));
    }
    printf("\n");

    uint32_t key[4] = { 0x4a, 0x61, 0x63, 0x6b };
    uint32_t len = strlen(data);
    len = len / sizeof(uint32_t);
    printf("encrypted: ");
    btea_encrypt((uint32_t*)data, len, key);

    for (size_t i = 0; i < orig_len; i++)
    {
        printf("0x%02x ", (data[i] & 0xff));
    }
    printf("\n");
}

