#include <stdio.h>
#include <string.h>

#include "../thashx8.h"
#include "../thash.h"
#include "../randombytes.h"
#include "../params.h"
#include "../hash.h"

int main()
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    unsigned char input[8*CDS_N];
    unsigned char seed[CDS_N];
    unsigned char output[8*CDS_N];
    unsigned char out8[8*CDS_N];
    uint32_t addr[8*8] = {0};
    unsigned int j;

    randombytes(seed, CDS_N);
    randombytes(input, 8*CDS_N);
    randombytes((unsigned char *)addr, 8 * 8 * sizeof(uint32_t));

    initialize_hash_function(seed, seed);

    printf("Testing if thash matches thashx8.. ");

    for (j = 0; j < 8; j++) {
        thash(out8 + j * CDS_N, input + j * CDS_N, 1, seed, addr + j*8);
    }

    thashx8(output + 0*CDS_N,
            output + 1*CDS_N,
            output + 2*CDS_N,
            output + 3*CDS_N,
            output + 4*CDS_N,
            output + 5*CDS_N,
            output + 6*CDS_N,
            output + 7*CDS_N,
            input + 0*CDS_N,
            input + 1*CDS_N,
            input + 2*CDS_N,
            input + 3*CDS_N,
            input + 4*CDS_N,
            input + 5*CDS_N,
            input + 6*CDS_N,
            input + 7*CDS_N,
            1, seed, addr);

    if (memcmp(out8, output, 8 * CDS_N)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");
    return 0;
}
