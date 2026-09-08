#include <stdio.h>
#include <string.h>

#include "../thashx8.h"
#include "../thash.h"
#include "../randombytes.h"
#include "../params.h"
#include "../hash.h"

#if CDS_SHA512
#include "../sha2.h"
#include "../sha512x4.h"
#endif


int main(void)
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    unsigned char input[16*CDS_N];
    CDS_ctx ctx;
    unsigned char output[8*CDS_N];
    unsigned char out8[8*CDS_N];
    uint32_t addr[8*8] = {0};
    unsigned int j;

    randombytes(ctx.pub_seed, CDS_N);
    randombytes(input, 16*CDS_N);
    randombytes((unsigned char *)addr, 8 * 8 * sizeof(uint32_t));

    initialize_hash_function(&ctx);

    printf("Testing if thash matches thashx8 on one block ... ");

    for (j = 0; j < 8; j++) {
        thash(out8 + j * CDS_N, input + j * CDS_N, 1, &ctx, addr + j*8);
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
            1, &ctx, addr);

    if (memcmp(out8, output, 8 * CDS_N)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");

    printf("Testing if thash matches thashx8 on two blocks ... ");

    for (j = 0; j < 8; j++) {
        thash(out8 + j * CDS_N, input + (2*j) * CDS_N, 2, &ctx, addr + j*8);
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
            input + 2*CDS_N,
            input + 4*CDS_N,
            input + 6*CDS_N,
            input + 8*CDS_N,
            input + 10*CDS_N,
            input + 12*CDS_N,
            input + 14*CDS_N,
            2, &ctx, addr);

    if (memcmp(out8, output, 8 * CDS_N)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");
    return 0;
}
