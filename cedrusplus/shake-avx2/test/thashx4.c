#include <stdio.h>
#include <string.h>

#include "../thashx4.h"
#include "../thash.h"
#include "../randombytes.h"
#include "../params.h"

int main(void)
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    unsigned char input[4*CDS_N];
    unsigned char output[4*CDS_N];
    unsigned char out4[4*CDS_N];
    uint32_t addr[4*8] = {0};
    unsigned int j;
    CDS_ctx ctx;

    randombytes(ctx.pub_seed, CDS_N);
    randombytes(input, 4*CDS_N);
    randombytes((unsigned char *)addr, 4 * 8 * sizeof(uint32_t));

    printf("Testing if thash matches thashx4.. ");

    for (j = 0; j < 4; j++) {
        thash(out4 + j * CDS_N, input + j * CDS_N, 1, &ctx, addr + j*8);
    }

    thashx4(output + 0*CDS_N,
            output + 1*CDS_N,
            output + 2*CDS_N,
            output + 3*CDS_N,
            input + 0*CDS_N,
            input + 1*CDS_N,
            input + 2*CDS_N,
            input + 3*CDS_N,
            1, &ctx, addr);

    if (memcmp(out4, output, 4 * CDS_N)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");
    return 0;
}
