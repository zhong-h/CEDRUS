#include <stdint.h>
#include <string.h>

#include "address.h"
#include "params.h"
#include "harakax4.h"
#include "hashx4.h"

/*
 * 4-way parallel version of prf_addr; takes 4x as much input and output
 */
#define prf_addrx4 CDS_NAMESPACE(prf_addrx4)
void prf_addrx4(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3,
                const CDS_ctx *ctx,
                const uint32_t addrx4[4*8])
{
    unsigned char bufx4[4 * 64] = {0};
    /* Since CDS_N may be smaller than 32, we need temporary buffers. */
    unsigned char outbuf[4 * 32];
    unsigned int i;

    for (i = 0; i < 4; i++) {
        memcpy(bufx4 + i*64, addrx4 + i*8, CDS_ADDR_BYTES);
        memcpy(bufx4 + i*64 + CDS_ADDR_BYTES, ctx->sk_seed, CDS_N);
    }

    haraka512x4(outbuf, bufx4, ctx);

    memcpy(out0, outbuf, CDS_N);
    memcpy(out1, outbuf + 32, CDS_N);
    memcpy(out2, outbuf + 64, CDS_N);
    memcpy(out3, outbuf + 96, CDS_N);
}
