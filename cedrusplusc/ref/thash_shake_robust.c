#include <stdint.h>
#include <string.h>

#include "thash.h"
#include "address.h"
#include "params.h"

#include "fips202.h"

/**
 * Takes an array of inblocks concatenated arrays of CDS_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const cds_ctx *ctx, uint32_t addr[8])
{
    unsigned char buf[CDS_N + CDS_ADDR_BYTES + inblocks*CDS_N];
    unsigned char bitmask[inblocks * CDS_N];
    unsigned int i;

    memcpy(buf, ctx->pub_seed, CDS_N);
    memcpy(buf + CDS_N, addr, CDS_ADDR_BYTES);

    shake256(bitmask, inblocks * CDS_N, buf, CDS_N + CDS_ADDR_BYTES);

    for (i = 0; i < inblocks * CDS_N; i++) {
        buf[CDS_N + CDS_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    shake256(out, CDS_N, buf, CDS_N + CDS_ADDR_BYTES + inblocks*CDS_N);
}

/**
 * Takes an array of inblocks concatenated arrays of CDS_N bytes.
 */
void thash_init_bitmask(unsigned char *bitmask_out, unsigned int inblocks,
           const cds_ctx *ctx, uint32_t addr[8])
{
    unsigned char buf[CDS_N + CDS_ADDR_BYTES + inblocks*CDS_N];
    unsigned char bitmask[inblocks * CDS_N];

    memcpy(buf, ctx->pub_seed, CDS_N);
    memcpy(buf + CDS_N, addr, CDS_ADDR_BYTES);

    shake256(bitmask, inblocks * CDS_N, buf, CDS_N + CDS_ADDR_BYTES);
    memcpy(bitmask_out, bitmask, inblocks * CDS_N);
}

/**
 * Takes an array of inblocks concatenated arrays of CDS_N bytes.
 */
void thash_fin(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const cds_ctx *ctx, uint32_t addr[8], const unsigned char *bitmask)
{
    unsigned char buf[CDS_N + CDS_ADDR_BYTES + inblocks*CDS_N];
    unsigned int i;

    memcpy(buf, ctx->pub_seed, CDS_N);
    memcpy(buf + CDS_N, addr, CDS_ADDR_BYTES);

    for (i = 0; i < inblocks * CDS_N; i++) {
        buf[CDS_N + CDS_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    shake256(out, CDS_N, buf, CDS_N + CDS_ADDR_BYTES + inblocks*CDS_N);
}
