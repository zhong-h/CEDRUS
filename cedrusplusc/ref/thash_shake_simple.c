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

    memcpy(buf, ctx->pub_seed, CDS_N);
    memcpy(buf + CDS_N, addr, CDS_ADDR_BYTES);
    memcpy(buf + CDS_N + CDS_ADDR_BYTES, in, inblocks * CDS_N);

    shake256(out, CDS_N, buf, CDS_N + CDS_ADDR_BYTES + inblocks*CDS_N);
}

/**
 * Takes an array of inblocks concatenated arrays of CDS_N bytes.
 */
void thash_init_bitmask(unsigned char *bitmask_out, unsigned int inblocks,
           const cds_ctx *ctx, uint32_t addr[8])
{
    (void) bitmask_out;
    (void) inblocks;
    (void) ctx;
    (void) addr;
}

/**
 * Takes an array of inblocks concatenated arrays of CDS_N bytes.
 */
void thash_fin(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const cds_ctx *ctx, uint32_t addr[8], const unsigned char *bitmask)
{
    (void) bitmask;
    thash(out, in, inblocks, ctx, addr);
}