#include <stdint.h>
#include <string.h>

#include "thash.h"
#include "address.h"
#include "params.h"
#include "utils.h"
#include "sha2.h"

#if CDS_SHA512
static void thash_512(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const CDS_ctx *ctx, uint32_t addr[8]);
#endif

/**
 * Takes an array of inblocks concatenated arrays of CDS_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const CDS_ctx *ctx, uint32_t addr[8])
{
#if CDS_SHA512
    if (inblocks > 1) {
	thash_512(out, in, inblocks, ctx, addr);
        return;
    }
#endif

    unsigned char outbuf[CDS_SHA256_OUTPUT_BYTES];
    uint8_t sha2_state[40];
    CDS_VLA(uint8_t, buf, CDS_SHA256_ADDR_BYTES + inblocks*CDS_N);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx->state_seeded, 40 * sizeof(uint8_t));

    memcpy(buf, addr, CDS_SHA256_ADDR_BYTES);
    memcpy(buf + CDS_SHA256_ADDR_BYTES, in, inblocks * CDS_N);

    sha256_inc_finalize(outbuf, sha2_state, buf, CDS_SHA256_ADDR_BYTES + inblocks*CDS_N);
    memcpy(out, outbuf, CDS_N);
}

#if CDS_SHA512
static void thash_512(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const CDS_ctx *ctx, uint32_t addr[8])
{
    unsigned char outbuf[CDS_SHA512_OUTPUT_BYTES];
    uint8_t sha2_state[72];
    CDS_VLA(uint8_t, buf, CDS_SHA256_ADDR_BYTES + inblocks*CDS_N);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx->state_seeded_512, 72 * sizeof(uint8_t));

    memcpy(buf, addr, CDS_SHA256_ADDR_BYTES);
    memcpy(buf + CDS_SHA256_ADDR_BYTES, in, inblocks * CDS_N);

    sha512_inc_finalize(outbuf, sha2_state, buf, CDS_SHA256_ADDR_BYTES + inblocks*CDS_N);
    memcpy(out, outbuf, CDS_N);
}
#endif
