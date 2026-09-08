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
    CDS_VLA(uint8_t, bitmask, inblocks * CDS_N);
    CDS_VLA(uint8_t, buf, CDS_N + CDS_SHA256_OUTPUT_BYTES + inblocks*CDS_N);
    uint8_t sha2_state[40];
    unsigned int i;

    memcpy(buf, ctx->pub_seed, CDS_N);
    memcpy(buf + CDS_N, addr, CDS_SHA256_ADDR_BYTES);
    mgf1_256(bitmask, inblocks * CDS_N, buf, CDS_N + CDS_SHA256_ADDR_BYTES);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx->state_seeded, 40 * sizeof(uint8_t));

    for (i = 0; i < inblocks * CDS_N; i++) {
        buf[CDS_N + CDS_SHA256_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    sha256_inc_finalize(outbuf, sha2_state, buf + CDS_N,
                        CDS_SHA256_ADDR_BYTES + inblocks*CDS_N);
    memcpy(out, outbuf, CDS_N);
}

#if CDS_SHA512
static void thash_512(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const CDS_ctx *ctx, uint32_t addr[8])
{
    unsigned char outbuf[CDS_SHA512_OUTPUT_BYTES];
    CDS_VLA(uint8_t, bitmask, inblocks * CDS_N);
    CDS_VLA(uint8_t, buf, CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N);
    uint8_t sha2_state[72];
    unsigned int i;

    memcpy(buf, ctx->pub_seed, CDS_N);
    memcpy(buf + CDS_N, addr, CDS_SHA256_ADDR_BYTES);
    mgf1_512(bitmask, inblocks * CDS_N, buf, CDS_N + CDS_SHA256_ADDR_BYTES);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx->state_seeded_512, 72 * sizeof(uint8_t));

    for (i = 0; i < inblocks * CDS_N; i++) {
        buf[CDS_N + CDS_SHA256_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    sha512_inc_finalize(outbuf, sha2_state, buf + CDS_N,
                        CDS_SHA256_ADDR_BYTES + inblocks*CDS_N);
    memcpy(out, outbuf, CDS_N);
}
#endif
