#include <stdint.h>
#include <string.h>

#include "thash.h"
#include "address.h"
#include "params.h"
#include "sha256.h"

/**
 * Takes an array of inblocks concatenated arrays of CDS_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned char buf[CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N];
    unsigned char outbuf[CDS_SHA256_OUTPUT_BYTES];
    unsigned char bitmask[inblocks * CDS_N];
    uint8_t sha2_state[40];
    unsigned int i;

    memcpy(buf, pub_seed, CDS_N);
    memcpy(buf + CDS_N, addr, CDS_SHA256_ADDR_BYTES);
    mgf1_256(bitmask, inblocks * CDS_N, buf, CDS_N + CDS_SHA256_ADDR_BYTES);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, state_seeded, 40 * sizeof(uint8_t));

    for (i = 0; i < inblocks * CDS_N; i++) {
        buf[CDS_N + CDS_SHA256_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    sha256_inc_finalize(outbuf, sha2_state, buf + CDS_N,
                        CDS_SHA256_ADDR_BYTES + inblocks*CDS_N);
    memcpy(out, outbuf, CDS_N);
}
