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
    unsigned char buf[CDS_SHA256_ADDR_BYTES + inblocks*CDS_N];
    unsigned char outbuf[CDS_SHA256_OUTPUT_BYTES];
    uint8_t sha2_state[40];

    (void)pub_seed; /* Suppress an 'unused parameter' warning. */

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, state_seeded, 40 * sizeof(uint8_t));

    memcpy(buf, addr, CDS_SHA256_ADDR_BYTES);
    memcpy(buf + CDS_SHA256_ADDR_BYTES, in, inblocks * CDS_N);

    sha256_inc_finalize(outbuf, sha2_state, buf, CDS_SHA256_ADDR_BYTES + inblocks*CDS_N);
    memcpy(out, outbuf, CDS_N);
}
