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
           const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned char buf[CDS_N + CDS_ADDR_BYTES + inblocks*CDS_N];

    memcpy(buf, pub_seed, CDS_N);
    memcpy(buf + CDS_N, addr, CDS_ADDR_BYTES);
    memcpy(buf + CDS_N + CDS_ADDR_BYTES, in, inblocks * CDS_N);

    shake256(out, CDS_N, buf, CDS_N + CDS_ADDR_BYTES + inblocks*CDS_N);
}
