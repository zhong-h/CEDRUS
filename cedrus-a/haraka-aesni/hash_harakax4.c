#include <stdint.h>
#include <string.h>

#include "address.h"
#include "params.h"
#include "harakax4.h"
#include "hashx4.h"

/*
 * 4-way parallel version of prf_addr; takes 4x as much input and output
 */
void prf_addrx4(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3,
                const unsigned char *key,
                const uint32_t addrx4[4*8])
{
    unsigned char bufx4[4 * CDS_ADDR_BYTES];
    /* Since CDS_N may be smaller than 32, we need a temporary buffer. */
    unsigned char outbuf[4 * 32];
    unsigned int i;

    (void)key; /* Suppress an 'unused parameter' warning. */

    for (i = 0; i < 4; i++) {
        memcpy(bufx4 + i*CDS_ADDR_BYTES, addrx4 + i*8, CDS_ADDR_BYTES);
    }

    haraka256_skx4(outbuf, bufx4);

    memcpy(out0, outbuf, CDS_N);
    memcpy(out1, outbuf + 32, CDS_N);
    memcpy(out2, outbuf + 64, CDS_N);
    memcpy(out3, outbuf + 96, CDS_N);
}
