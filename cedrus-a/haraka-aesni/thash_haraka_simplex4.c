#include <stdint.h>
#include <string.h>

#include "thashx4.h"
#include "address.h"
#include "params.h"

#include "harakax4.h"

/**
 * 4-way parallel version of thash; takes 4x as much input and output
 */
void thashx4(unsigned char *out0,
             unsigned char *out1,
             unsigned char *out2,
             unsigned char *out3,
             const unsigned char *in0,
             const unsigned char *in1,
             const unsigned char *in2,
             const unsigned char *in3, unsigned int inblocks,
             const unsigned char *pub_seed, uint32_t addrx4[4*8])
{
    unsigned char buf0[CDS_ADDR_BYTES + inblocks*CDS_N];
    unsigned char buf1[CDS_ADDR_BYTES + inblocks*CDS_N];
    unsigned char buf2[CDS_ADDR_BYTES + inblocks*CDS_N];
    unsigned char buf3[CDS_ADDR_BYTES + inblocks*CDS_N];
    unsigned char outbuf[32 * 4];
    unsigned char buf_tmp[64 * 4];

    (void)pub_seed; /* Suppress an 'unused parameter' warning. */

    if (inblocks == 1) {
        memset(buf_tmp, 0, 64 * 4);

        memcpy(buf_tmp,       addrx4 + 0*8, 32);
        memcpy(buf_tmp + 64,  addrx4 + 1*8, 32);
        memcpy(buf_tmp + 128, addrx4 + 2*8, 32);
        memcpy(buf_tmp + 192, addrx4 + 3*8, 32);

        memcpy(buf_tmp + CDS_ADDR_BYTES,       in0, CDS_N);
        memcpy(buf_tmp + CDS_ADDR_BYTES + 64,  in1, CDS_N);
        memcpy(buf_tmp + CDS_ADDR_BYTES + 128, in2, CDS_N);
        memcpy(buf_tmp + CDS_ADDR_BYTES + 192, in3, CDS_N);

        haraka512x4(outbuf, buf_tmp);

        memcpy(out0, outbuf,      CDS_N);
        memcpy(out1, outbuf + 32, CDS_N);
        memcpy(out2, outbuf + 64, CDS_N);
        memcpy(out3, outbuf + 96, CDS_N);
    } else {
        /* All other tweakable hashes*/
        memcpy(buf0, addrx4 + 0*8, 32);
        memcpy(buf1, addrx4 + 1*8, 32);
        memcpy(buf2, addrx4 + 2*8, 32);
        memcpy(buf3, addrx4 + 3*8, 32);

        memcpy(buf0 + CDS_ADDR_BYTES, in0, inblocks * CDS_N);
        memcpy(buf1 + CDS_ADDR_BYTES, in1, inblocks * CDS_N);
        memcpy(buf2 + CDS_ADDR_BYTES, in2, inblocks * CDS_N);
        memcpy(buf3 + CDS_ADDR_BYTES, in3, inblocks * CDS_N);

        haraka_Sx4(out0, out1, out2, out3, CDS_N,
                   buf0, buf1, buf2, buf3, CDS_ADDR_BYTES + inblocks*CDS_N);
    }
}
