#include <stdint.h>
#include <string.h>

#include "address.h"
#include "utils.h"
#include "params.h"
#include "thashx8.h"
#include "sha2.h"
#include "sha256x8.h"
#include "sha256avx.h"

#if CDS_SHA512
#include "sha512x4.h"

static void thashx8_512(
    unsigned char *out0,
    unsigned char *out1,
    unsigned char *out2,
    unsigned char *out3,
    unsigned char *out4,
    unsigned char *out5,
    unsigned char *out6,
    unsigned char *out7,
    const unsigned char *in0,
    const unsigned char *in1,
    const unsigned char *in2,
    const unsigned char *in3,
    const unsigned char *in4,
    const unsigned char *in5,
    const unsigned char *in6,
    const unsigned char *in7,
    unsigned int inblocks,
    const CDS_ctx *ctx,
    uint32_t addrx8[8*8]
);
#endif

/**
 * 8-way parallel version of thash; takes 8x as much input and output
 */
void thashx8(unsigned char *out0,
             unsigned char *out1,
             unsigned char *out2,
             unsigned char *out3,
             unsigned char *out4,
             unsigned char *out5,
             unsigned char *out6,
             unsigned char *out7,
             const unsigned char *in0,
             const unsigned char *in1,
             const unsigned char *in2,
             const unsigned char *in3,
             const unsigned char *in4,
             const unsigned char *in5,
             const unsigned char *in6,
             const unsigned char *in7, unsigned int inblocks,
             const CDS_ctx *ctx, uint32_t addrx8[8*8])
{
#if CDS_SHA512
    if (inblocks > 1) {
        thashx8_512(
             out0, out1, out2, out3, out4, out5, out6, out7,
             in0, in1, in2, in3, in4, in5, in6, in7,
        inblocks, ctx, addrx8);
        return;
    }
#endif
    CDS_VLA(unsigned char, bufx8, 8 * (CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N));
    CDS_VLA(unsigned char, outbufx8, 8 * CDS_SHA256_OUTPUT_BYTES);
    CDS_VLA(unsigned char, bitmaskx8, 8 * (inblocks * CDS_N));
    unsigned int i;

    for (i = 0; i < 8; i++) {
        memcpy(bufx8 + i*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
               ctx->pub_seed, CDS_N);
        memcpy(bufx8 + CDS_N +
                         i*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
                         addrx8 + i*8, CDS_SHA256_ADDR_BYTES);
    }

    mgf1x8(bitmaskx8, inblocks * CDS_N,
           bufx8 + 0*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
           bufx8 + 1*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
           bufx8 + 2*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
           bufx8 + 3*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
           bufx8 + 4*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
           bufx8 + 5*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
           bufx8 + 6*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
           bufx8 + 7*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
           CDS_N + CDS_SHA256_ADDR_BYTES);

    for (i = 0; i < inblocks * CDS_N; i++) {
        bufx8[CDS_N + CDS_SHA256_ADDR_BYTES + i +
                0*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N)] =
            in0[i] ^ bitmaskx8[i + 0*(inblocks * CDS_N)];
        bufx8[CDS_N + CDS_SHA256_ADDR_BYTES + i +
                1*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N)] =
            in1[i] ^ bitmaskx8[i + 1*(inblocks * CDS_N)];
        bufx8[CDS_N + CDS_SHA256_ADDR_BYTES + i +
                2*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N)] =
            in2[i] ^ bitmaskx8[i + 2*(inblocks * CDS_N)];
        bufx8[CDS_N + CDS_SHA256_ADDR_BYTES + i +
                3*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N)] =
            in3[i] ^ bitmaskx8[i + 3*(inblocks * CDS_N)];
        bufx8[CDS_N + CDS_SHA256_ADDR_BYTES + i +
                4*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N)] =
            in4[i] ^ bitmaskx8[i + 4*(inblocks * CDS_N)];
        bufx8[CDS_N + CDS_SHA256_ADDR_BYTES + i +
                5*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N)] =
            in5[i] ^ bitmaskx8[i + 5*(inblocks * CDS_N)];
        bufx8[CDS_N + CDS_SHA256_ADDR_BYTES + i +
                6*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N)] =
            in6[i] ^ bitmaskx8[i + 6*(inblocks * CDS_N)];
        bufx8[CDS_N + CDS_SHA256_ADDR_BYTES + i +
                7*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N)] =
            in7[i] ^ bitmaskx8[i + 7*(inblocks * CDS_N)];
    }

    sha256x8_seeded(
        /* out */
        outbufx8 + 0*CDS_SHA256_OUTPUT_BYTES,
        outbufx8 + 1*CDS_SHA256_OUTPUT_BYTES,
        outbufx8 + 2*CDS_SHA256_OUTPUT_BYTES,
        outbufx8 + 3*CDS_SHA256_OUTPUT_BYTES,
        outbufx8 + 4*CDS_SHA256_OUTPUT_BYTES,
        outbufx8 + 5*CDS_SHA256_OUTPUT_BYTES,
        outbufx8 + 6*CDS_SHA256_OUTPUT_BYTES,
        outbufx8 + 7*CDS_SHA256_OUTPUT_BYTES,

        /* seed */
        ctx->state_seeded, 512,

        /* in */
        bufx8 + CDS_N + 0*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
        bufx8 + CDS_N + 1*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
        bufx8 + CDS_N + 2*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
        bufx8 + CDS_N + 3*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
        bufx8 + CDS_N + 4*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
        bufx8 + CDS_N + 5*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
        bufx8 + CDS_N + 6*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
        bufx8 + CDS_N + 7*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
        CDS_SHA256_ADDR_BYTES + inblocks*CDS_N /* len */
    );

    memcpy(out0, outbufx8 + 0*CDS_SHA256_OUTPUT_BYTES, CDS_N);
    memcpy(out1, outbufx8 + 1*CDS_SHA256_OUTPUT_BYTES, CDS_N);
    memcpy(out2, outbufx8 + 2*CDS_SHA256_OUTPUT_BYTES, CDS_N);
    memcpy(out3, outbufx8 + 3*CDS_SHA256_OUTPUT_BYTES, CDS_N);
    memcpy(out4, outbufx8 + 4*CDS_SHA256_OUTPUT_BYTES, CDS_N);
    memcpy(out5, outbufx8 + 5*CDS_SHA256_OUTPUT_BYTES, CDS_N);
    memcpy(out6, outbufx8 + 6*CDS_SHA256_OUTPUT_BYTES, CDS_N);
    memcpy(out7, outbufx8 + 7*CDS_SHA256_OUTPUT_BYTES, CDS_N);
}

#if CDS_SHA512
/**
 * 2x4-way parallel version of thash; this is for the uses of thash that are
 * based on SHA-512
 */
static void thashx8_512(
    unsigned char *out0,
    unsigned char *out1,
    unsigned char *out2,
    unsigned char *out3,
    unsigned char *out4,
    unsigned char *out5,
    unsigned char *out6,
    unsigned char *out7,
    const unsigned char *in0,
    const unsigned char *in1,
    const unsigned char *in2,
    const unsigned char *in3,
    const unsigned char *in4,
    const unsigned char *in5,
    const unsigned char *in6,
    const unsigned char *in7,
    unsigned int inblocks,
    const CDS_ctx *ctx,
    uint32_t addrx8[8*8])
{
    CDS_VLA(unsigned char, bufx8, 8 * (CDS_N + CDS_SHA256_ADDR_BYTES + inblocks * CDS_N));
    CDS_VLA(unsigned char, outbuf, 4 * CDS_SHA512_OUTPUT_BYTES);
    CDS_VLA(unsigned char, bitmaskx4, 4 * (inblocks * CDS_N));
    unsigned int i;

    for (i = 0; i < 8; i++) {
        memcpy(bufx8 + i*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
               ctx->pub_seed, CDS_N);
        memcpy(bufx8 + CDS_N +
                         i*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
                         addrx8 + i*8, CDS_SHA256_ADDR_BYTES);
    }

    mgf1x4_512(bitmaskx4, inblocks * CDS_N,
           bufx8 + 0*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
           bufx8 + 1*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
           bufx8 + 2*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
           bufx8 + 3*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
           CDS_N + CDS_SHA256_ADDR_BYTES);

    for (i = 0; i < inblocks * CDS_N; i++) {
        bufx8[CDS_N + CDS_SHA256_ADDR_BYTES + i +
                0*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N)] =
            in0[i] ^ bitmaskx4[i + 0*(inblocks * CDS_N)];
        bufx8[CDS_N + CDS_SHA256_ADDR_BYTES + i +
                1*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N)] =
            in1[i] ^ bitmaskx4[i + 1*(inblocks * CDS_N)];
        bufx8[CDS_N + CDS_SHA256_ADDR_BYTES + i +
                2*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N)] =
            in2[i] ^ bitmaskx4[i + 2*(inblocks * CDS_N)];
        bufx8[CDS_N + CDS_SHA256_ADDR_BYTES + i +
                3*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N)] =
            in3[i] ^ bitmaskx4[i + 3*(inblocks * CDS_N)];
    }

    mgf1x4_512(bitmaskx4, inblocks * CDS_N,
           bufx8 + 4*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
           bufx8 + 5*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
           bufx8 + 6*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
           bufx8 + 7*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
           CDS_N + CDS_SHA256_ADDR_BYTES);

    for (i = 0; i < inblocks * CDS_N; i++) {
        bufx8[CDS_N + CDS_SHA256_ADDR_BYTES + i +
                4*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N)] =
            in4[i] ^ bitmaskx4[i + 0*(inblocks * CDS_N)];
        bufx8[CDS_N + CDS_SHA256_ADDR_BYTES + i +
                5*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N)] =
            in5[i] ^ bitmaskx4[i + 1*(inblocks * CDS_N)];
        bufx8[CDS_N + CDS_SHA256_ADDR_BYTES + i +
                6*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N)] =
            in6[i] ^ bitmaskx4[i + 2*(inblocks * CDS_N)];
        bufx8[CDS_N + CDS_SHA256_ADDR_BYTES + i +
                7*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N)] =
            in7[i] ^ bitmaskx4[i + 3*(inblocks * CDS_N)];
    }

    sha512x4_seeded(
        outbuf + 0*CDS_SHA512_OUTPUT_BYTES,
        outbuf + 1*CDS_SHA512_OUTPUT_BYTES,
        outbuf + 2*CDS_SHA512_OUTPUT_BYTES,
        outbuf + 3*CDS_SHA512_OUTPUT_BYTES,
        ctx->state_seeded_512, /* seed */
        1024,                  /* seed length */
        bufx8 + CDS_N + 0*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
        bufx8 + CDS_N + 1*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
        bufx8 + CDS_N + 2*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
        bufx8 + CDS_N + 3*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
        CDS_SHA256_ADDR_BYTES + inblocks*CDS_N /* len */
    );

    memcpy(out0, outbuf + 0*CDS_SHA512_OUTPUT_BYTES, CDS_N);
    memcpy(out1, outbuf + 1*CDS_SHA512_OUTPUT_BYTES, CDS_N);
    memcpy(out2, outbuf + 2*CDS_SHA512_OUTPUT_BYTES, CDS_N);
    memcpy(out3, outbuf + 3*CDS_SHA512_OUTPUT_BYTES, CDS_N);

    sha512x4_seeded(
        outbuf + 0*CDS_SHA512_OUTPUT_BYTES,
        outbuf + 1*CDS_SHA512_OUTPUT_BYTES,
        outbuf + 2*CDS_SHA512_OUTPUT_BYTES,
        outbuf + 3*CDS_SHA512_OUTPUT_BYTES,
        ctx->state_seeded_512, /* seed */
        1024,                  /* seed length */
        bufx8 + CDS_N + 4*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
        bufx8 + CDS_N + 5*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
        bufx8 + CDS_N + 6*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
        bufx8 + CDS_N + 7*(CDS_N + CDS_SHA256_ADDR_BYTES + inblocks*CDS_N),
        CDS_SHA256_ADDR_BYTES + inblocks*CDS_N /* len */
    );

    memcpy(out4, outbuf + 0*CDS_SHA512_OUTPUT_BYTES, CDS_N);
    memcpy(out5, outbuf + 1*CDS_SHA512_OUTPUT_BYTES, CDS_N);
    memcpy(out6, outbuf + 2*CDS_SHA512_OUTPUT_BYTES, CDS_N);
    memcpy(out7, outbuf + 3*CDS_SHA512_OUTPUT_BYTES, CDS_N);
}
#endif
