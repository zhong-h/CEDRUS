#include <stdint.h>
#include <string.h>

#include "address.h"
#include "utils.h"
#include "params.h"
#include "hash.h"
#include "sha256.h"

#if CDS_N==32
#define CDS_SHAX_OUTPUT_BYTES CDS_SHA512_OUTPUT_BYTES
#define CDS_SHAX_BLOCK_BYTES CDS_SHA512_BLOCK_BYTES
#define shaX_inc_init sha512_inc_init
#define shaX_inc_blocks sha512_inc_blocks
#define shaX_inc_finalize sha512_inc_finalize
#define shaX sha512
#define mgf1_X mgf1_512
#else
#define CDS_SHAX_OUTPUT_BYTES CDS_SHA256_OUTPUT_BYTES
#define CDS_SHAX_BLOCK_BYTES CDS_SHA256_BLOCK_BYTES
#define shaX_inc_init sha256_inc_init
#define shaX_inc_blocks sha256_inc_blocks
#define shaX_inc_finalize sha256_inc_finalize
#define shaX sha256
#define mgf1_X mgf1_256
#endif


/* For SHA, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
void initialize_hash_function(const unsigned char *pub_seed,
                              const unsigned char *sk_seed)
{
    seed_state(pub_seed);
    (void)sk_seed; /* Suppress an 'unused parameter' warning. */
}

/*
 * Computes PRF(key, addr), given a secret key of CDS_N bytes and an address
 */
void prf_addr(unsigned char *out, const unsigned char *key,
              const uint32_t addr[8])
{
    unsigned char buf[CDS_N + CDS_SHA256_ADDR_BYTES];
    unsigned char outbuf[CDS_SHA256_OUTPUT_BYTES];

    memcpy(buf, key, CDS_N);
    memcpy(buf + CDS_N, addr, CDS_SHA256_ADDR_BYTES);

    sha256(outbuf, buf, CDS_N + CDS_SHA256_ADDR_BYTES);
    memcpy(out, outbuf, CDS_N);
}

/**
 * Computes the message-dependent randomness R, using a secret seed as a key
 * for HMAC, and an optional randomization value prefixed to the message.
 * This requires m to have at least CDS_SHAX_BLOCK_BYTES + CDS_N space
 * available in front of the pointer, i.e. before the message to use for the
 * prefix. This is necessary to prevent having to move the message around (and
 * allocate memory for it).
 */
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen)
{
    unsigned char buf[CDS_SHAX_BLOCK_BYTES + CDS_SHAX_OUTPUT_BYTES];
    uint8_t state[8 + CDS_SHAX_OUTPUT_BYTES];
    int i;

#if CDS_N > CDS_SHAX_BLOCK_BYTES
    #error "Currently only supports CDS_N of at most CDS_SHAX_BLOCK_BYTES"
#endif

    /* This implements HMAC-SHA */
    for (i = 0; i < CDS_N; i++) {
        buf[i] = 0x36 ^ sk_prf[i];
    }
    memset(buf + CDS_N, 0x36, CDS_SHAX_BLOCK_BYTES - CDS_N);

    shaX_inc_init(state);
    shaX_inc_blocks(state, buf, 1);

    memcpy(buf, optrand, CDS_N);

    /* If optrand + message cannot fill up an entire block */
    if (CDS_N + mlen < CDS_SHAX_BLOCK_BYTES) {
        memcpy(buf + CDS_N, m, mlen);
        shaX_inc_finalize(buf + CDS_SHAX_BLOCK_BYTES, state,
                            buf, mlen + CDS_N);
    }
    /* Otherwise first fill a block, so that finalize only uses the message */
    else {
        memcpy(buf + CDS_N, m, CDS_SHAX_BLOCK_BYTES - CDS_N);
        shaX_inc_blocks(state, buf, 1);

        m += CDS_SHAX_BLOCK_BYTES - CDS_N;
        mlen -= CDS_SHAX_BLOCK_BYTES - CDS_N;
        shaX_inc_finalize(buf + CDS_SHAX_BLOCK_BYTES, state, m, mlen);
    }

    for (i = 0; i < CDS_N; i++) {
        buf[i] = 0x5c ^ sk_prf[i];
    }
    memset(buf + CDS_N, 0x5c, CDS_SHAX_BLOCK_BYTES - CDS_N);

    shaX(buf, buf, CDS_SHAX_BLOCK_BYTES + CDS_SHAX_OUTPUT_BYTES);
    memcpy(R, buf, CDS_N);
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen)
{
#define CDS_TREE_BITS (CDS_FULL_HEIGHT-CDS_BOTTOM_TREE_HEIGHT)
#define CDS_TREE_BYTES ((CDS_TREE_BITS + 7) / 8)
#define CDS_LEAF_BITS CDS_BOTTOM_TREE_HEIGHT
#define CDS_LEAF_BYTES ((CDS_LEAF_BITS + 7) / 8)
#define CDS_DGST_BYTES (CDS_FORS_MSG_BYTES + CDS_TREE_BYTES + CDS_LEAF_BYTES)

    unsigned char seed[2*CDS_N + CDS_SHAX_OUTPUT_BYTES];

    /* Round to nearest multiple of CDS_SHAX_BLOCK_BYTES */
#if (CDS_SHAX_BLOCK_BYTES & (CDS_SHAX_BLOCK_BYTES-1)) != 0
    #error "Assumes that CDS_SHAX_BLOCK_BYTES is a power of 2"
#endif
#define CDS_INBLOCKS (((CDS_N + CDS_PK_BYTES + CDS_SHAX_BLOCK_BYTES - 1) & \
                        -CDS_SHAX_BLOCK_BYTES) / CDS_SHAX_BLOCK_BYTES)
    unsigned char inbuf[CDS_INBLOCKS * CDS_SHAX_BLOCK_BYTES];

    unsigned char buf[CDS_DGST_BYTES];
    unsigned char *bufp = buf;
    uint8_t state[8 + CDS_SHAX_OUTPUT_BYTES];

    shaX_inc_init(state);

    // seed: SHA-256(R || PK.seed || PK.root || M)
    memcpy(inbuf, R, CDS_N);
    memcpy(inbuf + CDS_N, pk, CDS_PK_BYTES);

    /* If R + pk + message cannot fill up an entire block */
    if (CDS_N + CDS_PK_BYTES + mlen < CDS_INBLOCKS * CDS_SHAX_BLOCK_BYTES) {
        memcpy(inbuf + CDS_N + CDS_PK_BYTES, m, mlen);
        shaX_inc_finalize(seed + 2*CDS_N, state, inbuf, CDS_N + CDS_PK_BYTES + mlen);
    }
    /* Otherwise first fill a block, so that finalize only uses the message */
    else {
        memcpy(inbuf + CDS_N + CDS_PK_BYTES, m,
               CDS_INBLOCKS * CDS_SHAX_BLOCK_BYTES - CDS_N - CDS_PK_BYTES);
        shaX_inc_blocks(state, inbuf, CDS_INBLOCKS);

        m += CDS_INBLOCKS * CDS_SHAX_BLOCK_BYTES - CDS_N - CDS_PK_BYTES;
        mlen -= CDS_INBLOCKS * CDS_SHAX_BLOCK_BYTES - CDS_N - CDS_PK_BYTES;
        shaX_inc_finalize(seed + 2*CDS_N, state, m, mlen);
    }

    // H_msg: MGF1-SHA-256(R || PK.seed || seed)
    memcpy(seed, R, CDS_N);
    memcpy(seed + CDS_N, pk, CDS_N);

    /* By doing this in two steps, we prevent hashing the message twice;
       otherwise each iteration in MGF1 would hash the message again. */
    mgf1_X(bufp, CDS_DGST_BYTES, seed, 2*CDS_N + CDS_SHAX_OUTPUT_BYTES);

    memcpy(digest, bufp, CDS_FORS_MSG_BYTES);
    bufp += CDS_FORS_MSG_BYTES;

#if CDS_TREE_BITS > 64
    #error For given height and depth, 64 bits cannot represent all subtrees
#endif

    *tree = bytes_to_ull(bufp, CDS_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - CDS_TREE_BITS);
    bufp += CDS_TREE_BYTES;

    *leaf_idx = bytes_to_ull(bufp, CDS_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - CDS_LEAF_BITS);
}


