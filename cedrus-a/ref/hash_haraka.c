#include <stdint.h>
#include <string.h>

#include "address.h"
#include "utils.h"
#include "params.h"

#include "haraka.h"
#include "hash.h"

void initialize_hash_function(const unsigned char *pk_seed,
                              const unsigned char *sk_seed)
{
    tweak_constants(pk_seed, sk_seed, CDS_N);
}

/*
 * Computes PRF(key, addr), given a secret key of CDS_N bytes and an address
 */
void prf_addr(unsigned char *out, const unsigned char *key,
              const uint32_t addr[8])
{
    /* Since CDS_N may be smaller than 32, we need a temporary buffer. */
    unsigned char outbuf[32];

    (void)key; /* Suppress an 'unused parameter' warning. */

    haraka256_sk(outbuf, (const void *)addr);
    memcpy(out, outbuf, CDS_N);
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value as well as the message.
 */
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen)
{
    uint8_t s_inc[65];

    haraka_S_inc_init(s_inc);
    haraka_S_inc_absorb(s_inc, sk_prf, CDS_N);
    haraka_S_inc_absorb(s_inc, optrand, CDS_N);
    haraka_S_inc_absorb(s_inc, m, mlen);
    haraka_S_inc_finalize(s_inc);
    haraka_S_inc_squeeze(R, CDS_N, s_inc);
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

    unsigned char buf[CDS_DGST_BYTES];
    unsigned char *bufp = buf;
    uint8_t s_inc[65];

    haraka_S_inc_init(s_inc);
    haraka_S_inc_absorb(s_inc, R, CDS_N);
    haraka_S_inc_absorb(s_inc, pk + CDS_N, CDS_N); // Only absorb root part of pk
    haraka_S_inc_absorb(s_inc, m, mlen);
    haraka_S_inc_finalize(s_inc);
    haraka_S_inc_squeeze(buf, CDS_DGST_BYTES, s_inc);

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
