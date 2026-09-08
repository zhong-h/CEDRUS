#include <stddef.h>
#include <string.h>
#include <stdint.h>

#include "api.h"
#include "params.h"
#include "wots.h"
#include "fors.h"
#include "hash.h"
#include "thash.h"
#include "address.h"
#include "randombytes.h"
#include "utils.h"
#include "merkle.h"

/*
 * Returns the length of a secret key, in bytes
 */
unsigned long long crypto_sign_secretkeybytes(void)
{
    return CRYPTO_SECRETKEYBYTES;
}

/*
 * Returns the length of a public key, in bytes
 */
unsigned long long crypto_sign_publickeybytes(void)
{
    return CRYPTO_PUBLICKEYBYTES;
}

/*
 * Returns the length of a signature, in bytes
 */
unsigned long long crypto_sign_bytes(void)
{
    return CRYPTO_BYTES;
}

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
unsigned long long crypto_sign_seedbytes(void)
{
    return CRYPTO_SEEDBYTES;
}

/*
 * Generates an CDS key pair given a seed of length
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed)
{
    CDS_ctx ctx;

    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    memcpy(sk, seed, CRYPTO_SEEDBYTES);

    memcpy(pk, sk + 2*CDS_N, CDS_N);

    memcpy(ctx.pub_seed, pk, CDS_N);
    memcpy(ctx.sk_seed, sk, CDS_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    /* Compute root node of the top-most subtree. */
    merkle_gen_root(sk + 3*CDS_N, &ctx);

    memcpy(pk + CDS_N, sk + 3*CDS_N, CDS_N);

    return 0;
}

/*
 * Generates an CDS key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
  unsigned char seed[CRYPTO_SEEDBYTES];
  randombytes(seed, CRYPTO_SEEDBYTES);
  crypto_sign_seed_keypair(pk, sk, seed);

  return 0;
}

/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk)
{
    CDS_ctx ctx;

    const unsigned char *sk_prf = sk + CDS_N;
    const unsigned char *pk = sk + 2*CDS_N;

    unsigned char optrand[CDS_N];
    unsigned char mhash[CDS_FORS_MSG_BYTES];
    unsigned char root[CDS_N];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    memcpy(ctx.sk_seed, sk, CDS_N);
    memcpy(ctx.pub_seed, pk, CDS_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, CDS_ADDR_TYPE_WOTS);
    set_type(tree_addr, CDS_ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    randombytes(optrand, CDS_N);
    /* Compute the digest randomization value. */
    gen_message_random(sig, sk_prf, optrand, m, mlen, &ctx);

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += CDS_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    fors_sign(sig, root, mhash, &ctx, wots_addr);
    sig += CDS_FORS_BYTES;

    uint32_t merkle_tree_heights[CDS_D];
    uint32_t num_k = CDS_FULL_HEIGHT - CDS_TREE_HEIGHT*CDS_D;
    for (uint32_t j = 0; j < num_k; j++) {
        merkle_tree_heights[j] = CDS_TREE_HEIGHT+1;
    }
    for (uint32_t j = num_k; j < CDS_D; j++) {
        merkle_tree_heights[j] = CDS_TREE_HEIGHT;
    }
    for (i = 0; i < CDS_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        merkle_sign(sig, root, &ctx, wots_addr, tree_addr, idx_leaf,merkle_tree_heights[i]);
        sig += CDS_WOTS_BYTES + merkle_tree_heights[i] * CDS_N;

        /* Update the indices for the next layer. */
        if (i + 1 < CDS_D) {
            idx_leaf = (tree & ((1 << merkle_tree_heights[i + 1]) - 1));
            tree = tree >> merkle_tree_heights[i + 1];
        }
    }
    *siglen = CDS_BYTES;

    return 0;
}

/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk)
{
    CDS_ctx ctx;
    const unsigned char *pub_root = pk + CDS_N;
    unsigned char mhash[CDS_FORS_MSG_BYTES];
    unsigned char wots_pk[CDS_WOTS_BYTES];
    unsigned char root[CDS_N];
    unsigned char leaf[CDS_N];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    if (siglen != CDS_BYTES) {
        return -1;
    }

    memcpy(ctx.pub_seed, pk, CDS_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, CDS_ADDR_TYPE_WOTS);
    set_type(tree_addr, CDS_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, CDS_ADDR_TYPE_WOTSPK);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional CDS_N is a result of the hash domain separator. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += CDS_N;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig(root, sig, mhash, &ctx, wots_addr);
    sig += CDS_FORS_BYTES;

    uint32_t merkle_tree_heights[CDS_D];
    uint32_t num_k = CDS_FULL_HEIGHT - CDS_TREE_HEIGHT*CDS_D;
    for (uint32_t j = 0; j < num_k; j++) {
        merkle_tree_heights[j] = CDS_TREE_HEIGHT+1;
    }
    for (uint32_t j = num_k; j < CDS_D; j++) {
        merkle_tree_heights[j] = CDS_TREE_HEIGHT;
    }

    /* For each subtree.. */
    for (i = 0; i < CDS_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */

        wots_pk_from_sig(wots_pk, sig, root, &ctx, wots_addr);
        sig += CDS_WOTS_BYTES;

        /* Compute the leaf node using the WOTS public key. */
        thash(leaf, wots_pk, CDS_WOTS_LEN, &ctx, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root(root, leaf, idx_leaf, 0, sig, merkle_tree_heights[i],
                     &ctx, tree_addr);
        sig += merkle_tree_heights[i] * CDS_N;

        /* Update the indices for the next layer. */
        if (i + 1 < CDS_D) {
            idx_leaf = (tree & ((1 << merkle_tree_heights[i + 1]) - 1));
            tree = tree >> merkle_tree_heights[i + 1];
        }
    }

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, CDS_N)) {
        return -1;
    }

    return 0;
}


/**
 * Returns an array containing the signature followed by the message.
 */
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk)
{
    size_t siglen;

    crypto_sign_signature(sm, &siglen, m, (size_t)mlen, sk);

    memmove(sm + CDS_BYTES, m, mlen);
    *smlen = siglen + mlen;

    return 0;
}

/**
 * Verifies a given signature-message pair under a given public key.
 */
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
{
    /* The API caller does not necessarily know what size a signature should be
       but cedrus+ signatures are always exactly CDS_BYTES. */
    if (smlen < CDS_BYTES) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    *mlen = smlen - CDS_BYTES;

    if (crypto_sign_verify(sm, CDS_BYTES, sm + CDS_BYTES, (size_t)*mlen, pk)) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    /* If verification was successful, move the message to the right place. */
    memmove(m, sm + CDS_BYTES, *mlen);

    return 0;
}
