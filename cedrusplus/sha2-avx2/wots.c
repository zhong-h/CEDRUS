#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "utilsx8.h"
#include "hash.h"
#include "hashx8.h"
#include "thash.h"
#include "thashx8.h"
#include "wots.h"
#include "wotsx8.h"
#include "address.h"
#include "params.h"

// TODO clarify address expectations, and make them more uniform.
// TODO i.e. do we expect types to be set already?
// TODO and do we expect modifications or copies?

/**
 * Computes up the chains
 */
const unsigned int wots_w[]    = CDS_WOTS_W_ARRAY;
const unsigned int wots_wlog[] = CDS_WOTS_LOGW_ARRAY;
static void gen_chain(unsigned char *out, const unsigned char *in,
                      unsigned int start[CDS_WOTS_LEN], unsigned int steps[CDS_WOTS_LEN],
                      const CDS_ctx *ctx, uint32_t addr[8]);
static void base_w(unsigned int *output, const int out_len,
                   const unsigned char *input,int start);
static void wots_checksum(unsigned int *csum_base_w,
                          const unsigned int *msg_base_w);

static void gen_chains(
        unsigned char *out,
        const unsigned char *in,
        unsigned int start[CDS_WOTS_LEN],
        unsigned int steps[CDS_WOTS_LEN],
        const CDS_ctx *ctx,
        uint32_t addr[8])
{
    uint32_t i, j, k, idx, watching;
    int done;
    unsigned char empty[CDS_N];
    unsigned char *bufs[8];
    uint32_t addrs[8*8];

    int l;
    uint16_t counts[CDS_MAX_WOTS_W] = { 0 };
    uint16_t idxs[CDS_WOTS_LEN];
    uint16_t total, newTotal;

    /* set addrs = {addr, addr, ..., addr} */
    for (j = 0; j < 8; j++) {
        memcpy(addrs+j*8, addr, sizeof(uint32_t) * 8);
    }

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, CDS_WOTS_LEN*CDS_N);

    /* Sort the chains in reverse order by steps using counting sort. */
    for (i = 0; i < CDS_WOTS_LEN; i++) {
        counts[steps[i]]++;
    }
    total = 0;
    for (l = CDS_MAX_WOTS_W - 1; l >= 0; l--) {
        newTotal = counts[l] + total;
        counts[l] = total;
        total = newTotal;
    }
    for (i = 0; i < CDS_WOTS_LEN; i++) {
        idxs[counts[steps[i]]] = i;
        counts[steps[i]]++;
    }

    /* We got our work cut out for us: do it! */
    for (i = 0; i < CDS_WOTS_LEN; i += 8) {
        for (j = 0; j < 8 && i+j < CDS_WOTS_LEN; j++) {
            idx = idxs[i+j];
            set_chain_addr(addrs+j*8, idx);
            bufs[j] = out + CDS_N * idx;
        }

        /* As the chains are sorted in reverse order, we know that the first
         * chain is the longest and the last one is the shortest.  We keep
         * an eye on whether the last chain is done and then on the one before,
         * et cetera. */
        watching = 7;
        done = 0;
        while (i + watching >= CDS_WOTS_LEN) {
            bufs[watching] = &empty[0];
            watching--;
        }

        for (k = 0;; k++) {
            while (k == steps[idxs[i+watching]]) {
                bufs[watching] = &empty[0];
                if (watching == 0) {
                    done = 1;
                    break;
                }
                watching--;
            }
            if (done) {
                break;
            }
            for (j = 0; j < watching + 1; j++) {
                set_hash_addr(addrs+j*8, k + start[idxs[i+j]]);
            }

            thashx8(bufs[0], bufs[1], bufs[2], bufs[3],
                    bufs[4], bufs[5], bufs[6], bufs[7],
                    bufs[0], bufs[1], bufs[2], bufs[3],
                    bufs[4], bufs[5], bufs[6], bufs[7], 1, ctx, addrs);
        }
    }
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void base_w(unsigned int *output, const int out_len,
                   const unsigned char *input, int start)
{
    int bitbuf = 0;
    int bits_in_buf = 0;
    const unsigned char *in = input;

    for (int i = 0; i < out_len; i++) {
        while (bits_in_buf < wots_wlog[start + i]) {
            bitbuf = (bitbuf << 8) | *in++;
            bits_in_buf += 8;
        }
        bits_in_buf -= wots_wlog[start + i];
        output[i] = (bitbuf >> bits_in_buf) & (wots_w[start + i] - 1);
    }
}

/* Computes the WOTS+ checksum over a message (in base_w). */
static void wots_checksum(unsigned int *csum_base_w,
                          const unsigned int *msg_base_w)
{
    unsigned int csum = 0;
    unsigned int i;

    /* Compute checksum. */
    for (i = 0; i < CDS_WOTS_LEN1; i++) {
        csum += wots_w[i]- 1 - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    size_t total_bits = 0;
    for (i = CDS_WOTS_LEN1; i < CDS_WOTS_LEN; i++) {
        total_bits += wots_wlog[i];
    }
    size_t csum_size = (total_bits + 7) / 8;
    unsigned char *csum_bytes = malloc(csum_size);
    csum = csum << ((8 - (total_bits % 8)) % 8);
    ull_to_bytes(csum_bytes, csum_size, csum);
    base_w(csum_base_w, CDS_WOTS_LEN2, csum_bytes,CDS_WOTS_LEN1);
    free(csum_bytes);
}

/* Takes a message and derives the matching chain lengths. */
void chain_lengths(unsigned int *lengths, const unsigned char *msg)
{
    base_w(lengths, CDS_WOTS_LEN1, msg,0);
    wots_checksum(lengths + CDS_WOTS_LEN1, lengths);
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const CDS_ctx *ctx, uint32_t addr[8])
{
    unsigned int steps[CDS_WOTS_LEN];
    unsigned int start[CDS_WOTS_LEN];
    uint32_t i;

    chain_lengths(start, msg);

    for (i = 0; i < CDS_WOTS_LEN; i++) {
        steps[i] = wots_w[i] - 1 - start[i];
    }

    gen_chains(pk, sig, start, steps, ctx, addr);
}

/*
 * This generates 8 sequential WOTS public keys
 * It also generates the WOTS signature if leaf_info indicates
 * that we're signing with one of these WOTS keys
 */
void wots_gen_leafx8(unsigned char *dest,
                   const CDS_ctx *ctx,
                   uint32_t leaf_idx, void *v_info) {
    struct leaf_info_x8 *info = v_info;
    uint32_t *leaf_addr = info->leaf_addr;
    uint32_t *pk_addr = info->pk_addr;
    unsigned int i, j, k;
    unsigned char pk_buffer[ 8 * CDS_WOTS_BYTES ];
    unsigned wots_offset = CDS_WOTS_BYTES;
    unsigned char *buffer;
    uint32_t wots_k_mask;
    unsigned wots_sign_index;

    if (((leaf_idx ^ info->wots_sign_leaf) & ~7) == 0) {
        /* We're traversing the leaf that's signing; generate the WOTS */
        /* signature */
        wots_k_mask = 0;
        wots_sign_index = info->wots_sign_leaf & 7; /* Which of of the 8 */
                                  /* slots do the signatures come from */
    } else {
        /* Nope, we're just generating pk's; turn off the signature logic */
        wots_k_mask = ~0;
	wots_sign_index = 0;
    }

    for (j = 0; j < 8; j++) {
        set_keypair_addr( leaf_addr + j*8, leaf_idx + j );
        set_keypair_addr( pk_addr + j*8, leaf_idx + j );
    }

    for (i = 0, buffer = pk_buffer; i < CDS_WOTS_LEN; i++, buffer += CDS_N) {
        uint32_t wots_k = info->wots_steps[i] | wots_k_mask; /* Set wots_k */
            /* to the step if we're generating a signature, ~0 if we're not */

        /* Start with the secret seed */
        for (j = 0; j < 8; j++) {
            set_chain_addr(leaf_addr + j*8, i);
            set_hash_addr(leaf_addr + j*8, 0);
            set_type(leaf_addr + j*8, CDS_ADDR_TYPE_WOTSPRF);
        }
        prf_addrx8(buffer + 0*wots_offset,
                   buffer + 1*wots_offset,
                   buffer + 2*wots_offset,
                   buffer + 3*wots_offset,
                   buffer + 4*wots_offset,
                   buffer + 5*wots_offset,
                   buffer + 6*wots_offset,
                   buffer + 7*wots_offset,
                   ctx, leaf_addr);

        for (j = 0; j < 8; j++) {
            set_type(leaf_addr + j*8, CDS_ADDR_TYPE_WOTS);
        }

        /* Iterate down the WOTS chain */
        for (k=0;; k++) {
            /* Check if one of the values we have needs to be saved as a */
            /* part of the WOTS signature */
            if (k == wots_k) {
                memcpy( info->wots_sig + i * CDS_N,
                        buffer + wots_sign_index*wots_offset, CDS_N );
            }

            /* Check if we hit the top of the chain */
            if (k == wots_w[i] - 1) break;

            /* Iterate one step on all 8 chains */
            for (j = 0; j < 8; j++) {
                set_hash_addr(leaf_addr + j*8, k);
            }
            thashx8(buffer + 0*wots_offset,
                    buffer + 1*wots_offset,
                    buffer + 2*wots_offset,
                    buffer + 3*wots_offset,
                    buffer + 4*wots_offset,
                    buffer + 5*wots_offset,
                    buffer + 6*wots_offset,
                    buffer + 7*wots_offset,
                    buffer + 0*wots_offset,
                    buffer + 1*wots_offset,
                    buffer + 2*wots_offset,
                    buffer + 3*wots_offset,
                    buffer + 4*wots_offset,
                    buffer + 5*wots_offset,
                    buffer + 6*wots_offset,
                    buffer + 7*wots_offset, 1, ctx, leaf_addr);
        }
    }

    /* Do the final thash to generate the public keys */
    thashx8(dest + 0*CDS_N,
            dest + 1*CDS_N,
            dest + 2*CDS_N,
            dest + 3*CDS_N,
            dest + 4*CDS_N,
            dest + 5*CDS_N,
            dest + 6*CDS_N,
            dest + 7*CDS_N,
            pk_buffer + 0*wots_offset,
            pk_buffer + 1*wots_offset,
            pk_buffer + 2*wots_offset,
            pk_buffer + 3*wots_offset,
            pk_buffer + 4*wots_offset,
            pk_buffer + 5*wots_offset,
            pk_buffer + 6*wots_offset,
            pk_buffer + 7*wots_offset, CDS_WOTS_LEN, ctx, pk_addr);
}
