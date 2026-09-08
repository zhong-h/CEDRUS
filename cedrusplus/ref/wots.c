#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "utilsx1.h"
#include "hash.h"
#include "thash.h"
#include "wots.h"
#include "wotsx1.h"
#include "address.h"
#include "params.h"

// TODO clarify address expectations, and make them more uniform.
// TODO i.e. do we expect types to be set already?
// TODO and do we expect modifications or copies?

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */
const unsigned int wots_w[]    = CDS_WOTS_W_ARRAY;
const unsigned int wots_wlog[] = CDS_WOTS_LOGW_ARRAY;
static void gen_chain(unsigned char *out, const unsigned char *in,
                      unsigned int start, unsigned int steps,
                      const CDS_ctx *ctx, uint32_t addr[8],uint32_t chain_idx);
static void base_w(unsigned int *output, const int out_len,
                   const unsigned char *input,int start);
static void wots_checksum(unsigned int *csum_base_w,
                          const unsigned int *msg_base_w);
                          

static void gen_chain(unsigned char *out, const unsigned char *in,
                      unsigned int start, unsigned int steps,
                      const CDS_ctx *ctx, uint32_t addr[8],uint32_t chain_idx)
{
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, CDS_N);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start+steps) && i < wots_w[chain_idx]; i++) {
        set_hash_addr(addr, i);
        thash(out, out, 1, ctx, addr);
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
        csum += wots_w[i] - 1 - msg_base_w[i];
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
    unsigned int lengths[CDS_WOTS_LEN];
    uint32_t i;

    chain_lengths(lengths, msg);

    for (i = 0; i < CDS_WOTS_LEN; i++) {
        set_chain_addr(addr, i);
        gen_chain(pk + i*CDS_N, sig + i*CDS_N,
                  lengths[i], wots_w[i] - 1 - lengths[i], ctx, addr,i);
    }
}
