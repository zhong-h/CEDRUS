#ifndef CDS_WOTS_H
#define CDS_WOTS_H

#include <stdint.h>

#include "params.h"
#include "context.h"

extern const unsigned int wots_w[];
extern const unsigned int wots_wlog[];
/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
#define wots_pk_from_sig CDS_NAMESPACE(wots_pk_from_sig)
void wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const CDS_ctx *ctx, uint32_t addr[8]);

/*
 * Compute the chain lengths needed for a given message hash
 */
#define chain_lengths CDS_NAMESPACE(chain_lengths)
void chain_lengths(unsigned int *lengths, const unsigned char *msg);

#endif
