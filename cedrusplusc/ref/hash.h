#ifndef CDS_HASH_H
#define CDS_HASH_H

#include <stdint.h>
#include "context.h"

void initialize_hash_function(cds_ctx *ctx);

void prf_addr(unsigned char *out, const cds_ctx *ctx,
              const uint32_t addr[8]);

void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const cds_ctx *ctx);

int hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const cds_ctx *ctx, uint32_t *counter);

#endif
