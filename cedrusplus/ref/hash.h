#ifndef CDS_HASH_H
#define CDS_HASH_H

#include <stdint.h>
#include "context.h"
#include "params.h"

#define initialize_hash_function CDS_NAMESPACE(initialize_hash_function)
void initialize_hash_function(CDS_ctx *ctx);

#define prf_addr CDS_NAMESPACE(prf_addr)
void prf_addr(unsigned char *out, const CDS_ctx *ctx,
              const uint32_t addr[8]);

#define gen_message_random CDS_NAMESPACE(gen_message_random)
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const CDS_ctx *ctx);

#define hash_message CDS_NAMESPACE(hash_message)
void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const CDS_ctx *ctx);

#endif
