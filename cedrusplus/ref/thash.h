#ifndef CDS_THASH_H
#define CDS_THASH_H

#include "context.h"
#include "params.h"

#include <stdint.h>

#define thash CDS_NAMESPACE(thash)
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const CDS_ctx *ctx, uint32_t addr[8]);

#endif
