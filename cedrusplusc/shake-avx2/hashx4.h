#ifndef CDS_HASHX4_H
#define CDS_HASHX4_H

#include <stdint.h>
#include "context.h"

void prf_addrx4(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3,
                const cds_ctx *ctx,
                const uint32_t addrx4[4*8]);

#endif
