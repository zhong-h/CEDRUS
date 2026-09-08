#ifndef CDS_CONTEXT_H
#define CDS_CONTEXT_H

#include <stdint.h>

#include "params.h"

typedef struct {
    uint8_t pub_seed[CDS_N];
    uint8_t sk_seed[CDS_N];
} CDS_ctx;

#endif
