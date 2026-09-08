#ifndef CDS_PARAMS_H
#define CDS_PARAMS_H

/* Hash output length in bytes. */
#define CDS_N 32
/* Height of the hypertree. */
#define CDS_FULL_HEIGHT 64
/* Number of subtree layer. */
#define CDS_D 16
/* FORS tree dimensions. */
#define CDS_FORS_HEIGHT 8
#define CDS_FORS_TREES 48
/* Winternitz parameter, */
#define CDS_WOTS_W_ARRAY {15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16}

/* The hash function is defined by linking a different hash.c file, as opposed
   to setting a #define constant. */

/* For clarity */
#define CDS_ADDR_BYTES 32

#define CDS_MAX_WOTS_W 16
#define CDS_WOTS_LEN 66

#define CDS_WOTS_S 487

#define CDS_WOTS_BYTES (CDS_WOTS_LEN * CDS_N)
#define CDS_WOTS_PK_BYTES CDS_WOTS_BYTES

/* Subtree size. */
#define CDS_TREE_HEIGHT (CDS_FULL_HEIGHT / CDS_D)
#if CDS_TREE_HEIGHT * CDS_D != CDS_FULL_HEIGHT
    #define CDS_BOTTOM_TREE_HEIGHT  (CDS_TREE_HEIGHT + 1)
#else
    #define CDS_BOTTOM_TREE_HEIGHT  CDS_TREE_HEIGHT 
#endif

/* FORS parameters. */

#define CDS_FORS_W 2
#define CDS_FORS_LOGW 1


#define CDS_FORS_MSG_BYTES (( (CDS_FORS_HEIGHT+CDS_FORS_LOGW) * CDS_FORS_TREES + 7) / 8)
#define CDS_FORS_BYTES ((CDS_FORS_HEIGHT + 1) * CDS_FORS_TREES * CDS_N)
#define CDS_FORS_PK_BYTES CDS_N

/* Resulting CDS sizes. */
#define CDS_BYTES (CDS_N + CDS_FORS_BYTES + CDS_D * CDS_WOTS_BYTES +\
                   CDS_FULL_HEIGHT * CDS_N)
#define CDS_PK_BYTES (2 * CDS_N)
#define CDS_SK_BYTES (2 * CDS_N + CDS_PK_BYTES)

/* Optionally, signing can be made non-deterministic using optrand.
   This can help counter side-channel attacks that would benefit from
   getting a large number of traces when the signer uses the same nodes. */
#define CDS_OPTRAND_BYTES 32

#include "../shake256_offsets.h"

#endif
