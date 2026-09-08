#ifndef CDS_PARAMS_H
#define CDS_PARAMS_H

/* Hash output length in bytes. */
#define CDS_N 16
/* Height of the hypertree. */
#define CDS_FULL_HEIGHT 66
/* Number of subtree layer. */
#define CDS_D 11
/* FORS tree dimensions. */
#define CDS_FORS_HEIGHT 13
#define CDS_FORS_TREES 9 
/* Winternitz parameter, */

#define CDS_WOTS_W_ARRAY {64, 64, 64, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128}
#define CDS_WOTS_LOGW_ARRAY {6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7}
#define CDS_MAX_WOTS_W 128

#define CDS_WOTS_LEN 18
#define WOTS_ZERO_BITS 5
#define CDS_FORS_ZERO_LAST_BITS 18 
#define WANTED_CHECKSUM  1047  /*(SUM_W - CDS_WOTS_LEN) / 2*/

/* The hash function is defined by linking a different hash.c file, as opposed
   to setting a #define constant. */

/* For clarity */
#define CDS_ADDR_BYTES 32

#define CDS_WOTS_BYTES (CDS_WOTS_LEN * CDS_N)
#define CDS_WOTS_PK_BYTES CDS_WOTS_BYTES

/* Subtree size. */
#define CDS_TREE_HEIGHT (CDS_FULL_HEIGHT / CDS_D)

#if CDS_TREE_HEIGHT * CDS_D != CDS_FULL_HEIGHT
    #define CDS_BOTTOM_TREE_HEIGHT  (CDS_TREE_HEIGHT + 1)
#else
    #define CDS_BOTTOM_TREE_HEIGHT  (CDS_TREE_HEIGHT) 
#endif

/* FORS parameters. */
#define CDS_FORS_MSG_BYTES ((CDS_FORS_HEIGHT * CDS_FORS_TREES + 7) / 8)
#define CDS_FORS_BYTES ((CDS_FORS_HEIGHT + 1) * CDS_FORS_TREES * CDS_N)
#define CDS_FORS_PK_BYTES CDS_N

/* Resulting CDS sizes. */
#define CDS_BYTES ((CDS_N + CDS_FORS_BYTES + CDS_D * CDS_WOTS_BYTES +\
                   CDS_FULL_HEIGHT * CDS_N+(CDS_D*COUNTER_SIZE))+COUNTER_SIZE)
#define CDS_PK_BYTES (2 * CDS_N)
#define CDS_SK_BYTES (2 * CDS_N + CDS_PK_BYTES)

#include "../shake_offsets.h"

/* custom upgrade parameter definitions */
#define COUNTER_SIZE 4


#endif
