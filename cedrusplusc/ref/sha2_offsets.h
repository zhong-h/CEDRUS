#if !defined( SHA2_OFFSETS_H_ )
#define SHA2_OFFSETS_H_

/*
 * Offsets of various fields in the address structure when we use SHA2 as
 * the cedrus+ hash function
 */

#define CDS_OFFSET_LAYER     0   /* The byte used to specify the Merkle tree layer */
#define CDS_OFFSET_TREE      1   /* The start of the 8 byte field used to specify the tree */
#define CDS_OFFSET_TYPE      9   /* The byte used to specify the hash type (reason) */
#define CDS_OFFSET_KP_ADDR2  12  /* The high byte used to specify the key pair (which one-time signature) */
#define CDS_OFFSET_KP_ADDR1  13  /* The low byte used to specify the key pair */
#define CDS_OFFSET_CHAIN_ADDR 17  /* The byte used to specify the chain address (which Winternitz chain) */
#define CDS_OFFSET_HASH_ADDR 21  /* The byte used to specify the hash address (where in the Winternitz chain) */
#define CDS_OFFSET_TREE_HGT  17  /* The byte used to specify the height of this node in the FORS or Merkle tree */
#define CDS_OFFSET_TREE_INDEX 18 /* The start of the 4 byte field used to specify the node in the FORS or Merkle tree */
#define CDS_OFFSET_COUNTER 14 /* The start of the 4 byte field used to specify the counter for the WOTS signature */

#define CDS_SHA2 1

#endif /* SHA2_OFFSETS_H_ */
