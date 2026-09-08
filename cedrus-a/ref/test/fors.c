#include <stdio.h>
#include <string.h>

#include "../hash.h"
#include "../fors.h"
#include "../randombytes.h"
#include "../params.h"

int main()
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    unsigned char sk_seed[CDS_N];
    unsigned char pub_seed[CDS_N];
    unsigned char pk1[CDS_FORS_PK_BYTES];
    unsigned char pk2[CDS_FORS_PK_BYTES];
    unsigned char sig[CDS_FORS_BYTES];
    unsigned char m[CDS_FORS_MSG_BYTES];
    uint32_t addr[8] = {0};

    randombytes(sk_seed, CDS_N);
    randombytes(pub_seed, CDS_N);
    randombytes(m, CDS_FORS_MSG_BYTES);
    randombytes((unsigned char *)addr, 8 * sizeof(uint32_t));

    printf("Testing FORS signature and PK derivation.. \n");

    initialize_hash_function(pub_seed, sk_seed);

    puts("sign");
    fors_sign(sig, pk1, m, sk_seed, pub_seed, addr);
    puts("verify");
    fors_pk_from_sig(pk2, sig, m, pub_seed, addr);

    if (memcmp(pk1, pk2, CDS_FORS_PK_BYTES)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");
    return 0;
}
