#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "../wots.h"
#include "../api.h"
#include "../params.h"
#include "../randombytes.h"

#define CDS_MLEN 32
#define CDS_SIGNATURES 1

int main()
{
    int ret = 0;
    int i;

    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    unsigned char pk[CDS_N*CDS_WOTS_LEN];
    unsigned char sig[CDS_N*CDS_WOTS_LEN];
    unsigned char pub_seed[CDS_N];
    unsigned char m[CDS_MLEN];
    uint32_t addr[8];

    randombytes(m, CDS_MLEN);


    memset(sig,0,sizeof(sig));
    memset(addr,0,sizeof(addr));
    memset(pub_seed,0,sizeof(pub_seed));
    
    
    
    double st=clock();
    for(int T=0;T<1000;T++){
        wots_pk_from_sig(pk,sig,m,pub_seed,addr);
    }
    printf("%.6f\n",(clock()-st)/CLOCKS_PER_SEC);


    return ret;
}

