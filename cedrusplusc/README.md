## CEDRUS+C

This repository contains the software that accompanies the CEDRUS+C.
The CEDRUS+C extends the hypertree strucure that underlies the SPHINCS+C framework, and plugs generalized hash-based one-time signatures. 

It is based on the [SPHINCS+C submission repository](https://github.com/eyalr0/sphincsplusc).

The standard reference implementation is contained in `ref`, while optimized implementations are provided in `shake-avx2`.

### Parameters

We present named instances for specific hash functions and concrete parameters for the security level, tree dimensions, inhomogeneous WOTS+C and FORS+C. This reference implementation allows for more flexibility, as parameters can be specified in a `params.h` file. The proposed parameter sets have been predefined in `ref/params/params-*.h`, and the hash function can be varied by linking with the `hash_shake.c`, as well as different implementations of `thash.h`, i.e., `*_robust.c` and `*_simple.c`. This is demonstrated in the `Makefile`. See the table below for a summary of the parameter sets. These parameters target the NIST security categories 1, 3 and 5; for each category, there is a parameter set geared towards either small signatures or fast signature generation.
 
|               | n  | h  | d  |  a | k  |                    w          | a' | z_b | bit security | pk bytes | sk bytes | sig bytes |
| :------------ | -: | -: | -: | -: | -: | :---------------------------- | -: |  -: | -----------: | -------: | -------: | --------: |
| CEDRUS+C-128s | 16 | 66 | 11 | 13 | 9  |  $[64]^{3} \times [128]^{15}$ | 18 |  5  |          128 |       32 |       64 |     6,304 |
| CEDRUS+C-128f | 16 | 66 | 20 |  7 | 23 |  $[8] \times [16]^{31}$       | 6  |  1  |          128 |       32 |       64 |    14,340 |
| CEDRUS+C-192s | 24 | 66 |  9 | 13 | 15 |  $[64]^{31}$                  | 17 |  6  |          192 |       48 |       96 |    13,384 |
| CEDRUS+C-192f | 24 | 65 | 19 |  7 | 41 |  $[8] \times [16]^{47}$       | 10 |  1  |          192 |       48 |       96 |    31,424 |
| CEDRUS+C-256s | 32 | 67 | 10 | 12 | 23 |  $[64]^{42}$                  | 14 |  4  |          256 |       64 |      128 |    25,228 |
| CEDRUS+C-256f | 32 | 67 | 16 |  9 | 35 |  $[8] \times [16]^{63}$       | 8  |  1  |          256 |       64 |      128 |    46,212 |


### License

Following the original code from the SPHINCS+C submission repository, all included code is available under the CC0 1.0 Universal Public Domain Dedication, with the exception of rng.c, rng.h and PQCgenKAT_sign.c, which were provided by NIST.
