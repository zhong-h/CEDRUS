## CEDRUS-a

This repository contains the software that accompanies the CEDRUS-a.
The CEDRUS-a extends the hypertree strucure that underlies the SPHINCS-a framework, and plugs generalized hash-based one-time signatures. 

It is based on the [SPHINCS-a submission repository](https://github.com/sphincs-alpha/sphincs-a).

The standard reference implementation is contained in `ref`, while optimized implementations are provided in `shake-avx2`, `sha2-avx2`, and `haraka-aesni`, each corresponding to the respective hash function optimizations.

### Parameters

We present named instances for specific hash functions and concrete parameters for the security level, tree dimensions, inhomogeneous WOTS-a and FORC. This reference implementation allows for more flexibility, as parameters can be specified in a `params.h` file. The proposed parameter sets have been predefined in `ref/params/params-*.h`, and the hash function can be varied by linking with the different implementations of `hash.h`, i.e., `hash_haraka.c`, `hash_sha2.c` and `hash_shake.c`, as well as different implementations of `thash.h`, i.e., `*_robust.c` and `*_simple.c`. This is demonstrated in the `Makefile`. See the table below for a summary of the parameter sets. These parameters target the NIST security categories 1, 3 and 5; for each category, there is a parameter set geared towards either small signatures or fast signature generation.
 
|               | n  | h  | d  | log(t) | k  |                    w          | w' | bit security | pk bytes | sk bytes | sig bytes |
| :------------ | -: | -: | -: | -----: | -: | :---------------------------- | -: | -----------: | -------: | -------: | --------: |
| CEDRUS-a-128s | 16 | 64 |  8 |     13 | 11 |  $[31] \times [32]^{26}$      | 2  |          128 |       32 |       64 |     6,960 |
| CEDRUS-a-128f | 16 | 65 | 21 |      7 | 24 |  $[12]^{27} \times [13]^{10}$ | 2  |          128 |       32 |       64 |    16,560 |
| CEDRUS-a-192s | 24 | 66 |  8 |     11 | 19 |  $[31]^{17} \times [32]^{23}$ | 4  |          193 |       48 |       96 |    14,760 |
| CEDRUS-a-192f | 24 | 66 | 22 |      7 | 37 |  $[14]^{9} \times [15]^{42}$  | 2  |          193 |       48 |       96 |    35,640 |
| CEDRUS-a-256s | 32 | 65 |  9 |     11 | 27 |  $[38]^{17} \times [39]^{33}$ | 4  |          256 |       64 |      128 |    26,880 |
| CEDRUS-a-256f | 32 | 64 | 16 |      8 | 48 |  $[15]^{15} \times [16]^{51}$ | 2  |          256 |       64 |      128 |    49,696 |

### License

The project's [LICENSE](LICENSE) contains the CC0 1.0 Universal text and the MIT copyright and permission notice for the BearSSL-derived portions of [ref/haraka.c](ref/haraka.c). Third-party code retains its own applicable terms:

Preserve the applicable copyright notices, license conditions, and disclaimers when redistributing third-party code.