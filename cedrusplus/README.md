## CEDRUS+

This repository contains the software that accompanies the CEDRUS+.
The CEDRUS+ extends the hypertree strucure that underlies the SPHINCS+ framework, and plugs generalized hash-based one-time signatures. 

It is based on the [SPHINCS+ submission repository](https://github.com/sphincs/sphincsplus) that contains the software that accompanies the [SPHINCS+ submission](https://sphincs.org/) to [NIST's Post-Quantum Cryptography](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography) project.

The standard reference implementation is contained in `ref`, while optimized implementations are provided in `shake-avx2`, `sha2-avx2`, and `haraka-aesni`, each corresponding to the respective hash function optimizations.

### Parameters

We present named instances for specific hash functions and concrete parameters for the security level, tree dimensions, inhomogeneous WOTS+ and FORS. This reference implementation allows for more flexibility, as parameters can be specified in a `params.h` file. The proposed parameter sets have been predefined in `ref/params/params-*.h`, and the hash function can be varied by linking with the different implementations of `hash.h`, i.e., `hash_haraka.c`, `hash_sha2.c` and `hash_shake.c`, as well as different implementations of `thash.h`, i.e., `*_robust.c` and `*_simple.c`. This is demonstrated in the `Makefile`. See the table below for a summary of the parameter sets. These parameters target the NIST security categories 1, 3 and 5; for each category, there is a parameter set geared towards either small signatures or fast signature generation.
 
|               | n  | h  | d  | log(t) | k  |                    w                       | bit security | pk bytes | sk bytes | sig bytes |
| :------------ | -: | -: | -: | -----: | -: | :----------------------------------------- | -----------: | -------: | -------: | --------: |
| CEDRUS+-128s  | 16 | 62 |  7 |     13 | 13 |  $[16]^{32} \times [8]^{3}$                |          130 |       32 |       64 |     7,840 |
| CEDRUS+-128f  | 16 | 64 | 16 |      7 | 29 |  $[4] \times [8]^{42} \times [8]^{3}$      |          128 |       32 |       64 |    16,528 |
| CEDRUS+-192s  | 24 | 64 |  7 |     13 | 18 |  $[16]^{48} \times [8]^{2} \times [16]$    |          194 |       48 |       96 |    16,176 |
| CEDRUS+-192f  | 24 | 68 | 17 |      7 | 37 |  $[8]^{56} \times [16]^{6} \times [8]^{3}$ |          195 |       48 |       96 |    35,280 |
| CEDRUS+-256s  | 32 | 66 |  8 |     13 | 23 |  $[16]^{64} \times [8]^{2} \times [16]$    |          259 |       64 |      128 |    29,600 |
| CEDRUS+-256f  | 32 | 64 | 16 |      9 | 43 |  $[16]^{64} \times [32]^{2}$               |          259 |       64 |      128 |    49,632 |

### License

The [LICENSE](LICENSE) preserves the upstream SPHINCS+ SPDX license expression. The corresponding public-domain declaration and full CC0-1.0, 0BSD, MIT-0, and MIT texts are provided in [LICENSES](LICENSES/). The upstream licensing options are subject to the following third-party exceptions:

Preserve the applicable copyright notices, license conditions, and disclaimers when redistributing third-party code.