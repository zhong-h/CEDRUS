# CEDRUS

This repository provides the implementations and parameter-search code accompanying our paper on the CEDRUS family of hash-based signature schemes. It includes implementations of CEDRUS-α, CEDRUS+, and CEDRUS+C, together with code for exploring their parameter sets.

## Repository structure

| Directory | Contents |
| --- | --- |
| [`cedrus-a/`](cedrus-a/) | Implementation of CEDRUS-α. |
| [`cedrusplus/`](cedrusplus/) | Implementation of CEDRUS+. |
| [`cedrusplusc/`](cedrusplusc/) | Implementation of CEDRUS+C. |
| [`para-search/`](para-search/) | Parameter-search script for CEDRUS-α, CEDRUS+, and CEDRUS+C and CEDRUS+C-FP. |

The implementation directories contain their own README files with further details about the code and parameter sets.

## CEDRUS+C-FP status

The CEDRUS+C-FP variant discussed in the paper is currently supported only by the parameter-search script [`CEDRUS+C-FP.py`](para-search/CEDRUS+C-FP.py). An implementation of the signature scheme is not yet provided.
