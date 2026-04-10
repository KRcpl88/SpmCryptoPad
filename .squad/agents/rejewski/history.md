# Rejewski — History

## Learnings

- **2025-07-15 — S-box & Permutation Analysis completed.** Analyzed the full mathematical structure of the SPM block cipher. Key findings:
  - CSimplePrng64 is an additive counter (state += key mod 2^64) with 2^127 effective seed space. This confines S-boxes to a tiny subset of the ~2^954,009 possible 16-bit permutations. The PRNG's algebraic structure (low-bit periodicity, linear recurrence) makes it vulnerable to recovery attacks.
  - The shuffle algorithm is a non-standard Fisher-Yates (naive variant selecting from [0,n-1] instead of [i,n-1]), introducing non-uniform permutation distribution.
  - The overlapping 16-bit sliding-window S-box design is the cipher's strongest feature — it creates cascading byte dependencies that achieve full left-to-right diffusion in a single forward pass.
  - Bidirectional (forward + reverse) passes achieve full block diffusion per round. 3 rounds × (127 + 126) = 759 S-box lookups per block.
  - Byte 127 is an asymmetric weak point — processed only once per round vs. ~4 times for interior bytes.
  - Byte-level permutation lacks the algebraic mixing of AES's MixColumns; no MDS-style guaranteed diffusion bounds.
  - Static codebook layer adds security only if its key varies per deployment; otherwise it's obfuscation.
  - Report delivered to `.squad/decisions/inbox/rejewski-sbox-analysis.md`.
