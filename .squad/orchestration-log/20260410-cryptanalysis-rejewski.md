# Orchestration Report: Rejewski — S-box & Permutation Mathematical Analysis
**Date:** 2025-04-10  
**Agent:** Rejewski (Cipher Analyst)  
**Scope:** S-box construction, permutation layer, diffusion mechanisms, mathematical properties  
**Status:** ✅ Complete

---

## Assignment

Deep mathematical analysis of the SPM cipher's substitution and permutation layers:
- S-box generation and state space coverage
- Fisher-Yates shuffle correctness
- Permutation layer diffusion properties
- Byte-level vs. bit-level mixing
- Bidirectional pass effectiveness

## Deliverables

**Artifact:** `.squad/decisions/inbox/rejewski-sbox-analysis.md`

### Findings: 8 Total (3 HIGH, 2 MEDIUM, 3 POSITIVE design elements)

| # | Finding | Severity |
|---|---------|----------|
| 1.1 | PRNG state space (2^127) vs. permutation space (2^954,009): infinite gap | **HIGH** |
| 1.3 | Non-standard Fisher-Yates produces non-uniform distributions | **MEDIUM** |
| 2.2 | Additive-counter PRNG has algebraic structure exploitable for S-box recovery | **HIGH** |
| 2.3 | Overlapping 16-bit windows provide excellent cascading diffusion | **POSITIVE** |
| 3.1 | Byte-level permutation lacks bit-level algebraic mixing (cf. AES MixColumns) | **MEDIUM** |
| 3.2 | Per-block permutation re-shuffling resists slide attacks | **POSITIVE** |
| 4.1 | Bidirectional pass achieves full diffusion in one round | **POSITIVE** |
| 4.2 | Byte 127 receives fewer S-box transformations than other bytes | **LOW** |

---

## Key Conclusions

- **Diffusion architecture is sound.** The overlapping sliding-window S-box design with bidirectional passes is clever and achieves full block diffusion efficiently.
- **Critical weakness is the PRNG.** CSimplePrng64 confines S-boxes to 2^127 of 2^954,009 possible permutations — an infinitesimally small fraction.
- **S-box recovery is practical.** Given the key, reconstructing the S-box requires ~3M operations (Fisher-Yates replay).
- **Absence of bit-level mixing.** Diffusion depends entirely on cascading S-box windows, lacking the provable guarantees of algebraic mixing layers (MDS matrices).

## Assessment

**Strengths:**
- Overlapping windows provide excellent left-to-right diffusion in a single forward pass
- Per-block permutation re-shuffling defends against slide attacks
- Full bidirectional diffusion achieved in one complete round

**Weaknesses:**
- Infinite gap between achievable S-box space and theoretical permutation space
- Non-standard shuffle algorithm introduces subtle distribution bias
- Absence of algebraic mixing (e.g., MixColumns equivalent) reduces robustness

---

**Prepared by:** Rejewski, Cipher Analyst  
**Timestamp:** 2025-04-10T14:32:15Z
