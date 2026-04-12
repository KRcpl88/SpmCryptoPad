# Phase 2: Synthesis of Phase 1 Findings

**Date:** 2026-04-11
**Synthesized from:** Turing, Rejewski, Friedman, Driscoll Phase 1 reports

---

## 1. Consensus Findings (All or Most Agents Agree)

### C1: The "≈ 24+ AES diffusion layers" comparison is MISLEADING
**Agents:** Turing, Rejewski, Friedman, Driscoll (4/4)
The serial cascade achieves full byte dependency, but this is NOT comparable to AES's MDS-based algebraic mixing. No formal differential/linear bounds exist. Recommendation: retract the AES comparison.

### C2: Masks provide ZERO differential resistance
**Agents:** Rejewski (primary), Friedman (confirmed), Driscoll (implicit)
XOR masks cancel in differential computations: S(x ⊕ m) ⊕ S(x' ⊕ m) = S(a) ⊕ S(a ⊕ Δx). The DDT of S is invariant across all mask values. Masks protect against absolute value recovery only.

### C3: S-box state space math is ACCURATE
**Agents:** All (4/4)
2^127 vs ~2^954,017 is correct. But this is not exploitable - the relevant security boundary is the 127-bit PRNG seed space, not the permutation space coverage.

### C4: No practical statistical distinguisher found for 3-round cipher
**Agents:** Friedman (primary), Driscoll (confirmed)
The S-box + cascade barrier blocks all PRNG isolation attacks. No byte-frequency, bigram, or cross-block correlation distinguisher identified.

### C5: Fisher-Yates is NAIVE, not standard - but 16 passes compensate
**Agents:** Rejewski (detailed analysis), Driscoll, Turing
Single-pass bias is massive (~24,000× at position 0). After 16 passes, total variation distance ≈ 0.6% - practically negligible. Document incorrectly calls it "Fisher-Yates."

### C6: Byte 127 is the WEAKEST position
**Agents:** Turing, Rejewski (2/2 who analyzed it)
Only 1 S-box operation per round (vs ~4 for interior bytes). Only touched by forward pass, never by reverse pass at byte 127 directly.

### C7: No block chaining - ECB-like mode
**Agents:** Turing, Friedman, Driscoll (3/3)
Inter-block variation relies entirely on PRNG state advancement. No ciphertext feedback. Document doesn't address mode-of-operation weaknesses.

### C8: No ciphertext authentication
**Agents:** Turing, Driscoll
Block substitution, reordering, and truncation attacks are possible. Driscoll: cross-message block substitution at same position is a zero-computation attack.

## 2. Key Contradiction / Disagreement

### D1: Key decomposition - Is effective security 2^128 or 2^254?

**Turing:** Claims S-box key (127 bits) and mask key (127 bits) can be attacked independently. Attack: guess S-box seed → generate S-box → verify against known plaintext by checking mask consistency. Total: 2^127 + 2^127 ≈ **2^128**.

**Driscoll:** Lists brute force as O(2^255) and says "No technique reduces below brute force" in his summary table. BUT also notes in NF-4 that "S-box / Mask Key Independence Enables Partitioned Search" and that learning the S-box reduces remaining search to 2^127.

**Rejewski:** Also identifies this in NF-5: "2^127 S-box seed guesses, each verifiable in O(1)" - supporting Turing's claim.

**RESOLUTION NEEDED:** Phase 3 should resolve: Is the key decomposition attack at 2^128 actually feasible? Driscoll should validate Turing's claim, and Turing should validate Driscoll's attack feasibility assessment.

### D2: S-box severity rating
**Friedman:** Recommends downgrading S-box state space from MEDIUM to LOW (not exploitable in practice).
**Turing, Rejewski:** Maintain MEDIUM (the PRNG linearity may contaminate S-box structure).
**RESOLUTION NEEDED:** Is the PRNG-generated S-box distinguishable from random?

## 3. New Attack Surfaces NOT in cryptanalysis.md

| # | Finding | Source | Severity |
|---|---------|--------|----------|
| N1 | Key decomposition: effective security ~2^128 not 2^254 | Turing, Rejewski | **HIGH** (if confirmed) |
| N2 | Masks transparent to differential cryptanalysis | Rejewski, Friedman | **MEDIUM** |
| N3 | Restricted differential trail space (low-byte-only propagation) | Rejewski | **MEDIUM** |
| N4 | No block chaining - ECB-like mode with PRNG-only variation | Turing, Friedman, Driscoll | **MEDIUM** |
| N5 | No ciphertext authentication - block substitution attacks | Turing, Driscoll | **MEDIUM-HIGH** |
| N6 | Byte 127 asymmetry - weakest position | Turing, Rejewski | **LOW-MEDIUM** |
| N7 | Two known-plaintext blocks theoretically determine key | Rejewski | **LOW** (solving is hard) |
| N8 | No key schedule - related-key attack surface | Rejewski | **LOW-MEDIUM** |
| N9 | Same S-box across all rounds and positions | Turing | **LOW** |
| N10 | CPA can recover partial S-box structure (low-byte classes) | Driscoll | **LOW** (doesn't lead to key recovery) |

## 4. Flaws in cryptanalysis.md

| # | Claim | Issue |
|---|-------|-------|
| F1 | "Fisher-Yates shuffled" | Incorrect - uses naive shuffle (swap with any element, not tail-only) |
| F2 | "≈ 24+ AES diffusion layers" | Misleading - different diffusion mechanism, no formal bounds |
| F3 | Only 2 findings listed | Misses at least 10 additional weaknesses (see §3 above) |
| F4 | "Does not make cipher immediately breakable" (S-box space) | Understates risk - PRNG linearity may contaminate S-box quality |
| F5 | No discussion of block mode of operation | Missing entirely - ECB-like behavior unaddressed |
| F6 | No discussion of authentication | Missing entirely |
| F7 | Effective key strength not analyzed | Key decomposition to ~2^128 not mentioned |

## 5. Phase 3 Cross-Review Assignments

Based on the most critical disagreements and questions:

| Reviewer | Reviews | Key Question |
|----------|---------|-------------|
| **Turing** → reviews Driscoll | Is Driscoll's O(2^255) correct, or does the key decomposition attack reduce to O(2^128)? Validate the CPA S-box partition attack. |
| **Rejewski** → reviews Friedman | Are Friedman's "non-findings" correct? Is the PRNG sub-period truly undetectable through the cipher? Validate the DDT invariance finding. |
| **Friedman** → reviews Rejewski | Is the restricted differential trail space (NF-2) a real concern? How does the low-byte-only propagation interact with 3 rounds? |
| **Driscoll** → reviews Turing | Validate the 2^128 key decomposition attack. How many known-plaintext blocks does it need? What is the per-guess verification cost? |
