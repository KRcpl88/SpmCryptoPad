# Orchestration Report: Friedman — Statistical & PRNG Analysis
**Date:** 2025-04-10  
**Agent:** Friedman (Statistician)  
**Scope:** PRNG statistical properties, nonce entropy, cross-block state continuity, avalanche properties  
**Status:** ✅ Complete

---

## Assignment

Statistical cryptanalysis of random number generation, entropy sources, and diffusion properties:
- CSimplePrng64 period structure and linear complexity
- PRNG state recovery complexity
- Nonce entropy quantification and collision risk
- Cross-block PRNG state vulnerability
- Avalanche and diffusion empirical modeling

## Deliverables

**Artifact:** `.squad/decisions/inbox/friedman-statistical.md`

### Findings: 5 Total (2 CRITICAL, 1 HIGH, 1 MEDIUM, 1 LOW-MEDIUM)

| # | Finding | Severity | Exploitability |
|---|---------|----------|----------------|
| 1 | PRNG state recoverable from 8 outputs | **CRITICAL** | Trivial (O(4) arithmetic) |
| 2 | Masks algebraically equivalent to S-box shift | **MEDIUM** | Requires known-plaintext |
| 3 | Full bidirectional stream compromise from any state | **CRITICAL** | Immediate once #1 is achieved |
| 4 | Nonce has ~35 bits entropy, collisions at ~185K ops | **HIGH** | Passive (timing observation) |
| 5 | Avalanche structurally sound but unproven | **LOW-MEDIUM** | Theoretical; needs empirical validation |

---

## Key Conclusions

**PRNG State Recovery:**
- Attack complexity: **O(4)** — negligible
- Given 8 consecutive 16-bit PRNG outputs, recover full 64-bit state and key with 4 trivial guesses
- Linear complexity over Z/(2^64): minimum possible (1), equivalent to Berlekamp-Massey convergence in 4 samples

**Nonce Entropy Deficit:**
- Effective entropy: ~35 bits (conservative: 30–40 bits, optimistic: 50–60 bits)
- Required for 1024-bit nonce: 128+ bits
- **Deficit: 68–98 bits**
- Birthday collision risk: 50% probability after ~185,000 encryptions (2^17.5)

**Stream Compromise:**
- Per-block PRNG state NOT reset; state evolves continuously across entire file
- Given state at any block B, compute state at B±k in O(1) each
- Recovery of PRNG state at ANY point compromises ALL blocks (past and future)

**Avalanche Properties:**
- Cascade mechanism is structurally sound (forward+reverse passes, overlapping windows)
- After 3 rounds: convergence toward 50% bit-flip rate (ideal)
- Caveat: S-box is PRNG-generated, not algebraically designed; no formal guarantees

---

## Recommendations

1. Replace CSimplePrng64 with CSPRNG (ChaCha20 core, AES-CTR, or OS BCryptGenRandom)
2. Use OS entropy for nonces: BCryptGenRandom(NULL, pNonce, 128, ...) for ≥128 bits
3. Add ciphertext feedback or proper mode of operation (CBC, CTR, GCM)
4. Empirically validate S-box differential/linear approximation properties
5. Remove hardcoded nonce "hash key" — provides no security

---

**Prepared by:** Friedman, Statistical Cryptanalyst  
**Timestamp:** 2025-04-10T14:32:15Z
