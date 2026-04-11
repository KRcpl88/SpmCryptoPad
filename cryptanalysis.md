# Cryptanalysis Findings

**Date:** 2025-07-15

---


## 1. Findings

| Priority | Finding | Severity | Rationale |
|----------|---------|----------|-----------|
| **#1** | **S-box state space** — Key-dependent S-box generated via PRNG with 2^127 seed space, covering an infinitesimal fraction of the 2^954,009 possible 16-bit permutations. | **MEDIUM** | Theoretical concern. Does not make cipher immediately breakable but violates principle of maximizing S-box space. Mitigated if CSPRNG is adopted (Finding #2). |
| **#2** | **Plaintext file-size leakage** — DWORD at offset 128 reveals exact plaintext length. | **LOW** | Enables content fingerprinting. Minor in most threat models. Include file size in first encrypted block. |


---

## 2. Non Findings

| # | Issue | Analysis | Finding |
|---|----------------|-------|------------|
| **1** | **Round Count:** AES uses 10–14 rounds on 128 bits. Increase round count to to 8–12. | Compares raw round counts without accounting for per-round diffusion rate. SPM's overlapping 2-byte sliding window (`s_SmForwardPass`: 127 steps, `s_SmReversePass`: 126 steps) creates a cascade where each step's output feeds the next step's input via the shared overlapping byte. A single forward pass propagates any byte change across all 128 bytes (left→right); the reverse pass does the same right→left. One SPM round achieves **full bidirectional block diffusion**. AES requires ~4 rounds for full block diffusion (ShiftRows + MixColumns). 3 SPM rounds = 6 full diffusion sweeps ≈ 24+ AES diffusion layers. | SPM achieves full block diffusion per round. **Recommendation:** "3 rounds provide strong diffusion coverage. However, resistance to differential and linear cryptanalysis at this round count is formally unknown. Commission targeted cryptanalysis to determine the actual security margin before changing the round count." |
| **2** | **PRNG**: PRNG state trivially recoverable from 8 outputs (O(4) work) | PRNG mask outputs cannot be directly observed from ciphertext. Each mask is consumed inside `S(plaintext[k:k+1] ⊕ mask)`, so extraction requires knowing both the plaintext AND the key-dependent S-box. Exploitation requires the key to be broken first (to derive both PRNGs and thus the S-box). The PRNG weakness is a **compounding factor** (full stream compromise after key recovery), not a primary attack vector. The sliding-window S-box structure prevents trivial extraction of mask values from known plaintext. | PRNG weakness enables full past/future block compromise once the password is brute-forced, but it is not independently exploitable without key knowledge. |
| **3** | **Password Weakness** | Password brute-force would be the cheapest, most practical attack. However, the cipher's security boundary assumes a using a full-strength 32-byte key. The password parsing algorithm is provided as a convenience to easily generate a strong key from a psuedo random password, but the algorithm does not rely on it for its security.  Proper secure implementation would use a full 256 bit key for secure encryption. | Password attacks are not in scope for cryptanalysis. |
| **4** | **Nonce entropy ~35 bits.** | Nonce entropy is estimated at ~30–50 bits depending on assumptions about clock resolution and process/thread ID predictability. The range matters: 35 bits vs 50 bits is a 32,768× difference in collision resistance (2^15). Pinning to a single point estimate obscures this uncertainty. Furthermore, the nonce is only used to prevent multiple ciphertexts from being used to attack the same key, because the nonce is effectiverly used as a one way hash of the key for each encryption session.  The fundamental cryptanalysis focuses on the security of the algorithm when used with a sigle key.  The nonce is only applicable to attacks that gather multiple ciphertext blocks accross multiple sessions | Use "**30–50 bits effective entropy**" consistently. Note that the lower bound (30 bits) implies 50% nonce collision probability after ~32,000 encryptions; the upper bound (50 bits) extends this to ~33 million. |


---

## 3. Cipher Strengths


**Overlapping sliding-window diffusion is structurally sound.** The core round function (`s_SmForwardPass` + `s_SmReversePass`) processes 127 + 126 = 253 overlapping 2-byte windows per round. Because each window overlaps the previous by one byte, and the S-box substitution is applied to the XOR'd result before moving to the next position, a change in any single input byte cascades through all 128 bytes in one directional pass. The bidirectional structure (forward then reverse) ensures complete mixing. This is a genuine design achievement — the cipher achieves per-round diffusion comparable to what AES achieves in ~4 rounds, despite operating on an 8× larger block.

The key-dependent 16-bit S-box (65,536 entries, Fisher-Yates shuffled) provides strong local nonlinearity at each sliding-window step, which further strengthens the avalanche cascade.


## 4. Recommendations

### 1. S-Box State Space Coverage — Acknowledged Limitation

**Decision:** Document that S-box generation is confined to 2^127 of 2^954,009 possible permutations.

**Rationale:**
- PRNG seed space: 2^127 (64-bit state + 63-bit odd key)
- Permutation space: 2^954,009 (from Stirling: log₂(65536!) ≈ 954,009)
- Infinitesimal coverage (~10^-287,615 of all permutations)
- Does not make cipher "immediately breakable," but violates principle of drawing S-boxes from large space

**Action:** If CSPRNG is adopted (Decision #1), this limitation is mitigated. Fixed S-boxes or properly seeded PRNGs both solve this.

**Severity:** MEDIUM

---

### 2. Plaintext File Size Leakage — Encrypt File Size

**Decision:** Encrypt the file size field or include it in first ciphertext block.

**Rationale:**
- Currently: plaintext DWORD at offset 128
- Leaks exact plaintext length, enabling content fingerprinting
- No impact in most threat models, but worth fixing for defense-in-depth

**Action:** Include file size in first encrypted block. Update file format version.

**Severity:** LOW

