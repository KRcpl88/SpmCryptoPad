# Squad Decisions

## Revised Findings (2026-04-10)

### Revised Cryptanalysis Findings — Error Corrections

**Author:** Turing (Cipher Architect)
**Date:** 2025-07-15
**Scope:** Corrections to `.squad/decisions.md` (2025-04-10 cryptanalysis)

---

## 1. Error Correction Table

| # | Original Claim | Error | Correction |
|---|----------------|-------|------------|
| **E1** | Decision #6: "3 rounds insufficient for 1024-bit block. AES uses 10–14 rounds on 128 bits. Increase to 8–12." | Compares raw round counts without accounting for per-round diffusion rate. SPM's overlapping 2-byte sliding window (`s_SmForwardPass`: 127 steps, `s_SmReversePass`: 126 steps) creates a cascade where each step's output feeds the next step's input via the shared overlapping byte. A single forward pass propagates any byte change across all 128 bytes (left→right); the reverse pass does the same right→left. One SPM round achieves **full bidirectional block diffusion**. AES requires ~4 rounds for full block diffusion (ShiftRows + MixColumns). 3 SPM rounds = 6 full diffusion sweeps ≈ 24+ AES diffusion layers. | Remove the blanket "increase to 8–12 rounds" recommendation. Acknowledge that SPM achieves full block diffusion per round. **Revised recommendation:** "3 rounds provide strong diffusion coverage. However, resistance to differential and linear cryptanalysis at this round count is formally unknown. Commission targeted cryptanalysis to determine the actual security margin before changing the round count." Severity: **REVISED** (was HIGH, now deferred pending formal analysis). |
| **E2** | Decision #1: "PRNG state trivially recoverable from 8 outputs (O(4) work)" rated CRITICAL #1. Turing's history said "4 consecutive Rand() outputs." | Two errors. (a) Internal inconsistency: Turing said 4 outputs, Friedman correctly said 8 (4 outputs to reconstruct one 64-bit state word, 4 more for the second word, then key = difference). Correct answer: **8 outputs**. (b) "Trivially recoverable" is misleading — PRNG mask outputs cannot be directly observed from ciphertext. Each mask is consumed inside `S(plaintext[k:k+1] ⊕ mask)`, so extraction requires knowing both the plaintext AND the key-dependent S-box. Exploitation requires the password to be broken first (to derive both PRNGs and thus the S-box). The PRNG weakness is a **compounding factor** (full stream compromise after key recovery), not a primary attack vector. Driscoll noted this: "the sliding-window S-box structure prevents trivial extraction of mask values from known plaintext." | Fix the 4-vs-8 inconsistency (correct: 8 outputs). Downgrade from CRITICAL to **HIGH**. Reframe: PRNG weakness enables full past/future block compromise once the password is brute-forced, but it is not independently exploitable without key knowledge. |
| **E3** | Severity ordering led with PRNG (#1 CRITICAL) over No-KDF (#2 CRITICAL). | Password brute-force (no KDF) was originally the cheapest, most practical attack. However, per user directive (2026-04-10), password-path attacks are **out of scope** — the cipher's security boundary assumes a full-strength 32-byte key. With password attacks excluded, the remaining prioritization error is that PRNG was rated CRITICAL when it's only a compounding factor. | Reprioritize: No-authentication → CRITICAL #1, PRNG → HIGH #1, Nonce → HIGH #2. No-KDF → OUT OF SCOPE (per user directive). See revised table below. |
| **E4** | Decision #5: Nonce entropy "~35 bits." | Friedman's detailed analysis estimated "~30–50 bits" depending on assumptions about clock resolution and process/thread ID predictability. The range matters: 35 bits vs 50 bits is a 32,768× difference in collision resistance (2^15). Pinning to a single point estimate obscures this uncertainty. | Use "**30–50 bits effective entropy**" consistently. Note that the lower bound (30 bits) implies 50% nonce collision probability after ~32,000 encryptions; the upper bound (50 bits) extends this to ~33 million. |

---

## 2. Revised Severity-Ranked Findings

| Priority | Finding | Severity | Rationale |
|----------|---------|----------|-----------|
| **#1** | **No ciphertext authentication** — no MAC, HMAC, or AEAD construction. Bit-flipping and truncation attacks possible. Silent decryption to garbage. | **CRITICAL** | Enables active attacks. Plaintext file-size field at offset 128 exacerbates this. Standard requirement for any modern encryption scheme. |
| **#2** | **PRNG weakness** — `CSimplePrng64` is an additive counter (`state += key`). Given the full 32-byte key (both PRNG seeds), all blocks for all files encrypted with that key are compromised (no forward secrecy). Recovery requires 8 consecutive `Rand()` outputs + S-box knowledge. | **HIGH** | Compounding factor after key recovery. Not independently exploitable without the key. Replace with CSPRNG (ChaCha20 core / AES-CTR-DRBG / BCryptGenRandom). |
| **#3** | **Nonce entropy deficit** — 30–50 bits effective entropy from clock/tick/PID/TID sources, vs. 128 bytes available. Hardcoded "hash key" is public knowledge. | **HIGH** | Collision risk: 50% after 32K–33M encryptions depending on entropy estimate. Replace with `BCryptGenRandom`. |
| **#4** | **S-box state space** — Key-dependent S-box generated via PRNG with 2^127 seed space, covering an infinitesimal fraction of the 2^954,009 possible 16-bit permutations. | **MEDIUM** | Theoretical concern. Does not make cipher immediately breakable but violates principle of maximizing S-box space. Mitigated if CSPRNG is adopted (Finding #2). |
| **#5** | **Round count** — 3 rounds. Previously recommended 8–12; this recommendation is **withdrawn**. | **REVISED** | SPM's overlapping sliding-window achieves full block diffusion per round. 3 rounds = 6 full diffusion sweeps. Round count may be adequate from a diffusion standpoint. Formal differential/linear cryptanalysis needed to determine actual security margin. |
| **#6** | **Plaintext file-size leakage** — DWORD at offset 128 reveals exact plaintext length. | **LOW** | Enables content fingerprinting. Minor in most threat models. Include file size in first encrypted block. |
| — | **No KDF / Password brute-force** | **OUT OF SCOPE** | Per user directive: `ParsePasswordW/A` is a convenience feature only. The cipher's security boundary assumes a full-strength 32-byte key or a properly derived key via cryptographically secure KDF. Password-path attacks are acknowledged but not part of this cipher analysis. |

---

## 3. Cipher Strengths (Updated Assessment)

The original analysis undervalued the following design strength:

**Overlapping sliding-window diffusion is structurally sound.** The core round function (`s_SmForwardPass` + `s_SmReversePass`) processes 127 + 126 = 253 overlapping 2-byte windows per round. Because each window overlaps the previous by one byte, and the S-box substitution is applied to the XOR'd result before moving to the next position, a change in any single input byte cascades through all 128 bytes in one directional pass. The bidirectional structure (forward then reverse) ensures complete mixing. This is a genuine design achievement — the cipher achieves per-round diffusion comparable to what AES achieves in ~4 rounds, despite operating on an 8× larger block.

The key-dependent 16-bit S-box (65,536 entries, Fisher-Yates shuffled) provides strong local nonlinearity at each sliding-window step, which further strengthens the avalanche cascade.

---

## 4. Updated Recommendations

1. **Immediate (CRITICAL):** Add encrypt-then-MAC authentication (HMAC-SHA256 over nonce + file_size + ciphertext). Verify before decryption. This is the single most impactful security improvement for the core cipher.

2. **High priority:** Replace `CSimplePrng64` with a cryptographically secure PRNG for all key-dependent randomness (S-box generation, XOR masks). This eliminates the forward-secrecy weakness.

3. **High priority:** Replace nonce generation with `BCryptGenRandom(NULL, pNonce, 128, BCRYPT_USE_SYSTEM_PREFERRED_RNG)`. Remove the hardcoded hash key.

4. **Deferred:** Do NOT increase the round count from 3 to 8–12. The sliding-window structure achieves full diffusion per round, so the original recommendation was based on a flawed comparison. Instead, commission formal differential and linear cryptanalysis to determine whether 3 rounds provide adequate resistance to those specific attack classes. Adjust only if formal analysis reveals insufficient security margin.

5. **Low priority:** Encrypt the file-size field. Move it into the first ciphertext block.

6. **Out of scope:** KDF/password hardening — per user directive, `ParsePasswordW/A` is a convenience feature. The security boundary assumes a properly derived full-strength key.

---

*This document supersedes the round-count, PRNG severity, and prioritization aspects of the 2025-04-10 findings in `.squad/decisions.md`.*

---

## Critical Issues — SPM Cipher Cryptanalysis (2025-04-10)

### 1. PRNG Weakness (CSimplePrng64) — Replace Immediately

**Decision:** Replace CSimplePrng64 with cryptographically secure PRNG.

**Rationale:**
- Linear additive counter (state += key) is trivially recoverable from 8 outputs (O(4) work)
- Underpins all cipher randomness: S-box generation, XOR masks, permutation shuffling
- Trivial recovery compromises entire cipher

**Action:** Use ChaCha20 core, AES-CTR-DRBG, or Windows BCryptGenRandom for all key-dependent randomness.

**Severity:** ⚠️ REVISED — Downgraded from CRITICAL to HIGH per Revised Findings above. See section 2 for clarification.

---

### 2. No Key Derivation Function — Add KDF + Salt

**Decision:** ⚠️ Superseded — see Revised Findings above

**Rationale:**
- ⚠️ **OUT OF SCOPE** per user directive (2026-04-10). Password-path attacks are not within this cipher's security boundary.
- Original decision is acknowledged but no longer active guidance.

**Action:** N/A — Password convenience feature assumes proper key derivation or full-strength key at boundary.

**Severity:** OUT OF SCOPE

---

### 3. No Ciphertext Authentication — Add MAC or AEAD

**Decision:** Implement HMAC-SHA256 (encrypt-then-MAC) or adopt AEAD construction.

**Rationale:**
- No integrity check on ciphertext
- Bit-flipping attacks possible (attacker can manipulate ciphertext to produce controlled plaintext changes)
- Silent corruption undetectable — file decrypts to garbage with no warning
- File size field is plaintext, enabling truncation attacks

**Action:** Add HMAC-SHA256 covering nonce + file_size + ciphertext. Store authentication tag after ciphertext. Verify before decryption.

**Severity:** CRITICAL

---

### 4. Algorithm Naming Convention — Use "SPM" not "SPN"

**Decision:** Refer to cipher as SPM (Substitution-Permutation-Mask), not SPN.

**Rationale:** User clarification: SPM more accurately reflects the three core operations (substitution, permutation, XOR masking).

**Action:** Update all team references, documentation, and code comments to use "SPM."

**Severity:** LOW (documentation/clarity)

---

### 5. Nonce Entropy Deficit — Use BCryptGenRandom

**Decision:** Replace time/PID/TID-based nonce generation with cryptographically secure random bytes.

**Rationale:**
- ⚠️ **REVISED ESTIMATE** (see Revised Findings): 30–50 bits effective entropy (was ~35 bits)
- Required: 128 bits (to fill 128-byte nonce)
- Deficit: 78–98 bits
- Current nonce collision risk: 50% after ~32K–33M encryptions (range depends on entropy estimate)
- Hardcoded "hash key" is public knowledge, provides no security

**Action:** Use `BCryptGenRandom(NULL, pNonce, 128, BCRYPT_USE_SYSTEM_PREFERRED_RNG)` for full nonce generation. Remove hardcoded key. No "hashing" needed — nonce is not secret.

**Severity:** HIGH

---

### 6. Insufficient Round Count — Increase to 8–12

**Decision:** ⚠️ Superseded — see Revised Findings above

**Rationale:**
- ⚠️ **WITHDRAWN** (original recommendation was based on flawed comparison). See Revised Findings section 1, error E1.
- SPM's overlapping sliding-window achieves full block diffusion per round (1 round ≈ 6 AES diffusion layers)
- 3 rounds may be adequate; formal cryptanalysis needed, not blanket round increase

**Action:** Commission formal differential/linear cryptanalysis instead of arbitrary round increase. Do not increase round count without formal analysis showing insufficient security margin.

**Severity:** REVISED (deferred pending formal analysis)

### 7. S-Box State Space Coverage — Acknowledged Limitation

**Decision:** Document that S-box generation is confined to 2^127 of 2^954,009 possible permutations.

**Rationale:**
- PRNG seed space: 2^127 (64-bit state + 63-bit odd key)
- Permutation space: 2^954,009 (from Stirling: log₂(65536!) ≈ 954,009)
- Infinitesimal coverage (~10^-287,615 of all permutations)
- Does not make cipher "immediately breakable," but violates principle of drawing S-boxes from large space

**Action:** If CSPRNG is adopted (Decision #1), this limitation is mitigated. Fixed S-boxes or properly seeded PRNGs both solve this.

**Severity:** MEDIUM

---

### 8. Plaintext File Size Leakage — Encrypt File Size

**Decision:** Encrypt the file size field or include it in first ciphertext block.

**Rationale:**
- Currently: plaintext DWORD at offset 128
- Leaks exact plaintext length, enabling content fingerprinting
- No impact in most threat models, but worth fixing for defense-in-depth

**Action:** Include file size in first encrypted block. Update file format version.

**Severity:** LOW

### 9. Password Directive — Out of Scope (2026-04-10)

**Decision:** Password-path attacks are out of scope. The cipher's security boundary assumes a full-strength 32-byte key.

**Rationale:**
- `ParsePasswordW/A` is a convenience feature only, not the intended security boundary.
- User directive: The real algorithm is based on a full 32-byte key.
- ParsePassword is known to be insecure. A proper implementation would use a sufficiently secure key or a crypto-secure one-way hash on a sufficiently complex password to cover the full key space.
- Analysis focus: the core cipher algorithm assuming a properly derived full-strength key.

**Action:** Disregard all attacks on password/ParsePassword in threat model analysis. Security boundary is the key derivation and key strength, not the password convenience wrapper.

**Severity:** GOVERNANCE

---

## Governance

- All meaningful changes require team consensus
- Document architectural decisions here
- Keep history focused on work, decisions focused on direction
