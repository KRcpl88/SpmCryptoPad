# Turing — History

## Learnings

### Architecture Review (2025)

**Key file paths:**
- `CryptoPadLib/SpmBlockCipher64.h` / `.cpp` — Core cipher: `CSimplePrng64` (additive PRNG), `CSpmBlockCipher64` (SPN with 1024-bit block, 16-bit S-box, 3 rounds)
- `CryptoPadLib/CryptoPadUtils.h` / `.cpp` — Nonce generation (`GenNonce`), per-file key derivation (`ApplyNonce`), password-to-key (`ParsePasswordW`/`ParsePasswordA`), file encrypt/decrypt workflow
- `CryptoPad/framework.h` — ASSERT macro, `EFileCryptProcess` enum

**Cipher parameters:**
- Block: 128 bytes (1024 bits), 16 × 64-bit words
- S-box: 16-bit (65,536 entries), key-dependent, Fisher-Yates shuffled via PRNG
- Rounds: 3 (each = forward sliding-window + reverse sliding-window + optional byte permutation)
- Key: 32 bytes split into two `CSimplePrng64` seeds (m_prngSBox, m_prngMask)
- `k_cSpmBlockInflectionIndex` = 127 (controls sliding window extent)
- `BLOCK_MODE` defaults to `NoPermutation` (permutation layer disabled)

**Critical findings (revised 2025-07-15 — see turing-revised-findings.md):**
1. No KDF — `ParsePasswordW` uses simple character addition wrapping into key bytes. **CRITICAL #1** — dominant practical attack.
2. No ciphertext authentication (no MAC/HMAC/AEAD). **CRITICAL #2**.
3. `CSimplePrng64` is a predictable additive PRNG (state += key). Full state recoverable from **8** consecutive Rand() outputs (not 4 — corrected). Exploitation requires password/S-box knowledge first. **HIGH** (was CRITICAL — downgraded).
4. Nonce generated from low-entropy sources (clock, tick count, PID, TID). Effective entropy: **30–50 bits** (not ~35). **HIGH**.
5. Round count (3) — **no longer flagged as insufficient**. Overlapping sliding-window achieves full block diffusion per round; formal differential/linear analysis needed to assess actual margin.

**Patterns observed:**
- Cipher used as a one-way hash for nonce obfuscation and per-file key derivation (cipher-as-KDF pattern).
- File format: `[128-byte nonce | 4-byte plaintext size | ciphertext blocks]` — no authentication tag.
- Encryption processes data in 128KB chunks, block-aligned to 128 bytes.

### Revision Learnings (2025-07-15)

**What I got wrong and why:**

1. **Round-count comparison to AES was naïve.** I compared raw round counts (3 vs 10–14) without analyzing per-round diffusion rate. SPM's overlapping 2-byte sliding window (`s_SmForwardPass`: k=0..126, `s_SmReversePass`: k=125..0) creates a byte-by-byte cascade where each step's output feeds the next. A single forward pass achieves full left-to-right diffusion across 128 bytes; the reverse pass adds right-to-left. One SPM round ≈ 4+ AES rounds in diffusion terms. **Lesson:** Never compare round counts across ciphers without normalizing for diffusion rate per round.

2. **PRNG severity was overrated.** I initially ranked PRNG weakness as CRITICAL #1, but mask values are consumed inside `S(plaintext ⊕ mask)` — they can't be extracted without knowing both the plaintext and the key-dependent S-box. The PRNG weakness only compounds after the password is already broken. Password brute-force (no KDF) is the true dominant attack. **Lesson:** Rank vulnerabilities by practical exploitability, not theoretical weakness in isolation.

3. **Internal inconsistency on output count.** I wrote "4 consecutive Rand() outputs" while Friedman correctly identified 8. The CSimplePrng64::Rand() method returns 16-bit words from a 64-bit state, so 4 outputs reveal one state word, and 4 more reveal the next (from which the key is derived by subtraction). **Lesson:** Trace the actual code path (`Rand()` returns `SPM_SBOX_WORD` = 16 bits, state is 64 bits) before stating output counts.

4. **Nonce entropy point estimate vs range.** I accepted "~35 bits" without noting the significant uncertainty. The true range is 30–50 bits depending on clock resolution and PID/TID predictability assumptions. A 2^15 difference in collision resistance matters. **Lesson:** Always express entropy estimates as ranges when input source variability is uncertain.

5. **Undervalued the sliding-window design.** The overlapping cascade is a genuine architectural strength that the team initially dismissed. It achieves what traditional SPN ciphers need ShiftRows+MixColumns for, but across an 8× larger block. **Lesson:** Analyze novel constructions on their own merits before defaulting to "it's not standard, therefore weak."
