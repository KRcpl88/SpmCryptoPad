# Squad Decisions

## Critical Issues — SPM Cipher Cryptanalysis (2025-04-10)

### 1. PRNG Weakness (CSimplePrng64) — Replace Immediately

**Decision:** Replace CSimplePrng64 with cryptographically secure PRNG.

**Rationale:**
- Linear additive counter (state += key) is trivially recoverable from 8 outputs (O(4) work)
- Underpins all cipher randomness: S-box generation, XOR masks, permutation shuffling
- Trivial recovery compromises entire cipher

**Action:** Use ChaCha20 core, AES-CTR-DRBG, or Windows BCryptGenRandom for all key-dependent randomness.

**Severity:** CRITICAL

---

### 2. No Key Derivation Function — Add KDF + Salt

**Decision:** Implement PBKDF2-HMAC-SHA256, bcrypt, or Argon2id for password-to-key conversion.

**Rationale:**
- Current implementation: direct byte accumulation with no iterations, no salt
- 4-character password brute force: <1 minute on commodity hardware
- With bcrypt (cost 12): same attack becomes ~42 years
- Weakest link in current design — cipher strength is irrelevant if password is trivial to crack

**Action:**
- Add per-file random salt (generate with BCryptGenRandom, store in file header)
- Use minimum 100,000 PBKDF2 iterations OR bcrypt cost factor 12 OR Argon2id with >64MB memory

**Severity:** CRITICAL

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
- Current nonce: ~35 bits effective entropy (from clock/GetTickCount64/FILETIME/PID/TID)
- Required: 128 bits (to fill 128-byte nonce)
- Deficit: 93 bits
- Current nonce collision risk: 50% after ~185,000 encryptions
- Hardcoded "hash key" is public knowledge, provides no security

**Action:** Use `BCryptGenRandom(NULL, pNonce, 128, BCRYPT_USE_SYSTEM_PREFERRED_RNG)` for full nonce generation. Remove hardcoded key. No "hashing" needed — nonce is not secret.

**Severity:** HIGH

---

### 6. Insufficient Round Count — Increase to 8–12

**Decision:** Increase encryption rounds from 3 to 8–12.

**Rationale:**
- SPM: 3 rounds on 1024-bit block (8× larger than AES)
- AES: 10–14 rounds on 128-bit block
- Current 3 rounds insufficient; expected differential/linear cryptanalysis complexity unknown
- Design principle: more rounds = larger security margin

**Action:** Benchmark performance impact. Increase to 8–12 rounds. Commission formal cryptanalysis.

**Severity:** HIGH

---

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

## Governance

- All meaningful changes require team consensus
- Document architectural decisions here
- Keep history focused on work, decisions focused on direction
