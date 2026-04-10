# Orchestration Report: Driscoll — Practical Attack Vectors
**Date:** 2025-04-10  
**Agent:** Driscoll (Attack Specialist)  
**Scope:** Concrete, exploitable attack vectors with step-by-step execution paths  
**Status:** ✅ Complete

---

## Assignment

Identification and analysis of practical attack vectors exploiting the SPM cipher:
- PRNG mask state recovery mechanisms
- S-box recovery feasibility
- Password/key brute force execution
- Nonce exploitation methods
- File format and block-level attacks

## Deliverables

**Artifact:** `.squad/decisions/inbox/driscoll-attacks.md`

### Findings: 6 Attacks (4 TRIVIAL, 1 EASY, 1 MODERATE)

| # | Attack | Feasibility | Time to Exploit |
|---|--------|------------|-----------------|
| 1 | PRNG Mask State Recovery | MODERATE (standalone) / EASY (via password brute force) | Subsumed by #3 |
| 2 | S-Box Recovery | EASY (via password) | ~3M operations |
| 3 | **Password/Key Brute Force** | **TRIVIAL–EASY** | **4-char: <1 min; 6-char: hours; dictionary: seconds** |
| 4 | Nonce Exploitation | TRIVIAL | Immediate (nonce plaintext) |
| 5 | File Format Exploitation | TRIVIAL | Immediate (no authentication) |
| 6 | Block-Level Attacks | TRIVIAL (given key) | Instant (deterministic PRNG) |

---

## Key Conclusions

**The Weakest Link: Password-to-Key Conversion**

- **No KDF:** Direct password → key conversion via byte accumulation with wrapping
- **No salt:** Identical passwords produce identical keys; rainbow tables directly applicable
- **No computational cost:** Each candidate evaluated in ~100 CPU operations
- **Comparison to bcrypt (cost 12):** Attack is ~125,000× faster because KDF iterations are absent

**Brute Force Attack Times (Commodity Hardware):**

| Scenario | 1 CPU Core | 16 Cores | GPU |
|----------|-----------|----------|-----|
| 4-char ASCII (~95^4 ≈ 8×10^7) | ~3 hours | ~12 min | **<1 minute** |
| 6-char ASCII (~95^6 ≈ 7×10^11) | ~3 years | ~70 days | **~hours** |
| Dictionary 10K | <1 sec | <1 sec | <1 sec |
| Wordlist 14M | ~30 sec | ~2 sec | <1 sec |

**File Format Weaknesses:**
- Nonce stored in plaintext (128 bytes, attackers already have it)
- File size stored in plaintext (enables content fingerprinting)
- No ciphertext authentication (silent tampering possible)
- Potential buffer over-read if attacker crafts false file_size

**Optimal Attack Chain:**

```
1. Read file header (nonce, file_size) — ZERO cost
2. Brute-force password with per-candidate cost ~6–7M ops
3. Validate decryption (check for UTF-16, known headers, etc.)
4. Decrypt entire file — trivial normal decryption speed
```

**Against 4-character password:** Total time <1 minute on commodity hardware.

---

## Most Exploitable Weakness

**No Key Derivation Function (KDF)**

- Cipher's theoretical strength becomes irrelevant when the password is brute-forced directly
- Adding bcrypt (cost 12) would increase 4-char attack from 3 hours to ~42 years
- Adding Argon2id would further exponentially increase cost
- Currently: security margin is the password entropy alone, not cipher strength

---

## Recommendations

1. **Immediate (Critical):**
   - Add PBKDF2-HMAC-SHA256 (minimum 100,000 iterations) or bcrypt/Argon2id
   - Use per-file random salt stored in file header
   - This single change makes attacks infeasible for typical passwords

2. **Secondary (High):**
   - Add ciphertext authentication (HMAC-SHA256 encrypt-then-MAC)
   - Encrypt the file_size field
   - Replace the nonce with BCryptGenRandom output

3. **Tertiary (Medium):**
   - Replace CSimplePrng64 with CSPRNG
   - Increase round count

---

**Prepared by:** Driscoll, Attack Specialist  
**Timestamp:** 2025-04-10T14:32:15Z
