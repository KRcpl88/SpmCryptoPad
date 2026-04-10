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

**Critical findings:**
1. `CSimplePrng64` is a trivially predictable additive PRNG (state += key). Full state recoverable from 4 consecutive Rand() outputs.
2. No KDF — `ParsePasswordW` uses simple character addition wrapping into key bytes.
3. No ciphertext authentication (no MAC/HMAC/AEAD).
4. Nonce generated from low-entropy sources (clock, tick count, PID, TID) and "hashed" with a hardcoded key baked into the binary.
5. Only 3 rounds for a 1024-bit block — well below standard margins of safety.

**Patterns observed:**
- Cipher used as a one-way hash for nonce obfuscation and per-file key derivation (cipher-as-KDF pattern).
- File format: `[128-byte nonce | 4-byte plaintext size | ciphertext blocks]` — no authentication tag.
- Encryption processes data in 128KB chunks, block-aligned to 128 bytes.
