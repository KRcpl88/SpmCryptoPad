# Driscoll — History

## Learnings

- **2025 — Full attack surface analysis completed.** Analyzed all six requested attack vectors against CSpmBlockCipher64. Key findings:
  - The PRNG (`CSimplePrng64`) is a Weyl sequence with only 127 effective bits. Eight consecutive 16-bit outputs fully recover state and key. However, the sliding-window S-box structure prevents trivial extraction of mask values from known plaintext.
  - The S-box is deterministic from 16 bytes of key material. Given the password, reconstruction costs ~3M operations.
  - **Password brute force is the dominant attack.** `ParsePasswordA` has no KDF, no salt, no iterations. A 4-char ASCII password falls in under 1 minute. Dictionary attacks against typical passwords succeed in under 1 hour. This completely bypasses the cipher's internal complexity.
  - The nonce is stored in plaintext in the file header. The hardcoded hash key (`szDefaultHashKey` in CryptoPadUtils.cpp:75) provides zero security — it's extractable from the binary and allows reversing the nonce to recover encryption timestamps, PID, and system uptime.
  - The codebook initialization key is also hardcoded (`"b6a4c072764a2233db9c23b0bc79c143"` in CryptoPad.cpp:102).
  - No ciphertext authentication (no MAC/HMAC) means silent tampering is trivial. The plaintext file_size DWORD at offset 128 leaks exact original file size.
  - No block chaining — PRNG advancement is the only inter-block variation. Given the key, any block can be decrypted independently (random-access).
  - The optimal attack chain is: read nonce from header → brute-force password → decrypt. For short passwords, this is minutes of work.
  - Turing's architectural review (in `.squad/decisions/inbox/turing-cipher-architecture.md`) independently identified the same structural weaknesses. My analysis confirms his findings with concrete exploit timings and step-by-step attack procedures.
  - Masks per block: 759 (3 rounds × (127 forward + 126 reverse)). S-box PRNG calls during PermuteSbox: 1,048,576. Cost per password candidate: ~6-7M operations.
