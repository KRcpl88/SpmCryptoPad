# Friedman — History

## Learnings

### 2025-07-14 — Initial Statistical Cryptanalysis

Completed full statistical analysis of SpmBlockCipher64 and supporting components. Key findings:

1. **CSimplePrng64 is a Weyl sequence** (`state += key mod 2^64`). It produces 4 × 16-bit slices per state advance. Full state+key recovery requires only 8 consecutive outputs with O(4) alignment guesses. Linear complexity is 1 over Z/(2^64). The low-16-bit slice has a sub-period of only 2^16 state advances (~345 blocks), providing a statistical distinguisher.

2. **Mask generator (m_prngMask)** produces 759 masks per block (3 rounds × 253). The mask-XOR-then-S-box composition `S(x ⊕ m)` has identical differential properties to the base S-box — masks add positional variation but zero independent entropy.

3. **Cross-block PRNG state** is never reset. The linear structure means state at any block gives full forward AND backward prediction of all masks. Any single-point state recovery compromises the entire file.

4. **Nonce entropy** is ~30–50 bits from clock/tick/FILETIME/PID/TID, with 100 of 128 bytes as zero padding. The hardcoded encryption key is a public bijection that adds zero entropy. Birthday collision risk at ~185K encryptions.

5. **Avalanche** is structurally sound — the 1-byte overlap cascade reaches all 128 bytes in one forward pass. After 3 rounds, bit-level diffusion converges to ~50%. No formal proof exists; the randomly-generated 16-bit S-box has expected differential uniformity of ~4–6.

**Cipher parameters memorized:** Block = 128 bytes, S-box = 16-bit (65536 entries), inflection = 127, cipher key = 32 bytes (two PRNGs × 16 bytes each), 3 rounds per block.
