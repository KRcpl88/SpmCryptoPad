# SPM vs AES-256 — Structural and Cryptanalytic Comparison

**Date:** 2026-04-11

---

## 1. Brute-Force Strength Comparison

| Property | AES-256 | SPM-256 |
|----------|---------|---------|
| Key size | 256 bits | 256 bits (254 effective) |
| Brute force complexity | O(2^256) | O(2^254) |
| Best known cryptanalytic attack | O(2^254.4) biclique — theoretical, not practical | O(2^254) brute force — no shortcut found |
| Practical security margin | ~2^254 | ~2^254 |

Both ciphers are effectively unbreakable by brute force. The 2-bit difference (254 vs 256) is negligible — both require work far beyond any conceivable computation.

---

## 2. Algorithmic Complexity Comparison

### AES-256: 14 Rounds × 4 Operations per Round

Each AES round applies four distinct transformations in sequence:

1. **SubBytes** — substitute each byte through a fixed 256-entry S-box (derived from GF(2^8) multiplicative inverse + affine transform)
2. **ShiftRows** — cyclically shift each row of the 4×4 state matrix by a fixed offset
3. **MixColumns** — multiply each column by a fixed 4×4 matrix over GF(2^8)
4. **AddRoundKey** — XOR the state with a 128-bit round key derived from the key schedule

Plus a **key schedule** that expands the 256-bit key into 15 × 128-bit round keys using SubBytes, rotation, and round constants.

**Total operations per block:** 14 rounds × 16 S-box lookups = 224 S-box lookups, plus 14 × 16 GF(2^8) multiplications (MixColumns), plus 14 × 128-bit XORs (AddRoundKey).

### SPM-256: 3 Rounds × 253 Cascade Steps per Round

Each SPM round applies a single repeated operation in a bidirectional cascade:

1. **Forward pass (k = 0..126):** `block[k:k+2] = S[block[k:k+2] ⊕ mask_k]` — XOR a 16-bit mask, then substitute through a 65,536-entry S-box
2. **Reverse pass (k = 125..0):** Same operation, traversing backward

No matrix multiplication. No row shifting. No key schedule. No round constants.

**Total operations per block:** 3 rounds × 253 steps = 759 S-box lookups + 759 XORs.

### Side-by-Side

| Dimension | AES-256 | SPM-256 |
|-----------|---------|---------|
| Rounds | 14 | 3 |
| Distinct operation types per round | 4 (SubBytes, ShiftRows, MixColumns, AddRoundKey) | 1 (XOR + S-box lookup) |
| S-box lookups per block | 224 (8-bit) | 759 (16-bit) |
| Matrix multiplications per block | 160 (GF(2^8)) | 0 |
| Key schedule complexity | Complex — 15 round keys via SubWord, RotWord, Rcon | None — two PRNG seeds used directly |
| Setup cost | Negligible (key expansion: ~100 operations) | Heavy (~1,049,000 operations for S-box generation) |
| Code complexity | Moderate — requires GF(2^8) arithmetic or precomputed tables | Low — only array indexing, XOR, and PRNG |

**SPM is algorithmically simpler.** It uses a single primitive (XOR + table lookup) applied repeatedly in a cascade. AES requires four distinct transformations, one of which (MixColumns) involves Galois field arithmetic — a non-trivial mathematical operation that must either be computed on-the-fly or replaced with precomputed lookup tables (T-tables).

---

## 3. Predefined Constants and Structures

This is where the two ciphers differ most fundamentally.

### AES: Extensive Predefined Structure

AES is built entirely from fixed, publicly known mathematical objects:

| Constant/Structure | Size | Origin |
|---|---|---|
| **S-box** | 256 bytes | GF(2^8) multiplicative inverse composed with affine transform over GF(2). Algebraically defined: S(x) = A · x^{-1} + c in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 |
| **Inverse S-box** | 256 bytes | Algebraic inverse of the above |
| **MixColumns matrix** | 4×4 over GF(2^8) | Fixed MDS (Maximum Distance Separable) matrix: {2,3,1,1; 1,2,3,1; 1,1,2,3; 3,1,1,2} |
| **InvMixColumns matrix** | 4×4 over GF(2^8) | Fixed inverse: {14,11,13,9; 9,14,11,13; 13,9,14,11; 11,13,9,14} |
| **Round constants (Rcon)** | 10 values | Powers of 2 in GF(2^8): {01, 02, 04, 08, 10, 20, 40, 80, 1B, 36} |
| **ShiftRows offsets** | 4 values | Fixed: {0, 1, 2, 3} |
| **Irreducible polynomial** | 1 value | x^8 + x^4 + x^3 + x + 1 (0x11B) — defines the finite field |
| **Affine constant** | 1 value | 0x63 — used in S-box construction |

**Total predefined data:** ~530 bytes of constants plus the algebraic framework of GF(2^8).

Every one of these values is publicly known, fixed for all keys, and mathematically derived. An attacker has complete knowledge of every transformation except the key itself.

### SPM: Zero Predefined Structure

| Constant/Structure | Size | Origin |
|---|---|---|
| **S-box** | 131,072 bytes (65,536 × 16-bit) | Generated at runtime from key — different for every key |
| **Inverse S-box** | 131,072 bytes | Computed from the forward S-box |
| **MixColumns equivalent** | None | No matrix layer |
| **Round constants** | None | No key schedule |
| **ShiftRows equivalent** | None | Cascade topology is the only fixed structure |
| **Irreducible polynomial** | None | No finite field arithmetic |
| **Fixed structural constants** | 3 values | Block size (128 bytes), round count (3), S-box size (65,536) — these define the cipher's dimensions, not its cryptographic behavior |

**Total predefined data:** 0 bytes of cryptographic constants. The only fixed elements are dimensional parameters (block size, round count, S-box width) — analogous to AES's "128-bit block, 14 rounds" specification.

---

## 4. Does the Absence of A Priori Structure Make SPM Better Than AES?

**It is a meaningful structural advantage, but it does not make SPM categorically "better" than AES.** The comparison is nuanced.

### Where SPM's Approach Is Stronger

**1. No algebraic structure to exploit.**

AES's S-box is defined as x → x^{-1} in GF(2^8), composed with an affine transform. This elegant construction gives AES its provable differential and linear bounds (δ = 4, nonlinearity = 112), but it also means the S-box has a compact algebraic description — it can be expressed as a system of 23 quadratic equations in 16 variables over GF(2). This algebraic structure has been the basis of an entire class of attacks:

- **Algebraic attacks (XL, XSL, Gröbner basis):** Attempt to solve the equation system representing the full cipher. These have not succeeded against full AES, but they exist precisely because AES's S-box has low algebraic degree.
- **Interpolation attacks:** Exploit the fact that the S-box is a low-degree polynomial over GF(2^8).
- **Invariant subspace attacks:** Exploit algebraic symmetries in the round function.

SPM's S-box is a random-looking permutation generated by a PRNG-driven shuffle. It has **no compact algebraic description**. There is no polynomial, no finite field structure, no invariant subspace to exploit. An attacker cannot write the S-box as a system of low-degree equations — the algebraic degree is expected to be maximal (close to 2^16). This eliminates an entire family of attacks that are at least theoretically applicable to AES.

**2. No "nothing up my sleeve" trust requirement.**

AES's constants were chosen by Joan Daemen and Vincent Rijmen based on mathematical criteria (optimal diffusion, maximal nonlinearity). The cryptographic community trusts these choices because the design rationale is published and the constants are verifiable. But this trust is a social consensus, not a mathematical proof. In principle, a designer could choose constants that create a subtle backdoor — and the user has no way to verify this didn't happen.

SPM eliminates this trust requirement entirely. There are no designer-chosen constants. The S-box is derived from the user's key. The cipher's security properties are generated fresh for each key, not baked in by a designer. The user doesn't need to trust anyone's constant selection because there are no constants to select.

**3. Each key creates a unique cipher.**

When two AES users encrypt with different keys, they use the same S-box, the same MixColumns matrix, the same algebraic structure. Only the round keys differ. A cryptanalytic breakthrough against AES's structure (however unlikely) would break all keys simultaneously.

When two SPM users encrypt with different keys, they use entirely different S-boxes — different permutations, different DDTs, different LATs. A structural attack against one user's S-box tells the attacker nothing about another user's S-box. The attack surface is per-key, not per-cipher.

### Where AES's Approach Is Stronger

**1. Provable security bounds.**

AES's fixed algebraic structure enables mathematical proofs:
- The S-box has **proven** differential uniformity δ = 4 and nonlinearity 112 — the theoretical optimum for an 8-bit permutation.
- The MDS MixColumns matrix guarantees that any differential characteristic across 4 rounds activates at least 25 S-boxes, giving a proven lower bound on differential probability: ≤ (4/256)^25 = 2^{−150}.
- The wide trail strategy provides a formal framework for bounding linear and differential attacks.

SPM has **no proven bounds**. The S-box has expected δ ≈ 4–6 for a random 16-bit permutation, but this is a statistical expectation, not a guarantee for every key. No formal bound exists on the number of active S-boxes or the minimum differential probability across the cascade. The cipher is likely secure — but "likely" is weaker than "proven."

**2. 28 years of intensive public cryptanalysis.**

AES was selected in 2001 after a multi-year public competition. It has been subjected to more cryptanalytic scrutiny than any cipher in history. Thousands of papers have attacked AES; none have succeeded against full AES with practical complexity. This depth of analysis provides an enormous confidence margin that no novel cipher can match.

SPM has undergone limited analysis. This assessment is thorough within its scope, but it represents a fraction of the collective effort applied to AES. There may be attack vectors that we have not considered.

**3. Hardware acceleration.**

AES has dedicated hardware instructions on all modern x86 (AES-NI), ARM (ARMv8-CE), and RISC-V processors. A single AES-NI round takes ~1 clock cycle. Full AES-256 encryption: ~14 cycles per block.

SPM requires 759 table lookups from a 128 KB S-box that spans many cache lines. On modern hardware, this is orders of magnitude slower than AES-NI and creates an inherent cache-timing side-channel attack surface. No hardware acceleration exists or is likely to be developed for a key-dependent S-box cipher.

**4. Constant-time implementation is straightforward for AES.**

AES's fixed S-box can be implemented in constant time using bitslicing or AES-NI instructions, eliminating timing side channels. SPM's 128 KB key-dependent S-box makes constant-time implementation extremely difficult — the table is too large for bitslicing and no hardware instruction set supports it.

### Verdict

| Dimension | Advantage |
|-----------|-----------|
| Algebraic attack resistance | **SPM** — no algebraic structure to exploit |
| Trust model (no designer constants) | **SPM** — nothing to trust |
| Per-key uniqueness | **SPM** — each key creates a distinct cipher |
| Proven security bounds | **AES** — formal differential/linear proofs |
| Depth of public cryptanalysis | **AES** — 28 years, thousands of papers |
| Performance | **AES** — hardware acceleration, 14 cycles/block |
| Side-channel resistance | **AES** — constant-time implementations exist |
| Implementation simplicity | **SPM** — one operation type vs. four |
| Setup cost | **AES** — negligible key expansion |

The absence of predefined structure is a **genuine cryptographic advantage** in the dimensions of algebraic attack resistance, trust, and per-key diversity. These are real and meaningful properties. However, AES's advantages in proven bounds, public scrutiny depth, performance, and side-channel resistance are equally real.

**Neither cipher is categorically superior.** They represent fundamentally different design philosophies: AES optimizes for provable security within a fixed algebraic framework; SPM optimizes for per-key unpredictability at the cost of provability and performance. Both achieve the same brute-force security margin (~2^254) and both resist all known practical attacks.

---

*Prepared as an addendum to the SPM Cipher Strength Assessment.*
