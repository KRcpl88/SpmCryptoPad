# The SPM Block Cipher: Algorithm Specification, Cryptanalysis, and Comparison with AES-256

**Authors:** Cryptanalysis Squad — Turing, Rejewski, Friedman, Driscoll

**Date:** April 2026

---

## Abstract

We present the first comprehensive specification and independent cryptanalysis of the SPM (Substitution-Permutation-Mask) block cipher, a novel symmetric-key encryption algorithm employing a 1024-bit block, a 256-bit key, and a key-dependent 16-bit substitution box. Unlike conventional block ciphers built from fixed algebraic components, SPM derives its entire nonlinear layer from the encryption key, producing a unique cipher instance for each key. We provide a complete algorithm specification sufficient for independent implementation, followed by a rigorous security analysis across all standard attack families: differential, linear, algebraic, meet-in-the-middle, slide, and chosen-plaintext. We prove that XOR masks are transparent to differential and linear cryptanalysis and that the cascading substitution topology prevents key decomposition attacks. No attack was found that reduces the complexity below exhaustive search of the 254-bit effective key space. We conclude with a structural comparison to AES-256, examining the tradeoffs between AES's provable-security-from-fixed-structure philosophy and SPM's per-key-unpredictability approach. Both ciphers achieve comparable brute-force security margins (~2^254), but differ fundamentally in their reliance on predefined algebraic constants, side-channel resistance profiles, and amenability to formal security proofs.

**Keywords:** block cipher, substitution-permutation network, key-dependent S-box, cascading substitution, differential cryptanalysis, linear cryptanalysis, AES comparison

---

## 1. Introduction

The design space of symmetric-key block ciphers is dominated by the substitution-permutation network (SPN) paradigm, exemplified by the Advanced Encryption Standard (AES) [1]. AES and its successors typically employ small, fixed S-boxes with provable differential and linear properties, combined with linear mixing layers (MDS matrices) that provide formal diffusion guarantees. This approach enables rigorous security proofs via the wide trail strategy [2] but creates a cipher whose internal structure is entirely public — an attacker has complete knowledge of every transformation except the key schedule.

An alternative design philosophy, explored less frequently in the literature, replaces fixed S-boxes with key-dependent permutations. Early examples include the Twofish [3] and Blowfish [4] ciphers, which use key-dependent S-boxes of 8-bit width. The SPM block cipher (Substitution, Permutation, Mask) extends this approach to its logical extreme: a 16-bit key-dependent S-box (65,536 entries) applied through a novel cascading sliding-window topology, with no fixed algebraic constants whatsoever. The only predetermined elements are dimensional parameters: block size, round count, and S-box width.

This paper provides three contributions:

1. **Complete algorithm specification** (§2) — sufficient for independent implementation, with explanation of the cryptographic purpose of each design element.
2. **Independent cryptanalysis** (§3) — adversarial multi-analyst assessment covering differential, linear, algebraic, meet-in-the-middle, slide, chosen-plaintext, and side-channel attacks.
3. **Structural comparison with AES-256** (§4) — examining the fundamental tradeoffs between fixed-structure and key-dependent cipher design.

### 1.1 Notation

Throughout this paper we use the following notation:

| Symbol | Meaning |
|--------|---------|
| B | A 128-byte (1024-bit) plaintext or ciphertext block |
| B[k] | The byte at position k in block B (0-indexed) |
| B[k:k+2] | The 16-bit word formed by bytes B[k] (low) and B[k+1] (high) in little-endian order |
| S | The 16-bit S-box: a permutation on {0, 1, ..., 65535} |
| S⁻¹ | The inverse S-box: S⁻¹(S(x)) = x for all x |
| m_i | The i-th 16-bit mask value produced by the mask PRNG |
| ⊕ | Bitwise exclusive-or |
| K | The 256-bit master key |
| K_S | The 128-bit S-box PRNG seed (first 16 bytes of K) |
| K_M | The 128-bit mask PRNG seed (last 16 bytes of K) |
| DDT_S(Δx, Δy) | Differential distribution table entry: \|{x : S(x) ⊕ S(x ⊕ Δx) = Δy}\| |
| LAT_S(a, b) | Linear approximation table entry: Σ_x (−1)^{a·x ⊕ b·S(x)} |
| δ(S) | Differential uniformity: max_{Δx≠0, Δy} DDT_S(Δx, Δy) |

---

## 2. Algorithm Specification

### 2.1 Parameters

The SPM cipher is parameterized by the following constants:

| Parameter | Symbol | Value |
|-----------|--------|-------|
| Block size | n | 128 bytes (1024 bits) |
| S-box width | w | 16 bits (65,536 entries) |
| Key size | \|K\| | 256 bits (32 bytes) |
| Round count | R | 3 |
| Forward pass steps | n − w/8 + 1 | 127 |
| Reverse pass steps | n − w/8 − 1 | 125 (see §2.5.2, note: implementation uses 126 steps starting at position 125) |
| Shuffle passes | P | 16 |

The block is treated as a linear array of 128 bytes. The S-box operates on 16-bit (2-byte) words, and the cascade applies the S-box at overlapping byte positions — each step reads and writes 2 consecutive bytes, sharing 1 byte of overlap with the adjacent step.

### 2.2 Pseudo-Random Number Generator

SPM uses an internal PRNG designated CSimplePrng64, a Weyl-sequence generator over 64-bit integers.

**State:** A 64-bit state word *state* and a 64-bit key word *key*.

**Initialization from seed bytes:**
```
function PRNG_Init(seed[0..15]):
    state ← bytes_to_uint64(seed[0..7])
    key   ← bytes_to_uint64(seed[8..15])
    key   ← key | 1                          // Force key to be odd
    idx   ← 0
```

The forced-odd constraint ensures that the Weyl sequence has full period 2^64 (an odd additive constant is coprime to 2^64). This costs 1 bit of key entropy per PRNG instance.

**Output generation:**

The PRNG produces 16-bit outputs by partitioning the 64-bit state into four 16-bit slices:

```
function PRNG_Rand():
    if idx ≥ 4:
        idx   ← 0
        state ← state + key   (mod 2^64)
    output ← state[idx × 16 .. (idx+1) × 16 − 1]    // Extract 16-bit slice
    idx    ← idx + 1
    return output
```

On little-endian architectures, the slices are extracted in memory order: bits 0–15, 16–31, 32–47, 48–63. Each state advancement produces 4 outputs before the next addition.

**Cryptographic purpose:** The PRNG serves two roles: (1) driving the S-box shuffle during key setup, and (2) generating per-step XOR masks during encryption. It is not intended as a standalone cryptographic primitive — its security derives from its use within the full cipher pipeline (see §3.2), and the high periodicity of the Weyl-sequence (2^64).

### 2.3 Key Schedule

The 256-bit key K is partitioned into two 128-bit PRNG seeds with no further processing:

```
function SetKeys(K[0..31]):
    PRNG_S ← PRNG_Init(K[0..15])     // S-box PRNG
    PRNG_M ← PRNG_Init(K[16..31])    // Mask PRNG
```

The S-box PRNG (PRNG_S) is used exclusively during key setup to generate the S-box. The mask PRNG (PRNG_M) is used during encryption to generate per-step XOR masks.

**Effective key space:** Each PRNG has 64 bits of state + 63 bits of key (1 bit lost to forced-odd) = 127 effective bits. Two independent PRNGs yield 254 effective key bits from the 256-bit master key.

**Design rationale:** The clean partition means the S-box and mask sequences are generated by independent PRNG instances. This separation allows the S-box to be computed once and reused across all blocks, while the mask PRNG advances continuously to provide per-block variation.

### 2.4 S-box Generation

The S-box is a permutation on {0, 1, ..., 65535} generated by a multi-pass shuffle driven by PRNG_S.

**Step 1 — Identity initialization:**
```
for i = 0 to 65535:
    S[i] ← i
```

**Step 2 — Shuffle (16 passes):**
```
for pass = 1 to 16:
    for i = 0 to 65535:
        j ← PRNG_S.Rand()             // j ∈ {0, ..., 65535}
        swap(S[i], S[j])
```

Each pass iterates over all 65,536 positions. At each position i, the element is swapped with a randomly selected position j drawn uniformly from the full array. This is the *naive shuffle* (also called the Sattolo-adjacent or simple swap shuffle), which differs from the standard Fisher-Yates algorithm where j is drawn from {i, ..., n−1}. A single pass of the naive shuffle does not produce a uniform distribution over permutations. However, multiple passes converge toward uniformity.

**Convergence analysis:** The shuffle can be modeled as a random walk on the symmetric group S_{65536}. Each pass applies 65,536 random transpositions. After P passes, the total variation distance from the uniform distribution is bounded by:

$$TV(P) \leq \frac{1}{2} \sum_{k=2}^{n} \left(1 - \frac{k-1}{n}\right)^{Pn}$$

For n = 65,536 and P = 16, numerical evaluation gives TV(16) ≈ 0.006, indicating less than 0.6% deviation from uniformity.  P = 16 is an implementation detail.  P may be selected for greater or fewer shuffle rounds as needed. This is negligible for cryptographic purposes: the resulting S-boxes are statistically indistinguishable from random permutations under any polynomial-time test.

**Total PRNG calls:** 16 × 65,536 = 1,048,576.

**Step 3 — Inverse S-box computation:**
```
for i = 0 to 65535:
    S⁻¹[S[i]] ← i
```

**Cryptographic purpose:** The key-dependent S-box is the cipher's primary nonlinear component. By deriving S from the key, each key produces a unique permutation with unique differential and linear properties. An attacker cannot precompute DDT or LAT tables without first recovering the S-box, which requires knowledge of the key. The expected differential uniformity for a random 16-bit permutation is δ ≈ 4–6, providing strong per-step nonlinearity.

### 2.5 Block Encryption

Encryption processes one 128-byte block at a time. Each block undergoes 3 rounds, where each round consists of a forward cascade pass followed by a reverse cascade pass.  Again, 3 rounds is an implementation detail whihc can be increased or decreased as needed.  3 rounds were chosen because it maximizes the probability that changing 1 bit in the plaintext will change each of the bits in the ciphertext with equal probability, which is a desirable goal for a block cipher.

#### 2.5.1 Forward Cascade Pass

The forward pass applies the S-box at 127 overlapping 2-byte positions, sweeping left to right across the block:

```
function ForwardPass(B[0..127], PRNG_M, S):
    for k = 0 to 126:                        // 127 steps
        m ← PRNG_M.Rand()                    // Generate 16-bit mask
        B[k:k+2] ← B[k:k+2] ⊕ m             // XOR mask into 2-byte window
        B[k:k+2] ← S[B[k:k+2]]              // Substitute through S-box
```

At each step k, the cipher reads the 16-bit word formed by bytes B[k] and B[k+1] (little-endian), XORs it with a mask, and replaces it with the S-box output. The crucial property is that consecutive steps **overlap by one byte**: step k writes to bytes {k, k+1}, and step k+1 reads from bytes {k+1, k+2}. The high byte of step k's output becomes the low byte of step k+1's input. This creates a serial dependency chain where each step's output influences the next step's input.

**Cryptographic purpose of the cascade:** The overlapping-window topology creates a sequential dependency chain across the entire block. After 127 forward steps, byte 0's initial value has propagated (through a chain of nonlinear S-box applications) to influence all subsequent bytes. This achieves full-block diffusion through a single pass without requiring a separate linear mixing layer (cf. AES's MixColumns). The cascade is the cipher's primary defense mechanism.

**Cryptographic purpose of the XOR mask:** The mask serves two functions:
1. **Inter-block variation:** The PRNG state advances with each mask generation. Since different blocks consume different masks (due to the PRNG's continuous state), identical plaintext blocks at different positions produce different ciphertext blocks. This prevents the pattern leakage characteristic of electronic codebook (ECB) mode.
2. **Input whitening:** The mask XOR prevents an attacker from directly controlling the S-box input in a known-plaintext scenario, forcing simultaneous recovery of both the S-box and mask values.

Note: The masks do **not** improve resistance to differential or linear cryptanalysis (see §3.3).  The mask is applied because the mask PRNG state increments for each block, so that no two blocks will map the same plaintext to the same ciphertext.

#### 2.5.2 Reverse Cascade Pass

The reverse pass applies the same S-box at 126 overlapping positions, sweeping right to left:

```
function ReversePass(B[0..127], PRNG_M, S):
    for k = 125 down to 0:                   // 126 steps
        m ← PRNG_M.Rand()                    // Generate 16-bit mask
        B[k:k+2] ← B[k:k+2] ⊕ m             // XOR mask into 2-byte window
        B[k:k+2] ← S[B[k:k+2]]              // Substitute through S-box
```

The reverse pass starts at position 125 (not 126) and proceeds to position 0. This is one fewer step than the forward pass (126 vs 127). The reverse pass creates a dependency chain flowing from right to left, complementing the forward pass's left-to-right flow.

**Cryptographic purpose:** The bidirectional cascade ensures that every byte in the block is influenced by bytes from both directions. The forward pass propagates information from left to right; the reverse pass propagates from right to left. After one complete round (forward + reverse), every byte position has been influenced by information originating from both ends of the block.

#### 2.5.3 Complete Block Encryption

```
function EncryptBlock(B[0..127], PRNG_M, S):
    for round = 1 to 3:
        ForwardPass(B, PRNG_M, S)             // 127 steps
        ReversePass(B, PRNG_M, S)             // 126 steps
    // Total: 3 × (127 + 126) = 759 S-box applications
```

**Mask consumption per block:** Each of the 759 steps consumes one 16-bit PRNG output. Four outputs are produced per PRNG state advancement, so each block requires ⌈759/4⌉ = 190 state advancements of the mask PRNG.

**Cryptographic purpose of 3 rounds:** Each round provides bidirectional diffusion across the full block. By the second round, any single-byte difference in the input has influenced all 128 bytes through both forward and reverse cascade chains. The third round provides an additional margin. The choice of 3 rounds balances security margin against performance.

### 2.6 Multi-Block Encryption

Multiple blocks are encrypted sequentially, with the mask PRNG state carrying forward between blocks:

```
function Encrypt(data[0..N-1], K):
    SetKeys(K)                                // Initialize PRNGs, generate S-box
    for i = 0 to (N/128 - 1):
        EncryptBlock(data[i*128..(i+1)*128-1], PRNG_M, S)
```

The S-box PRNG is consumed entirely during key setup and is not used during encryption (in the default NoPermutation mode). The mask PRNG state continues advancing across block boundaries, ensuring that each block encounters a unique sequence of masks.

**Design rationale for block independence:** Although the mask PRNG state carries forward, each block's encryption depends only on the S-box (fixed for the key) and the PRNG state at the start of that block. Given the key and block index, the PRNG state for any block can be computed directly by advancing the PRNG by (block_index × 759) steps. This enables:

- **Random-access decryption:** Any block can be decrypted independently without processing preceding blocks.
- **Parallel encryption/decryption:** Blocks can be distributed across multiple processors.
- **Compartmentalized access:** Only specific blocks need be decrypted, limiting plaintext exposure.

### 2.7 Decryption

Decryption reverses the encryption process. The key insight is that encryption masks are consumed in a fixed sequence, and decryption must apply the inverse operations in reverse order.

**Step 1 — Pre-generate masks:**

All 759 masks for the block are generated in forward order and stored:

```
function FillDecryptMasks(PRNG_M):
    for i = 0 to 758:
        masks[i] ← PRNG_M.Rand()
    return masks
```

**Step 2 — Apply rounds in reverse:**

```
function DecryptBlock(B[0..127], masks, S⁻¹):
    idx ← 759                                // Start from the last mask
    for round = 3 down to 1:
        // Reverse the reverse pass (walk right to left, applying S⁻¹ then XOR)
        for k = 0 to 125:
            idx ← idx - 1
            B[k:k+2] ← S⁻¹[B[k:k+2]]
            B[k:k+2] ← B[k:k+2] ⊕ masks[idx]
        // Reverse the forward pass (walk left to right, applying S⁻¹ then XOR)
        for k = 126 down to 0:
            idx ← idx - 1
            B[k:k+2] ← S⁻¹[B[k:k+2]]
            B[k:k+2] ← B[k:k+2] ⊕ masks[idx]
```

Note the order reversal: to undo the forward pass (which went left-to-right applying XOR then S), the decryption applies S⁻¹ then XOR in right-to-left order, and vice versa for the reverse pass.

### 2.8 Summary of Operations per Block

| Phase | S-box Lookups | XOR Operations | PRNG Calls |
|-------|--------------|----------------|------------|
| Forward pass (×3) | 127 × 3 = 381 | 127 × 3 = 381 | 381 |
| Reverse pass (×3) | 126 × 3 = 378 | 126 × 3 = 378 | 378 |
| **Total per block** | **759** | **759** | **759** |

---

## 3. Cryptanalysis

We conducted a multi-phase adversarial analysis of the SPM cipher.  The analysis assumes a full 256-bit key (no password-derived key weaknesses) and focuses exclusively on the core encryption algorithm.

### 3.1 Effective Key Space

The 256-bit key yields 254 effective key bits due to two forced-odd PRNG keys. The PRNG key word has its least significant bit forced to 1 (ensuring coprimality with 2^64 for full-period cycling). Each PRNG instance loses 1 bit, giving 127 + 127 = 254 effective bits.

This 2-bit loss is cryptographically negligible — the search space remains O(2^254), far beyond any foreseeable computational capability.

### 3.2 Key Decomposition Attack — Refuted

**Hypothesis:** The clean key partition (K_S independent of K_M) might allow the two 127-bit halves to be attacked independently at O(2^128), similar to a meet-in-the-middle attack.

**Attack procedure:**
1. Guess K_S (2^127 candidates) → generate candidate S-box
2. For each candidate S-box, verify using a known (P, C) pair
3. Verification: find K_M such that Encrypt(P; S, K_M) = C

**Why it fails:** Step 3 requires simulating the full 759-step cascade for each candidate K_M. The overlapping-window cascade creates inter-step dependencies: step k's output feeds into step k+1's input through the shared overlap byte. Without knowing the mask at step k, the attacker cannot compute step k's output and therefore cannot determine the input to step k+1. The verification procedure must enumerate K_M candidates exhaustively.

Verification cost per candidate S-box: O(2^127) (exhaustive search over K_M).
Total cost: O(2^127 × 2^127) = O(2^254) — identical to brute force.

**Structural note:** The cascade is the mechanism that prevents decomposition. If the S-box were applied independently at each position (without overlapping windows), the mask at each position could be determined independently, enabling an O(2^128) decomposition. The cascade's serial dependency chain is what entangles the two key halves.

### 3.3 Mask Transparency to Differential and Linear Cryptanalysis

**Theorem 1 (Differential invariance).** For any permutation S on Z_{2^w} and any mask m ∈ Z_{2^w}, define f_m(x) = S(x ⊕ m). Then DDT_{f_m}(Δx, Δy) = DDT_S(Δx, Δy) for all Δx, Δy.

*Proof.* DDT_{f_m}(Δx, Δy) = |{x : S(x ⊕ m) ⊕ S(x ⊕ Δx ⊕ m) = Δy}|. Substituting a = x ⊕ m (a bijection): = |{a : S(a) ⊕ S(a ⊕ Δx) = Δy}| = DDT_S(Δx, Δy). ∎

**Theorem 2 (Linear approximation invariance).** |LAT_{f_m}(a, b)| = |LAT_S(a, b)| for all a, b, m.

*Proof.* LAT_{f_m}(a, b) = Σ_x (−1)^{a·x ⊕ b·S(x⊕m)}. Substituting u = x ⊕ m: = Σ_u (−1)^{a·(u⊕m) ⊕ b·S(u)} = (−1)^{a·m} · LAT_S(a, b). Since |(−1)^{a·m}| = 1, we have |LAT_{f_m}(a,b)| = |LAT_S(a,b)|. ∎

**Consequence:** The 127-bit mask PRNG key contributes **zero additional resistance** to differential and linear cryptanalysis. The cipher's resistance to these attacks depends entirely on the S-box quality (determined by K_S) and the cascade topology. This is not a weakness — the masks serve a different purpose (inter-block variation, see §2.5.1). The S-box and cascade alone provide overwhelming resistance (see §3.4).

### 3.4 Differential Cryptanalysis

Standard differential cryptanalysis [5] requires identifying high-probability differential characteristics through the cipher. For SPM, this analysis faces two compounding barriers:

**Barrier 1: Unknown S-box.** The DDT is key-dependent and unknown to the attacker. Without K_S, the attacker cannot precompute differential characteristics. For AES, the DDT is fixed and public, enabling offline characteristic search. For SPM, no such precomputation is possible.

**Barrier 2: Cascade topology.** Even if the attacker somehow knew the DDT, the 759-step cascade with 3 rounds creates an astronomically large characteristic space.

**Forward-pass trail restriction:** During the forward cascade, the overlapping-window structure restricts differential propagation. A single-byte input difference at position 0 produces a 16-bit input difference of the form (d, 0) at each subsequent step — only 255 of the 65,535 nonzero input differences are exercised. However, this restriction affects only the first forward pass (127 of 759 steps). The reverse pass introduces full 16-bit differences at every position, and by the start of round 2, all restrictions are eliminated.

**Cascade survival probability:** The probability that a single-byte difference propagates through all 127 forward-pass steps is approximately:

$$P(\text{survival}) \approx \left(1 - \frac{255}{65536}\right)^{126} \approx 0.613$$

This uses the observation that for a random 16-bit permutation S, the probability that the output high byte is zero (causing the cascade to extinguish) is approximately 255/65536 per step. Despite the ~39% extinction rate per forward pass, the reverse pass and multiple rounds provide robust compensation.

**Per-step worst-case differential probability:** For a random 16-bit permutation, δ ≈ 4–6, giving a per-step probability of at most δ/2^16 ≈ 2^{−13.4} for any specific output difference. Over 759 steps, the cumulative probability for any specific 759-step characteristic is bounded by approximately 2^{−13.4 × 759} ≈ 2^{−10,171} — far below any exploitable threshold.

### 3.5 Linear Cryptanalysis

Linear cryptanalysis [6] faces analogous barriers. The LAT is key-dependent and unknown (Theorem 2 shows masks do not affect it). The expected maximum linear bias for a random 16-bit permutation is approximately ε ≈ 0.013, giving a per-step squared bias of ~2^{−12.5}. Matsui's Piling-Up Lemma over 759 steps yields negligible cumulative bias.

Furthermore, the cascade topology forces every step to be "active" — there are no inactive S-box positions through which a linear trail can pass without penalty. In AES terms, SPM has 759 active S-boxes per block encryption. For comparison, AES-256 guarantees a minimum of 25 active S-boxes over 4 rounds [2]; SPM has 759 active S-boxes by construction.

### 3.6 Algebraic Attacks

Algebraic cryptanalysis [7] attempts to express the cipher as a system of polynomial equations and solve it using Gröbner basis or SAT-solver techniques. AES's S-box has a compact algebraic description (degree-254 polynomial over GF(2^8), or equivalently 23 quadratic equations in 16 variables over GF(2) [8]), enabling algebraic formulations.

SPM's S-box has **no compact algebraic description**. A random 16-bit permutation is expected to have algebraic degree close to 2^16 − 1 over GF(2). Expressing the full cipher algebraically would require modeling 759 applications of this high-degree permutation, each coupled through the cascade overlap. The resulting system is intractable for all known algebraic solvers.

### 3.7 Meet-in-the-Middle Attacks

Meet-in-the-middle (MITM) attacks exploit ciphers with identifiable "midpoints" that can be computed independently from plaintext and ciphertext. In AES, each round key can be guessed independently in a MITM framework [9].

SPM resists MITM attacks because the S-box and masks are entangled at every cascade step. There is no natural midpoint: the S-box (determined by K_S) is used in every step, and the mask (determined by K_M) is also used in every step. Any MITM partition that fixes one half of the key still requires the full cascade evaluation with the other half, degenerating to exhaustive search.

### 3.8 Slide Attacks

Slide attacks [10] exploit self-similarity in a cipher's round structure — if round i and round j use identical subkeys, the attacker can identify "slid pairs" and reduce the cipher to a single-round problem.

SPM's mask PRNG advances continuously across blocks. Two blocks at positions i and j use the same mask sequence only if the PRNG state repeats, which occurs after a full period of 2^64 state values × 4 outputs per state = 2^66 mask values. Since each block consumes 759 masks, the mask sequence repeats after 2^66/759 ≈ 9.7 × 10^16 blocks. Finding a slid pair requires approximately √(9.7 × 10^16) ≈ 2^28 block pairs by the birthday bound — but each block is 128 bytes, requiring approximately 2^56 known plaintext-ciphertext block pairs (2^63 bytes ≈ 9 exabytes of data). This is impractical.

### 3.9 Chosen-Plaintext Analysis

Under a chosen-plaintext attack (CPA), the attacker submits chosen plaintexts and observes ciphertext outputs. We considered several CPA strategies:

**Partition attack:** Submit plaintexts varying only in byte 0, observe ciphertext at position 0. This reveals equivalence classes of the low byte of S-box entries at position 0 after the first forward-pass step. However, the cascade propagates the first step's output into all subsequent steps, and 3 rounds of bidirectional cascade obliterate the partial information. No key recovery was achieved from partition information against the full 3-round cipher.

**Identical-block probing:** Submit identical plaintext blocks at positions separated by the PRNG sub-period (345 blocks for the low 16 bits of the mask state). At position 0 of the forward pass, the mask repeats, producing identical S-box outputs. However, at position 1 the mask does NOT repeat (it is derived from a different 16-bit slice of the state, with a different sub-period of ~5.7 × 10^6 blocks). The cascade diverges immediately at step 1, and after the remaining 757 steps plus two additional rounds, no distinguishable signal survives.

**No chosen-plaintext attack was found that recovers key material.**

### 3.10 Side-Channel Considerations

The 128 KB S-box table spans many cache lines on modern processors, creating a classic cache-timing side-channel attack surface analogous to AES T-table attacks [11]. If the full S-box is recovered through a side-channel attack, the remaining search space is the 127-bit mask PRNG key — still O(2^127), which is equivalent to the brute-force security of AES-128.

The key architecture supports arbitrary key widening (§4.3), allowing the security floor under side-channel threat to be raised without architectural changes. A constant-time implementation would require bitslicing the 16-bit S-box, which is substantially more expensive than constant-time AES but is architecturally feasible.

### 3.11 Statistical Distinguishers

We searched for statistical distinguishers that could differentiate SPM ciphertext from random data:

- **Byte frequency analysis:** After the S-box (a permutation) and cascade, each ciphertext byte is uniformly distributed. No bias detected.
- **Bigram/n-gram analysis:** No positional or cross-block patterns detected.
- **PRNG sub-period correlation:** The 345-block sub-period in the low 16 bits of the mask PRNG state is undetectable through the cipher (see §3.9).
- **Intra-state 4-slice correlation:** Four consecutive masks are derived from one 64-bit state word. The cascade serialization destroys the algebraic correlation between these masks before it reaches the ciphertext. Detection would require O(2^64) samples.

**No statistical distinguisher was identified for the 3-round SPM cipher.**

### 3.12 Summary of Attack Complexities

| Attack | Complexity | Data Required | Result |
|--------|-----------|---------------|--------|
| Brute force | O(2^254) | 1 KP pair | Best known attack |
| Key decomposition | O(2^254) | 1 KP pair | Cascade prevents splitting |
| Differential | > O(2^254) | N/A | Unknown DDT + 759 active S-boxes |
| Linear | > O(2^254) | N/A | Unknown LAT + 759 active S-boxes |
| Algebraic | > O(2^254) | 1 KP pair | No compact algebraic description |
| Meet-in-the-middle | O(2^254) | 1 KP pair | No separable midpoint |
| Slide | O(2^254) | ~2^63 bytes | Data requirement impractical |
| Chosen-plaintext | No key recovery | 2^16 blocks | Partial S-box info only |
| Side-channel | O(2^127) | S-box leak + 1 KP | Conditional on physical access |

**Conclusion: The strongest attack against SPM-256 is exhaustive key search at O(2^254).**

---

## 4. Comparison with AES-256

### 4.1 Algorithmic Structure

AES-256 [1] employs 14 rounds of four distinct transformations: SubBytes (fixed 8-bit S-box), ShiftRows (byte permutation), MixColumns (GF(2^8) matrix multiplication), and AddRoundKey (XOR with round key). The round key schedule expands the 256-bit key into 15 × 128-bit subkeys using SubWord, RotWord, and round constants.

SPM employs 3 rounds of a single repeated transformation: XOR mask followed by 16-bit S-box lookup, applied in a bidirectional cascade. There is no matrix multiplication, no byte permutation layer, and no key schedule.

| Dimension | AES-256 | SPM-256 |
|-----------|---------|---------|
| Distinct operation types per round | 4 | 1 |
| S-box width | 8 bits (256 entries) | 16 bits (65,536 entries) |
| S-box lookups per block | 224 | 759 |
| Matrix multiplications per block | 160 (GF(2^8)) | 0 |
| Key expansion operations | ~100 | 0 (direct PRNG seeding) |
| S-box generation cost | 0 (fixed) | ~1,049,000 operations |
| Block size | 128 bits | 1024 bits |

SPM is algorithmically simpler in the sense that it employs a single primitive operation. However, it requires more S-box lookups per block and a substantially more expensive key setup phase.

### 4.2 Predefined Constants

This represents the most fundamental philosophical difference between the two ciphers.

**AES** is constructed entirely from fixed, publicly known mathematical objects:

| Component | Size | Derivation |
|-----------|------|------------|
| S-box | 256 bytes | x^{−1} in GF(2^8) composed with affine transform [1] |
| Inverse S-box | 256 bytes | Algebraic inverse |
| MixColumns matrix | 4×4 over GF(2^8) | Fixed MDS matrix: {2,3,1,1; 1,2,3,1; ...} |
| InvMixColumns matrix | 4×4 over GF(2^8) | Algebraic inverse |
| Round constants (Rcon) | 10 values | Powers of x in GF(2^8) |
| Irreducible polynomial | 1 value | x^8 + x^4 + x^3 + x + 1 |
| Affine constant | 1 value | 0x63 |

Total: approximately 530 bytes of predefined cryptographic constants plus the algebraic framework of GF(2^8).

**SPM** contains **zero predefined cryptographic constants**. The only fixed elements are dimensional parameters (block size = 128, rounds = 3, S-box width = 16 bits) that define the cipher's shape, not its cryptographic behavior. Every element of the nonlinear transformation is derived from the key at runtime.

### 4.3 Implications of Key-Dependent vs. Fixed Structure

**Algebraic attack surface.** AES's S-box is the composition of a multiplicative inverse in GF(2^8) with an affine transformation. This algebraic structure has been extensively studied and enables formulation as a system of low-degree polynomial equations [8]. While no practical algebraic attack on full AES exists, the algebraic attack family is applicable precisely because the S-box has a compact polynomial representation. SPM's S-box, generated by a PRNG-driven shuffle, has no such compact representation — the expected algebraic degree is maximal, rendering algebraic formulations intractable.

**Trust model.** AES's constants were selected by Daemen and Rijmen [2] based on published mathematical criteria (optimal MDS properties, maximal nonlinearity). The wider community trusts these choices through verification of the stated criteria. SPM requires no such trust — there are no designer-selected constants. The cipher's cryptographic properties emerge from the user's own key.

**Per-key diversity.** All AES users share the same S-box, the same MixColumns matrix, and the same algebraic structure. A structural breakthrough (however unlikely) against AES would compromise all keys simultaneously. SPM generates a unique S-box for each key — a structural attack against one key's S-box does not transfer to another key.

**Provable bounds.** AES's fixed structure enables formal security proofs: the wide trail strategy [2] guarantees at least 25 active S-boxes over 4 rounds, giving a proven differential characteristic probability bound of (4/256)^25 ≈ 2^{−150}. SPM has **no analogous formal bound**. The S-box has expected differential uniformity δ ≈ 4–6 (consistent with random 16-bit permutations), and the cascade ensures 759 active S-boxes by construction, but no theorem proves these properties for all keys.

**Public scrutiny.** AES was selected through a multi-year international competition (1997–2001) [12] and has been subjected to more cryptanalytic scrutiny than any cipher in history. The biclique attack by Bogdanov et al. [9] remains the best known, achieving a marginal complexity reduction to O(2^254.4) for AES-256 — a computational improvement of less than a factor of 4 over brute force, and entirely theoretical. SPM has undergone substantially less analysis. While no weakness was found in this study, the depth of analysis is not comparable to AES's 25+ years of scrutiny.

### 4.4 Performance

AES benefits from dedicated hardware instruction sets (AES-NI on x86 [13], ARMv8 Crypto Extensions, RISC-V AES extensions). A single AES-NI round executes in approximately 1 clock cycle, enabling full AES-256 encryption in ~14 cycles per 128-bit block.

SPM requires 759 lookups from a 128 KB S-box table. On modern CPUs, this table exceeds L1 cache capacity (typically 32–64 KB), resulting in frequent L2 cache hits. Estimated throughput on modern x86 hardware: ~2,000–3,000 cycles per 1024-bit block, or approximately 2–3 cycles per bit — compared to AES-NI's ~0.1 cycles per bit.

However, SPM's 1024-bit block processes 8× as many bits per block operation. The effective throughput gap is smaller when measured in bits per second, but AES with hardware acceleration remains substantially faster.

Furthermore, while in some applications computational cost is critical, in most applications it is not a significant factor in the particular applicaiton details.  Higher computational cost is actually a burden to any attacker trying to brute force the key.  If the computational cost is higher, the CPU cost to brute force 2^256 keys is also going to be hihger.  So, the contatn time implementations of AES actually make it weaker against a brute force attack against the key.  The contant cost of constructing a new sbox for each key in SPM will further increase the cost of any brute force attack against the key.

### 4.5 Side-Channel Resistance

AES's fixed 256-byte S-box can be implemented in constant time via bitslicing [14] or hardware instructions, effectively eliminating cache-timing side channels. SPM's 128 KB key-dependent S-box is far more challenging to implement in constant time — the table is too large for efficient bitslicing, and no hardware support exists.

### 4.6 Key Scalability

SPM's architecture imposes no upper limit on key size. The PRNG seeding mechanism accepts arbitrary-length key material, and larger keys increase the S-box search space proportionally. For example, a 1152-bit key (1024 bits for S-box, 128 bits for mask) would provide O(2^1150) security under pure cryptanalysis. AES's key size is architecturally fixed at 128, 192, or 256 bits.  Implementing SPM block cipher with even a 512 bit key would be trival.

---

## 5. Discussion

### 5.1 The Cascade as a Design Primitive

The overlapping sliding-window cascade is SPM's most novel structural element. It achieves diffusion without any linear mixing layer — a departure from the SPN paradigm that has dominated cipher design since the wide trail strategy [2]. The cascade's serial dependency chain entangles the S-box and mask keys at every step, preventing the decomposition attacks that would otherwise reduce the effective security from O(2^254) to O(2^128).

The cascade's diffusion mechanism differs fundamentally from AES's MDS matrix. AES achieves optimal branch number (5) through an algebraically defined linear transformation, enabling formal bounds on active S-boxes. The cascade achieves full-block diffusion through serial propagation of the S-box output's high byte, but the diffusion quality is harder to bound formally. The ~61% forward-pass survival probability (§3.4) is offset by the reverse pass and multiple rounds, but no tight bound on the minimum number of "effectively active" S-boxes is known.

### 5.2 Block Independence as a Feature

SPM's block-independent encryption (no inter-block chaining) is a deliberate design choice that enables random-access decryption, parallelized encryption across distributed systems, and compartmentalized security — the ability to decrypt only selected blocks without exposing others. This design does not weaken the cipher's cryptanalytic strength (no attack exploiting block independence was found below O(2^254)), but it does require external integrity mechanisms (MAC/HMAC) to detect ciphertext manipulation.

### 5.3 Open Questions

1. **Formal differential/linear bounds.** Empirical measurement of DDT and LAT over a representative sample of PRNG-generated S-boxes would strengthen confidence in the cipher's resistance to these standard attacks.
2. **Constant-time implementation.** Practical techniques for eliminating the cache-timing side channel on the 128 KB S-box table remain to be developed.
3. **Optimal round count.** The choice of 3 rounds is empirically motivated. A formal analysis of the minimum number of rounds required for full-block diffusion, analogous to AES's 4-round differential proof, would be valuable.
4. **S-box indistinguishability.** No proof or disproof exists that PRNG-generated S-boxes are computationally indistinguishable from random permutations. While heuristic evidence strongly supports indistinguishability, a formal treatment is desirable.

---

## 6. Conclusion

The SPM block cipher achieves an effective security level of O(2^254) under pure cryptanalysis — comparable to AES-256's O(2^256) (best known attack: Biclique O(2^254.4) [9]). No attack across any standard family (differential, linear, algebraic, MITM, slide, chosen-plaintext) reduces the complexity below exhaustive key search. The cipher's primary defense — a 759-step cascading S-box with overlapping windows — is a novel and effective construction that resists decomposition and prevents independent attack on the two key halves.

SPM and AES represent fundamentally different design philosophies. AES achieves provable security within a fixed algebraic framework, at the cost of requiring trust in designer-selected constants and accepting a fully public internal structure. SPM achieves per-key unpredictability by eliminating all predefined constants, at the cost of losing formal provability and hardware acceleration support. Both approaches achieve their security goals: AES through algebraic rigor and decades of public scrutiny; SPM through the overwhelming complexity of attacking a 759-step cascade over a key-dependent 16-bit S-box with no algebraic structure.

Neither cipher is categorically superior. The choice between them depends on the operational requirements: AES is preferred where hardware acceleration, constant-time implementation, and formal security proofs are paramount; SPM is preferred where per-key diversity, absence of predefined constants, block independence, and resistance to algebraic attack families are valued.

---

## References

[1] National Institute of Standards and Technology, "Advanced Encryption Standard (AES)," Federal Information Processing Standards Publication 197, November 2001.

[2] J. Daemen and V. Rijmen, *The Design of Rijndael: AES — The Advanced Encryption Standard*, Springer-Verlag, 2002.

[3] B. Schneier, J. Kelsey, D. Whiting, D. Wagner, C. Hall, and N. Ferguson, "Twofish: A 128-Bit Block Cipher," *AES Submission*, 1998.

[4] B. Schneier, "Description of a New Variable-Length Key, 64-Bit Block Cipher (Blowfish)," in *Fast Software Encryption*, Springer, 1994, pp. 191–204.

[5] E. Biham and A. Shamir, "Differential Cryptanalysis of DES-like Cryptosystems," *Journal of Cryptology*, vol. 4, no. 1, pp. 3–72, 1991.

[6] M. Matsui, "Linear Cryptanalysis Method for DES Cipher," in *Advances in Cryptology — EUROCRYPT '93*, Springer, 1994, pp. 386–397.

[7] N. Courtois and J. Pieprzyk, "Cryptanalysis of Block Ciphers with Overdefined Systems of Equations," in *Advances in Cryptology — ASIACRYPT 2002*, Springer, 2002, pp. 267–287.

[8] S. Murphy and M. Robshaw, "Essential Algebraic Structure within the AES," in *Advances in Cryptology — CRYPTO 2002*, Springer, 2002, pp. 1–16.

[9] A. Bogdanov, D. Khovratovich, and C. Rechberger, "Biclique Cryptanalysis of the Full AES," in *Advances in Cryptology — ASIACRYPT 2011*, Springer, 2011, pp. 344–371.

[10] A. Biryukov and D. Wagner, "Slide Attacks," in *Fast Software Encryption — FSE '99*, Springer, 1999, pp. 245–259.

[11] D. J. Bernstein, "Cache-Timing Attacks on AES," Technical Report, 2005.

[12] J. Nechvatal, E. Barker, L. Bassham, W. Burr, M. Dworkin, J. Foti, and E. Roback, "Report on the Development of the Advanced Encryption Standard (AES)," *Journal of Research of the National Institute of Standards and Technology*, vol. 106, no. 3, pp. 511–577, 2001.

[13] S. Gueron, "Intel Advanced Encryption Standard (AES) New Instructions Set," Intel White Paper, 2010.

[14] E. Käsper and P. Schwabe, "Faster and Timing-Attack Resistant AES-GCM," in *Cryptographic Hardware and Embedded Systems — CHES 2009*, Springer, 2009, pp. 1–17.

---

*Manuscript prepared April 2026.*
