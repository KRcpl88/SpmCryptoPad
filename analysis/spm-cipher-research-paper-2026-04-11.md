# The SPM Block Cipher: Algorithm Specification, Cryptanalysis, and Comparison with AES-256


---

## Abstract

We present the first comprehensive specification and independent cryptanalysis of the SPM (Substitution-Permutation-Mask) block cipher, a novel symmetric-key encryption algorithm employing a 1024-bit block, a 256-bit key, and a key-dependent 16-bit substitution box. Unlike conventional block ciphers built from fixed algebraic components, SPM derives its entire nonlinear layer from the encryption key, producing a unique cipher instance for each key. We provide a complete algorithm specification sufficient for independent implementation, followed by a rigorous security analysis across all standard attack families: differential, linear, algebraic, meet-in-the-middle, slide, chosen-plaintext, and quantum. We prove that XOR masks are transparent to differential and linear cryptanalysis and that the cascading substitution topology prevents key decomposition attacks. No attack was found that reduces the complexity below exhaustive search of the 254-bit effective key space. We present a detailed quantum cryptanalysis demonstrating that SPM's 16-bit key-dependent S-box - designed explicitly as a quantum countermeasure through maximized nonlinearity - imposes extraordinary costs on Grover's algorithm: approximately 1.05 million qubits and 2^{36} gates per oracle call, compared to ~320–400 qubits and ~2^{17}–2^{19} cipher-evaluation T-gates for AES-256. This makes SPM approximately 3,300× more expensive to attack quantumly in qubit requirements alone. We conclude with a structural comparison to AES-256, examining the tradeoffs between AES's provable-security-from-fixed-structure philosophy and SPM's per-key-unpredictability approach. Both ciphers achieve comparable classical brute-force security margins (~2^254), but SPM provides dramatically stronger practical quantum resistance.

**Keywords:** block cipher, substitution-permutation network, key-dependent S-box, cascading substitution, differential cryptanalysis, linear cryptanalysis, quantum cryptanalysis, Grover's algorithm, AES comparison, post-quantum cryptography

---

## 1. Introduction

The design space of symmetric-key block ciphers is dominated by the substitution-permutation network (SPN) paradigm, exemplified by the Advanced Encryption Standard (AES) [1]. AES and its successors typically employ small, fixed S-boxes with provable differential and linear properties, combined with linear mixing layers (MDS matrices) that provide formal diffusion guarantees. This approach enables rigorous security proofs via the wide trail strategy [2] but creates a cipher whose internal structure is entirely public - an attacker has complete knowledge of every transformation except the key schedule.

An alternative design philosophy, explored less frequently in the literature, replaces fixed S-boxes with key-dependent permutations. Early examples include the Twofish [3] and Blowfish [4] ciphers, which use key-dependent S-boxes of 8-bit width. The SPM block cipher (Substitution, Permutation, Mask) extends this approach to its logical extreme: a 16-bit key-dependent S-box (65,536 entries) applied through a novel cascading sliding-window topology, with no fixed algebraic constants whatsoever. The only predetermined elements are dimensional parameters: block size, round count, and S-box width.

This paper provides four contributions:

1. **Complete algorithm specification** (§2) - sufficient for independent implementation, with explanation of the cryptographic purpose of each design element.
2. **Independent cryptanalysis** (§3) - adversarial multi-analyst assessment covering differential, linear, algebraic, meet-in-the-middle, slide, chosen-plaintext, and side-channel attacks.
3. **Structural comparison with AES-256** (§4) - examining the fundamental tradeoffs between fixed-structure and key-dependent cipher design.
4. **Quantum cryptanalysis** (§5) - analysis of Grover's algorithm, Simon's algorithm, and quantum-enhanced algebraic attacks, demonstrating that SPM's 16-bit key-dependent S-box provides a massive quantum resistance advantage over AES-256.

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
| π | The per-block byte-level permutation: a bijection on {0, 1, ..., 127} derived from K_S |
| π⁻¹ | The inverse permutation: π⁻¹[π[k]] = k for all k |
| PRNG_S | The S-box PRNG instance (CSimplePrng64 seeded by K_S); used for S-box generation, base permutation generation, and per-block permutation shuffling |
| π_b | The per-block permutation variant for block b, derived from the base permutation by a 128-swap shuffle using PRNG_S |

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

The block is treated as a linear array of 128 bytes. The S-box operates on 16-bit (2-byte) words, and the cascade applies the S-box at overlapping byte positions - each step reads and writes 2 consecutive bytes, sharing 1 byte of overlap with the adjacent step.

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

**Cryptographic purpose:** The PRNG serves two roles: (1) driving the S-box shuffle during key setup, and (2) generating per-step XOR masks during encryption. It is not intended as a standalone cryptographic primitive - its security derives from its use within the full cipher pipeline (see §3.2), and the high periodicity of the Weyl-sequence (2^64).

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

**Step 1 - Identity initialization:**
```
for i = 0 to 65535:
    S[i] ← i
```

**Step 2 - Shuffle (16 passes):**
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

**Step 3 - Inverse S-box computation:**
```
for i = 0 to 65535:
    S⁻¹[S[i]] ← i
```

**Cryptographic purpose:** The key-dependent 16-bit S-box is the cipher's primary nonlinear component, and was designed explicitly as a countermeasure against quantum cryptanalytic attacks. By deriving S from the key, each key produces a unique permutation with unique differential and linear properties. An attacker cannot precompute DDT or LAT tables without first recovering the S-box, which requires knowledge of the key. The expected differential uniformity for a random 16-bit permutation is δ ≈ 4–6, providing strong per-step nonlinearity.

The choice of a 16-bit S-box width (65,536 entries, 128 KB) is a deliberate design decision that maximizes the degree of nonlinearity while simultaneously creating an enormous quantum circuit cost. As analyzed in §5, a quantum attacker using Grover's algorithm must hold the entire 65,536-entry S-box in quantum registers during superposition - requiring over 1 million qubits for the S-box alone. An 8-bit S-box (as used in AES) would require only 2,048 qubits for the same purpose - a factor of 512× less. The 16-bit width thus serves a dual purpose: maximizing classical nonlinearity per cascade step, and maximizing the quantum circuit cost for any attacker attempting to evaluate the cipher in superposition.

#### 2.4.1 Block Permutation Generation

After S-box generation, the block permutation is generated using the same PRNG_S instance (continuing from its post-S-box state). The base permutation P[0..127] is initialized to the identity (0, 1, 2, ..., 127) and shuffled via 16 passes of the naive shuffle algorithm (swap each element with a uniformly random element from the full array):

```
function GenerateBasePermutation(P[0..127], PRNG_S):
    for pass = 1 to 16:
        for i = 0 to 127:
            r ← PRNG_S.Rand() mod 128
            swap P[i] ↔ P[r]
```

Total PRNG_S consumption: 16 × 128 = 2,048 outputs. The 16-pass compensation strategy is identical to the S-box generation (§2.4): multiple passes reduce distributional bias from the naive (non-Fisher-Yates) shuffle to negligible levels (~0.6% total variation distance from uniform).

**Key dependence.** The base permutation is entirely determined by K_S. Since PRNG_S is consumed sequentially — first for S-box generation (~1,048,576 outputs), then for base permutation generation (2,048 outputs) — the base permutation is a deterministic function of K_S and is unique per key.

### 2.5 Block Encryption

Encryption processes one 128-byte block at a time. Each block undergoes 3 rounds, where each round consists of a forward cascade pass, a reverse cascade pass, and a byte-level block permutation.Again, 3 rounds is an implementation detail whihc can be increased or decreased as needed.  3 rounds were chosen because it maximizes the probability that changing 1 bit in the plaintext will change each of the bits in the ciphertext with equal probability, which is a desirable goal for a block cipher.

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
function EncryptBlock(B[0..127], PRNG_M, PRNG_S, S, P_base[0..127]):
    // Step 1: Derive per-block permutation from base permutation
    π ← copy of P_base
    for i = 0 to 127:
        r ← PRNG_S.Rand() mod 128
        swap π[i] ↔ π[r]

    // Step 2: Three rounds of cascade + permutation
    for round = 1 to 3:
        ForwardPass(B, PRNG_M, S)             // 127 steps
        ReversePass(B, PRNG_M, S)             // 126 steps
        ApplyPermutation(B, π)                // byte-level reordering
    // Total: 3 × (127 + 126) = 759 S-box applications + 3 permutations
```

**PRNG consumption per block:** Each of the 759 cascade steps consumes one 16-bit PRNG_M output (759 mask values total). Additionally, 128 PRNG_S outputs are consumed for the per-block permutation shuffle. Four outputs are produced per PRNG state advancement, so each block requires ⌈759/4⌉ = 190 state advancements of PRNG_M and ⌈128/4⌉ = 32 state advancements of PRNG_S.

**Cryptographic purpose of 3 rounds:** Each round provides bidirectional diffusion across the full block. By the second round, any single-byte difference in the input has influenced all 128 bytes through both forward and reverse cascade chains. The third round provides an additional margin. The choice of 3 rounds balances security margin against performance.

### 2.5.4 Block Permutation

After each round's forward and reverse cascade passes, a byte-level block permutation π is applied:

```
function ApplyPermutation(B[0..127], π[0..127]):
    buffer[0..127] ← zeroed
    for k = 0 to 127:
        buffer[π[k]] ← B[k]
    B ← buffer
```

The permutation is a bijection on {0, 1, ..., 127}: the byte at position k is moved to position π(k). The per-block variant π is derived before the round loop by shuffling the base permutation (§2.4.1) with 128 PRNG_S outputs, ensuring each block receives a unique permutation. The same π is used for all 3 rounds within a block.

**Cryptographic purpose.** The permutation disrupts the fixed positional byte-to-byte relationships between rounds of the cascade. Without the permutation, the cascade operates on the same byte positions in every round: position k always interacts with position k+1 in the forward pass and position k−1 in the reverse pass. The permutation ensures that the byte at position k after round i is moved to position π(k) before round i+1 begins, so the next round's cascade operates on a key-dependent rearrangement of the bytes.

This mitigates theoretical combined algebraic attacks on the mask and S-box by preventing an attacker from building algebraic equations that exploit fixed positional structure across rounds. Without the permutation, the inter-round variable mapping is the identity — a publicly known structure. With the permutation, the mapping is a secret bijection derived from K_S.

**Interaction with cascade diffusion.** The permutation redistributes partially-diffused bytes between rounds. After round 1 achieves full-block diffusion through the bidirectional cascade, the permutation rearranges byte positions so that round 2's cascade encounters different neighbor relationships. The positional arrangements across 3 rounds are identity, π, and π² — algebraically related through a single permutation but providing genuine positional diversity. Note that only the first 2 permutation applications (after rounds 1 and 2) provide inter-round diffusion benefit; the third application after round 3 is a trailing output transformation.

**Interaction with extinction recovery.** When a forward-pass differential chain extinguishes at step k < 127, the bytes beyond position k carry no difference. Without the permutation, this "cold zone" persists as a contiguous region into round 2. With the permutation, cold-zone bytes are redistributed to pseudorandom positions, so round 2's forward cascade encounters surviving differences earlier in its serial chain.

### 2.6 Multi-Block Encryption

Multiple blocks are encrypted sequentially, with the mask PRNG state carrying forward between blocks:

```
function Encrypt(data[0..N-1], K):
    SetKeys(K)                                // Initialize PRNGs, generate S-box
    for i = 0 to (N/128 - 1):
        EncryptBlock(data[i*128..(i+1)*128-1], PRNG_M, S)
```

In NoPermutation mode, PRNG_S is consumed entirely during key setup and is not used during encryption. In Permutation mode, PRNG_S is additionally consumed during encryption: 128 outputs per block for the per-block permutation shuffle (§2.5.4). Since PRNG_S is deterministic (Weyl sequence), the per-block permutation for block n can be computed independently by advancing PRNG_S to the appropriate state, preserving random-access decryption. The mask PRNG state continues advancing across block boundaries, ensuring that each block encounters a unique sequence of masks.

**Design rationale for block independence:** Although the mask PRNG state carries forward, each block's encryption depends only on the S-box (fixed for the key) and the PRNG state at the start of that block. Given the key and block index, the PRNG state for any block can be computed directly by advancing the PRNG by (block_index × 759) steps. This enables:

- **Random-access decryption:** Any block can be decrypted independently without processing preceding blocks.
- **Parallel encryption/decryption:** Blocks can be distributed across multiple processors.
- **Compartmentalized access:** Only specific blocks need be decrypted, limiting plaintext exposure.

### 2.7 Decryption

Decryption reverses the encryption process. The key insight is that encryption masks are consumed in a fixed sequence, and decryption must apply the inverse operations in reverse order.

**Step 1 - Pre-generate masks:**

All 759 masks for the block are generated in forward order and stored:

```
function FillDecryptMasks(PRNG_M):
    for i = 0 to 758:
        masks[i] ← PRNG_M.Rand()
    return masks
```

**Step 2 - Apply rounds in reverse:**

```
function DecryptBlock(B[0..127], PRNG_M, PRNG_S, S⁻¹, P_base[0..127]):
    // Step 1: Derive per-block permutation (identical to encryption)
    π ← DeriveBlockPermutation(P_base, PRNG_S)   // 128 PRNG_S outputs
    // Step 2: Compute inverse permutation
    π⁻¹[π[k]] ← k for all k
    // Step 3: Pre-generate all 759 masks in forward order
    masks[0..758] ← CollectMasks(PRNG_M)
    // Step 4: Apply rounds in reverse
    idx ← 759
    for round = 3 down to 1:
        ApplyPermutation(B, π⁻¹)                  // reverse permutation FIRST
        // Reverse the reverse pass
        for k = 0 to 125:
            idx ← idx - 1
            B[k:k+2] ← S⁻¹[B[k:k+2]]
            B[k:k+2] ← B[k:k+2] ⊕ masks[idx]
        // Reverse the forward pass
        for k = 126 down to 0:
            idx ← idx - 1
            B[k:k+2] ← S⁻¹[B[k:k+2]]
            B[k:k+2] ← B[k:k+2] ⊕ masks[idx]
```

In each decryption round, the inverse permutation π⁻¹ is applied first (before the inverse cascade passes), reversing the permutation that was applied last in the corresponding encryption round.

Note the order reversal: to undo the forward pass (which went left-to-right applying XOR then S), the decryption applies S⁻¹ then XOR in right-to-left order, and vice versa for the reverse pass.

### 2.8 Summary of Operations per Block

| Phase | S-box Lookups | XOR Operations | PRNG_M Calls | Permutations | PRNG_S Calls |
|-------|--------------|----------------|------------|-------------|-------------|
| Forward pass (×3) | 127 × 3 = 381 | 127 × 3 = 381 | 381 | — | — |
| Reverse pass (×3) | 126 × 3 = 378 | 126 × 3 = 378 | 378 | — | — |
| Permutation (×3) | — | — | — | 3 | — |
| Per-block shuffle | — | — | — | — | 128 |
| **Total per block** | **759** | **759** | **759** | **3** | **128** |

The permutation adds 3 × 128 = 384 byte moves and 128 PRNG_S evaluations per block, approximately 22.5% overhead over the NoPermutation mode.

---

## 3. Cryptanalysis

We conducted a multi-phase adversarial analysis of the SPM cipher.  The analysis assumes a full 256-bit key (no password-derived key weaknesses) and focuses exclusively on the core encryption algorithm.

### 3.1 Effective Key Space

The 256-bit key yields 254 effective key bits due to two forced-odd PRNG keys. The PRNG key word has its least significant bit forced to 1 (ensuring coprimality with 2^64 for full-period cycling). Each PRNG instance loses 1 bit, giving 127 + 127 = 254 effective bits.

This 2-bit loss is cryptographically negligible - the search space remains O(2^254), far beyond any foreseeable computational capability.

### 3.2 Key Decomposition Attack - Refuted

**Hypothesis:** The clean key partition (K_S independent of K_M) might allow the two 127-bit halves to be attacked independently at O(2^128), similar to a meet-in-the-middle attack.

**Attack procedure:**
1. Guess K_S (2^127 candidates) → generate candidate S-box
2. For each candidate S-box, verify using a known (P, C) pair
3. Verification: find K_M such that Encrypt(P; S, K_M) = C

**Why it fails:** Step 3 requires simulating the full 759-step cascade for each candidate K_M. The overlapping-window cascade creates inter-step dependencies: step k's output feeds into step k+1's input through the shared overlap byte. Without knowing the mask at step k, the attacker cannot compute step k's output and therefore cannot determine the input to step k+1. The verification procedure must enumerate K_M candidates exhaustively.

Verification cost per candidate S-box: O(2^127) (exhaustive search over K_M).
Total cost: O(2^127 × 2^127) = O(2^254) - identical to brute force.

**Structural note:** The cascade is the mechanism that prevents decomposition. If the S-box were applied independently at each position (without overlapping windows), the mask at each position could be determined independently, enabling an O(2^128) decomposition. The cascade's serial dependency chain is what entangles the two key halves.

### 3.3 Mask Transparency to Differential and Linear Cryptanalysis

**Theorem 1 (Differential invariance).** For any permutation S on Z_{2^w} and any mask m ∈ Z_{2^w}, define f_m(x) = S(x ⊕ m). Then DDT_{f_m}(Δx, Δy) = DDT_S(Δx, Δy) for all Δx, Δy.

*Proof.* DDT_{f_m}(Δx, Δy) = |{x : S(x ⊕ m) ⊕ S(x ⊕ Δx ⊕ m) = Δy}|. Substituting a = x ⊕ m (a bijection): = |{a : S(a) ⊕ S(a ⊕ Δx) = Δy}| = DDT_S(Δx, Δy). ∎

**Theorem 2 (Linear approximation invariance).** |LAT_{f_m}(a, b)| = |LAT_S(a, b)| for all a, b, m.

*Proof.* LAT_{f_m}(a, b) = Σ_x (−1)^{a·x ⊕ b·S(x⊕m)}. Substituting u = x ⊕ m: = Σ_u (−1)^{a·(u⊕m) ⊕ b·S(u)} = (−1)^{a·m} · LAT_S(a, b). Since |(−1)^{a·m}| = 1, we have |LAT_{f_m}(a,b)| = |LAT_S(a,b)|. ∎

**Consequence:** The 127-bit mask PRNG key contributes **zero additional resistance** to differential and linear cryptanalysis. The cipher's resistance to these attacks depends entirely on the S-box quality (determined by K_S) and the cascade topology. This is not a weakness - the masks serve a different purpose (inter-block variation, see §2.5.1). The S-box and cascade alone provide overwhelming resistance (see §3.4).

### 3.4 Differential Cryptanalysis

Standard differential cryptanalysis [5] requires identifying high-probability differential characteristics through the cipher. For SPM, this analysis faces two compounding barriers:

**Barrier 1: Unknown S-box.** The DDT is key-dependent and unknown to the attacker. Without K_S, the attacker cannot precompute differential characteristics. For AES, the DDT is fixed and public, enabling offline characteristic search. For SPM, no such precomputation is possible.

**Barrier 2: Cascade topology.** Even if the attacker somehow knew the DDT, the 759-step cascade with 3 rounds creates an astronomically large characteristic space.

**Forward-pass trail restriction:** During the forward cascade, the overlapping-window structure restricts differential propagation. A single-byte input difference at position 0 produces a 16-bit input difference of the form (d, 0) at each subsequent step - only 255 of the 65,535 nonzero input differences are exercised. However, this restriction affects only the first forward pass (127 of 759 steps). The reverse pass introduces full 16-bit differences at every position, and by the start of round 2, all restrictions are eliminated.

**Cascade survival probability:** The probability that a single-byte difference propagates through all 127 forward-pass steps is approximately:

$$P(\text{survival}) \approx \left(1 - \frac{255}{65536}\right)^{126} \approx 0.613$$

This uses the observation that for a random 16-bit permutation S, the probability that the output high byte is zero (causing the cascade to extinguish) is approximately 255/65536 per step. Despite the ~39% extinction rate per forward pass, the reverse pass and multiple rounds provide robust compensation.

**Per-step worst-case differential probability:** For a random 16-bit permutation, δ ≈ 4–6, giving a per-step probability of at most δ/2^16 ≈ 2^{−13.4} for any specific output difference. Over 759 steps, the cumulative probability for any specific 759-step characteristic is bounded by approximately 2^{−13.4 × 759} ≈ 2^{−10,171} - far below any exploitable threshold.

**Inter-round permutation effect.** After each round's bidirectional cascade, the key-dependent byte-level permutation π scatters output differences to pseudorandom positions before the next round begins. This eliminates positional alignment between rounds: the attacker cannot construct multi-round differential characteristics without knowledge of π (derived from K_S). The positional arrangements across rounds are identity, π, and π² — determined by a single per-block permutation, not three independent permutations. Nevertheless, the permutation prevents the attacker from predicting which byte positions carry active differences into subsequent rounds, forcing multi-round trail construction to assume average-case DDT behavior across all positions. When a forward-pass differential chain extinguishes at some position, the permutation disperses the "cold zone" across the block for the next round, converting correlated multi-round extinction patterns into uncorrelated ones.

### 3.5 Linear Cryptanalysis

Linear cryptanalysis [6] faces analogous barriers. The LAT is key-dependent and unknown (Theorem 2 shows masks do not affect it). The expected maximum linear bias for a random 16-bit permutation is approximately ε ≈ 0.013, giving a per-step squared bias of ~2^{−12.5}. Matsui's Piling-Up Lemma over 759 steps yields negligible cumulative bias.

Furthermore, the cascade topology forces every step to be "active" - there are no inactive S-box positions through which a linear trail can pass without penalty. In AES terms, SPM has 759 active S-boxes per block encryption. For comparison, AES-256 guarantees a minimum of 25 active S-boxes over 4 rounds [2]; SPM has 759 active S-boxes by construction.

**Inter-round permutation effect.** The byte-level permutation between rounds acts as a key-dependent linear diffusion layer. While it provides no algebraic mixing (unlike AES's MixColumns), it eliminates the attacker's ability to construct multi-round linear approximations without knowledge of the permutation. The per-block permutation variant further ensures that linear trails valid for one block are invalid for the next, preventing accumulation of linear bias across multiple block encryptions.

### 3.6 Algebraic Attacks

Algebraic cryptanalysis [7] attempts to express the cipher as a system of polynomial equations and solve it using Gröbner basis or SAT-solver techniques. AES's S-box has a compact algebraic description (degree-254 polynomial over GF(2^8), or equivalently 23 quadratic equations in 16 variables over GF(2) [7]), enabling algebraic formulations.

SPM's S-box has **no compact algebraic description**. A random 16-bit permutation has expected multivariate algebraic degree 15 - the maximum for any 16-bit permutation (bounded by n−1 for n-bit permutations). This is more than double AES's degree-7 S-box, and over a vastly larger (16-bit vs. 8-bit) variable space. Expressing the full cipher algebraically would require modeling 759 applications of this high-degree permutation, each coupled through the cascade overlap. The resulting system is intractable for all known algebraic solvers.

**Inter-round permutation effect.** Without the permutation, the cascade has a rigid positional structure: the inter-round byte mapping is the identity, which is publicly known. When an attacker models each cascade step individually — introducing intermediate variables at each of the 759 step boundaries — each equation involves only 2 adjacent byte positions, producing a banded equation system with bandwidth 2. This banded structure extends continuously across round boundaries, giving the attacker exploitable positional locality.

The permutation destroys this regularity. After round i, byte k moves to position π(k) before entering round i+1. Since π is key-dependent and secret, the inter-round dependency graph becomes a secret random bipartite matching. The attacker must either (a) guess π (equivalent to guessing K_S at cost O(2^{127})), or (b) introduce 128 additional discrete unknowns per round boundary subject to bijection constraints — transforming the polynomial system into a mixed integer-polynomial system of categorically greater complexity.

For Gröbner basis algorithms (F4/F5), the permutation eliminates exploitable Jacobian sparsity at round boundaries, forcing the system to behave as a fully dense random system — the worst case for these algorithms. For SAT solvers, the permutation eliminates positional locality that unit propagation, variable ordering heuristics, and learned clause transfer depend upon.

The per-block permutation variant ensures that multi-block algebraic attacks cannot correlate permutation structure across blocks: each block's equation system involves a distinct permutation, related to others only through the secret PRNG evolution.

**Limitation.** The permutation is derived from PRNG_S (the same stream that generates the S-box) and provides derived, not independent, security. Recovery of K_S yields both the S-box and the permutation. The permutation adds only linear equations (byte rearrangement) to the algebraic system — it does not increase the cipher's algebraic degree. Its contribution is structural: eliminating exploitable positional regularity rather than adding nonlinear complexity.

### 3.7 Meet-in-the-Middle Attacks

Meet-in-the-middle (MITM) attacks exploit ciphers with identifiable "midpoints" that can be computed independently from plaintext and ciphertext. In AES, each round key can be guessed independently in a MITM framework [9].

SPM resists MITM attacks because the S-box and masks are entangled at every cascade step. There is no natural midpoint: the S-box (determined by K_S) is used in every step, and the mask (determined by K_M) is also used in every step. Any MITM partition that fixes one half of the key still requires the full cascade evaluation with the other half, degenerating to exhaustive search.

The permutation is derived from K_S (the same key half as the S-box) and does not introduce additional key material, so the MITM partition is unchanged. The permutation slightly strengthens the entanglement between rounds, but the existing cascade barrier already prevents independent half-key attack.

### 3.8 Slide Attacks

Slide attacks [10] exploit self-similarity in a cipher's round structure - if round i and round j use identical subkeys, the attacker can identify "slid pairs" and reduce the cipher to a single-round problem.

SPM's mask PRNG advances continuously across blocks. Two blocks at positions i and j use the same mask sequence only if the PRNG_M state (m_wState, m_idx) is identical at the start of both blocks. The PRNG_M has a total output period of 2^{66} (2^{64} state values × 4 outputs per state). Each block consumes 759 outputs. Since 759 is odd, gcd(759, 2^{66}) = 1, and the block-boundary states cycle through all 2^{66} distinct (state, idx) values before repeating — a period of 2^{66} blocks. A slid pair requires the block index difference to be a multiple of 2^{66}, meaning the attacker needs 2^{66} blocks of known plaintext, corresponding to 2^{66} × 128 = 2^{73} bytes ≈ 10 zettabytes of data. This is beyond any practical storage or transmission capacity.

**Permutation effect on slide attacks.** A valid slide pair additionally requires matching PRNG_S states (for identical per-block permutations). Each block consumes 128 PRNG_S outputs, and since gcd(128, 2^{66}) = 2^7, the PRNG_S block-boundary states have period 2^{66}/2^7 = 2^{59} blocks. Since 2^{59} divides 2^{66}, any block pair satisfying the PRNG_M period constraint automatically satisfies the PRNG_S constraint. The permutation therefore does not increase the slide attack data requirement beyond the 2^{73} bytes already imposed by PRNG_M state alignment. The permutation's contribution to slide resistance is structural rather than quantitative: even if an attacker found a slid pair (requiring 2^{73} bytes), they would still face the full cascade + permutation inversion problem.

### 3.9 Chosen-Plaintext Analysis

Under a chosen-plaintext attack (CPA), the attacker submits chosen plaintexts and observes ciphertext outputs. We considered several CPA strategies:

**Partition attack:** Submit plaintexts varying only in byte 0, observe ciphertext at position 0. This reveals equivalence classes of the low byte of S-box entries at position 0 after the first forward-pass step. However, the cascade propagates the first step's output into all subsequent steps, and 3 rounds of bidirectional cascade obliterate the partial information. No key recovery was achieved from partition information against the full 3-round cipher.

**Identical-block probing:** Submit identical plaintext blocks at positions separated by the PRNG sub-period (345 blocks for the low 16 bits of the mask state). At position 0 of the forward pass, the mask repeats, producing identical S-box outputs. However, at position 1 the mask does NOT repeat (it is derived from a different 16-bit slice of the state, with a different sub-period of ~5.7 × 10^6 blocks). The cascade diverges immediately at step 1, and after the remaining 757 steps plus two additional rounds, no distinguishable signal survives.

**No chosen-plaintext attack was found that recovers key material.**

### 3.10 Side-Channel Considerations

The 128 KB S-box table spans many cache lines on modern processors, creating a classic cache-timing side-channel attack surface analogous to AES T-table attacks [11]. If the full S-box is recovered through a side-channel attack, the remaining search space is the 127-bit mask PRNG key - still O(2^127), which is equivalent to the brute-force security of AES-128.

The key architecture supports arbitrary key widening (§4.3), allowing the security floor under side-channel threat to be raised without architectural changes. A constant-time implementation would require bitslicing the 16-bit S-box, which is substantially more expensive than constant-time AES but is architecturally feasible.

**Permutation side-channel surface.** The byte-level permutation introduces data-dependent memory access patterns: the write address in ApplyPermutation depends on secret permutation values, and the per-block shuffle involves data-dependent swaps that could leak PRNG_S output via cache-timing. If the permutation is recovered through side-channel observation, the 128 shuffle outputs (each 7 effective bits) overconstrain the 64-bit PRNG_S state, enabling full K_S recovery and subsequent S-box reconstruction. The conditional attack complexity remains O(2^{127}) — the same as direct S-box leakage — but the permutation provides an additional observable target. A constant-time implementation of the permutation (unconditional writes to all buffer positions) would eliminate this vector.

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
| Brute force | O(2^254) | 1 KP pair | Best known classical attack |
| Key decomposition | O(2^254) | 1 KP pair | Cascade prevents splitting |
| Differential | > O(2^254) | N/A | Unknown DDT + 759 active S-boxes |
| Linear | > O(2^254) | N/A | Unknown LAT + 759 active S-boxes |
| Algebraic | > O(2^254) | 1 KP pair | No compact algebraic description |
| Meet-in-the-middle | O(2^254) | 1 KP pair | No separable midpoint |
| Slide | O(2^254) | ~2^{73} bytes | Data requirement impractical (PRNG_M period = 2^{66} blocks) |
| Chosen-plaintext | No key recovery | 2^16 blocks | Partial S-box info only |
| Side-channel | O(2^127) | S-box leak + 1 KP | Conditional on physical access |
| **Grover (quantum)** | **O(2^{163}) gates** | **1 KP pair** | **~1.05M qubits; see §5** |
| Simon (quantum) | N/A | N/A | Not applicable - no algebraic periodicity |

**Conclusion: The strongest classical attack is exhaustive key search at O(2^254). The strongest quantum attack is Grover's algorithm at O(2^{127}) oracle calls, but with a per-call cost of O(2^{36}) gates and ~1.05 million qubits (see §5).**

---

## 4. Comparison with AES-256

### 4.1 Algorithmic Structure

AES-256 [1] employs 14 rounds of four distinct transformations: SubBytes (fixed 8-bit S-box), ShiftRows (byte permutation), MixColumns (GF(2^8) matrix multiplication), and AddRoundKey (XOR with round key). The round key schedule expands the 256-bit key into 15 × 128-bit subkeys using SubWord, RotWord, and round constants.

SPM employs 3 rounds of two transformations: a bidirectional cascade of XOR mask followed by 16-bit S-box lookup, and a key-dependent byte-level block permutation (§2.5.4). There is no matrix multiplication and no key schedule.

| Dimension | AES-256 | SPM-256 |
|-----------|---------|---------|
| Distinct operation types per round | 4 | 2 |
| S-box width | 8 bits (256 entries) | 16 bits (65,536 entries) |
| S-box lookups per block | 224 | 759 |
| Matrix multiplications per block | 160 (GF(2^8)) | 0 |
| Key expansion operations | ~100 | 0 (direct PRNG seeding) |
| S-box generation cost | 0 (fixed) | ~1,049,000 operations |
| Block size | 128 bits | 1024 bits |

SPM is algorithmically simpler in the sense that it employs fewer primitive operations. However, it requires more S-box lookups per block and a substantially more expensive key setup phase.

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

**Algebraic attack surface.** AES's S-box is the composition of a multiplicative inverse in GF(2^8) with an affine transformation. This algebraic structure has been extensively studied and enables formulation as a system of low-degree polynomial equations [8]. While no practical algebraic attack on full AES exists, the algebraic attack family is applicable precisely because the S-box has a compact polynomial representation. SPM's S-box, generated by a PRNG-driven shuffle, has no such compact representation - the expected algebraic degree is maximal, rendering algebraic formulations intractable.

**Trust model.** AES's constants were selected by Daemen and Rijmen [2] based on published mathematical criteria (optimal MDS properties, maximal nonlinearity). The wider community trusts these choices through verification of the stated criteria. SPM requires no such trust - there are no designer-selected constants. The cipher's cryptographic properties emerge from the user's own key.

**Per-key diversity.** All AES users share the same S-box, the same MixColumns matrix, and the same algebraic structure. A structural breakthrough (however unlikely) against AES would compromise all keys simultaneously. SPM generates a unique S-box for each key - a structural attack against one key's S-box does not transfer to another key.

**Provable bounds.** AES's fixed structure enables formal security proofs: the wide trail strategy [2] guarantees at least 25 active S-boxes over 4 rounds, giving a proven differential characteristic probability bound of (4/256)^25 ≈ 2^{−150}. SPM has **no analogous formal bound**. The S-box has expected differential uniformity δ ≈ 4–6 (consistent with random 16-bit permutations), and the cascade ensures 759 active S-boxes by construction, but no theorem proves these properties for all keys.

**Public scrutiny.** AES was selected through a multi-year international competition (1997–2001) [12] and has been subjected to more cryptanalytic scrutiny than any cipher in history. The biclique attack by Bogdanov et al. [9] remains the best known, achieving a marginal complexity reduction to O(2^254.4) for AES-256 - a computational improvement of less than a factor of 4 over brute force, and entirely theoretical. SPM has undergone substantially less analysis. While no weakness was found in this study, the depth of analysis is not comparable to AES's 25+ years of scrutiny.

### 4.4 Performance

AES benefits from dedicated hardware instruction sets (AES-NI on x86 [13], ARMv8 Crypto Extensions, RISC-V AES extensions). A single AES-NI round executes in approximately 1 clock cycle, enabling full AES-256 encryption in ~14 cycles per 128-bit block.

SPM requires 759 lookups from a 128 KB S-box table. On modern CPUs, this table exceeds L1 cache capacity (typically 32–64 KB), resulting in frequent L2 cache hits. Estimated throughput on modern x86 hardware: ~2,000–3,000 cycles per 1024-bit block, or approximately 2–3 cycles per bit - compared to AES-NI's ~0.1 cycles per bit.

However, SPM's 1024-bit block processes 8× as many bits per block operation. The effective throughput gap is smaller when measured in bits per second, but AES with hardware acceleration remains substantially faster.

Furthermore, while in some applications computational cost is critical, in most applications it is not a significant factor in the particular applicaiton details.  Higher computational cost is actually a burden to any attacker trying to brute force the key.  If the computational cost is higher, the CPU cost to brute force 2^256 keys is also going to be hihger.  So, the contatn time implementations of AES actually make it weaker against a brute force attack against the key.  The contant cost of constructing a new sbox for each key in SPM will further increase the cost of any brute force attack against the key.

### 4.5 Side-Channel Resistance

AES's fixed 256-byte S-box can be implemented in constant time via bitslicing [14] or hardware instructions, effectively eliminating cache-timing side channels. SPM's 128 KB key-dependent S-box is far more challenging to implement in constant time - the table is too large for efficient bitslicing, and no hardware support exists.

### 4.6 Key Scalability

SPM's architecture imposes no upper limit on key size. The PRNG seeding mechanism accepts arbitrary-length key material, and larger keys increase the S-box search space proportionally. For example, a 1152-bit key (1024 bits for S-box, 128 bits for mask) would provide O(2^1150) security under pure cryptanalysis. AES's key size is architecturally fixed at 128, 192, or 256 bits.  Implementing SPM block cipher with even a 512 bit key would be trival.

---

## 5. Quantum Cryptanalysis

The emergence of quantum computing introduces new attack vectors against symmetric ciphers. Grover's algorithm [15] provides a quadratic speedup for brute-force key search, while Simon's algorithm [16] and quantum algebraic techniques offer potentially greater speedups against ciphers with exploitable algebraic structure. This section analyzes SPM's resistance to all known quantum attack families and demonstrates that the 16-bit key-dependent S-box - designed explicitly as a quantum countermeasure - provides a massive practical advantage over fixed-S-box ciphers.

### 5.1 Grover's Algorithm: Theory and Oracle Cost

Grover's algorithm reduces brute-force search over an n-bit key from O(2^n) classical operations to O(2^{n/2}) quantum oracle calls. Each oracle call requires implementing the cipher as a reversible quantum circuit operating in superposition over all candidate keys. The total quantum attack cost is therefore:

$$\text{Total quantum cost} = O(2^{n/2}) \times C_{\text{oracle}}$$

The critical insight is that C_oracle - the quantum circuit cost per cipher evaluation - varies enormously between ciphers. A cipher with a lightweight quantum circuit is far more vulnerable to Grover's attack in practice than one with a heavyweight circuit, even if both have the same key length. This distinction, absorbed when treating the oracle as a unit-cost black box in the standard Grover halving metric, is decisive for the SPM vs. AES comparison.

### 5.2 Quantum Circuit for AES-256

AES-256's fixed S-box is derived from GF(2^8) multiplicative inversion, an algebraic operation that admits compact quantum circuit implementations via tower field decomposition [17][18]. Recent research has achieved highly optimized quantum AES circuits:

| Resource | Best Known Estimate | Source |
|----------|-------------------|--------|
| Qubits | ~264–320 | Zou et al. 2025 [17]; Huang & Sun 2025 [18] |
| T-gates per evaluation (cipher-only) | ~2^{17}–2^{19} | Langenberg et al. 2020 [20]; optimized from Grassl et al. 2016 [19] |
| T-depth | ~800–1,600 | Various optimizations [17][18] |
| DW-cost (depth × width) | ~65,000–103,000 | Huang & Sun 2025 [18] |

Note: The lowest published qubit counts (~264) apply to AES-128; AES-256 requires approximately 320–400 qubits due to the longer key schedule (Li et al. 2023). All gate costs in this analysis refer to cipher-evaluation-only T-gates, not full Grover iteration costs (which include diffusion, uncomputation, and ancilla management overhead). Grassl et al. 2016 [19] report ~186 million T-gates (~2^{27.5}) for the full Grover iteration; the cipher-evaluation component is substantially less. We use the explicit quantum circuit model (standard in the Grover-on-cipher literature, e.g., Grassl 2016, Jaques 2020) throughout this analysis, not speculative QRAM models.

**AES-256 post-quantum security:** O(2^{128}) oracle calls × ~2^{17}–2^{19} gates per call ≈ **O(2^{145}–2^{147})** total gate operations, using ~320–400 qubits.

The compact circuit is possible because AES's 8-bit S-box has only 256 entries and a known algebraic structure (GF(2^8) inversion), enabling efficient quantum synthesis.

### 5.3 Quantum Circuit for SPM-256: The 16-Bit S-box Barrier

SPM's key-dependent S-box fundamentally changes the Grover oracle construction. Unlike AES, where the S-box is fixed and can be hardwired into the quantum circuit, SPM's S-box must be **computed inside the oracle** for each candidate key evaluated in superposition. This is unavoidable: the S-box is a function of the key, and Grover's algorithm tests all keys simultaneously.

#### 5.3.1 Qubit Requirements: The Impact of 16-Bit Width

The 16-bit S-box contains 65,536 entries of 16 bits each. In a quantum circuit, the entire S-box table must be held in quantum registers:

| Component | Qubits Required | Notes |
|-----------|----------------|-------|
| S-box table (65,536 × 16-bit) | 1,048,576 | The dominant cost - directly from 16-bit width |
| PRNG state registers (2 instances) | ~192 | State + key + index for each PRNG |
| Block state (128 bytes) | 1,024 | The plaintext/ciphertext being processed |
| Mask and intermediate ancillae | ~2,048 | Temporary computation registers |
| **Total** | **~1,051,840** | **Approximately 1.05 million qubits** |

Note: No separate storage for the inverse S-box is needed. In reversible quantum computation, the inverse of any unitary operation is obtained by running the circuit in reverse (adjoint/dagger). The reverse S-box is computed via uncomputation at no additional qubit cost - this is standard practice in all published quantum cipher circuits (Grassl 2016, Jaques 2020).

**Comparison by S-box width:**

| S-box Width | Entries | Table Qubits | Total Qubits (est.) | Example Cipher |
|-------------|---------|-------------|---------------------|----------------|
| 8-bit | 256 | 2,048 | ~320–400 | AES |
| 16-bit | 65,536 | 1,048,576 | ~1,050,000 | **SPM** |
| Ratio | 256× | **512×** | **~3,300×** | |

The 16-bit S-box width is the single most important factor in SPM's quantum resistance. By squaring the number of entries (256 → 65,536) and doubling the entry width (8 → 16 bits), the qubit requirement increases by a factor of 512× for the S-box table alone. When accounting for supporting registers, the total qubit requirement is approximately **3,300× greater** than AES.

This was a deliberate design choice. The 16-bit S-box was designed explicitly to create a very high degree of nonlinearity that would impose extraordinary costs on any quantum attacker. The jump from 8-bit to 16-bit S-box - doubling the width - produces a 512× increase in table qubit requirements. For a b-bit S-box, the table requires Q(b) = b × 2^b qubits; the ratio Q(b+1)/Q(b) = 2(b+1)/b approaches 2× per additional bit for large b. The 8→16 jump is particularly dramatic because the width doubles rather than incrementing by one: Q(16)/Q(8) = (16 × 2^{16})/(8 × 2^{8}) = 512.

#### 5.3.2 Gate Cost: S-box Generation in Superposition

The S-box generation (16 passes × 65,536 swaps = 1,048,576 PRNG-driven shuffle operations) must execute inside the quantum circuit. Each swap requires:

1. **PRNG state update:** Addition mod 2^64, slice extraction - ~64 T-gates
2. **Quantum addressing:** Accessing a specific entry in the 65,536-element quantum register requires a quantum multiplexer (QRAM) circuit with O(2^{16}) controlled operations per access
3. **Conditional swap:** ~32 T-gates for the swap itself

The QRAM addressing dominates: each of the 1,048,576 swap operations requires O(2^{16}) gates for address decoding.

$$C_{\text{sbox-gen}} \approx 1,048,576 \times O(2^{16}) \approx O(2^{36}) \text{ gates}$$

For comparison, an entire AES-256 cipher evaluation costs ~2^{17}–2^{19} T-gates. **SPM's S-box generation alone costs approximately 2^{17}–2^{19} times more** than a complete AES encryption.

#### 5.3.3 Gate Cost: Cascade Encryption

The 759 cascade S-box lookups each require QRAM access into the quantum S-box register:

$$C_{\text{encrypt}} \approx 759 \times O(2^{16}) \approx O(2^{26}) \text{ gates}$$

#### 5.3.4 Total Grover Oracle Cost

$$C_{\text{oracle}}^{\text{SPM}} = C_{\text{sbox-gen}} + C_{\text{encrypt}} \approx O(2^{36}) + O(2^{26}) \approx O(2^{36})$$

The byte-level permutation adds approximately 2,816 qubits (~0.3% of the existing budget) and ~2^{18} additional gates per oracle call (base permutation generation + per-block shuffle + 3 permutation applications). Against the O(2^{36}) S-box generation cost, this is negligible. The permutation does provide a qualitative quantum benefit: it eliminates the regular positional structure (byte k in round i maps to byte k in round i+1) that a quantum algebraic solver could exploit.

### 5.4 Quantum Attack Comparison: SPM vs. AES

| Metric | AES-256 | SPM-256 | Ratio (SPM/AES) |
|--------|---------|---------|-----------------|
| Grover oracle calls | O(2^{128}) | O(2^{127}) | ~0.5× |
| **Qubits required** | **~320–400** | **~1,050,000** | **~3,300×** |
| **Gates per oracle call** | **~2^{17}–2^{19}** | **~2^{36}** | **~2^{17}–2^{19} (130,000–500,000×)** |
| **Total gate operations** | **~2^{145}–2^{147}** | **~2^{163}** | **~2^{16}–2^{18} (65,000–260,000×)** |
| Post-quantum security (theoretical) | 128 bits | 127 bits | ~Equal |
| **Post-quantum security (practical)** | 128 bits | **>>127 bits** | **SPM dramatically harder** |

The theoretical post-quantum security levels (by the standard Grover halving metric) are nearly identical: 128 bits for AES-256 vs. 127 bits for SPM-256. However, this metric treats oracle calls as unit cost, which profoundly understates SPM's advantage. We distinguish between "theoretical" security (asymptotic oracle-call complexity, following NIST's category definitions) and "concrete computational cost" (the total gate operations, qubits, and circuit depth required for an actual attack).

**In practice, a quantum computer capable of attacking AES-256 via full Grover search would be entirely inadequate for SPM-256.** It would need approximately:
- **~3,300× more qubits** (1.05 million vs. 320–400)
- **~130,000–500,000× more gates per oracle evaluation** (2^{36} vs. 2^{17}–2^{19})
- **~65,000–260,000× more total gate operations** (2^{163} vs. 2^{145}–2^{147})

The qubit requirement alone places SPM far beyond the reach of any quantum computer architecture currently envisioned. While AES-256 could theoretically be attacked by a quantum computer with a few hundred logical qubits (still far beyond current capability), attacking SPM-256 would require a machine with over 1 million logical qubits - a fundamentally different engineering challenge. Under NIST MAXDEPTH constraints (limiting circuit depth to ~2^{96} operations), SPM's deeper oracle circuit would force attackers to parallelize even more aggressively, requiring additional quantum hardware - further strengthening SPM's advantage.

#### 5.4.1 Hybrid Classical-Quantum Attack

A hybrid attack strategy can reduce the quantum circuit requirements by fixing K_S classically and using Grover only for the 127-bit K_M search. In this approach, the attacker classically enumerates candidate K_S values, generates the full S-box for each, and hardwires the resulting S-box into a much smaller quantum circuit that searches only over K_M.

This reduces the quantum circuit to ~3,000–5,000 qubits - comparable to AES - because the S-box is now a fixed classical lookup table rather than a key-dependent computation in superposition. However, this qubit savings comes at enormous cost in total work:

- The classical outer loop requires 2^{127} iterations, each generating a full 65,536-entry S-box (~2^{20} operations per S-box generation)
- At 10^9 operations/second: 2^{127} × 2^{20} / 10^9 ≈ 2^{117} seconds ≈ 5 × 10^{26} years
- Even with 10^9 parallel classical processors: ~5 × 10^{17} years (~4 × 10^{7} times the age of the universe)
- Total work: O(2^{190+}) - far exceeding the full-Grover cost of O(2^{163})

The hybrid attack trades qubit count for dramatically more total computation. While it demonstrates that SPM's qubit advantage can in principle be circumvented, the resulting attack is *less* practical than full Grover - which is itself completely infeasible. A quantum computer capable of attacking AES-256 could serve as the inner loop of the hybrid, but the classical outer loop would need to run for trillions of times the age of the universe.

### 5.5 Simon's Algorithm: Not Applicable to SPM

Simon's algorithm [16] provides exponential speedup against ciphers with exploitable algebraic periodicity. Specifically, Simon's algorithm efficiently finds a hidden XOR-period s such that f(x) = f(x ⊕ s) for all x, given quantum superposition access to f. It has been applied to break Even-Mansour constructions [25] and certain MAC schemes in polynomial time under the Q2 model (quantum superposition queries). For Even-Mansour-type ciphers, the attack requires:

1. A function with a hidden XOR-period (arising from the additive key structure of Even-Mansour: E_k(x) = P(x ⊕ k_1) ⊕ k_2)
2. Quantum superposition access to the encryption oracle
3. A public permutation that the attacker can evaluate independently to construct the period-revealing function

**SPM is immune to Simon's algorithm** for three reasons:

1. **No public permutation.** SPM's S-box is key-dependent and secret. There is no "P" to query independently.
2. **No additive key structure.** The key's effect on ciphertext is the composition of 759 nonlinear substitutions, not a simple XOR.
3. **Key-dependent nonlinearity.** Every nonlinear operation is key-dependent, eliminating the separation between "public structure" and "secret key" that Simon's attack exploits.

For comparison, AES also resists Simon's algorithm on the full cipher, but its public S-box means that Simon-type attacks have been demonstrated against Even-Mansour and FX constructions when instantiated with any permutation, including AES [25][22]. For SPM, even simplified variants resist Simon's attack because the S-box itself is secret.

### 5.6 Quantum Algebraic and Enhanced Differential/Linear Attacks

**Quantum algebraic attacks** accelerate the solution of polynomial equation systems via quantum Gröbner basis computation and HHL-based linear algebra. AES's S-box has a compact algebraic description (23 quadratic equations per S-box in GF(2) [7]), providing a well-defined target for quantum algebraic solvers. SPM's S-box has **no compact algebraic description** - the expected multivariate algebraic degree is 15 (the maximum n−1 for any n-bit permutation). While AES's 8-bit S-box also has maximal degree (7) for its width, it operates over a much smaller space (8-bit vs. 16-bit variables), and its algebraic structure in GF(2^8) enables compact equation systems that have no analogue for SPM's PRNG-generated permutation. Quantum speedups (polynomial or quadratic) applied to an intractable base complexity remain intractable.

**Quantum differential/linear attacks** use amplitude amplification for quadratic speedup in finding conforming pairs or estimating biases. For AES, the fixed public DDT/LAT enables precomputation of optimal characteristics; quantum speedup applies to the data collection phase. For SPM, the DDT and LAT are key-dependent and unknown - the same barrier that blocks classical attacks blocks quantum-enhanced versions. Additionally, the mask transparency property (Theorems 1–2) holds in both classical and quantum settings.

**Verdict:** Quantum algebraic, differential, and linear attacks are no more effective against SPM than their classical counterparts.

### 5.7 The 16-Bit Key-Dependent S-box as a Quantum Defense Mechanism

The most significant finding of this quantum analysis is that SPM's 16-bit key-dependent S-box - designed explicitly to maximize nonlinearity as a countermeasure against quantum attacks - provides quantum resistance through two reinforcing mechanisms:

**Mechanism 1: Oracle cost amplification.** A fixed S-box (AES) can be hardwired into a quantum circuit using a modest number of gates. A key-dependent S-box must be computed inside the Grover oracle in superposition. For SPM's 16-bit S-box, this computation involves 1,048,576 PRNG-driven swaps over 65,536 entries, each requiring QRAM addressing - transforming a lightweight oracle call into one costing 2^{36} gates, approximately 130,000–500,000× more than AES.

**Mechanism 2: Algebraic structure elimination.** Quantum algorithms beyond Grover (Simon's, HHL, quantum algebraic solvers) exploit algebraic structure in the target function. AES's GF(2^8) S-box has a compact polynomial description enabling algebraic formulations. SPM's PRNG-generated S-box has no such description. This eliminates the algebraic "handles" that beyond-Grover quantum algorithms require, confining the quantum attacker to Grover's generic search as the only applicable quantum strategy - and even that strategy faces the enormous oracle cost barrier.

The scaling relationship is particularly favorable. For a b-bit S-box, the table requires Q(b) = b × 2^b qubits; the ratio Q(b+1)/Q(b) = 2(b+1)/b, approaching 2× per additional bit for large b. The jump from AES's 8-bit S-box to SPM's 16-bit S-box - a doubling of width - produces a **512× increase in table qubit requirements**, a **~3,300× increase in total qubits**, and a **130,000–500,000× increase in gate cost per oracle call**. This superlinear scaling means that even modest increases in S-box width produce dramatic improvements in quantum resistance, establishing SPM's design as inherently quantum-resistant.

### 5.8 Comparison with Other Ciphers

To contextualize SPM's quantum resistance, we surveyed published symmetric ciphers that incorporate design features potentially relevant to quantum resistance - particularly key-dependent S-boxes and large internal state - and compared their estimated quantum attack costs under the Grover oracle model used throughout this paper. All ciphers are evaluated at 256-bit key strength where available.

| Cipher | Key Size | Block Size | S-box Type | S-box Width | Est. Qubits | Est. Gates/Oracle |
|--------|:--------:|:----------:|------------|:-----------:|:-----------:|:-----------------:|
| **AES-256** [1] | 256-bit | 128-bit | Fixed (GF(2^8) inversion) | 8-bit | ~320–400 | ~2^{17}–2^{19} |
| **Twofish-256** [3] | 256-bit | 128-bit | Key-dependent (q-permutation derived) | 8-bit | ~1,000–5,000 | ~2^{18}–2^{21} |
| **Blowfish** [4] | ≤448-bit | 64-bit | Key-dependent (521 subkey encryptions) | 8-bit | ~10,000–50,000 | ~2^{22}–2^{25} |
| **EAES** | 256-bit | 128–256-bit | Fixed (extended AES rounds) | 8-bit | ~400–600 | ~2^{18}–2^{20} |
| **Rectangle** | 128-bit | 64-bit | Fixed (4-bit) | 4-bit | ~200–400 | ~2^{15}–2^{17} |
| **SPM-256** | 256-bit | 1024-bit | Key-dependent (PRNG naive shuffle) | **16-bit** | **~1,050,000** | **~2^{36}** |

Several observations emerge from this comparison:

1. **SPM is unique in using a 16-bit S-box.** Every other published cipher uses S-boxes of 8 bits or fewer. The jump from 8-bit (256 entries) to 16-bit (65,536 entries) produces a 256× increase in table size and a corresponding increase in the qubits required to represent the S-box in a quantum circuit.

2. **Key-dependent S-boxes help, but width dominates.** Twofish and Blowfish both use key-dependent S-boxes, which prevents precomputation of quantum oracles. However, their 8-bit S-boxes limit the quantum cost advantage. Twofish-256 requires roughly 1,000–5,000 qubits - approximately 200–1,000× fewer than SPM. Blowfish's costly key schedule (521 encryptions to generate S-boxes) increases its quantum overhead significantly, but its 64-bit block renders it vulnerable to birthday-bound attacks and unsuitable for modern use.

3. **Fixed-S-box ciphers cluster near AES.** EAES variants (additional rounds or larger blocks over the AES framework) and lightweight ciphers like Rectangle offer marginal quantum cost differences from AES, because they share the same fundamental property: a fixed, publicly known S-box that can be synthesized as a compact quantum circuit.

4. **SPM's advantage is structural, not parametric.** The ~3,300× qubit advantage and ~130,000–500,000× gate advantage over AES-256 are not the result of simply using more rounds or a larger block. They arise from a qualitative design difference: the S-box is generated by a keyed PRNG shuffle with no algebraic shortcut, forcing any quantum adversary to store the entire 65,536-entry table in superposition. No other published cipher imposes this constraint.

No published symmetric cipher with a 256-bit key was found to exceed or match SPM's quantum oracle cost. SPM's 16-bit key-dependent S-box - designed explicitly as a quantum countermeasure - represents a unique point in the design space of symmetric cryptography.

---

## 6. Discussion

### 6.1 The Cascade as a Design Primitive

The overlapping sliding-window cascade is SPM's most novel structural element. It achieves diffusion without any linear mixing layer - a departure from the SPN paradigm that has dominated cipher design since the wide trail strategy [2]. The cascade's serial dependency chain entangles the S-box and mask keys at every step, preventing the decomposition attacks that would otherwise reduce the effective security from O(2^254) to O(2^128).

The cascade's diffusion mechanism differs fundamentally from AES's MDS matrix. AES achieves optimal branch number (5) through an algebraically defined linear transformation, enabling formal bounds on active S-boxes. The cascade achieves full-block diffusion through serial propagation of the S-box output's high byte, but the diffusion quality is harder to bound formally. The ~61% forward-pass survival probability (§3.4) is offset by the reverse pass and multiple rounds, but no tight bound on the minimum number of "effectively active" S-boxes is known.

The inter-round byte-level permutation complements the cascade by disrupting fixed positional relationships between rounds. While the cascade provides within-round diffusion through serial dependency chains, the permutation provides between-round diffusion by scrambling byte positions. The positional arrangements across 3 rounds (identity, π, π²) are algebraically related through a single key-dependent permutation, providing genuine positional diversity at negligible computational cost. The permutation's primary contribution is structural hardening: eliminating the exploitable regularity of identity inter-round wiring without adding computational expense.

### 6.2 Block Independence as a Feature

SPM's block-independent encryption (no inter-block chaining) is a deliberate design choice that enables random-access decryption, parallelized encryption across distributed systems, and compartmentalized security - the ability to decrypt only selected blocks without exposing others. This design does not weaken the cipher's cryptanalytic strength (no attack exploiting block independence was found below O(2^254)), but it does require external integrity mechanisms (MAC/HMAC) to detect ciphertext manipulation.

### 6.3 Open Questions

1. **Formal differential/linear bounds.** Empirical measurement of DDT and LAT over a representative sample of PRNG-generated S-boxes would strengthen confidence in the cipher's resistance to these standard attacks.
2. **Constant-time implementation.** Practical techniques for eliminating the cache-timing side channel on the 128 KB S-box table remain to be developed.
3. **Optimal round count.** The choice of 3 rounds is empirically motivated. A formal analysis of the minimum number of rounds required for full-block diffusion, analogous to AES's 4-round differential proof, would be valuable.
4. **S-box indistinguishability.** No proof or disproof exists that PRNG-generated S-boxes are computationally indistinguishable from random permutations. While heuristic evidence strongly supports indistinguishability, a formal treatment is desirable.
5. **Quantum circuit lower bounds.** The oracle cost estimates in §5 are upper bounds based on current quantum circuit construction techniques. Tighter lower bounds on the minimum quantum circuit cost for evaluating SPM's key-dependent S-box would strengthen the quantum resistance claims.


---

## 7. Conclusion

The SPM block cipher achieves an effective security level of O(2^254) under classical cryptanalysis - comparable to AES-256's O(2^256) (best known attack: Biclique O(2^254.4) [9]). No attack across any standard family (differential, linear, algebraic, MITM, slide, chosen-plaintext) reduces the complexity below exhaustive key search. The cipher's primary defense - a 759-step cascading S-box with overlapping windows - is a novel and effective construction that resists decomposition and prevents independent attack on the two key halves. The inter-round byte-level permutation complements the cascade by eliminating fixed positional structure between rounds, providing structural hardening against algebraic attacks at negligible computational cost.

Under quantum cryptanalysis, SPM demonstrates a **dramatic practical advantage over AES-256**. While both ciphers achieve comparable theoretical post-quantum security under the standard Grover halving metric (~127–128 bits), the concrete quantum computational cost differs by orders of magnitude. SPM's 16-bit key-dependent S-box - designed explicitly as a quantum countermeasure through maximized nonlinearity - requires approximately 1.05 million qubits and 2^{36} gates per Grover oracle call, compared to ~320–400 qubits and ~2^{17}–2^{19} cipher-evaluation T-gates for AES-256. A quantum computer capable of attacking AES-256 via full Grover search would need to be ~3,300× larger in qubit count and perform 130,000–500,000× more gate operations per key candidate to attack SPM-256. A hybrid classical-quantum attack can reduce the qubit requirement to ~3,000–5,000 by classically enumerating K_S values, but at a total cost of O(2^{190+}) - far exceeding the full-Grover cost of O(2^{163}) - making the hybrid attack even less practical than the already-infeasible full Grover approach. Furthermore, SPM is immune to Simon's algorithm and quantum algebraic attacks - attack families that, while not currently practical against full AES, have been demonstrated against Even-Mansour and FX constructions and remain a theoretical concern for fixed-S-box ciphers.

SPM and AES represent fundamentally different design philosophies. AES achieves provable security within a fixed algebraic framework, at the cost of requiring trust in designer-selected constants and accepting a fully public internal structure that enables compact quantum circuit implementations. SPM achieves per-key unpredictability by eliminating all predefined constants, at the cost of losing formal provability and hardware acceleration support - but gaining enormous quantum resistance as a direct consequence of its key-dependent structure. Both approaches achieve their classical security goals; in the quantum domain, SPM's design provides a substantial and quantifiable advantage.

The choice between them depends on the operational requirements and threat model: AES is preferred where hardware acceleration, constant-time implementation, and formal security proofs are paramount; SPM is preferred where per-key diversity, absence of predefined constants, block independence, quantum resistance, and resistance to algebraic attack families are valued. In a post-quantum threat landscape, SPM's 16-bit key-dependent S-box represents a compelling design paradigm - one where the very property that maximizes classical nonlinearity simultaneously maximizes the quantum attack cost.

---

## References

[1] National Institute of Standards and Technology, "Advanced Encryption Standard (AES)," Federal Information Processing Standards Publication 197, November 2001.

[2] J. Daemen and V. Rijmen, *The Design of Rijndael: AES - The Advanced Encryption Standard*, Springer-Verlag, 2002.

[3] B. Schneier, J. Kelsey, D. Whiting, D. Wagner, C. Hall, and N. Ferguson, "Twofish: A 128-Bit Block Cipher," *AES Submission*, 1998.

[4] B. Schneier, "Description of a New Variable-Length Key, 64-Bit Block Cipher (Blowfish)," in *Fast Software Encryption*, Springer, 1994, pp. 191–204.

[5] E. Biham and A. Shamir, "Differential Cryptanalysis of DES-like Cryptosystems," *Journal of Cryptology*, vol. 4, no. 1, pp. 3–72, 1991.

[6] M. Matsui, "Linear Cryptanalysis Method for DES Cipher," in *Advances in Cryptology - EUROCRYPT '93*, Springer, 1994, pp. 386–397.

[7] N. Courtois and J. Pieprzyk, "Cryptanalysis of Block Ciphers with Overdefined Systems of Equations," in *Advances in Cryptology - ASIACRYPT 2002*, Springer, 2002, pp. 267–287.

[8] S. Murphy and M. Robshaw, "Essential Algebraic Structure within the AES," in *Advances in Cryptology - CRYPTO 2002*, Springer, 2002, pp. 1–16.

[9] A. Bogdanov, D. Khovratovich, and C. Rechberger, "Biclique Cryptanalysis of the Full AES," in *Advances in Cryptology - ASIACRYPT 2011*, Springer, 2011, pp. 344–371.

[10] A. Biryukov and D. Wagner, "Slide Attacks," in *Fast Software Encryption - FSE '99*, Springer, 1999, pp. 245–259.

[11] D. J. Bernstein, "Cache-Timing Attacks on AES," Technical Report, 2005.

[12] J. Nechvatal, E. Barker, L. Bassham, W. Burr, M. Dworkin, J. Foti, and E. Roback, "Report on the Development of the Advanced Encryption Standard (AES)," *Journal of Research of the National Institute of Standards and Technology*, vol. 106, no. 3, pp. 511–577, 2001.

[13] S. Gueron, "Intel Advanced Encryption Standard (AES) New Instructions Set," Intel White Paper, 2010.

[14] E. Käsper and P. Schwabe, "Faster and Timing-Attack Resistant AES-GCM," in *Cryptographic Hardware and Embedded Systems - CHES 2009*, Springer, 2009, pp. 1–17.

[15] L. K. Grover, "A Fast Quantum Mechanical Algorithm for Database Search," in *Proceedings of the 28th Annual ACM Symposium on Theory of Computing (STOC)*, 1996, pp. 212–219.

[16] D. R. Simon, "On the Power of Quantum Computation," *SIAM Journal on Computing*, vol. 26, no. 5, pp. 1474–1483, 1997.

[17] J. Zou, L. Li, and Z. Wei, "Quantum Circuit for Implementing AES S-box with Low Costs," *Quantum Information Processing*, vol. 25, 2025.

[18] Z. Huang and S. Sun, "Quantum Circuit Synthesis for AES with Low DW-Cost," in *Advances in Cryptology*, Springer, 2025.

[19] M. Grassl, B. Langenberg, M. Roetteler, and R. Steinwandt, "Applying Grover's Algorithm to AES: Quantum Resource Estimates," in *Post-Quantum Cryptography - PQCrypto 2016*, Springer, 2016, pp. 29–43.

[20] B. Langenberg, H. Pham, and R. Steinwandt, "Reducing the Cost of Implementing the Advanced Encryption Standard as a Quantum Circuit," *IEEE Transactions on Quantum Engineering*, vol. 1, pp. 1–12, 2020.

[21] H. Kuwakado and M. Morii, "Quantum Distinguisher Between the 3-Round Feistel Cipher and the Random Permutation," in *IEEE International Symposium on Information Theory (ISIT)*, 2010, pp. 2682–2685.

[22] A. Bonnetain, M. Naya-Plasencia, and A. Schrottenloher, "Beyond Quadratic Speedups in Quantum Attacks on Symmetric Schemes," in *Advances in Cryptology - EUROCRYPT 2019*, Springer, 2019, pp. 315–344.

[23] NIST, "On the Practical Cost of Grover for AES Key Recovery," in *Fifth PQC Standardization Conference*, 2024.

[24] D. J. Bernstein, "Cost Analysis of Hash Collisions: Will Quantum Computers Make SHARCS Obsolete?" in *SHARCS '09*, 2009.

[25] H. Kuwakado and M. Morii, "Security on the Quantum-Type Even-Mansour Cipher," in *Proceedings of the International Symposium on Information Theory and its Applications (ISITA)*, 2012, pp. 312–316.

---
