# Phase 1: Turing — Architectural Assessment of cryptanalysis.md

**Date:** 2025-07-15
**Scope:** Core algorithm with full 256-bit key via `SetKeys()`. Nonce secondary.

---

## 1. Accuracy Assessment

### Finding #1 — S-box State Space (rated MEDIUM)

**Verdict: ACCURATE but INCOMPLETE**

The math is correct: 2^127 reachable permutations of the 2^954,009 possible 16-bit permutations. However, the document frames this as a theoretical concern analogous to AES's fixed S-box. This is misleading — AES's fixed S-box was *designed* with optimal differential/linear properties (max differential probability 2^-6, max linear bias 2^-3 per S-box). SPM's S-boxes are *random* permutations drawn from a tiny, structurally biased subset (the PRNG is a simple additive counter — see §2.1 below). The concern is not just coverage but *quality*: a random 16-bit permutation will have average-case differential/linear properties, but the PRNG's linearity may produce S-boxes with exploitable structure.

### Finding #2 — Plaintext File-Size Leakage (rated LOW)

**Verdict: ACCURATE**

Straightforward information leak. LOW severity is appropriate.

### Non-Finding #1 — Round Count / Diffusion Claim

**Verdict: INCOMPLETE / MISLEADING**

The core claim is: *"One SPM round achieves full bidirectional block diffusion"* and *"3 SPM rounds = 6 full diffusion sweeps ≈ 24+ AES diffusion layers."*

I have traced the actual byte dependencies through the code:

**Forward pass** (`s_SmForwardPass`, k=0..126): At each step k, the 16-bit window at bytes `[k, k+1]` is XORed with a mask then S-box substituted. Because step k+1 reads byte[k+1] which was just modified by step k, a left-to-right cascade occurs:
- After forward pass: byte[0] depends on original bytes {0,1} only
- byte[i] for i≥1 depends on original bytes {0..min(i+1, 127)}
- byte[126] and byte[127] depend on all 128 bytes

**Reverse pass** (`s_SmReversePass`, k=125..0): Right-to-left cascade. By the time k=0 is processed, byte[1] carries dependencies from the entire forward-pass output, which includes all 128 bytes. So after the full round:
- **Every byte depends on all 128 input bytes** — the "full diffusion" claim is technically TRUE

**But the comparison to AES is misleading for three reasons:**

1. **Serial chain vs. algebraic mixing.** SPM's diffusion is a *serial cascade* through a chain of 127+126 S-box lookups. Each S-box sees only 16 bits. A change in byte[0] reaches byte[127] through 127 sequential S-box hops. AES's MixColumns provides *algebraic* mixing with MDS (Maximum Distance Separable) properties — a single MixColumns guarantees that any 1-byte change produces ≥4 changed bytes with branch number 5. SPM has no equivalent guarantee about *how many* bytes change, only that all bytes have *some* dependency.

2. **Diffusion quality is unquantified.** The document claims diffusion parity with AES without measuring it. Proper comparison requires computing the *differential branch number* and *linear branch number* of the round function. A single SPM S-box has a 16-bit → 16-bit substitution with 1-byte overlap at each step. The XOR-mask adds key-dependent variation but is *linear* (XOR), so it contributes zero nonlinear diffusion. All nonlinearity comes from the S-box, and the overlap means each step's nonlinear mixing covers only 2 bytes.

3. **Boundary asymmetry.** byte[127] is processed only in the forward pass (at k=126) and never in the reverse pass (reverse starts at k=125). byte[0] is processed in both passes. This creates a structural asymmetry — the right edge has weaker mixing than the interior. Over 3 rounds this is probably washed out, but it contradicts the "full bidirectional" framing.

**My assessment:** The "full diffusion per round" claim is defensible in the strict dependency sense. The "≈ 24+ AES diffusion layers" comparison is **not defensible** and should be retracted. These are fundamentally different diffusion mechanisms with different algebraic properties.

### Non-Finding #2 — PRNG Not Independently Exploitable

**Verdict: ACCURATE with caveats**

The document correctly identifies that PRNG mask values cannot be directly observed from ciphertext because they are consumed inside `S(plaintext[k:k+1] ⊕ mask)`. Correct — you'd need to know the S-box to extract masks, and the S-box requires the key.

However, the document understates the *structural* weakness. The PRNG is `state += key (mod 2^64)`, outputting 4×16-bit words per state advance. This is a *linear congruential generator with zero multiplication* — it is the weakest possible PRNG that still has full period. Any 2 consecutive 64-bit states reveal the key entirely. The document should note: if *any* cryptanalytic technique recovers even 128 bits of consecutive mask stream, the entire past/future mask sequence for all blocks is immediately known.

### Non-Finding #3 — Password Weakness Out of Scope

**Verdict: ACCURATE**

Agreed. With a full 256-bit key, password attacks are irrelevant.

### Non-Finding #4 — Nonce Entropy

**Verdict: ACCURATE**

The "30–50 bits effective entropy" range and collision analysis are reasonable. Nonce is secondary per standing orders.

### Cipher Strengths Section

**Verdict: PARTIALLY ACCURATE**

The claim that *"the cipher achieves per-round diffusion comparable to what AES achieves in ~4 rounds"* is **not supported** (see Non-Finding #1 above). The claim that the overlapping sliding window creates cascading dependencies is accurate. The claim that the key-dependent 16-bit S-box provides "strong local nonlinearity" is accurate on average for random permutations, but unverified for PRNG-generated permutations.

---

## 2. Missing Analysis

### 2.1 PRNG Linearity Contaminates S-box Structure

The S-box is generated by 16 passes of Fisher-Yates shuffling using the additive PRNG (`m_prngSBox`). Because the PRNG is `state += key`, consecutive outputs have a rigid arithmetic relationship: `output[n+1] - output[n] = constant (mod 2^16)` within each 64-bit state, and `state[n+1] - state[n] = key` across advances.

This means the Fisher-Yates shuffle indices are not independent random variables. The swap targets follow a deterministic, algebraically simple pattern. While 16 passes (1,048,576 swaps) likely produce a permutation that *looks* random to simple statistical tests, the underlying structure is exploitable in principle:
- The entire S-box is determined by 2 values (state, key) = 127 bits
- An attacker who can test candidate S-boxes can enumerate all 2^127 possibilities
- Each candidate S-box can be validated in O(1) using a known-plaintext pair

This is not mentioned in the document's S-box analysis, which focuses only on state-space coverage.

### 2.2 No Block Chaining — Structural ECB Weakness

The `Encrypt()` function processes blocks sequentially:
```cpp
for (size_t i = 0; i < cbData; i += k_cSpmBlockSizeBytes)
    s_EncryptBlock(pData + i, &m_prngMask, &m_prngSBox, ...);
```

Inter-block variation comes *only* from PRNG state advancement. There is no CBC, CTR, or any standard mode of operation. This has consequences:

1. **No ciphertext feedback:** Block N's ciphertext does not influence block N+1's encryption. The PRNG state is the sole differentiator.
2. **Block-level malleability:** An attacker can reorder, duplicate, or delete 128-byte ciphertext blocks. Without a MAC or block chaining, the decryptor cannot detect this. Block deletion would desynchronize the PRNG for subsequent blocks, but block reordering within a known PRNG-state window could go undetected if the attacker can predict or precompute the state differences.
3. **Deterministic from key:** Given the key, the mask sequence for every block position is entirely determined. This is equivalent to a stream cipher with a block-structured keystream. The PRNG carries state forward, which is good, but the state evolution is a trivial addition — no entropy is introduced between blocks.

The document does not mention mode-of-operation weaknesses at all.

### 2.3 No Authentication (MAC / AEAD)

The cipher provides confidentiality only. There is no integrity protection. Ciphertext is malleable. This is a significant gap in any modern threat model. The document does not address this.

### 2.4 Same S-box Used for Both Forward and Reverse Passes

Within each round, `s_EncryptRound` calls:
```cpp
s_SmForwardPass(pBlock, pPrngMask, prgSbox);   // same prgSbox
s_SmReversePass(pBlock, pPrngMask, prgSbox);    // same prgSbox
```

Both passes use the identical S-box. Furthermore, the same S-box is used across all 3 rounds and all blocks. In AES, while the S-box is also fixed, the round keys differ per round via the key schedule. In SPM, per-step variation comes from the mask PRNG, but the nonlinear component (S-box) is static.

This means a differential characteristic through the S-box at position k in round 1 has the *same* differential probability at position k in round 3. There is no key-schedule-induced variation in the nonlinear layer. The mask XOR before the S-box changes the *input* to the S-box per step, but the S-box *structure* is invariant. An attacker who learns the differential distribution table (DDT) of the S-box can apply it uniformly across all positions and rounds.

### 2.5 Sliding-Window 1-Byte Overlap Creates Exploitable Structure

The 1-byte overlap means that consecutive S-box lookups at positions k and k+1 share exactly one byte. This creates a system of equations:

```
S(pBlock[k] || pBlock[k+1] ⊕ mask_k) = ciphertext window at k
S(pBlock[k+1] || pBlock[k+2] ⊕ mask_{k+1}) = ciphertext window at k+1
```

The shared byte `pBlock[k+1]` (after modification by step k) appears in both equations. If the S-box were known, this overlap provides a constraint that chains windows together. In a known-plaintext scenario with a candidate S-box, the entire forward-pass output can be verified step-by-step in O(127) operations — there is no "width" to the nonlinear barrier at any single step (only 16 bits).

For differential cryptanalysis, the overlap means a differential at position k propagates with probability 1 to the input of position k+1 (via the shared byte). Only the S-box provides nonlinear resistance, and it operates on 16 bits — meaning the best differential probability per step is at most 2^-1 (for the average random 16-bit S-box, the max differential probability is approximately 2^-8 to 2^-10). Over 127 steps, this multiplies, but the *serial* structure means the attacker only needs to find a high-probability path through the chain.

### 2.6 Codebook Layer Analysis

In `NoPermutation` mode (the default), `s_ConstructCodebook` initializes `s_rgCodebook` to identity `[0, 1, 2, ..., 65535]`. `InitSbox()` copies this identity to `m_rgSbox`. Then `PermuteSbox()` shuffles using the key PRNG.

When `s_PermuteCodebook` is called with a separate key, it pre-shuffles the codebook before key setup. This means the S-box becomes `KeyShuffle(CodebookShuffle(identity))` — a composition of two permutations. Since permutation composition is itself a permutation, this is equivalent to a single different permutation. The codebook layer adds no structural security — it's equivalent to using a different key. It provides defense-in-depth only if the codebook key is independent of the main key.

The document does not analyze the codebook layer.

### 2.7 Permutation Mode vs. NoPermutation Mode

`NoPermutation` is the default (`s_eBlockMode`). When enabled, `Permutation` mode adds a byte-level permutation (shuffle of the 128-byte block) after each round's forward+reverse passes. This permutation is key-dependent and shuffled per-block using `m_prngSBox`.

The permutation layer would break the serial chain structure of the sliding window by rearranging bytes between rounds. This is architecturally significant — without it, the same byte positions interact with the same neighbors across all 3 rounds. With it, different bytes become neighbors in each round, dramatically improving diffusion quality.

**The default mode (NoPermutation) is the weaker mode.** The document does not discuss this trade-off.

---

## 3. New Findings

### 3.1 Effective Key Strength May Be Below 256 Bits

The 32-byte key is split: bytes [0..15] → `m_prngSBox` (state + key), bytes [16..31] → `m_prngMask` (state + key). Each PRNG takes 8 bytes as state and 8 bytes as key, then forces `key |= 1` (making it odd). This loses 1 bit per PRNG key, so the effective key space is 2^(64+63) × 2^(64+63) = 2^254, not 2^256.

More critically: the `m_prngSBox` seed determines the S-box (used for all blocks), while `m_prngMask` seed determines the mask stream. These are independent. An attacker could:
1. Attack `m_prngSBox` (127 bits) to recover the S-box
2. Then attack `m_prngMask` (127 bits) to recover the mask stream
3. Total work: 2^127 + 2^127 ≈ 2^128 — NOT 2^254

This is a classic **key decomposition attack**. The two halves of the key are used independently and can be attacked independently. The effective security level is **~128 bits**, not 256.

**Verification:** With a single known plaintext-ciphertext pair:
- For each candidate S-box key (2^127 trials): generate S-box, attempt to find a consistent mask sequence for the known pair. If the S-box is wrong, inconsistency will be detected within the first few sliding-window steps.
- For the correct S-box: the mask sequence is determined, and can be verified against the PRNG structure to recover the mask key.

This is the most significant finding not in the document.

### 3.2 Decryption Order Reveals Structural Symmetry Concerns

In `s_DecryptRound`, the operations are:
```cpp
s_ReverseSmForwardPass(...)   // undoes one pass using masks in reverse
s_ReverseSmReversePass(...)   // undoes other pass using masks in reverse
```

The decrypt round processes the mask array in strictly reverse order. Because the PRNG is `state += key`, the mask sequence is an arithmetic progression. In reverse, it's still an arithmetic progression (with negated step). This means the decrypt mask sequence has identical algebraic structure to the encrypt mask sequence — there is no asymmetry that would distinguish the two. An attacker analyzing the cipher algebraically sees the same linear structure in both directions.

### 3.3 Block Boundary Fixed Points

The forward pass ends at byte[127], and the reverse pass starts at byte[125] and works backward to byte[0]. This means:
- byte[127] is only touched by the forward pass (once per round, at k=126)
- byte[126] is the "pivot" touched last in forward (k=126 window covers [126,127]) and first in reverse (k=125 covers [125,126])

Over 3 rounds, byte[127] receives only 3 S-box applications (one per round, always as the high byte of the last window). Compare this to an interior byte like byte[64], which receives 6 S-box applications per round (twice per forward pass window, twice per reverse pass window, more precisely touched at k=63 and k=64 in forward, and similar in reverse). The edges of the block are weaker than the interior.

---

## 4. Architecture Strength Assessment

### What the cipher genuinely does well:

1. **Large block size (1024 bits) with efficient diffusion.** The sliding-window design achieves full-block dependency in a single pass using only sequential memory access. This is cache-friendly and efficient. The 128-byte block makes many classical attacks (birthday-bound ECB collisions at 2^64 blocks for 128-bit blocks) irrelevant — the birthday bound is 2^512.

2. **Key-dependent S-box.** Unlike AES's fixed S-box, the key-dependent S-box means an attacker cannot precompute the DDT or LAT. They must recover the key (or S-box) first. This raises the bar for offline differential/linear cryptanalysis.

3. **16-bit S-box provides strong local nonlinearity.** A 16-bit → 16-bit random permutation has exponentially more structure than an 8-bit S-box. Expected maximum differential probability ≈ 2^-8 to 2^-10, maximum linear bias ≈ 2^-8 to 2^-9. Per step, this is stronger than AES's 8-bit S-box.

4. **Simple, auditable construction.** The cipher has no complex algebraic structure (no GF(2^8) arithmetic, no key schedule). This makes implementation bugs less likely but also makes formal analysis harder.

5. **PRNG state carry-forward across blocks.** This provides implicit inter-block variation without explicit modes of operation, preventing trivial block-repetition attacks.

6. **Bidirectional passes prevent one-directional bias.** The reverse pass compensates for the forward pass's left-edge weakness, ensuring all bytes eventually depend on all other bytes.

---

## 5. Key Questions for Other Agents

### For Rejewski (Statistical Analyst):
1. **Avalanche measurement:** For a randomly-keyed SPM instance, flip one input bit and measure the output Hamming distance. Does the cipher achieve the ideal 512-bit (50%) avalanche after 1 round? After 3 rounds? Measure separately for bit flips at position 0, position 64, and position 127 to detect boundary effects.
2. **S-box quality under PRNG generation:** Generate 1000 S-boxes using the additive PRNG with random seeds. Compute the DDT and LAT for each. What is the distribution of max differential probability and max linear bias? Compare to the expected values for truly random 16-bit permutations.
3. **PRNG output correlation:** The additive PRNG produces 4 × 16-bit words per state advance. Consecutive 16-bit outputs within the same state are *subwords of the same 64-bit value*. Measure the correlation between consecutive mask values — are they independent?

### For Friedman (Algebraic Analyst):
1. **Differential characteristic search:** What is the best 1-round differential characteristic? Given the serial sliding-window structure, can a local differential (affecting 2-3 bytes) propagate with high probability through the chain? The 1-byte overlap means differentials are NOT independent across positions.
2. **Key decomposition attack validation:** Verify or refute the 2^128 effective key strength claim from §3.1. Can the S-box key and mask key be attacked independently, or does the interaction between S-box and masks create a dependency that prevents decomposition?
3. **Algebraic degree:** What is the algebraic degree of the round function as a polynomial over GF(2)? The S-box is degree 15 (for a random 16-bit permutation), but the serial chain may reduce the effective degree through the overlap structure.

### For Driscoll (Applied Cryptanalyst):
1. **Known-plaintext attack:** Given one known plaintext-ciphertext pair (128 bytes each), what is the minimum work to recover the key? Specifically, test whether the key decomposition attack (§3.1) is practical.
2. **Chosen-plaintext attack:** Design an adaptive chosen-plaintext attack targeting the sliding-window structure. Can differentials be injected at one edge and observed at the other with fewer than 2^128 queries?
3. **Mode-of-operation exploitation:** Given the lack of block chaining, demonstrate a concrete attack: block reordering, block deletion, or block duplication. What is the practical impact?
4. **Boundary byte analysis:** Craft inputs that test whether byte[0] and byte[127] are weaker than interior bytes after 3 rounds. Use chosen-plaintext pairs that differ only at position 127 and measure output differences.

---

*Report prepared by Turing, Lead / Cipher Architect. All assessments based on code review of `SpmBlockCipher64.cpp` (rev at analysis time) and `cryptanalysis.md` dated 2025-07-15.*
