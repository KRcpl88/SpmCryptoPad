# Phase 1: Friedman — Statistical Assessment of cryptanalysis.md

**Date:** 2025-07-15
**Scope:** Statistical critique of claims in `cryptanalysis.md`, all analysis end-to-end through the full cipher pipeline (mask → XOR → S-box → cascade).

---

## 1. Accuracy Assessment

### Finding #1: S-box state space (2^127 of 2^954,009) — ACCURATE, severity OVERSTATED

The mathematics are correct: 64-bit state × 63-bit odd key = 2^127 seed space, vs log₂(65536!) ≈ 954,009 bits for the full permutation space. However, the MEDIUM severity rating overstates the practical impact.

**Statistical justification:** For a 16-bit permutation, 2^127 seeds is vastly more than the ~2^17 samples an attacker could ever probe through chosen-plaintext queries (each query reveals one S-box input→output pair through the cascade). The relevant question is not "what fraction of permutation space is covered?" but "can an attacker distinguish a PRNG-generated permutation from a truly random one?" For Fisher-Yates with a 2^127-seed Weyl PRNG, the expected differential uniformity of the resulting 16-bit S-box is ≈2 (same as a truly random permutation). No statistical test on the S-box output can distinguish these cases. **Recommend: LOW severity.**

### Finding #2: Plaintext file-size leakage — ACCURATE

No statistical issues with this claim. The DWORD at offset 128 is an unambiguous information leak.

### Non-Finding #1: Round count comparison ("3 SPM rounds ≈ 24+ AES diffusion layers") — INCOMPLETE / MISLEADING

The claim that SPM achieves "full bidirectional block diffusion" per round is **correct at the byte level** — the forward pass (127 steps) cascades left-to-right through all 128 bytes, and the reverse pass (126 steps) cascades right-to-left. After one round, every output byte depends on every input byte.

**However, the AES comparison is misleading in two ways:**

1. **Diffusion ≠ security margin.** AES's round count is not determined by diffusion alone — it's determined by proven bounds on differential and linear trail probabilities accumulated over rounds. SPM has no analogous proofs. The document correctly flags this ("resistance to differential and linear cryptanalysis at this round count is formally unknown") but then undercuts its own caveat with the "≈ 24+ AES diffusion layers" headline.

2. **Byte-level diffusion ≠ bit-level avalanche completeness.** Each S-box step operates on 16 bits with an 8-bit overlap to the next position. A single-bit change at position 0 produces a ~random 16-bit output from the S-box (good), but this enters position 1 as only an 8-bit perturbation to the high byte of a 16-bit input. After 1 forward pass, positions far from the change origin have been reached, but the bit-level avalanche quality at distant positions depends on the specific S-box differential propagation characteristics. The document's implicit claim of "convergence toward 50% bit-flip rate" after 1 round is **unsubstantiated** — it is plausible after 3 rounds but not formally demonstrated even empirically.

### Non-Finding #2: PRNG not independently exploitable — ACCURATE with CAVEAT

The document's core claim is correct: the 8-output PRNG state recovery attack requires observing raw mask values, which sit behind the S-box and cascade. Without the S-box, mask values cannot be extracted from ciphertext.

**Caveat:** The document understates the _compounding_ risk. Because cross-block PRNG state is never reset, recovering the mask PRNG state at any point (e.g., via a side channel, partial key compromise, or future algebraic breakthrough against the S-box) exposes the entire mask stream for all past and future blocks. This is a design fragility even if it's not currently exploitable. See §2 for details.

### Non-Finding #4: Nonce entropy — ACCURATE

The "30–50 bits" range and the collision probability analysis are statistically sound.

### Section 3: Cipher Strengths — MOSTLY ACCURATE

The description of overlapping sliding-window diffusion is technically correct. The claim that the "key-dependent 16-bit S-box provides strong local nonlinearity" is reasonable — a random 16-bit permutation has expected nonlinearity close to the theoretical maximum. However, the Fisher-Yates shuffle driven by CSimplePrng64 produces S-boxes from a restricted family; while this family is large enough (2^127) to be practically indistinguishable from random, the nonlinearity of each specific instance is not verified.

---

## 2. End-to-End PRNG Analysis

### 2.1 Cross-Block Mask Correlation Through the Pipeline

**PRNG structure recap:** CSimplePrng64 is a Weyl sequence (state += key mod 2^64). The 64-bit state is sliced into 4 × 16-bit outputs per advance. The mask PRNG (`m_prngMask`) is never reset between blocks, consuming 759 masks per 128-byte block (3 rounds × 253 steps).

**Sub-period analysis:** Since key is odd (forced by `m_wKey |= 1`), key mod 2^16 is odd, so the low-16-bit slice (index 0 of each state) has period exactly 2^16 state advances. At 4 outputs per advance, that's 262,144 mask outputs. At 759 masks/block, the cycle length is ≈345.4 blocks.

**Can this sub-period be observed through the cipher?** No, for the following reasons:

1. **The S-box barrier.** Even when the same mask value m appears at position k in two different blocks, the S-box input differs: S(x₁ ⊕ m) vs S(x₂ ⊕ m). Unless x₁ = x₂ (identical plaintext at the same cascade position), the outputs are independent. For random 128-byte plaintext blocks, the probability of identical cascade inputs at any given position is 2^{-16}.

2. **Cascade dependency.** The input to position k in the forward pass depends on the outputs of positions 0 through k−1 (via the 1-byte overlap). Even if the mask at position k repeats, the cascade inputs differ because all prior masks and plaintexts differ. The cascade amplifies input differences exponentially.

3. **Partial mask repetition.** Only slice-0 masks (≈190 of 759 per block) participate in the sub-period. Slices 1–3 have longer periods (up to 2^64 advances for slice 3). So even the mask sequence itself doesn't fully repeat at the 345-block period — only 25% of mask positions share the sub-period.

**Conclusion:** The low-16-bit sub-period does NOT create a detectable statistical signature in ciphertext. The S-box and cascade prevent any practical distinguisher at this period.

### 2.2 Known-Plaintext Statistical Attacks Through the S-box

Given many (P, C) pairs under the same key (but different PRNG mask states), can the attacker extract key information?

**Analysis:** Consider the first step of the forward pass (position 0). For known-plaintext block i:

```
C₀ⁱ = S(P₀ⁱ ⊕ mᵢ)
```

where P₀ⁱ is the 16-bit value at bytes [0,1] of plaintext block i, and mᵢ is the mask at position 0 of block i. The attacker knows P₀ⁱ but NOT C₀ⁱ directly (because position 0's output is then modified by positions 1, 2, ..., 126 in the forward pass, plus the entire reverse pass, plus two more rounds). The final ciphertext byte at position 0 is a deeply nonlinear function of P₀ⁱ, the S-box, and all 759 masks.

**For a purely statistical attack (no algebraic structure exploitation):** The attacker would need to correlate plaintext-ciphertext pairs at a specific byte position across many blocks. The S-box + cascade creates an effectively random mapping for each block (since the masks change). With n known-plaintext blocks, the attacker gets n samples of `Encrypt_key(Pⁱ)` where the encryption function varies pseudo-randomly per block. Standard statistical distinguishers (chi-squared, mutual information) would require approximately 2^16 samples to detect any bias at a single 16-bit position, and this bias would be obscured by the cascade.

**The PRNG linearity concern:** The masks follow mᵢ = f(state₀ + i × key_advance_per_block) where f extracts 16-bit slices and state advances linearly. If the attacker could observe masks directly, the linear structure would allow efficient recovery. But through the S-box, the linear structure is hidden behind a secret permutation. A statistical attack would require simultaneously solving for the S-box and exploiting the mask linearity — this is equivalent to a joint estimation of 65,536 S-box unknowns plus PRNG parameters, which is computationally infeasible with realistic data.

**Conclusion:** Known-plaintext statistical attacks through the full pipeline are not practical. The cascade + S-box barrier is effective.

---

## 3. Statistical Distinguishers

### 3.1 Byte Frequency Distribution

For a well-keyed cipher, each ciphertext byte should be uniformly distributed over [0, 255]. The SPM cipher's output after 3 rounds of cascade + S-box substitution should produce near-uniform byte distribution, assuming:
- The S-box is a permutation (confirmed — Fisher-Yates preserves bijectivity)
- The cascade propagates input entropy across all output positions
- The masks provide per-block uniqueness

**Assessment:** No byte-frequency distinguisher is expected. Each output byte depends nonlinearly on all 128 input bytes plus 759 mask values. Even for structured plaintext (e.g., all-zeros), the 3-round cascade should produce near-uniform ciphertext bytes. **Empirical testing is recommended to verify.**

### 3.2 Bigram/N-gram Frequency

Adjacent ciphertext bytes are produced by overlapping S-box applications, so there is a structural relationship: bytes at positions k and k+1 share one byte of the S-box output at position k. After the reverse pass and subsequent rounds, this overlap is thoroughly mixed.

**Assessment:** After 3 rounds, no bigram bias is expected. After 1 round, the last few positions in the reverse pass might show slight correlation with the first few positions (since the reverse pass ends at position 0, which was the starting point of the forward pass). **This is a potential 1-round distinguisher that warrants empirical investigation, but is almost certainly eliminated by 3 rounds.**

### 3.3 Cross-Block Byte Correlations

The question: for ciphertext blocks B₁, B₂, ..., Bₙ (encrypting different plaintexts under the same key), is `corr(Bᵢ[k], Bⱼ[k])` different from zero?

**Analysis:** Each block uses a different mask sequence (PRNG advances deterministically between blocks). The S-box is fixed. For the same plaintext position k, different blocks see different effective permutations (because different masks). The correlation between ciphertext bytes at the same position across blocks is:

```
E[Bᵢ[k] · Bⱼ[k]] − E[Bᵢ[k]]·E[Bⱼ[k]]
```

For a random permutation S and independent random masks, each ciphertext byte is uniform, and bytes across blocks at the same position are independent. The PRNG-generated masks are not truly independent, but the S-box obscures the mask structure. **No cross-block correlation distinguisher is expected.**

### 3.4 Position-Dependent Biases

The forward pass processes positions 0→126, the reverse pass processes 125→0. This asymmetry could create position-dependent statistical properties:

- Position 127 (the last byte of the block) is only directly modified by forward-pass positions 126 and reverse-pass positions 0. It receives the least "cascade mixing" from both directions.
- Position 0 is modified first (forward) and last (reverse), receiving maximum cascade coverage.

**Assessment:** After 3 rounds, position-dependent biases should be negligible. After 1 round, edge positions (0, 127) might exhibit slightly different statistical properties than interior positions. **This is a theoretical concern, not a practical distinguisher for 3 rounds.**

### 3.5 Overall Distinguisher Verdict

**No practical statistical distinguisher was identified for the 3-round cipher.** The S-box (random 16-bit permutation) provides sufficient nonlinearity, and the cascade (127+126 overlapping steps per round) provides sufficient diffusion to obscure PRNG mask structure, byte-position biases, and cross-block correlations.

---

## 4. New Findings

### 4.1 Missing: Block Independence Relies Entirely on PRNG Uniqueness (not in document)

**Finding:** The cipher has no explicit block chaining mechanism (no IV/ciphertext feedback between blocks, no block counter mixed into plaintext). Block independence — i.e., the property that identical plaintext blocks produce different ciphertext — depends entirely on the mask PRNG advancing to produce unique mask sequences per block.

**Why this matters through the pipeline:** This is NOT an ECB weakness (identical plaintext blocks do produce different ciphertext, because the PRNG mask stream always advances). However, if the PRNG mask stream ever produces the exact same 759-mask subsequence for two blocks (which cannot happen within the 2^64 full period, since the Weyl sequence visits each state exactly once), those blocks would produce identical ciphertext for identical plaintext.

**Practical impact:** None within the PRNG's period. But the design PHILOSOPHY of relying solely on a non-cryptographic PRNG for block independence is fragile compared to standard designs (CTR mode, CBC chaining). The document does not acknowledge this design choice.

**Severity:** LOW (theoretical, not exploitable).

### 4.2 Avalanche Completeness After 1 Round Is Not Verified (not in document)

**Finding:** The document claims per-round diffusion comparable to "~4 AES rounds" and "full bidirectional block diffusion." While byte-level diffusion is achieved in 1 round (every output byte depends on every input byte), **bit-level avalanche completeness** (each output bit has approximately 50% probability of flipping when any input bit flips) is not demonstrated.

**Statistical concern:** The 8-bit overlap between adjacent sliding-window positions means that at each cascade step, only 8 bits of "new" information propagate. For a random 16-bit S-box, the expected weight of S(x) ⊕ S(x ⊕ Δ) for a random single-bit Δ in 8 bits is approximately 8 out of 16 output bits (50%). But this is an *expected* value — the variance is significant for any specific S-box. After 127 cascade steps, the avalanche effect at distant positions depends on the *product* of these per-step avalanche probabilities, which could deviate from 50% depending on the S-box's specific differential distribution.

**After 3 rounds:** The avalanche should converge to near-50% for any reasonable S-box, since 3 × (127 + 126) = 759 cascade steps provide extensive mixing. But formal verification (empirical bit-flip statistics over many keys) would strengthen the document's claims.

**Severity:** LOW (informational — likely not a weakness in practice, but the claim needs empirical backing).

### 4.3 The Composition Family {S(· ⊕ m)} Has a Fixed Differential Signature (not in document)

**Finding:** For fixed S-box S, the family of permutations {π_m : x ↦ S(x ⊕ m)} parameterized by mask m has a structural invariant: the *difference distribution table* (DDT) of S is shared across all members.

Formally: for any input difference Δx, the multiset `{S(x ⊕ m) ⊕ S((x ⊕ Δx) ⊕ m) : x ∈ Z_{2^16}}` is independent of m (it equals the DDT row for Δx). This means the differential properties of every cascade step are identical regardless of the mask used.

**Through the pipeline:** This is relevant because it means the PRNG mask values do NOT add differential diversity — every step has the same differential profile (that of S). An attacker performing differential cryptanalysis needs only characterize the DDT of S once; the masks add no additional resistance to differential attacks.

**Practical impact:** For a random 16-bit S-box, the maximum differential probability is ≈ 2/2^16 = 2^{−15}. Over 759 cascade steps, even this small bias would not accumulate into a practical differential attack. However, this is a structural observation that the document should note: **masks protect against absolute value recovery but not against differential analysis.** The S-box quality alone determines differential resistance.

**Severity:** LOW (the random S-box's low differential uniformity makes this non-exploitable, but it's a theoretically important structural property).

### 4.4 PRNG Key Bit 0 Is Discarded (minor, not in document)

**Finding:** `m_wKey |= 1` forces the PRNG key to be odd. This means bit 0 of the key material fed to `m_prngMask` (and `m_prngSBox`) is always set, reducing effective key entropy by 1 bit per PRNG instance. With two PRNG instances, total effective key loss is 2 bits: 256 → 254 bits of effective key material.

**Through the pipeline:** This has negligible practical impact (254-bit security is still astronomically strong). But the document's implicit assumption of "full 256-bit key" should note this 2-bit reduction.

**Severity:** NEGLIGIBLE.

---

## 5. Non-Findings (PRNG Isolation Attacks Ruled Out)

### 5.1 Raw PRNG State Recovery — NOT exploitable through the cipher

**The attack in isolation:** Given 8 consecutive PRNG outputs, the Weyl sequence state and key can be recovered in O(4) work (4 alignment guesses to determine which 16-bit slices correspond to which state words).

**Why it fails through the cipher:** The 8 PRNG outputs are never observable. Each mask is consumed inside `S(x ⊕ mask)` where S is the secret key-dependent S-box. Recovering mask values requires knowing S, and knowing S requires knowing the key. The attacker faces a circular dependency: they need the key to get the masks, and the masks to get the PRNG state, and the PRNG state still doesn't give the key (the mask PRNG key is derived from the second half of the 256-bit key, not the S-box PRNG key).

**The S-box barrier is complete:** For any ciphertext value c at a given cascade position, the corresponding mask is m = S⁻¹(c) ⊕ input. Without S (65,536 unknown entries), every mask value in [0, 65535] is equally likely. The 16-bit S-box provides full equivocation.

### 5.2 Low-16-Bit Sub-Period (~345 blocks) — NOT observable through the cipher

**The weakness in isolation:** The lowest 16-bit slice of PRNG output has a sub-period of 2^16 state advances (≈345 blocks). In isolation, this would mean ~25% of masks repeat at a 345-block period.

**Why it fails through the cipher:**

1. **The S-box destroys direct observability.** Even when mask m repeats at position k across two blocks separated by 345 blocks, the cipher output is S(x₁ ⊕ m) and S(x₂ ⊕ m). Unless x₁ = x₂ (probability 2^{-16} per position for random plaintext), these outputs are unrelated.

2. **Cascade dependency prevents input matching.** The input xₖ at cascade position k depends on all prior positions (0 through k−1) via the overlapping S-box substitutions. Different plaintext blocks produce completely different cascade trajectories. The probability that two blocks match at ALL cascade positions simultaneously is astronomically small.

3. **Partial periodicity.** Only slice-0 masks (≈25% of all masks) participate in the 345-block sub-period. The other 75% of masks have longer periods. So the mask sequence never fully repeats at 345 blocks.

**Statistical test:** An attacker computing χ² statistics on ciphertext byte distributions at 345-block intervals vs. other intervals would find no significant difference, because the S-box maps each mask-input combination to a pseudorandom output.

### 5.3 PRNG Linear Predictability — NOT exploitable through the cipher

**The weakness in isolation:** Once state and key are known, all future and past outputs are trivially computed. The PRNG has zero resistance to prediction.

**Why it fails through the cipher:** Prediction requires first recovering the state, which requires observing outputs (§5.1). Even if the state were somehow recovered (e.g., via side channel), the attacker would know all mask values but still need the S-box to decrypt. Knowing masks without the S-box provides no advantage: the cipher becomes `S(P ⊕ known_value)` which is still a secret permutation applied to a known input — equivalent to a codebook attack against the S-box.

---

## 6. Key Questions for Other Agents

1. **For the Differential Cryptanalysis Agent:** Finding 4.3 shows that the DDT of S is invariant under all mask values. What are the actual maximum differential probabilities for PRNG-generated 16-bit S-boxes? Can a multi-round differential trail exploit the cascade's 8-bit overlap structure? After 3 rounds (759 cascade steps), what is the best differential characteristic probability?

2. **For the Algebraic Analysis Agent:** The composition S(x ⊕ m) where S is a random permutation and m varies — does this family have exploitable algebraic invariants (e.g., linear approximation biases that survive the cascade)? Specifically, what is the maximum linear bias for PRNG-generated 16-bit S-boxes, and does the cascade amplify or attenuate linear biases?

3. **For the Implementation/Side-Channel Agent:** The PRNG state is stored in memory and advances deterministically. Is there a timing or cache side-channel that could leak PRNG outputs, bypassing the S-box barrier described in §5.1? The S-box lookup `prgSbox[value]` is a table-indexed memory access — classic cache-timing side-channel territory.

4. **For the Empirical Testing Agent:** Can you run bit-flip avalanche tests on the 1-round and 3-round cipher across multiple random keys? Specifically: for each input bit position, flip it and measure the Hamming distance of the output. Report the distribution of Hamming distances and whether they converge to 512 ± √512 (i.e., 50% ± expected standard deviation for 1024-bit blocks).

5. **For the Mode-of-Operation Agent:** The cipher has no block chaining (Finding 4.1). What are the concrete security implications? If an attacker can reorder or duplicate ciphertext blocks, the decryption will produce garbled plaintext for reordered blocks (since the PRNG state will be wrong), but duplicated-then-appended blocks would not be detected. Is there an integrity/authentication concern?
