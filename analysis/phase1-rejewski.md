# Phase 1: Rejewski - Mathematical Assessment of cryptanalysis.md

**Analyst:** Rejewski (Cipher Mathematician)
**Date:** 2025-07-15
**Scope:** Mathematical rigor of claims in `cryptanalysis.md`, with deep analysis of S-box generation, Fisher-Yates bias, algebraic structure, and sliding-window cascade properties.
**Assumption:** Full 256-bit (32-byte) key; password attacks out of scope.

---

## 1. Accuracy Assessment

### Finding #1: S-box state space - 2^127 vs 2^954,009

**Verdict: ACCURATE but INCOMPLETE**

The claim that the PRNG seed space is 2^127 and the permutation space is ~2^954,009 is mathematically correct. Verification:

**PRNG seed space:**
- `CSimplePrng64` has two 64-bit words: `m_wState` (64 bits) and `m_wKey` (64 bits, but forced odd via `m_wKey |= 1`).
- Effective key space: 2^64 × 2^63 = 2^127. ✓

**Permutation space:**
- A 16-bit S-box is a permutation on {0, 1, ..., 65535}. The number of such permutations is 65536!
- By Stirling's approximation: log₂(n!) ≈ n·log₂(n) − n·log₂(e) + ½·log₂(2πn)
- log₂(65536!) ≈ 65536 × 16 − 65536 × 1.4427 + ½ × log₂(2π × 65536)
- = 1,048,576 − 94,558.7 + 9.67
- ≈ 954,027

The document rounds to 954,009. Applying a more precise Stirling computation:
- ln(65536!) = 65536·ln(65536) − 65536 + ½·ln(2π·65536) + 1/(12·65536) − ...
- = 65536 × 11.09036 − 65536 + ½ × 11.9212 + ...
- = 726,758.2 − 65536 + 5.9606 + ε
- = 661,228.2
- log₂(65536!) = 661,228.2 / ln(2) = 661,228.2 / 0.69315 ≈ **954,017**

The document's 954,009 is approximately correct (within rounding of Stirling terms). The exact value is not critical - the point is that 2^127 ≪ 2^954,017 by a factor of ~2^953,890, which is correct.

**What's INCOMPLETE:** The document does not address whether the 2^127 reachable permutations form an algebraically structured subset. See §2.3 for analysis.

### Finding #2: Plaintext file-size leakage

**Verdict: ACCURATE (trivially)**

This is a metadata concern, not a cryptographic-mathematical one. No mathematical assessment needed. The claim that a DWORD at offset 128 reveals plaintext length is an implementation detail; the severity rating of LOW is reasonable.

### Non-Finding #1: Round count comparison with AES

**Verdict: INCOMPLETE - overstates security equivalence**

The document claims "3 SPM rounds = 6 full diffusion sweeps ≈ 24+ AES diffusion layers." This is **qualitatively reasonable but mathematically imprecise** for the following reasons:

1. **"Full block diffusion" ≠ "cryptographic mixing"**: AES diffusion is measured via the *branch number* of MixColumns (branch number = 5 over GF(2^8)), giving a **provable** minimum of 25 active S-boxes over 4 rounds. SPM has no analogous provable bound. The forward pass propagates *some* influence of every byte to every other byte, but the *minimum weight* of differential trails is unknown.

2. **The comparison is category error**: AES diffusion metrics (active S-box counts, branch numbers) are properties of the *linear layer*. SPM's diffusion comes from the overlapping S-box cascade, which mixes nonlinear and linear components inseparably. Comparing "diffusion sweeps" to "AES diffusion layers" is not mathematically meaningful.

3. **No differential/linear trail bounds exist**: The document correctly notes "resistance to differential and linear cryptanalysis at this round count is formally unknown" but then still asserts the 24+ comparison. The comparison should be removed or qualified as heuristic.

### Non-Finding #2: PRNG weakness assessment

**Verdict: ACCURATE with one CAVEAT**

The claim that PRNG mask outputs cannot be directly observed from ciphertext is correct: each mask is consumed inside S(plaintext ⊕ mask), so recovering the mask requires inverting the S-box, which requires the key.

**Caveat:** The document does not address *known-plaintext* attacks. If an attacker knows a full plaintext block, they can compute:
- C[k:k+2] = S(P[k:k+2] ⊕ mask_k) where C is the intermediate state after this step
- But C[k:k+2] is not directly observable either - it's further modified by position k+1

This creates a system of coupled equations that may be solvable. See §2.5.

### Non-Finding #3: Password weakness

**Verdict: ACCURATE** (out of scope per standing orders)

### Non-Finding #4: Nonce entropy

**Verdict: ACCURATE** (out of scope per standing orders - nonce is secondary)

### Strength: "Overlapping sliding-window diffusion is structurally sound"

**Verdict: INCOMPLETE**

The claim that "a change in any single input byte cascades through all 128 bytes in one directional pass" is correct as a *qualitative* statement about bit influence. However, "structurally sound" implies security guarantees that don't follow from mere cascade existence. See §2.5 for the mathematical analysis of the cascade structure.

The claim that the S-box "provides strong local nonlinearity" is **UNSUBSTANTIATED** - no nonlinearity metrics (Walsh spectrum, differential uniformity) are provided. See §2.3.

---

## 2. Mathematical Analysis

### 2.1 S-box State Space: Reachability and Structure

The PRNG generates S-boxes via a deterministic shuffle. Each of the 2^127 seeds produces exactly one permutation. The mapping seed → permutation is many-to-one in general (multiple seeds *could* produce the same permutation), so the number of *distinct* reachable permutations is at most 2^127 and likely close to it (collision probability among 2^127 samples from a space of ~2^954,017 is negligible).

**Key question:** Do the ~2^127 reachable permutations share algebraic properties that distinguish them from random permutations?

Yes. Because the PRNG is an additive counter (state += key mod 2^64), the sequence of 16-bit outputs used for shuffling is:
- Extract 16-bit words from successive states: s₀, s₀, s₀+k, s₀+k, s₀+2k, s₀+2k, ...
  (each 64-bit state yields four 16-bit words before advancing)

This sequence has extremely low linear complexity. A 16-bit LFSR could reproduce any 4-word segment. The total number of random values consumed during PermuteSbox is 16 × 65536 = 1,048,576 16-bit values, generated from 1,048,576/4 = 262,144 state transitions. The entire shuffle sequence is determined by 127 bits and has the algebraic structure of an additive group element.

**Implication:** An attacker who can test a candidate S-box against known plaintext-ciphertext pairs can search the 2^127 seed space rather than the 2^954,017 permutation space. This is the *intended* security level (256-bit key → 127-bit S-box PRNG + 127-bit mask PRNG), but it means the S-box provides zero additional security beyond the key.

### 2.2 Fisher-Yates Bias Analysis

The code in `PermuteSbox()` implements:

```
for j = 0 to 15:          // 16 passes
  for i = 0 to 65535:     // each position
    swap(sbox[i], sbox[Rand()])   // Rand() ∈ [0, 65535]
```

This is the **naive shuffle** (sometimes called "Knuth's wrong algorithm"). Standard Fisher-Yates requires `Rand() ∈ [i, n-1]`.

**Single-pass bias:**

For a single pass of naive shuffle on n elements, the probability that element originally at position 0 ends up at position 0 is:

P(0→0) = ((n-1)/n)^n ≈ 1/e ≈ 0.3679

For a true random permutation: P(0→0) = 1/n = 1/65536 ≈ 0.0000153

This is a **massive bias for a single pass** - position 0 is ~24,000× more likely to stay at position 0 than expected.

More generally, for the naive shuffle, the probability matrix M where M[i][j] = P(element originally at i ends at j) is not the uniform matrix (1/n for all entries). The deviations follow a known pattern first characterized by Mironov (2002): the distribution has a specific bias structure where positions tend to shift rightward.

**Multi-pass compensation:**

With 16 passes, we compose 16 independent naive shuffles. If M is the transition matrix for one pass, then M^16 is the effective transition matrix. The eigenvalues of M for the naive shuffle on n elements are:

λ₀ = 1, λ₁ = ((n-1)/n)^n ≈ 1/e, λ₂, ...

After 16 passes, the second-largest eigenvalue contributes at most (1/e)^16 ≈ 8.9 × 10^-8 bias. For n = 65536, the total variation distance from uniform after t passes of naive shuffle is bounded by:

TV ≤ (n-1) · |λ₁|^t ≤ 65535 · (1/e)^16 ≈ 65535 · 8.9 × 10^-8 ≈ 0.0058

This means after 16 passes, the total variation distance from a uniform random permutation is approximately **0.6%**. This is small but nonzero.

**Assessment:** 16 passes of naive Fisher-Yates reduce the bias to negligible levels for practical purposes. The residual ~0.6% TV distance is unlikely to be exploitable, though it's theoretically imperfect. The document's claim that the S-box is "Fisher-Yates shuffled" is **misleading** - it should say "16-pass naive shuffle" and acknowledge the residual bias.

**Important caveat:** The above analysis assumes *independent random inputs* for each pass. The CSimplePrng64 outputs are not independent - they're deterministic given the seed. The actual bias may differ from the i.i.d. analysis. However, since the PRNG is the security bottleneck anyway (2^127 seed space), the Fisher-Yates bias is a secondary concern.

### 2.3 S-box Algebraic Properties

**Differential uniformity:**

For a random permutation S on {0,...,2^16 - 1}, the expected maximum value of the difference distribution table (DDT) entry is:

δ(S) = max_{Δx≠0, Δy} |{x : S(x ⊕ Δx) ⊕ S(x) = Δy}|

For a random 16-bit permutation, by birthday-bound heuristics, the expected δ is approximately:
- Each row of the DDT sums to 2^16 across 2^16 entries → average entry = 1
- Maximum over 2^16 entries in a row ≈ ln(2^16)/ln(ln(2^16)) ≈ 11.1/2.4 ≈ 4-6

For comparison, AES's 8-bit S-box has δ = 4 (optimal for that size). A random 16-bit permutation will typically have δ ≈ 4-8, which is excellent.

**However:** The S-box is generated by a *linear* PRNG. Does this create exploitable structure in the DDT?

The answer is **probably no**, but with no proof. The shuffle process (even naive Fisher-Yates) is a highly nonlinear function of the PRNG outputs - swapping elements based on indices creates complex combinatorial dependencies. The linearity of the PRNG is "absorbed" by the permutation-generation process. Nonetheless, no formal proof exists that the resulting DDT/LAT properties are indistinguishable from random.

**Linear approximation table (LAT):**

The maximum bias in the LAT for a random 16-bit permutation is expected to be:

max_{a≠0,b≠0} |Σ_x (-1)^{a·x ⊕ b·S(x)}| ≈ √(2^16 · ln(2^16)) ≈ √(65536 · 11.09) ≈ √(726,860) ≈ 853

The corresponding correlation is 853/65536 ≈ 0.013, or bias ε ≈ 0.0065. This is very small.

**Assessment:** A PRNG-generated 16-bit S-box is expected to have near-ideal differential and linear properties purely by size - the 16-bit permutation space is large enough that even a biased sample is overwhelmingly likely to have good cryptographic properties. This is a genuine strength.

### 2.4 Mask-S-box Interaction Analysis

The core operation at position k is:

```
block[k:k+2] ← S(block[k:k+2] ⊕ mask_k)
```

where S is the fixed (key-dependent) S-box permutation and mask_k is the k-th 16-bit PRNG output.

**Algebraic structure:** Define f_k(x) = S(x ⊕ m_k) for 16-bit x. This is a *translated permutation* - the composition of a fixed translation (XOR with m_k) and a fixed permutation S. The set {f_k} as m_k varies over all 16-bit values forms the **coset** of S in the symmetric group with respect to the translation subgroup.

Key property: f_k is itself a permutation for every m_k, and f_k ∘ f_j^{-1} = S ∘ T_{m_k ⊕ m_j} ∘ S^{-1}, which is a conjugate of a translation. If S were an affine map, this would be another translation - but for a nonlinear S, these conjugates are generally non-affine.

**Differential property of the cascade:** For two inputs x, x' differing by Δx at position k, the output difference after the S-box is:

Δy = S(x ⊕ m_k) ⊕ S(x' ⊕ m_k) = S(x ⊕ m_k) ⊕ S(x ⊕ m_k ⊕ Δx)

This is exactly the DDT entry for S at input difference Δx. **The mask cancels out of the differential.** This is critical: masks provide no resistance to differential cryptanalysis within a single known-plaintext pair.

The mask's role is to prevent the attacker from knowing the *absolute* S-box input - but differential attacks only need *differences*, for which the mask is transparent.

### 2.5 Sliding-Window Dependency Chain

Let B[k] denote the byte at position k. The forward pass processes positions k = 0, 1, ..., 126 (= k_cSpmBlockInflectionIndex - 1 = 127):

At position k, the operation reads the 16-bit word W_k = (B[k], B[k+1]) and writes:
```
(B'[k], B'[k+1]) ← S(W_k ⊕ m_k) = S((B[k], B[k+1]) ⊕ m_k)
```

The key observation: position k+1 then reads W_{k+1} = (B'[k+1], B[k+2]), where B'[k+1] is the *already-modified* byte from position k.

**Formal cascade structure:**

Let the S-box output at position k be (y_k^lo, y_k^hi) = S((B[k], B[k+1]) ⊕ m_k). Then:
- B'[k] = y_k^lo (final value for byte k, no further modification in this pass)
- B'[k+1] = y_k^hi (temporary - will be overwritten by position k+1)

At position k+1:
- Input word = (y_k^hi, B[k+2])
- S-box input = (y_k^hi, B[k+2]) ⊕ m_{k+1}
- Output = S((y_k^hi ⊕ m_{k+1}^lo, B[k+2] ⊕ m_{k+1}^hi))

The high byte of the S-box output at position k feeds into the low byte of the S-box input at position k+1. This creates a **sequential dependency chain** equivalent to a nonlinear feedback shift register.

**Differential propagation:**

If byte B[0] is changed by δ (with all other input bytes fixed), the forward pass propagates as follows:

1. Position 0: input difference = (δ, 0). Output difference (Δ₀^lo, Δ₀^hi) is determined by the DDT of S at row (δ, 0).
2. Position 1: input difference = (Δ₀^hi, 0). Output difference (Δ₁^lo, Δ₁^hi) is determined by the DDT of S at row (Δ₀^hi, 0).
3. Position k: input difference = (Δ_{k-1}^hi, 0). The chain continues until Δ_{k-1}^hi = 0 (if ever).

**Probability of chain extinction:** At each step, we need the DDT entry for S at input difference (d, 0) where d is a single-byte difference. The probability that (d, 0) → (0, 0) through S is at most δ(S)/2^16 where δ(S) is the differential uniformity. For a good 16-bit S-box with δ ≈ 6, this probability is ~6/65536 ≈ 0.0001 per step.

Over 127 steps, the probability that the chain *survives* (never maps to zero difference) is approximately (1 - 6/65536)^127 ≈ 0.988. So with ~98.8% probability, a single-byte input change propagates through the entire forward pass - confirming the diffusion claim.

**But:** The difference at each step is *concentrated in the low byte* of the 16-bit word (the overlap byte). The high byte of the input word at each step has zero difference. This means the cascade differential trail is constrained to a special form - the input to each S-box lookup has a nonzero difference only in the low 8 bits. This restricts the DDT rows that matter to the 255 rows of the form (d, 0) for d ∈ {1,...,255}, which is a tiny fraction of the 65535 possible nonzero input differences.

**Implication:** Differential trails through the forward pass are restricted to a 1-dimensional subspace of the 2-dimensional input difference space at each step. An attacker can precompute the DDT restricted to these 255 rows and build a truncated differential characteristic with much higher probability than a full 16-bit analysis would suggest.

### 2.6 Boundary Asymmetry: Byte 127

The block has 128 bytes indexed 0–127. The forward pass processes positions 0–126 (127 windows). The reverse pass processes positions 125–0 (126 windows, since k_cSpmBlockInflectionIndex - 2 = 125).

Byte 127 is involved in:
- Forward pass position 126: reads (B[126], B[127]), writes to both. **B[127] is written once.**
- Reverse pass: starts at position 125, reads (B[125], B[126]). **Byte 127 is never touched by the reverse pass.**

Per round, byte 127 participates in exactly **1 S-box operation** (forward pass position 126 only). Interior bytes participate in ~4 operations per round (written by position k-1, read/written by position k, in both passes).

Over 3 rounds: byte 127 participates in **3 S-box operations** vs ~12 for interior bytes.

**Mathematical implication:** Byte 127 has lower *confusion* (fewer nonlinear transformations applied) and lower *diffusion* (fewer cascade interactions). In a differential attack, fixing the plaintext difference to byte 127 produces a shorter cascade chain, making trail computation easier.

**Severity:** LOW-MEDIUM. The asymmetry is real but does not immediately yield an attack because:
1. After the first round, the reverse pass shuffles byte 127's value through interior positions
2. 3 rounds still apply 3 S-box operations to byte 127, each with a 16-bit S-box

However, it represents the weakest point in the structure.

### 2.7 Known-Plaintext Attack Surface

Given a known plaintext-ciphertext pair (P, C), consider the forward pass of round 1:

At position 0:
```
S(P[0:2] ⊕ m_0) = intermediate[0:2]
```

The attacker doesn't know S, m_0, or the intermediate state. However, consider the *system of equations* formed by the full forward pass on the known plaintext:

```
For k = 0, 1, ..., 126:
  S(in_k ⊕ m_k) = out_k
```

where in_k and out_k are determined by the cascade. Given P, the inputs in_k are determined by the cascade (each depends on the previous outputs). The masks m_k are generated by the mask PRNG with 127 bits of freedom. The S-box S has 127 bits of freedom.

Total unknowns: 127 (S-box seed) + 127 (mask seed) = 254 bits.
Total constraints from one block: 127 equations, each constraining a 16-bit S-box lookup.

With two known plaintext blocks, we have 254 equations - matching the 254 bits of key. This suggests that **two known plaintext blocks theoretically determine the key**, though extracting it requires solving a highly nonlinear system.

---

## 3. New Findings

### NF-1: Mask Transparency to Differential Cryptanalysis (MEDIUM)

As shown in §2.4, the XOR mask cancels in differential computations. The mask PRNG's 127-bit key space provides **zero additional security** against differential attacks. The effective security against differential cryptanalysis depends entirely on:
- The S-box's differential uniformity (§2.3: expected δ ≈ 4-6, which is good)
- The cascade structure (§2.5: restricted to low-byte-only trails)
- The number of rounds (3)

The document does not mention this. The mask's role is limited to preventing *absolute value* recovery (it acts as a stream cipher layer), not to resisting differential or linear attacks.

### NF-2: Restricted Differential Trail Space (MEDIUM)

The overlapping window structure restricts differential propagation through the forward pass to input differences of the form (d, 0) where d is a single-byte value. This means:
- Only 255 of the 65535 possible nonzero input differences matter per step
- The DDT can be analyzed on this restricted set
- Truncated differential attacks may be feasible with precomputation on these 255 rows

The reverse pass has an analogous restriction (propagation through the high byte). The combination of forward+reverse may cover the full 16-bit difference space, but this requires rigorous analysis.

### NF-3: Two-Block Key Recovery Threshold (LOW)

Two known plaintext-ciphertext pairs provide enough constraints (254 equations on 16-bit values) to determine the 254-bit key in theory. The practical complexity of solving this nonlinear system is unknown but could be explored via algebraic cryptanalysis (Gröbner basis, SAT solvers).

### NF-4: No Key Schedule (LOW-MEDIUM)

The 32-byte key is split into two 16-byte halves: one for the S-box PRNG, one for the mask PRNG. There is no key schedule - the S-box PRNG generates the S-box once, and the mask PRNG generates a fresh mask for every position. This means:
- Related-key attacks may be feasible: changing one byte of the S-box half changes only the S-box, leaving the mask stream identical
- Related-key differentials could be constructed to isolate S-box effects from mask effects
- AES-style related-key attacks exploit exactly this kind of structural separation

### NF-5: PRNG Linearity Enables Algebraic Attacks on Masks (LOW)

The mask PRNG is additive: state_{n+1} = state_n + key (mod 2^64). The sequence of 16-bit mask values is:

m_0 = low16(s), m_1 = high16(low32(s)), m_2 = low16(high32(s)), m_3 = high16(s),
then s ← s + k, repeat.

Each mask is a linear function of the initial state s and key k. If an attacker could observe *any two consecutive masks*, they could solve for s and k in O(1). The S-box prevents direct observation, but in a known-plaintext scenario with a guessed S-box, all masks become computable.

This creates an efficient **verify oracle**: guess 127-bit S-box seed → compute S-box → decrypt first few positions of known plaintext → check if mask sequence is consistent with a valid PRNG state. This reduces the effective attack to **2^127 S-box seed guesses**, each verifiable in O(1) work per known-plaintext block.

---

## 4. Strengths Confirmed

### SC-1: Large S-box provides strong local nonlinearity

A 16-bit S-box has DDT with 65536 × 65536 entries. Even a PRNG-generated permutation of this size will have excellent differential uniformity (δ ≈ 4-6) and linear bias (ε ≈ 0.006). These are near-optimal values. The document's qualitative claim is correct.

### SC-2: Cascade achieves empirical full diffusion

The mathematical analysis (§2.5) confirms that a single-byte change has ~98.8% probability of surviving 127 cascade steps without extinction, confirming that one forward pass achieves full-block influence. The bidirectional structure (forward + reverse) further strengthens this.

### SC-3: Practical key space is adequate

The 254-bit effective key space (127 bits for S-box PRNG + 127 bits for mask PRNG) is beyond brute-force reach. No shortcuts below 2^127 operations are evident from the mathematical structure, assuming the S-box is treated as a black box.

### SC-4: Reverse S-box computation is correct

The code `m_rgReverseSbox[m_rgSbox[i]] = i` correctly computes the inverse permutation. The debug-mode validation confirms bijectivity.

### SC-5: 128-byte block size provides large diffusion domain

Operating on 1024-bit blocks means that each S-box application mixes information across a much larger state than AES's 128-bit blocks. This is a legitimate structural advantage for diffusion, even if formal bounds are absent.

---

## 5. Key Questions for Other Agents

### For Turing (Implementation Analyst)

1. **Timing side channels:** The S-box lookup `prgSbox[*(reinterpret_cast<SPM_SBOX_WORD*>(pBlock + k))]` is a table lookup indexed by data. Is this vulnerable to cache-timing attacks analogous to those on AES T-tables? A 128KB S-box (65536 × 2 bytes) spans multiple cache lines.

2. **Unaligned memory access:** The code uses `reinterpret_cast<SPM_SBOX_WORD*>(pBlock + k)` where k is a byte offset. For k > 0, this performs *unaligned* 16-bit reads/writes. Is this safe on all target platforms? Does it cause performance penalties that could create timing signals?

3. **PRNG state after SetKeys:** After `PermuteSbox()` consumes 16 × 65536 = 1,048,576 PRNG outputs, the S-box PRNG state is at a deterministic position. Is this state then reused for block permutation generation? If so, the block permutation is fully determined by the S-box PRNG seed with no additional entropy.

### For Friedman (Statistical Analyst)

1. **Empirical DDT measurement:** Can you compute the actual DDT of an S-box generated by the PRNG with a random key and verify that δ ≈ 4-6? Also measure the LAT maximum correlation.

2. **Cascade survival rate:** Empirically verify the ~98.8% cascade survival probability by running differential propagation experiments through `s_SmForwardPass` with random S-boxes and single-byte input differences.

3. **Multi-round differential probability:** What is the probability of the best 3-round truncated differential characteristic, using the restricted trail space from §2.5 (NF-2)?

### For Driscoll (Attack Engineer)

1. **Algebraic attack feasibility:** Given NF-3 (two blocks determine the key), can SAT/SMT solvers or Gröbner basis methods solve the resulting system for toy-sized versions (e.g., 4-bit S-box, 8-byte block)?

2. **Related-key attack:** Given NF-4 (no key schedule, separated PRNG halves), construct a related-key scenario where changing one S-box PRNG byte produces a predictable S-box difference, and measure whether the mask stream (unchanged) reveals the relationship through ciphertext correlation.

3. **Verify oracle efficiency:** Implement the 2^127 S-box-seed-guess verify oracle from NF-5 and measure the per-guess cost. Is it truly O(1) per guess, or do cascade dependencies increase the constant?

---

*End of Phase 1 report - Rejewski*
