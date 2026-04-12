# Phase 3: Rejewski Reviews Friedman

**Reviewer:** Rejewski (Cipher Mathematician)
**Subject:** Friedman's Phase 1 Statistical Assessment
**Date:** 2025-07-15

---

## 1. PRNG Sub-Period Analysis — Verdict

**AGREE with reservations — Friedman's conclusion is correct but the argument has a gap for the CPA case.**

Friedman's §5.2 argues the 345-block low-16-bit sub-period is undetectable through the cipher, offering three reasons: (1) the S-box barrier, (2) cascade dependency preventing input matching, and (3) partial periodicity (only ~25% of masks share the sub-period).

### Where the argument is rigorous

The core substitution argument is sound. When slice-0 mask m repeats at position k across blocks B_i and B_{i+345}, the cipher outputs are S(x₁ ⊕ m) and S(x₂ ⊕ m). For random plaintext, x₁ ≠ x₂ with probability 1 − 2^{−16}, and the outputs are uncorrelated. This is correct.

### The gap: Chosen-Plaintext Attack (CPA)

Friedman's argument implicitly assumes random or unknown plaintext. Under CPA, the attacker can submit **identical plaintext blocks** at positions i and i+345. Consider the forward pass of round 1:

- **Position 0** (uses slice-0 mask): Identical plaintext + identical mask → identical S-box output. The intermediate states match at position 0.
- **Position 1** (uses slice-1 mask): The cascade input includes position 0's output (identical in both blocks), but the slice-1 mask does NOT repeat at 345 blocks (slice-1 has period 2^32 state advances ≈ 5.7 × 10⁶ blocks). Therefore the S-box inputs differ, and the cascade **diverges**.
- **Position 4** (uses slice-0 of state_{n+1}): Slice-0 mask repeats again, but by now the cascade inputs are completely different due to the divergence at positions 1, 2, 3.

The divergence at position 1 propagates through all subsequent positions with probability ≈ 1 − (δ(S)/2^16)^126 ≈ 1. After the remaining ~752 cascade steps in round 1 plus two more full rounds, any trace of the position-0 match is obliterated.

**Quantitative bound:** The single matching position contributes at most 1 identical 16-bit intermediate value out of 759 cascade steps per round × 3 rounds. The mutual information between two ciphertext blocks sharing one intermediate value out of 2277 total is negligible — well below any statistical test's detection threshold for realistic sample sizes.

### Verdict

Friedman's **conclusion** is mathematically sound: no distinguisher exists at the 345-block period. However, the argument should explicitly address the CPA case and note that the divergence at non-slice-0 positions (positions 1, 2, 3 within each group of 4) is what ultimately kills the attack, not just the probabilistic x₁ ≠ x₂ argument. The multi-slice structure of the PRNG is the key defense here — if ALL masks (not just slice-0) shared the same short period, CPA with identical blocks WOULD create a detectable signature.

**Severity of the gap:** Cosmetic. The conclusion stands.

---

## 2. DDT Invariance — Verification

**CONFIRMED. Friedman's §4.3 is mathematically exact.**

### Formal proof

Let S be a permutation on Z_{2^16}. Define f_m(x) = S(x ⊕ m). For any input difference Δx ≠ 0 and output difference Δy:

```
DDT_{f_m}(Δx, Δy) = |{x ∈ Z_{2^16} : f_m(x) ⊕ f_m(x ⊕ Δx) = Δy}|
                   = |{x : S(x ⊕ m) ⊕ S(x ⊕ Δx ⊕ m) = Δy}|
```

Substituting a = x ⊕ m (bijection, so the count is preserved):

```
                   = |{a : S(a) ⊕ S(a ⊕ Δx) = Δy}|
                   = DDT_S(Δx, Δy)
```

This holds for ALL m. QED. The DDT of S(· ⊕ m) equals the DDT of S, independent of m. ∎

### Implications for the mask PRNG

**Yes, the entire mask PRNG is irrelevant to differential security.** This is a strong and important structural result:

1. **Differential attacks:** The attacker needs only characterize DDT(S) once. Every cascade step has identical differential behavior regardless of which mask is applied. The 127-bit mask key contributes **zero bits** of differential resistance.

2. **Effective differential security** depends solely on:
   - The S-box's differential uniformity δ(S) — expected δ ≈ 4–6 for a random 16-bit permutation
   - The cascade topology (sequential 8-bit overlap, restricted to (d,0)-form trails per my NF-2)
   - The round count (3)

3. **What masks DO protect against:** Absolute value recovery. Without the mask, the attacker in a KPA scenario directly obtains S-box input-output pairs. The mask forces the attacker to solve for both S and the mask values simultaneously. This is valuable — but orthogonal to differential resistance.

### Extension: Linear approximation invariance

I note that the **linear approximation table (LAT)** is also mask-invariant, by an analogous argument:

```
LAT_{f_m}(a, b) = Σ_x (−1)^{a·x ⊕ b·f_m(x)}
                = Σ_x (−1)^{a·x ⊕ b·S(x⊕m)}
```

Substituting u = x ⊕ m:

```
                = Σ_u (−1)^{a·(u⊕m) ⊕ b·S(u)}
                = (−1)^{a·m} · Σ_u (−1)^{a·u ⊕ b·S(u)}
                = (−1)^{a·m} · LAT_S(a, b)
```

The absolute value |LAT_{f_m}(a,b)| = |LAT_S(a,b)| for all m. So masks also add **zero resistance to linear cryptanalysis.** Friedman does not state this explicitly, but it follows directly from his §4.3 methodology.

**Combined conclusion:** The mask PRNG provides zero resistance to both differential AND linear cryptanalysis. The S-box quality alone determines resistance to both standard attack families.

---

## 3. Statistical Distinguisher Challenge

**Friedman's "no practical distinguisher" verdict (§3.5) is well-supported. I identify one theoretical avenue he did not explicitly address, but conclude it is not exploitable.**

### Friedman's coverage (confirmed)

Friedman correctly rules out:
- Byte frequency distinguishers (§3.1) ✓
- Bigram/n-gram distinguishers (§3.2) ✓
- Cross-block correlation distinguishers (§3.3) ✓
- Position-dependent bias distinguishers (§3.4) ✓

I concur with all four conclusions.

### Potential avenue not addressed: Intra-state mask correlation

The PRNG produces 4 masks from a single 64-bit state word. At positions {4k, 4k+1, 4k+2, 4k+3} within a pass, the masks are the four 16-bit slices of one state value:

```
m_{4k}   = state[15:0]    (bits 0–15)
m_{4k+1} = state[31:16]   (bits 16–31)
m_{4k+2} = state[47:32]   (bits 32–47)
m_{4k+3} = state[63:48]   (bits 48–63)
```

These four values are algebraically correlated — they compose a single 64-bit integer. A hypothetical attacker could attempt a **multi-position higher-order statistical test**: examine the joint distribution of ciphertext at positions {4k, 4k+1, 4k+2, 4k+3} across many blocks, looking for deviations from independence caused by the 4-slice structure.

**Why this fails in practice:**

1. **Cascade serialization:** Positions 4k+1, 4k+2, 4k+3 each depend on the output of the preceding position through the cascade overlap. The cascade input at position 4k+1 includes the high byte of S(x_{4k} ⊕ m_{4k}), making the effective input to position 4k+1 a nonlinear function of m_{4k}. This destroys the algebraic relationship between m_{4k} and m_{4k+1} from the attacker's perspective.

2. **S-box nonlinearity barrier:** Even if the masks are correlated, each passes through the S-box independently. The composition S(cascade_input ⊕ m_i) destroys linear/additive correlations between mask values. Detecting the 64-bit algebraic structure would require simultaneously inverting the S-box at 4 positions — equivalent to knowing 4 S-box entries, which is not available without the key.

3. **Three-round mixing:** After 3 rounds, each ciphertext byte at these 4 positions depends on all 1024 input bits plus all 2277 masks. The 4-value correlation is diluted below any detectable threshold.

**Quantitative estimate:** The mutual information between the 4-slice structure and the ciphertext at these positions, after the S-box + cascade + 3 rounds, is bounded by the information leakage through a single S-box application (which provides full equivocation for a 16-bit permutation). The multi-position correlation requires O(2^64) samples to detect even a 2^{-32} bias, which is far beyond any realistic data collection.

### Verdict

**No distinguisher identified beyond Friedman's analysis.** The intra-state correlation is real in the PRNG but is completely obscured by the cascade serialization and S-box nonlinearity. Friedman's conclusion stands.

---

## 4. S-box Severity Resolution

**MEDIUM — I maintain my original assessment, with acknowledgment that Friedman's practical arguments are strong.**

### Friedman's case for LOW

Friedman argues (Finding #1):
1. 2^127 seeds > 2^17 testable S-box queries — attacker cannot distinguish
2. Expected differential uniformity δ ≈ 2 matches random permutations
3. No statistical test on S-box output can distinguish PRNG-generated from random

### My case for MEDIUM

The disagreement is about **what we're rating**: practical exploitability (Friedman) vs. cryptographic confidence (Rejewski).

1. **No indistinguishability proof exists.** Friedman's argument is heuristic: "the expected DDT looks random, therefore it IS random for practical purposes." This is likely true but unproven. Standard cryptographic practice rates findings at MEDIUM when the theoretical foundation is absent, even if exploitation seems unlikely. The PRNG is a Weyl sequence — the simplest possible linear generator. The shuffle process is nonlinear, but no theorem guarantees that Weyl-sequence-driven naive shuffle produces permutations whose DDT/LAT are computationally indistinguishable from random permutations.

2. **Friedman's δ ≈ 2 estimate is incorrect.** He states "the expected differential uniformity of the resulting 16-bit S-box is ≈2 (same as a truly random permutation)." For a random 16-bit permutation, the expected MAXIMUM DDT entry is NOT 2 — it's approximately 4–6 (as I computed in my Phase 1 §2.3, and consistent with the birthday bound for 2^16 values distributed across 2^16 bins within each DDT row). The value δ = 2 would be APN (Almost Perfect Nonlinear), which is the theoretical optimum and not the expected value for a random permutation. This is a factual error in Friedman's report, though it does not change his ultimate conclusion since δ ≈ 4–6 is still excellent.

3. **The 2^127 family structure.** The 2^127 reachable S-boxes are generated by a structured process (additive PRNG → naive shuffle). While 2^127 is enormous, the generation process creates a *family* with shared structural properties:
   - All members are generated by the same shuffle algorithm
   - The shuffle randomness has low linear complexity
   - Family members with "nearby" seeds (differing by a single key bit) produce S-boxes with potentially correlated structures

   No attack currently exploits this, but the structural concern is real and warrants MEDIUM.

4. **Precedent in cipher design:** Modern cipher design requires either proven bounds (AES S-box has provable δ = 4 and nonlinearity = 112) or extensive empirical validation (exhaustive DDT/LAT computation over representative sample keys). This cipher has neither. MEDIUM reflects the missing validation, not a known weakness.

### Resolution

**MEDIUM** is the appropriate severity for a cryptographic assessment document. Friedman's LOW would be appropriate for a penetration-testing report focused solely on practical exploitability. Since `cryptanalysis.md` is a cryptographic analysis document, the absence of formal guarantees warrants MEDIUM.

**Correction required:** Friedman should correct the δ ≈ 2 claim to δ ≈ 4–6.

---

## 5. Overall Assessment of Friedman's Analysis

### Quality: HIGH

Friedman's report is thorough, well-structured, and reaches correct conclusions on all major points. The end-to-end pipeline analysis (§2) is particularly valuable — Friedman consistently evaluates PRNG weaknesses through the full cipher stack rather than in isolation, which is the right methodology.

### Strengths of Friedman's analysis

1. **Pipeline-first methodology.** Every PRNG weakness is evaluated through the S-box + cascade barrier. This prevents false alarms about isolated PRNG properties that don't survive the cipher stack.

2. **DDT invariance (§4.3).** Independently discovered the same mask-transparency property I identified in my NF-1. The formal statement is correct and well-argued.

3. **Sub-period analysis (§5.2).** Correct conclusion with solid quantitative reasoning. The three-pronged argument (S-box barrier, cascade dependency, partial periodicity) is comprehensive.

4. **Cross-block correlation analysis (§3.3).** The argument that PRNG-driven mask variation prevents cross-block byte correlations is correct and clearly stated.

5. **Practical focus.** Friedman appropriately distinguishes between theoretical properties and practical threats. The discipline of asking "does this survive the pipeline?" at every step is methodologically sound.

### Issues identified

| # | Issue | Severity |
|---|-------|----------|
| 1 | δ ≈ 2 claim is factually incorrect (should be δ ≈ 4–6) | Minor — doesn't affect conclusions |
| 2 | §5.2 doesn't explicitly address CPA with identical plaintext | Cosmetic — conclusion still holds |
| 3 | LAT invariance under masks not mentioned (only DDT) | Minor omission |
| 4 | S-box severity LOW → should be MEDIUM | Methodological disagreement |
| 5 | No discussion of intra-state 4-slice mask correlation | Minor omission — not exploitable |

### Points of agreement

- The S-box + cascade barrier is effective against PRNG state recovery (§5.1) ✓
- The 345-block sub-period is not detectable through the cipher (§5.2) ✓
- No practical statistical distinguisher exists for 3-round cipher (§3.5) ✓
- Block independence relies on PRNG uniqueness — fragile design philosophy (§4.1) ✓
- Avalanche completeness is unverified but likely adequate at 3 rounds (§4.2) ✓
- Key bit loss of 2 bits (256 → 254) is negligible (§4.4) ✓
- Masks are transparent to differential cryptanalysis (§4.3) ✓

### Final verdict

Friedman's analysis is **reliable and can be incorporated into the final assessment** with the following corrections:
1. Fix δ ≈ 2 → δ ≈ 4–6
2. Upgrade S-box severity to MEDIUM (or document the LOW/MEDIUM disagreement with rationale for both)
3. Note LAT invariance alongside DDT invariance
4. Add CPA clarification to §5.2

No findings in Friedman's report are incorrect in their conclusions. The issues are precision and severity calibration, not analytical errors.

---

*End of Phase 3 cross-review — Rejewski*
