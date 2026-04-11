# Phase 3: Friedman Reviews Rejewski

**Reviewer:** Friedman (Statistician)
**Subject:** Rejewski Phase 1 Mathematical Assessment
**Date:** 2025-07-15
**Constraint:** Full 256-bit key. No password attacks. No nonce analysis. All PRNG attacks end-to-end through full cipher pipeline.

---

## 1. Restricted Differential Trails — Verdict

**Rejewski's claim (NF-2):** Forward-pass differentials are restricted to (d, 0) form — low-byte-only input differences at each cascade step.

**Verdict: CORRECT for a single forward pass, but INCOMPLETE in its implications for multi-pass and multi-round security.**

### 1.1 Forward Pass — Confirmed

Rejewski's analysis of the forward cascade is correct. At each step k, the 16-bit word is `(B[k], B[k+1])` in little-endian. The overlap byte (high byte of step k's output = B[k+1]) becomes the low byte of step k+1's input. Therefore, if a difference enters at byte 0 only, each subsequent step sees an input difference of the form (d, 0) where d is the propagated high-byte difference from the previous step. Only 255 of the 65,535 nonzero input differences are exercised. This is correct.

### 1.2 Reverse Pass — Restriction DOES NOT Survive

Rejewski states: "The reverse pass has an analogous restriction (propagation through the high byte). The combination of forward+reverse may cover the full 16-bit difference space, but this requires rigorous analysis."

I provide that analysis here. **The reverse pass does NOT have a restricted trail space.** After the forward pass completes with an initial single-byte difference at byte 0:

- Byte k (for k = 0, ..., 126) carries the low-byte component Δ_k^lo of step k's output difference
- Byte 127 carries Δ_126^hi

The reverse pass starts at step 125, reading `(B[125], B[126])`. Both B[125] and B[126] carry independent forward-pass residual differences. The 16-bit input difference to reverse step 125 is (Δ_125^lo, Δ_126^lo) — a **general 16-bit difference**, not restricted to any subspace.

At each subsequent reverse step k (going from 124 down to 0), the input word `(B[k], B[k+1])` contains:
- B[k]: forward-pass residual difference Δ_k^lo
- B[k+1]: freshly written difference from reverse step k+1

Both bytes carry nonzero differences, producing full 16-bit input differences at every reverse step. The reverse pass therefore explores the **complete DDT** of S — all 65,535 nonzero input differences — not just the 255-row restricted subset.

### 1.3 Multi-Round Implications

After one full round (forward + reverse), the block state has general differences in all byte positions. Round 2's forward pass then starts with a general difference at B[0] propagated through a **full 16-bit** input at step 0 (since B[0] and B[1] both carry differences from round 1's reverse pass). The (d, 0) restriction is broken from the very first step of round 2.

**Conclusion:** The restricted trail space is a **single-forward-pass phenomenon only**. By round 2, the full 16-bit difference space is explored at every step. The NF-2 finding is real but less severe than implied — it affects round 1's forward pass (127 steps out of 759 total) but not the remaining 632 steps.

---

## 2. Two-Block Key Determination — Equation Analysis

**Rejewski's claim (NF-3):** Two known-plaintext blocks provide 254 equations (127 per block) matching the 254-bit key, theoretically determining the key.

**Verdict: Equation count is MISLEADING; independence claim is WRONG.**

### 2.1 Equation Count

Rejewski counts only forward-pass equations from round 1: 127 per block. The actual number of S-box equations per block is 3 rounds × (127 forward + 126 reverse) = **759 equations per block**. Two blocks provide 1,518 equations. The claimed 254 is an undercount by 6×.

However, this undercounting does not help Rejewski's argument — more equations is seemingly better for the attacker. The real issues are below.

### 2.2 Equation Independence — Fundamentally Flawed

The 127 forward-pass equations per block form a **sequential chain**, not independent constraints:

```
out_0 = S(P[0:2] ⊕ m_0)
out_1 = S((out_0_hi, P[2]) ⊕ m_1)       // depends on out_0
out_2 = S((out_1_hi, P[3]) ⊕ m_2)       // depends on out_1
...
```

Each equation's input depends on the previous equation's output. The system is a recurrence relation, not a set of independent constraints. The effective information content is NOT 127 × 16 = 2,032 bits; it is closer to the information in the initial conditions plus the plaintext (which is known).

### 2.3 Unknowns Are Not 254 "Bits" — They Are Structural

The 254-bit key determines:
- An S-box: a permutation of {0, ..., 65535} with 65,536 entries (log₂(65536!) ≈ 954,017 bits of information for an unconstrained permutation)
- A mask sequence: 759 mask values per block (each 16-bit)

Rejewski frames this as "254 equations in 254 unknowns." But the unknowns are not bits — they are a 65,536-entry permutation table and a linear recurrence. The equations are S-box lookups at specific (unknown) inputs, coupled through the cascade. This is a highly nonlinear system with no known polynomial-time solution method.

### 2.4 The Information-Theoretic Argument

Two blocks provide at most 2 × 128 × 8 = 2,048 bits of ciphertext information (given known plaintext). The key has 254 effective bits. So information-theoretically, two blocks are **more than sufficient** to uniquely determine the key — Rejewski is correct on this narrow point.

But "uniquely determined" ≠ "efficiently recoverable." AES-128 is uniquely determined by ~2 known-plaintext blocks, yet no polynomial-time attack exists. The complexity of solving the nonlinear system is the real question, and Rejewski correctly flags this as unknown.

**Revised severity: LOW** (information-theoretic observation, not a practical attack vector).

---

## 3. Cascade Survival Probability — Statistical Verification

**Rejewski's claim (§2.5):** The probability that a single-byte difference survives 127 cascade steps is ~98.8%, modeled as (1 − 6/65536)^127.

**Verdict: The model contains TWO fundamental errors. The correct survival probability is approximately 61%, not 98.8%.**

### 3.1 Error 1: Permutation Property Ignored

Rejewski writes: "The probability that (d, 0) → (0, 0) through S is at most δ(S)/2^16."

For a **permutation** S, this probability is exactly **zero**. If Δ ≠ 0, then S(x ⊕ Δ) ≠ S(x) for all x (because S is injective and x ⊕ Δ ≠ x). Therefore DDT[Δ, 0] = 0 for all nonzero Δ. The output difference can never be (0, 0). Rejewski's use of the differential uniformity δ here is incorrect — δ bounds the maximum DDT entry for nonzero output differences, not the zero-output entry.

### 3.2 Error 2: Wrong Extinction Condition

The cascade chain extinguishes when the **high byte** of the output difference is zero — not when the full output difference is zero. If step k produces output difference (c, 0) with c ≠ 0, the cascade stops because step k+1's input difference becomes (0, 0). The difference at byte k is nonzero (value c), but no further propagation occurs.

The correct extinction probability per step is:

```
P(extinction) = P(output_hi = 0 | input_diff ≠ 0)
              = Σ_{c=1}^{255} DDT[(d,0), (c,0)] / 65536
```

For a random 16-bit permutation, each nonzero DDT entry has expected value ≈ 1. There are 255 target output differences of the form (c, 0) with c ∈ {1, ..., 255}. Therefore:

```
E[P(extinction per step)] ≈ 255 / 65536 ≈ 0.00389
```

### 3.3 Correct Survival Probability

With 126 propagation events in the forward pass (step 0 generates the initial difference; steps 1–126 each propagate from the previous step's high byte):

```
P(survival) ≈ (1 − 255/65536)^126
            = (0.99611)^126
            ≈ exp(−126 × 0.00389)
            ≈ exp(−0.490)
            ≈ 0.613
```

**The correct forward-pass survival probability is approximately 61%, not 98.8%.** Rejewski's estimate is off by a factor of ~1.6× and in the wrong direction for the security claim.

### 3.4 Impact on Diffusion Claims

A 61% survival rate means ~39% of single-byte input changes do NOT propagate through the entire forward pass. However, this does NOT mean 39% of inputs produce poor diffusion:

1. **Partial propagation still affects many bytes.** If the chain dies at step k, bytes 0 through k all carry differences. The expected extinction point (geometric distribution with p ≈ 0.00389) is at step ~257, well beyond the 126-step forward pass — confirming that most chains DO survive in practice.

2. **The reverse pass compensates.** Even when the forward chain extinguishes early, the reverse pass encounters forward-pass residual differences at every position it traverses, restarting the cascade in the opposite direction.

3. **Three rounds provide ample compensation.** After 759 total cascade steps across 3 rounds, full-block diffusion is virtually certain.

### 3.5 Model Validity

Beyond the two errors above, the geometric model `(1 − p)^n` assumes independence between steps. This is approximately valid: the extinction probability at step k depends on the specific high-byte difference Δ_{k−1}^hi entering that step, which varies unpredictably (determined by the S-box). For a random permutation, successive high-byte differences behave approximately independently. The i.i.d. approximation is reasonable.

---

## 4. Differential Security Estimate

**Question:** If masks add zero differential resistance (confirmed in both reports), what IS the actual differential security?

### 4.1 Components of Differential Security

The cipher's differential resistance rests on three pillars:

| Component | Contribution |
|-----------|-------------|
| S-box quality | Max differential probability ≈ δ/2^16 ≈ 6/65536 ≈ 2^{−13.4} per step for the worst-case DDT entry |
| Cascade length | 759 steps per block (3 rounds × 253 steps) |
| Masks | **Zero** (confirmed: DDT is invariant under XOR translation) |

### 4.2 Best Single-Round Truncated Differential

For the forward pass only (the most restricted phase):

- Input differences are restricted to 255 values of the form (d, 0)
- An attacker can precompute the DDT restricted to these 255 rows
- The best single-step transition probability (for a random S-box) is at most δ/65536 ≈ 6/65536 ≈ 2^{−13.4}
- But the attacker doesn't need a SPECIFIC output — they need ANY nonzero high byte (probability ≈ 65281/65536 ≈ 0.996)
- The truncated differential characteristic (tracking only whether the high byte is nonzero) has probability ≈ 0.61 per forward pass

For a full 3-round characteristic with specific output differences:
- Each step constrains the output to a specific DDT row
- Per-step probability for the best specific trail: ≈ δ/65536 ≈ 2^{−13.4}
- Over 759 steps (conservatively): probability ≈ 2^{−13.4 × 759} ≈ **2^{−10,171}**

This is astronomically small. Even truncated differentials (tracking byte-level activity patterns rather than exact values) face the 759-step cascade barrier.

### 4.3 Practical Differential Security Assessment

The cipher's differential security is **dominated by the S-box quality and cascade length**, with masks contributing nothing. For a random 16-bit permutation:

- **Per-step worst-case differential probability:** 2^{−13.4} (for specific output difference)
- **Per-step truncated probability (any nonzero propagation):** ≈ 0.996
- **Full 3-round specific trail probability:** negligible (< 2^{−10,000})
- **Practical exploitability:** None identified

The S-box alone, applied 759 times through the cascade, provides overwhelming differential resistance. The masks are irrelevant to this calculation, but this does not constitute a weakness — the S-box + cascade combination is sufficient.

### 4.4 Comparison Framework

For context, AES-128 achieves a proven lower bound of 2^{−150} for any 4-round differential characteristic (via the 25 active S-box bound). SPM has no proven bound, but heuristic estimates for its 3-round, 759-step cascade suggest differential probabilities far below 2^{−150}. The lack of a formal proof is a theoretical gap, not a practical weakness.

---

## 5. Overall Assessment of Rejewski's Analysis

### 5.1 What Rejewski Got Right

1. **Mask transparency (NF-1):** Completely correct. The DDT invariance under XOR masks is a clean, important observation. I independently confirmed this in my §4.3. This is Rejewski's strongest finding.

2. **Forward-pass (d, 0) restriction (NF-2, partial):** The observation that the forward cascade restricts input differences to the low-byte subspace is correct and insightful. This is a genuine structural property that the document should note.

3. **S-box algebraic analysis (§2.1–2.3):** Thorough and accurate. The Fisher-Yates bias analysis with eigenvalue bounds (TV ≈ 0.6% after 16 passes) is well-executed.

4. **Boundary asymmetry (§2.6):** Correct identification of byte 127 as the weakest position.

5. **PRNG linearity enabling verify oracle (NF-5):** The 2^127 S-box-seed-guess oracle is a valid observation, consistent with other analysts' findings.

### 5.2 What Rejewski Got Wrong

1. **Cascade survival probability (§2.5):** The (1 − 6/65536)^127 ≈ 98.8% model is incorrect on two counts: (a) the permutation property makes DDT[Δ, 0] = 0, not δ/2^16; (b) the relevant extinction event is zero high-byte (probability ≈ 255/65536), not zero full-output. The correct survival probability is ~61%. However, this error makes the cipher appear MORE secure than it is for single-pass diffusion, so it does not invalidate any attack claims.

2. **Equation counting for NF-3:** The claim of "254 equations matching 254 key bits" is misleading. The equations are deeply coupled (sequential chain), the unknowns are structural (65536-entry permutation), and the system is highly nonlinear. The information-theoretic conclusion (2 blocks suffice to determine the key) is correct but trivial — the same is true of AES with ~2 blocks.

### 5.3 What Rejewski Left Unresolved

1. **Reverse-pass differential structure:** Rejewski flagged this as needing analysis. I provide it in §1.2 above: the reverse pass has UNRESTRICTED 16-bit input differences, which is actually good for diffusion (and bad for the attacker).

2. **Multi-round differential accumulation:** No analysis of how the restricted/unrestricted trail structure interacts across 3 rounds. My analysis in §1.3 shows the restriction is eliminated by round 2.

3. **Practical exploitability of the restricted trail space:** Rejewski identifies the 255-row DDT restriction but does not estimate whether it leads to a practical attack. Given the cascade length (759 steps) and the transition to unrestricted trails after 127 steps, exploitability appears negligible.

### 5.4 Summary Table

| Claim | Rejewski | Friedman Verdict |
|-------|----------|-----------------|
| Forward-pass (d,0) restriction | Correct | **Confirmed** |
| Reverse-pass analogous restriction | Suggested | **Rejected** — reverse pass has full 16-bit differences |
| Cascade survival ≈ 98.8% | Claimed | **Rejected** — correct value ≈ 61%, but diffusion is still adequate due to reverse pass and 3 rounds |
| Two blocks determine key | Claimed | **Technically correct** (information-theoretically) but **misleading** (not efficiently solvable) |
| Masks transparent to differentials | Correct | **Confirmed** |
| Differential security from S-box alone | Implied | **Confirmed** — S-box quality × 759-step cascade provides overwhelming resistance |

---

*End of Phase 3 cross-review — Friedman*
