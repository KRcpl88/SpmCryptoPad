# Phase 3: Driscoll Reviews Turing

**Reviewer:** Driscoll (Attack Specialist)
**Subject:** Turing §3.1 — Key Decomposition Attack at 2^128
**Date:** 2025-07-15

---

## 1. Key Decomposition Attack — Step-by-Step Validation

### 1.1 Turing's Claim (§3.1)

Turing claims:
1. Guess the 127-bit S-box PRNG seed → generate candidate S-box S
2. With a known P/C pair, verify S by checking mask consistency
3. For the correct S, recover the mask PRNG key
4. Total work: 2^127 + 2^127 ≈ 2^128

I will now walk through this step by step against the actual cipher code.

### 1.2 Cipher Operation Trace

From `SpmBlockCipher64.cpp`, encryption of one 128-byte block in `NoPermutation` mode consists of 3 rounds, each round being:

```
s_SmForwardPass:  k = 0..126 (127 steps)
    block[k:k+2] ^= mask_k
    block[k:k+2] = S[block[k:k+2]]

s_SmReversePass:  k = 125..0 (126 steps)
    block[k:k+2] ^= mask_k
    block[k:k+2] = S[block[k:k+2]]
```

Total masks per round: 127 + 126 = 253. Over 3 rounds: **759 mask values consumed.**

The mask PRNG (`CSimplePrng64`) produces 16-bit values by slicing a 64-bit state. Every 4th `.Rand()` call advances the state: `state += key`. The 759 masks are fully determined by 127 bits: initial state `s` (64 bits) + key `k` (63 bits, LSB forced to 1).

### 1.3 The Critical Question: Can a Candidate S-box Be Verified in Poly Time?

Turing's attack hinges on step 2: given candidate S-box S, known plaintext P, and known ciphertext C, can we determine whether S is correct **without brute-forcing the mask PRNG seed**?

#### Attempt 1 — Forward Layer Peeling

Given S and P, step k=0 of round 1 forward pass:
```
block[0:1] = S[P[0:1] XOR m_0]
```

This is a function of the single unknown `m_0`. For each of 2^16 candidate values of `m_0`, we get a distinct block state. Byte 0 is "settled" (won't change again in the forward pass). But step k=1 requires `m_1`:
```
block[1:2] = S[(output_byte_1_from_step_0 || P[2]) XOR m_1]
```

`output_byte_1_from_step_0` depends on `m_0`. Each subsequent step depends on all prior masks through the cascading overlap. After 4 steps, the block state at bytes 0–3 is a function of `(m_0, m_1, m_2, m_3)` — i.e., the full 64-bit initial PRNG state `s`.

But this forward-peel only gives us partial intermediate state, NOT the ciphertext C. To reach C, we need all 759 masks, which requires knowing both `s` and `k` (the full 127-bit mask seed).

**Verdict: Forward peeling does not determine masks without the full seed.**

#### Attempt 2 — Backward Peeling from Ciphertext

The last encryption operation was step k=0 of round 3's reverse pass (mask `m_758`):
```
C[0:1] = S[prev[0:1] XOR m_758]
```

To invert: `prev[0:1] = S^{-1}(C[0:1]) XOR m_758`. But both `prev[0:1]` and `m_758` are unknown — one equation, two unknowns. The same circularity applies to every step peeled backward.

**Verdict: Backward peeling is equally blocked.**

#### Attempt 3 — Determine Masks from Known Block States

If we knew the block state before AND after each step, we could compute each mask:
```
m_k = S^{-1}(output[k:k+2]) XOR input[k:k+2]
```

But we only observe P (before step 0) and C (after step 758). The 759 intermediate block states are unknown. They are determined by the 127-bit mask seed, but recovering them IS the problem we're trying to solve.

**Verdict: Requires exactly the information we lack.**

#### Attempt 4 — Exhaustive Mask Seed Search per S-box Candidate

For each candidate S-box:
- For each candidate mask seed (2^127 possibilities):
  - Generate 759 masks
  - Encrypt P using candidate S-box and masks (O(759) work)
  - If output = C, key found

This WORKS but costs **2^127 per S-box candidate**. For 2^127 S-box candidates, total = **2^127 × 2^127 = 2^254**.

#### Attempt 5 — Early Rejection of Wrong S-boxes

Could we reject a wrong S-box quickly? For a wrong S-box, NO mask seed will produce C from P. But to confirm this, we'd need to exhaustively search all 2^127 mask seeds — which is the full cost.

Could we test a small random sample of mask seeds? If we test T random seeds per S-box candidate, the probability of hitting the correct seed for the correct S-box is T/2^127. To find the key with good probability, we need T × 2^127 ≈ 2^127 total trials — the same as brute force over the mask key for a single S-box. This provides zero improvement to the overall 2^254 cost.

#### Attempt 6 — PRNG Structure Exploitation

The mask PRNG has structure: masks come in groups of 4 (16-bit slices of a 64-bit state), and consecutive states differ by an additive constant `k`.

Could we enumerate the 64-bit state `s` (2^64 work) and determine `k` (63 bits) by some shortcut? No:
- Given `s`, we know `m_0..m_3` and can compute 4 forward-pass steps
- But completing the remaining 755 steps requires `k`, which has 63 unknown bits
- The carry propagation in 64-bit addition makes the relationship between 16-bit mask words nonlinear at the word level
- There is no known technique to infer `k` from the partial intermediate state and C

**Verdict: PRNG linearity does not help. The arithmetic carry chain breaks linearity at the 16-bit word level.**

---

## 2. Verification Procedure

### 2.1 Can a Candidate S-box Be Verified in Polynomial Time?

**NO.** I find no polynomial-time verification procedure.

The problem reduces to: given a nonlinear function `f: {0,1}^127 → {0,1}^1024` (parameterized by the candidate S-box and known plaintext), find `x` such that `f(x) = C`. The function `f` is the full 759-step cascaded encryption with overlapping windows. Its structure is:

1. **Deeply cascading**: each step's output feeds into the next step's input via the 1-byte overlap
2. **Nonlinear**: each step applies the 16-bit S-box (degree ≤ 15 in ANF)
3. **Mixed arithmetic**: masks enter via XOR, but the PRNG generates them via modular addition

No known algorithmic technique (SAT solvers, Gröbner bases, linearization, meet-in-the-middle) can invert this function faster than O(2^127) for the generic case.

### 2.2 Why Turing's Reasoning Fails

Turing states: *"If the S-box is wrong, inconsistency will be detected within the first few sliding-window steps."*

This is incorrect. The "inconsistency" Turing describes — that derived mask values won't satisfy the PRNG structure — requires first DERIVING the mask values. But deriving mask values at step k requires knowing the block state at step k, which depends on all prior masks. You cannot derive masks without already knowing the masks. The cascade creates a chicken-and-egg problem that has no efficient resolution.

The only way to test "mask consistency" is:
1. Assume specific mask values (= assume PRNG seed)
2. Run the full encryption
3. Check output against C

This is brute force over the mask seed, costing O(2^127) per S-box candidate.

### 2.3 What WOULD Make 2^128 Work

The 2^128 attack would be valid IF any of these held:
- **No cascade**: if each S-box step were independent (no overlapping window), masks could be determined step-by-step in O(759). But the overlap creates inter-step dependencies.
- **Linear mixing**: if the S-box were linear (e.g., matrix multiplication over GF(2)), the cascade would be a system of linear equations solvable in polynomial time. But S is a random 16-bit permutation — maximally nonlinear.
- **Known intermediate state**: if ANY intermediate block state (between any two steps) were known, the cascade could be split and solved more efficiently. But all 759 intermediate states are hidden.

None of these conditions hold. The cipher's design — cascading nonlinear S-box with overlapping windows — is precisely what prevents the decomposition attack.

---

## 3. Revised Attack Complexity

### 3.1 Key Decomposition: REFUTED for Active Cryptanalysis

| Turing's Claim | Driscoll's Assessment |
|---|---|
| S-box search: 2^127 | **Correct** — 2^127 candidate S-boxes exist |
| Per-candidate verification: O(1) | **WRONG** — verification requires O(2^127) mask search |
| Total: 2^127 + 2^127 ≈ 2^128 | **Incorrect** — actual total is O(2^254) |

### 3.2 The Structural Vulnerability IS Real (But Not Exploitable Purely Cryptanalytically)

The key decomposition is structurally real in a defensive sense:
- The two key halves are independent
- If the S-box is leaked (side-channel, memory dump, cold-boot), remaining search is O(2^127)
- If the mask PRNG state is leaked, and S is known, the key is fully recovered

This is a valid architectural concern (as I noted in my Phase 1 NF-4), but it requires a **side-channel** to trigger. Under a pure cryptanalytic model (attacker sees only P/C pairs), the decomposition cannot be exploited because the verification bottleneck remains O(2^127).

### 3.3 Corrected Attack Complexity Table

| Attack | Complexity | Notes |
|---|---|---|
| Brute force (full key) | O(2^254) | Baseline: 2^127 × 2^127, two LSBs forced |
| Key decomposition (Turing §3.1) | O(2^254) | Verification bottleneck prevents 2^128; decomposition is additive ONLY if one half leaks |
| Side-channel + brute force | O(2^127) | If S-box leaked via cache-timing, memory dump, etc. |
| Chosen-plaintext (Driscoll §2.2) | O(2^16) info / no key recovery | Low-byte partition only |

### 3.4 Strongest Pure Cryptanalytic Attack

**O(2^254) — exhaustive key search remains the strongest known attack under full-key, known-plaintext conditions.**

The cascade barrier — 759 nonlinear steps with overlapping windows — prevents decomposition, layer-peeling, meet-in-the-middle, differential, linear, and algebraic attacks from achieving sub-brute-force complexity.

---

## 4. Practical Attack Guide (If S-box Is Leaked)

If a side-channel leaks the S-box (e.g., cache-timing analysis of the 128 KB S-box table during encryption):

### 4.1 Recovering the Mask Key

1. **Obtain S-box**: 65536 × 2-byte entries = 128 KB. A cache-timing side-channel during one encryption is sufficient.
2. **Compute S^{-1}**: O(65536) — trivial.
3. **Obtain one known P/C pair**: 128 bytes each.
4. **Search mask PRNG seed**: For each candidate (s, k) pair (127-bit space):
   - Generate 759 masks from PRNG
   - Encrypt P with known S and candidate masks
   - Compare to C
   - Cost per trial: O(759) ≈ O(2^10)
5. **Total work**: O(2^127 × 2^10) = O(2^137) operations

### 4.2 Optimization: State-First Search

Enumerate `s` (64 bits) before `k` (63 bits):
1. For each candidate `s` (2^64 trials):
   - Compute first 4 masks from s
   - Run first 4 forward-pass steps
   - Store partial intermediate state (bytes 0–4)
2. For each surviving `s`, enumerate `k` (2^63 trials):
   - Complete all 759 steps
   - Check against C
3. Total: O(2^64 × 4) + O(2^64 × 2^63 × 759) ≈ O(2^137)

No improvement over linear search, but confirms the 2^127 mask search dominates.

### 4.3 Data Requirements

- **Minimum**: 1 known P/C block (128 bytes each)
- **Advantage of multiple pairs**: None for brute-force mask search. A second pair provides independent verification of the recovered key.

---

## 5. Other Findings from Turing's Report

### 5.1 Agreement Points

I concur with the following Turing findings:

- **§NF-1 (Round count comparison)**: The "≈ 24+ AES diffusion layers" claim is indefensible. Turing's byte-dependency trace is correct: the serial cascade achieves full dependency but not algebraically bounded diffusion.
- **§2.2 (No block chaining)**: ECB-like behavior is a real concern. My NF-2 independently identified this.
- **§2.3 (No authentication)**: Confirmed. My NF-1 detailed cross-message block substitution as a zero-computation attack.
- **§3.3 (Boundary byte weakness)**: Byte 127 receiving only 3 S-box applications (1 per round) vs ~6 for interior bytes is a valid structural asymmetry.
- **§2.5 (Sliding-window overlap)**: The 1-byte overlap analysis is correct — the shared byte chains consecutive S-box lookups, creating exploitable structure IF the S-box is known.

### 5.2 Correction to Turing §2.1

Turing states: *"Each candidate S-box can be validated in O(1) using a known-plaintext pair."*

This is the core error. As demonstrated in §§1–2 above, validation requires O(2^127) mask seed search, not O(1). The cascade prevents polynomial-time extraction of the mask sequence from a P/C pair, even with the correct S-box.

### 5.3 Correction to Turing §3.2 (Decryption Symmetry)

Turing notes that the decrypt mask sequence is an arithmetic progression with negated step, identical in structure to the encrypt sequence. This is correct but has no cryptanalytic implication — the attacker doesn't observe the decrypt sequence, and the algebraic structure of the masks is already known from the PRNG definition.

### 5.4 Turing's Key Questions for Driscoll (§5, Q1–Q4) — Brief Responses

**Q1 (Known-plaintext minimum work):** O(2^254) with current techniques. The cascade hides intermediates.

**Q2 (Chosen-plaintext differential injection):** Differentials at one edge CAN be injected (mask cancels in XOR), but the cascade prevents clean observation at the other edge after 759 steps. The step-0 output difference propagates through 758 subsequent nonlinear operations before reaching C. No useful differential characteristic through the full cascade has been constructed.

**Q3 (Mode-of-operation exploitation):** Concrete attack: cross-message block substitution at position N (see my Phase 1 NF-1). Block N from ciphertext A can replace block N in ciphertext B if both use the same key (without nonce). The substituted block decrypts correctly because the PRNG state at position N is deterministic.

**Q4 (Boundary byte analysis):** Byte 127 is touched 3 times (once per round, always as the high byte of window [126,127]). Byte 0 is touched 6 times per round (forward pass step 0 + reverse pass step 0, × 3 rounds = 6). This 2:1 ratio suggests byte 127 has weaker mixing, but over 3 rounds the cascade likely compensates. Formal measurement requires the avalanche analysis Turing requested from Rejewski.

---

## 6. Summary Verdict

| Turing Claim | Verdict |
|---|---|
| Key decomposition to 2^128 | **REFUTED** — verification bottleneck is O(2^127), making total O(2^254) |
| S-box/mask independence is structural weakness | **CONFIRMED** — but exploitable only via side-channel, not pure cryptanalysis |
| Effective security is ~128 bits | **INCORRECT** — effective security is ~254 bits against known-plaintext attacks |
| S-box verifiable in O(1) with known P/C | **INCORRECT** — cascade prevents polynomial-time verification |
| Boundary byte asymmetry | **CONFIRMED** — byte 127 weaker than interior |
| No block chaining / no authentication | **CONFIRMED** — most practical real-world vulnerability |

**Bottom line:** The cipher's effective security against pure cryptanalytic attack is **O(2^254)**, not O(2^128). Turing correctly identified the key's structural independence but incorrectly assumed the S-box could be verified in polynomial time. The 759-step cascading S-box with overlapping windows is the cipher's primary defense — it prevents not only layer-peeling but also decomposition attacks by making the two key halves cryptanalytically inseparable despite being structurally independent.

---

*Report prepared by Driscoll, Attack Specialist. Cross-review of Turing Phase 1 report §3.1.*
