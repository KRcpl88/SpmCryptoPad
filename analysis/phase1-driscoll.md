# Phase 1: Driscoll - Attack Surface Assessment of cryptanalysis.md

**Analyst:** Driscoll (Attack Specialist)
**Date:** 2025-07-15
**Scope:** All attacks assume a full 256-bit key via `SetKeys()`. No password attacks. Single session, single key.

---

## 1. Accuracy Assessment

### Finding #1 - S-box State Space (2^127 vs 2^954,009): **ACCURATE**

The PRNG `m_prngSBox` has 64-bit state + 63-bit effective key (LSB forced to 1) = 127 bits of seed entropy. The permutation space of a 16-bit S-box is log₂(65536!) ≈ 954,009 bits. The claim that only an infinitesimal fraction of permutations are reachable is mathematically correct.

**Additional note:** The S-box generation uses a *naive* shuffle (swap each element with a uniformly random element from the full array), not proper Fisher-Yates (which swaps with elements from the shrinking tail). A single pass of naive shuffle produces a biased distribution. However, with 16 passes, convergence toward uniformity over the reachable 2^127 permutations is strong. This is a terminology inaccuracy in the document ("Fisher-Yates shuffled") but not a security concern given 16 passes.

### Finding #2 - Plaintext File-Size Leakage: **ACCURATE**

Not independently verified from file-format code, but consistent with the described architecture. Low severity is appropriate.

### Non-Finding #1 - Round Count Comparison: **INCOMPLETE / MISLEADING**

The claim that "3 SPM rounds = 6 full diffusion sweeps ≈ 24+ AES diffusion layers" conflates *diffusion* (bit-spreading) with *overall security*. The analysis is correct that the sliding-window cascade achieves full byte diffusion in a single directional pass. However:

- **Diffusion ≠ resistance to differential/linear cryptanalysis.** AES round counts are chosen for provable resistance to differential and linear attacks, not just diffusion.
- The document correctly notes that "resistance to differential and linear cryptanalysis at this round count is formally unknown," but this critical caveat is buried in recommendation text while the bold comparison to AES is in the main analysis. The framing implies equivalence where none has been demonstrated.
- The sliding-window structure may or may not provide strong resistance - it simply hasn't been analyzed using standard cryptanalytic methods.

**Verdict:** The diffusion claim is accurate. The security equivalence to "24+ AES layers" is unsupported and should be removed or heavily qualified.

### Non-Finding #2 - PRNG Not Independently Exploitable: **ACCURATE**

Correct that the Weyl PRNG's weakness (state recoverable from 8 consecutive 16-bit outputs) is masked by the key-dependent S-box. Mask values are consumed inside `S(block[k:k+2] XOR mask)`, making direct extraction infeasible without knowing S. This is a compounding factor, not a primary vector.

### Non-Finding #3 - Password Out of Scope: **ACCURATE**

Consistent with standing orders.

### Non-Finding #4 - Nonce Entropy 30–50 bits: **ACCURATE**

The range estimate and collision probability calculations are correct. Per standing orders, nonce analysis is secondary to core algorithm.

### Cipher Strengths Section: **PARTIALLY ACCURATE**

The description of the sliding-window cascade and per-round diffusion is technically correct. However, the claim that "key-dependent 16-bit S-box provides strong local nonlinearity" is stated without evidence. For a random 16-bit permutation, the expected maximum entry in the difference distribution table (DDT) is ~6–8 (out of 65536). This is indeed excellent nonlinearity - but the S-box is not drawn uniformly from permutation space; it's drawn from a 2^127 subset via a biased (naive) shuffle. The nonlinearity properties of this specific subset have not been characterized.

---

## 2. Attack Analysis (Full 256-bit Key)

### 2.1 Known-Plaintext Attacks (KPA)

**Setup:** Attacker has N plaintext-ciphertext block pairs (P_i, C_i), all under the same key. For block position 0 (first block of multiple messages), the mask sequence and S-box are identical across all encryptions.

**Analysis:**

Each block encryption applies 759 cascaded operations of the form `block[k:k+2] = S[block[k:k+2] XOR m_k]`. The attacker observes P (before all 759 operations) and C (after all 759 operations). The intermediate values after each step are unobservable.

With N known pairs at the same block position, the attacker builds a partial codebook of the fixed 128-byte → 128-byte permutation. Since the domain has 2^1024 elements, even 2^40 pairs covers a negligible fraction. The codebook itself reveals nothing about S or the masks without structural decomposition.

**Key insight - same-ciphertext collision:** If two different plaintexts P and P' at the same block position produce identical ciphertexts, this implies a collision in the encryption function, which is impossible (it's a permutation composed of permutations). So no collision-based analysis applies.

**Feasibility:** No known technique extracts S-box or mask information from known P/C pairs alone when the intermediate cascade states are hidden. The 759-step cascade with overlapping windows creates a deeply nested dependency that resists layer-peeling.

**Complexity:** No advantage over brute force. O(2^255).
**Data required:** N/A (attack does not improve with more data under current techniques).

### 2.2 Chosen-Plaintext Attacks (CPA)

**Setup:** Attacker chooses plaintexts and observes ciphertexts, all at block position 0 (same mask sequence).

**Attack 1 - Zero block:** Encrypting the all-zero 128-byte block. Step 0 computes `S[0x0000 XOR m_0] = S[m_0]`. This writes the S-box output for the unknown input `m_0` to bytes 0–1. Step 1 reads the modified byte 1 along with the original byte 2 (= 0x00). The cascade continues, so the final ciphertext is a deeply nested function of S and all 759 masks. **No useful information is directly extractable.**

**Attack 2 - Single-position variation (most interesting CPA):**

Choose 65536 plaintexts that differ only in bytes 0:1 (values 0x0000 through 0xFFFF), with bytes 2–127 fixed (e.g., all zero).

- Step 0 for plaintext with P[0:1] = x computes: `S[x XOR m_0]`, writing to bytes 0–1.
- Step 1 reads byte 1 (low byte of S[x XOR m_0]) concatenated with byte 2 (fixed = 0x00).
- **Critical observation:** If two inputs x and x' produce `S[x XOR m_0]` and `S[x' XOR m_0]` with the same low byte, then from step 1 onward the cascades are *identical* (since byte 2+ are all zero/fixed). The ciphertexts C and C' would differ only in byte 0.
- By grouping the 65536 ciphertexts by the equality of C[1:127], the attacker partitions the 65536 S-box outputs by their low byte - recovering the **low-byte equivalence classes** of S (modulo the unknown mask m_0).

**What this reveals:** The partition of 65536 inputs into 256 groups of ~256 elements each, corresponding to S-box outputs sharing a low byte. This is real structural information about S, but:
1. Only the low byte is recovered, not the full 16-bit output.
2. The partition is shifted by the unknown m_0.
3. Extending this to step 1 requires controlling the cascade, which is circular - you'd need to know the S-box to predict step 0's output.
4. Repeating for all 127 forward-pass positions is infeasible because the cascade means positions beyond 0 can't be independently varied.

**Attack 3 - Differential chosen-plaintext:**

Choose pairs (P, P XOR Δ) where Δ is nonzero only in bytes 0:1. The input difference at step 0 is `(x XOR m_0) XOR ((x XOR Δ[0:1]) XOR m_0) = Δ[0:1]` - the mask cancels! So the S-box input difference is always Δ[0:1] regardless of the unknown mask.

The output difference `S[x XOR m_0] XOR S[x XOR m_0 XOR Δ]` depends on the specific S-box and the absolute value of `x XOR m_0`. Collecting many such pairs for the same Δ gives the *differential profile* of S for that input difference - one row of the DDT.

However, the cascade complicates observation: the output difference at step 0 propagates through 758 subsequent steps. Observing the *final* ciphertext difference doesn't directly reveal the step-0 output difference.

**Feasibility:** The CPA attacks extract partial structural information about the S-box but do not lead to full key recovery. The cascade depth of 759 steps, with overlapping windows creating inter-step dependencies, prevents clean isolation of individual operations.

**Complexity:** Best CPA structural analysis: O(2^16) plaintexts to learn one partial equivalence class. Full S-box recovery via this technique: not achievable due to cascade depth. Key recovery: no advantage over brute force.
**Data required:** 2^16 chosen plaintexts for partial S-box partition (low byte of first position only).

### 2.3 Differential Cryptanalysis

**Standard approach:** Find input difference Δ_in that propagates to predictable output difference Δ_out with high probability through all rounds.

**Obstacles specific to this cipher:**

1. **Unknown S-box:** The S-box is key-dependent. Standard differential cryptanalysis requires pre-computing the DDT of the S-box. Without knowing S, the attacker cannot build the DDT and thus cannot construct differential characteristics.

2. **Sliding-window coupling:** Each step's output at position k affects the input of step k+1 (overlapping byte). A difference at position k creates a difference at position k+1 that depends on the actual values (not just differences). This means the difference propagation is *data-dependent*, not just difference-dependent, dramatically increasing the analysis complexity.

3. **Bidirectional cascade:** The forward pass propagates differences left-to-right; the reverse pass propagates right-to-left. After one round, any single-byte difference has spread to all 128 bytes. Multi-round differentials through this structure have exponentially many possible paths.

4. **Large S-box:** A 16-bit S-box has DDT size 65536 × 65536 = 2^32 entries. Even if the attacker knew S, analyzing all possible differential characteristics through 759 steps is computationally intractable.

**Theoretical bound:** For a truly random 16-bit permutation, the maximum differential probability is approximately p_max ≈ 6/65536 ≈ 2^{-13.4}. For a 3-round path through 759 S-box applications (even if only a fraction are "active"), the cumulative probability drops to well below 2^{-128}.

**Feasibility:** Infeasible. The combination of unknown S-box, sliding-window coupling, and bidirectional passes makes constructing useful differential characteristics practically impossible.

**Complexity:** No useful differential attack exists. Security level: O(2^255).
**Data required:** N/A.

### 2.4 Linear Cryptanalysis

**Standard approach:** Find linear approximations through S-box with high bias, chain them across rounds.

**Obstacles:**

1. **Unknown S-box:** The linear approximation table (LAT) is key-dependent and unknown. The LAT for a 16-bit S-box is 65536 × 65536 = 2^32 entries. Without S, no linear trails can be constructed.

2. **Mask-XOR interaction:** Each step applies `S(x XOR m_k)`. For linear cryptanalysis, we need: `α·(x XOR m_k) ⊕ β·S(x XOR m_k)` with high bias for fixed masks α, β. The XOR with m_k shifts the linear approximation bias depending on the mask value, complicating trail construction even if S were known.

3. **759 active S-boxes:** Every S-box application is "active" (receives a unique mask). For a random 16-bit permutation, the maximum linear bias is approximately 2^{-8}. Chaining even 10 such operations drives the cumulative bias below 2^{-80}.

**Feasibility:** Infeasible. Same barriers as differential analysis, compounded by the large LAT and all-active S-box structure.

**Complexity:** No useful linear attack exists. Security level: O(2^255).
**Data required:** N/A.

### 2.5 Slide Attacks

**Setup:** Slide attacks exploit periodicity in the round key schedule. If two blocks are encrypted with identical round keys (mask sequences), their encryptions are identical functions.

**PRNG period analysis:** The Weyl PRNG has state period 2^64 (odd key modulo 2^64). Each state yields 4 × 16-bit outputs. Total output period: ~4 × 2^64 ≈ 2^66 values. With 759 masks per block, the mask sequence repeats every:

> 2^66 / 759 ≈ 2^56.4 blocks ≈ 2^63.4 bytes

Two blocks separated by exactly 2^56.4 positions in the ciphertext would use identical mask sequences and thus encrypt identically.

**Feasibility:** Requires the attacker to have a ciphertext of length ≥ 2^63.4 bytes (~9.2 exabytes). This is astronomically impractical.

**Additional nuance:** Even if mask sequences repeat, the attacker would need to *know* which blocks are slides of each other. Without knowing the plaintext, identifying slide pairs in the ciphertext requires additional information.

**Complexity:** O(2^56) blocks of data needed to observe one slide pair. Completely impractical.
**Data required:** ~2^56.4 blocks (2^63.4 bytes).

### 2.6 Meet-in-the-Middle (MITM)

**Standard approach:** Split the cipher into two halves, enumerate keys for each half independently, and match intermediate states.

**Analysis:**

The cipher has two independent key halves:
- Bytes 0–15 → `m_prngSBox` → S-box generation (127 effective bits)
- Bytes 16–31 → `m_prngMask` → mask stream (127 effective bits)

For a MITM to work, we'd need a split point where one half of the key determines the transformation from plaintext to some intermediate state, and the other half determines the transformation from that state to ciphertext.

**Problem:** Every one of the 759 S-box application steps uses *both* the S-box (determined by key bytes 0–15) and a mask (determined by key bytes 16–31) simultaneously: `S[block[k:k+2] XOR mask_k]`. There is no point in the cipher where only one key half is active.

**Alternative MITM on intermediate rounds:** Split at the boundary between round 1 and round 2. The intermediate state is 128 bytes = 1024 bits. Even with known plaintext:
- Forward: compute from P through round 1 → requires knowing *both* S-box and masks for round 1.
- Backward: compute from C through rounds 2–3 → requires knowing *both* S-box and masks for rounds 2–3.

Since the S-box is shared and the masks come from the same PRNG stream, there's no independent split.

**Feasibility:** Infeasible. The S-box and mask stream are entangled in every operation. No natural MITM split exists.

**Complexity:** No advantage. O(2^255).
**Data required:** N/A.

### 2.7 Algebraic Attacks

**Approach:** Express the cipher as a system of Boolean equations and solve (e.g., via SAT solvers, Gröbner bases, or XL algorithm).

**System size:**
- Input variables: 1024 bits (128-byte plaintext)
- Key variables: 256 bits (but only 254 effective due to two forced-odd constraints)
- S-box: 65536-entry 16-bit permutation → representable as 16-bit to 16-bit Boolean function with degree ≤ 16 in ANF.
- Mask XOR: linear operation.
- Each step: `S(x XOR m)` where x is 16 bits from the block state and m is a 16-bit mask.
- Total steps: 759 S-box applications per block, each consuming 2 overlapping bytes.

**Equation count:** Each step produces 16 output bits as nonlinear functions of 16 input bits + 16 mask bits. For 759 steps with cascading dependencies, the resulting system has:
- ~759 × 16 = 12,144 intermediate variables
- ~759 × 16 = 12,144 nonlinear equations (each of degree ≤ 16)
- Plus 127 × 16 = 2,032 bits of mask state derived from the PRNG (which is itself a simple function of 127 key bits)

The system is massively over-determined if we have multiple known P/C pairs, but the nonlinearity (degree-16 S-box) makes standard algebraic solvers impractical. Modern SAT solvers and Gröbner basis methods struggle with systems of this scale and nonlinearity.

**Key-dependent S-box complication:** The S-box itself is derived from key bytes 0–15 through 1,048,576 PRNG-based swaps. Expressing this as equations adds enormous complexity.

**Feasibility:** The algebraic system is too large and too nonlinear for current solvers. No known algebraic technique provides an advantage over brute force.

**Complexity:** No advantage. O(2^255).
**Data required:** 1 known P/C pair (but the solver can't handle it regardless).

### 2.8 Codebook / Dictionary Attacks

**Setup:** At a fixed block position (e.g., block 0 with same key and no nonce), encryption is a fixed permutation on 128-byte blocks. An attacker who collects enough pairs builds a lookup table.

**Analysis:** The block space is 2^1024. No practical amount of data covers a meaningful fraction. Even for 1-byte variations at a fixed position, the attacker needs 256 pairs to fully characterize one byte's behavior - but the cascade means one byte's behavior depends on all other bytes.

**Feasibility:** Completely impractical. The 128-byte block size makes codebook attacks irrelevant.

**Complexity:** O(2^1024) for full codebook. Even partial: O(2^16) for one position.
**Data required:** 2^1024 blocks (full codebook), impractical by any measure.

---

## 3. Strongest Attack Identified

### Chosen-Plaintext S-box Partition Recovery (Step-0 Low-Byte Classes)

**Significance: Informational / theoretical only. Does NOT lead to key recovery.**

**Step-by-step:**

1. **Choose plaintexts:** Generate 65536 plaintexts, each 128 bytes. All have bytes 2–127 set to zero. Bytes 0–1 vary systematically from 0x0000 to 0xFFFF.

2. **Encrypt:** Submit all 65536 plaintexts for encryption at block position 0 (all use the same mask sequence and S-box).

3. **Observe ciphertexts:** For each of the 65536 ciphertexts, extract bytes 1–127 (ignoring byte 0).

4. **Group by tail equality:** Partition the 65536 inputs into groups where C[1:127] are identical. Two inputs x, x' land in the same group if and only if the low byte of S[x XOR m_0] equals the low byte of S[x' XOR m_0].

5. **Result:** ~256 groups of ~256 inputs each. This reveals the **low-byte equivalence structure** of the S-box, shifted by the unknown mask m_0.

**What the attacker learns:**
- Partial structural information about S: which inputs (modulo unknown shift m_0) map to S-box outputs sharing a low byte.
- This is equivalent to learning one byte of S's output for all inputs, up to an unknown input permutation (XOR with m_0) and an unknown output byte position.

**What the attacker does NOT learn:**
- The value of m_0.
- The full 16-bit S-box outputs.
- Any mask values beyond m_0's influence.
- Anything about S-box behavior at positions beyond step 0.
- The key.

**Why it doesn't extend:**
- Step 1's input depends on step 0's output (the overlapping byte). To isolate step 1, you'd need to control the input to step 1, which requires knowing S[x XOR m_0]'s low byte - creating a circular dependency.
- The cascade prevents the attacker from independently probing any S-box position beyond the first.

**Complexity:** O(2^16) chosen plaintexts, O(2^16) computation to partition.
**Security impact:** Negligible. Does not reduce the effective key space.

---

## 4. Attack Complexity Summary Table

| Attack Class | Complexity (Key Recovery) | Data Required | Feasible? | Notes |
|---|---|---|---|---|
| **Brute force** | O(2^255) | 1 known P/C pair | No (impractical) | Baseline. Two forced-odd keys reduce 2^256 to 2^254, but keys are independent 127-bit values: enumerate over 2^127 × 2^127 = 2^254 |
| **Known-plaintext** | O(2^255) | Any N | No | No technique reduces below brute force; cascade hides intermediates |
| **Chosen-plaintext (S-box partition)** | O(2^16) partial info / O(2^255) key recovery | 2^16 chosen blocks | Partial info: Yes. Key recovery: No | Recovers low-byte equivalence classes of S at position 0 only |
| **Differential** | O(2^255) | N/A | No | Unknown S-box + sliding-window coupling blocks characteristic construction |
| **Linear** | O(2^255) | N/A | No | Unknown LAT + all-active S-boxes |
| **Slide** | O(2^56) blocks to find pair | 2^63 bytes | No | PRNG period ≈ 2^66 outputs; requires exabytes of data |
| **Meet-in-the-middle** | O(2^255) | 1 known P/C pair | No | S-box and masks entangled at every step; no clean split |
| **Algebraic** | O(2^255) | 1 known P/C pair | No | System of ~12K degree-16 equations; beyond solver capability |
| **Codebook** | O(2^1024) | 2^1024 blocks | No | Block space too large |
| **Ciphertext manipulation** | O(1) | 1 ciphertext | **Yes** | No authentication - blocks can be reordered, truncated, or modified undetectably |

---

## 5. New Findings

### NF-1: Ciphertext Malleability - Most Practical Real-World Attack (MEDIUM-HIGH)

The document notes "no ciphertext authentication" in passing but does not fully explore the consequences. Since there is no MAC, HMAC, or authenticated encryption mode:

1. **Block reordering:** An attacker can swap ciphertext blocks. Each block decrypts independently given the PRNG state, but the PRNG state for decryption is computed sequentially. Swapping blocks would cause incorrect PRNG states for decryption, producing garbage - which means the attack is *denial-of-service* rather than meaningful content manipulation.

2. **Block substitution across messages:** If the attacker has two ciphertexts encrypted with the same key (and no nonce), they can substitute block N from message A into message B at position N. The PRNG state at position N is deterministic (depends only on the key and N), so the substituted block would decrypt correctly. **This enables cut-and-paste attacks across same-key messages.**

3. **Truncation:** Removing trailing blocks from a ciphertext produces a valid shorter ciphertext. The recipient cannot detect the truncation.

4. **Bit-flipping:** Modifying ciphertext bits produces garbage on decryption (unlike CTR mode, where bit-flips pass through). But the recipient has no way to distinguish a corrupted ciphertext from a legitimately encrypted different message.

**Impact:** In a scenario where the same 256-bit key is reused across messages without a nonce (or with a predictable nonce), cross-message block substitution is a realistic, zero-computation attack.

### NF-2: ECB-Mode Behavior Without Nonce (LOW under standing orders)

Without nonce mixing into the key material, block position N across different messages encrypted with the same key uses the same mask sequence. This means:
- Identical plaintext blocks at the same position produce identical ciphertext blocks (classic ECB property).
- An observer can detect when two messages share a block at the same position.
- Cross-position comparison is safe (different mask sequences), but same-position comparison leaks equality.

This is mitigated if a unique nonce is mixed into the key before each encryption, which the application appears to do via `GenNonce`. But the core algorithm has no built-in nonce mechanism.

### NF-3: Naive Shuffle Bias in S-box Generation (LOW)

The `PermuteSbox()` function uses a naive shuffle (swap element i with a uniformly random element from the full array) rather than the correct Fisher-Yates/Knuth shuffle (swap element i with a random element from positions i to N-1). A single pass of naive shuffle produces a biased permutation distribution. However, 16 passes are applied, which strongly mitigates the bias. The resulting permutation distribution is not provably uniform over the 2^127 reachable permutations, but the deviation is cryptographically negligible after 16 passes.

**Impact:** Theoretical. Does not enable any practical attack. But the document incorrectly calls this "Fisher-Yates shuffled."

### NF-4: S-box / Mask Key Independence Enables Partitioned Search (INFORMATIONAL)

The 256-bit key splits cleanly into two independent 128-bit halves:
- Bytes 0–15 → S-box PRNG (127 effective bits, determines S-box)
- Bytes 16–31 → Mask PRNG (127 effective bits, determines mask stream)

While this doesn't enable MITM (both halves are used in every step), it does mean an attacker who somehow learns the S-box independently reduces the remaining search space from 2^254 to 2^127 - a dramatic reduction.

**Scenario:** If a side-channel attack leaks S-box entries (e.g., cache-timing attacks on the 128 KB S-box table during lookup), the attacker could reconstruct S and then brute-force only the mask PRNG (2^127 operations). This is not a cryptanalytic attack per se, but the key architecture's clean split means that partial key compromise has outsized impact.

### NF-5: Forward-Pass Decryption Ordering Reveals Design Constraint (INFORMATIONAL)

The decrypt routine (`s_FillDecryptMasks`) pre-generates all 759 masks and replays them in reverse. This means the full mask array (759 × 2 = 1,518 bytes) must be stored in memory during decryption. If an attacker can read process memory (e.g., cold-boot attack, memory dump), all mask values for the current block are exposed simultaneously, enabling trivial decryption of that block.

This is not unique to this cipher (AES round keys are also in memory), but the mask array is significantly larger (1,518 bytes vs. 176 bytes for AES-128 round keys).

---

## 6. Key Questions for Other Agents

1. **For the S-box Analyst:** What are the actual differential uniformity and linearity metrics of the S-box instances generated by this PRNG+naive-shuffle combination? Can you compute the DDT and LAT for a sample of S-boxes and report the maximum entry and distribution? This would confirm or refute the assumption that the key-dependent S-box behaves like a random permutation.

2. **For the PRNG Analyst:** The Weyl PRNG outputs 16-bit values by slicing a 64-bit state. Adjacent slices within the same state are *correlated* (they're bytes of the same 64-bit integer). Does this correlation between consecutive mask values (e.g., masks at positions 0,1,2,3 all come from one state) create exploitable structure in the cascade? Specifically: masks m_{4k}, m_{4k+1}, m_{4k+2}, m_{4k+3} are the four 16-bit chunks of a single 64-bit state value. An attacker who hypothesizes one chunk constrains the other three.

3. **For the Diffusion Analyst:** The document claims full block diffusion per round. Can you empirically measure the avalanche effect? Specifically: encrypt 1000 random blocks, flip one bit, re-encrypt, and measure the Hamming distance of the ciphertext. Report the mean and standard deviation after 1, 2, and 3 rounds. Ideal is mean = 512 bits (half of 1024) with low variance.

4. **For the Implementation Analyst:** The `s_EncryptBlock` function signature accepts `pPrngSBox` but in `NoPermutation` mode it is never used. Does the compiler optimize this away, or does the unused PRNG state still advance? Verify that `m_prngSBox` state does NOT change during encryption in `NoPermutation` mode - if it does, the S-box PRNG state after encrypting N blocks would differ from the fresh state, which matters for multi-block analysis.

5. **For the Protocol Analyst:** How is the nonce mixed into the key? If the nonce is concatenated or XORed with the password-derived key before `SetKeys()`, the effective key space for the S-box and mask PRNGs may be smaller than 2^127 each (depending on how nonce bits distribute across the two PRNG key halves). This directly impacts the brute-force complexity.

---

*End of Phase 1 Attack Assessment - Driscoll*
