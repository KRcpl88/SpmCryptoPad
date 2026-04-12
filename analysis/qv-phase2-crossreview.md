# QV Phase 2 - Cross-Review and Consensus Report

**Date:** 2025-07-15
**Coordinator:** Phase 2 Cross-Review Panel
**Cross-Review Assignments:**
- Turing reviews Driscoll's findings (Q27, Q28, cross-cutting omissions)
- Rejewski reviews Turing's findings (Q1–Q3, Q9–Q12, Q20–Q22)
- Friedman reviews Rejewski's findings (Q4–Q8, Q14–Q18)
- Driscoll reviews Friedman's findings (Q19, Q23–Q26, Q29–Q30)

**Scoring:** +10 points for each successful refutation of a Phase 1 weakness finding.

---

## Executive Summary

Of 30 Phase 1 findings across four analysts, this cross-review:
- **UPHELD** 16 findings (the weaknesses are valid)
- **PARTIALLY REFUTED** 11 findings (weaknesses have merit but are overstated)
- **REFUTED** 3 findings (+30 points for successful refutations)

The key disputes are resolved as follows:

1. **Hybrid Attack (Turing Q12, Driscoll §4):** UPHELD as a valid attack strategy, but PARTIALLY REFUTED as a practical concern - the classical outer loop takes ~10^{26} years, making the hybrid no more "practical" than full Grover. The paper should discuss it for completeness, but it does not invalidate the qubit-advantage narrative in any operationally meaningful sense.

2. **AES Gate Cost (Rejewski Q6–Q8):** PARTIALLY REFUTED - the paper's "2^{15}" figure is defensible as *cipher-evaluation-only* gates (not full Grover iteration gates). Grassl's 2^{27.5} includes the full Grover iteration overhead (oracle + diffusion + ancilla management). The true cipher-only figure is likely ~2^{17}–2^{19}, not 2^{15} but not 2^{27.5} either. The "2 million×" headline is still overstated, but by ~2^{2}–2^{4}, not 2^{12.5}.

3. **QRAM Model (Rejewski Q14–Q17):** PARTIALLY REFUTED - bucket-brigade QRAM is not viable for cryptanalytic applications per community consensus. The realistic model is explicit circuits, which supports the paper's general argument that SPM's S-box is expensive to evaluate quantumly. However, the paper should acknowledge the model choice.

4. **Algebraic Degree (Driscoll Q28):** UPHELD - the paper is wrong (should be 15, not 65,535). But PARTIALLY REFUTED in impact - degree 15 is still near-maximal and the qualitative argument holds.

5. **Citation Errors (Rejewski Q5, Friedman Q24):** Rejewski's Q5 finding is PARTIALLY REFUTED - "Zou et al. 2025" and "Huang & Sun 2025" appear to be real 2025 publications (newer than the 2020/2022 originals Rejewski identified). Friedman's Q24 is PARTIALLY REFUTED - the paper does not cite "2010" explicitly; the Kuwakado & Morii reference is to their 2010 Feistel paper, which is a valid (though imprecise) reference.

---

## Detailed Cross-Review

---

### TURING REVIEWS DRISCOLL'S FINDINGS

#### D-Q27: AES S-box "23 quadratic equations" (Murphy & Robshaw attribution)

**Phase 1 Verdict (Driscoll):** MISLEADING - wrong attribution, bi-affine vs. quadratic distinction omitted.

**Cross-Review Verdict: PARTIALLY REFUTED**

Driscoll is correct that the 23-equation result originates with Courtois & Pieprzyk 2002, not Murphy & Robshaw 2002. However, the distinction between "bi-affine" and "quadratic" is less consequential than Driscoll claims:

1. **Bi-affine equations ARE quadratic equations.** A bi-affine equation in input bits x_i and output bits y_j has terms like x_i·y_j, which is degree 2 (quadratic) in the combined variable space. Calling them "quadratic" is technically correct, even if "bi-affine" is more precise.

2. **Murphy & Robshaw 2002 did discuss the 23-equation characterization** and built upon it. While they did not originate the count, attributing it to them is imprecise but not fabricated - it's a secondary citation, common in survey-style writing.

3. **The paper's qualitative point stands:** AES's S-box has a compact, low-degree algebraic description that enables algebraic attack strategies. Whether there are 23 bi-affine or 39 general quadratic equations doesn't change the argument.

**Correction needed:** Attribution should be to Courtois & Pieprzyk 2002. The "bi-affine" qualifier is a nice-to-have clarification. The paper's argument is not materially affected.

**Refutation points: 0** (finding has merit, though overstated)

---

#### D-Q28: SPM algebraic degree ~2^{16}−1 (should be 15)

**Phase 1 Verdict (Driscoll):** FALSE - confuses univariate GF(2^16) with multivariate ANF degree.

**Cross-Review Verdict: UPHELD**

Driscoll is unambiguously correct:

1. The multivariate ANF degree of any n-bit permutation is bounded by n−1. For n=16, the maximum is **15**, not 65,535.
2. The univariate degree over GF(2^16) is cryptographically irrelevant for algebraic attack resistance.
3. The paper states "expected algebraic degree ~2^{16} − 1" in both `cryptanalysis.md` (line 304) and `SpmbcVAes.md` (line 115, 230). This is a clear mathematical error.

**However**, Driscoll himself notes that degree 15 is still near-maximal for a 16-bit permutation, and significantly higher than AES's degree 7 for its 8-bit S-box. The qualitative argument (SPM's S-box resists algebraic attacks better than AES's) survives - but the quantitative claim is wrong by a factor of 4,369.

**Correction needed:** Replace "~2^{16} − 1" with "15 (the maximum for any 16-bit permutation)" everywhere. The qualitative argument can be preserved.

**Refutation points: 0** (finding is correct)

---

#### D-Cross: Multi-target Grover omission

**Phase 1 Verdict (Driscoll):** UNSUPPORTED omission - should have been discussed.

**Cross-Review Verdict: REFUTED (+10 points)**

Multi-target Grover search reduces key search from O(2^{n/2}) to O(2^{n/2}/√T) when T target keys exist. But for block cipher key recovery:

1. **There is exactly one correct key** for a given plaintext-ciphertext pair. Multi-target search is irrelevant for single-key recovery.
2. **Multiple known P/C pairs help filter candidates** (reducing false positives), but this is already implicitly handled by the oracle's correctness check - it doesn't change the Grover iteration count.
3. **Multi-instance attacks** (attacking many users simultaneously) are a valid theoretical concern but equally applicable to AES and do not differentially affect the SPM-vs-AES comparison. The paper is comparing the two ciphers, not claiming absolute security.
4. The 1024-bit block size actually *helps* SPM in multi-target scenarios: larger blocks mean fewer false-positive key candidates per P/C pair.

The omission is defensible. Multi-target Grover does not provide a meaningful attack vector that the paper should have addressed in a comparative analysis.

**Refutation points: +10**

---

#### D-Cross: Hybrid classical-quantum attack omission

**Phase 1 Verdict (Driscoll):** MISLEADING - paper ignores a viable ~320-qubit attack.

**Cross-Review Verdict: PARTIALLY REFUTED**

The hybrid attack is a **valid theoretical construction** - Driscoll and Turing are both correct that it exists and that the paper should discuss it. However, describing it as "viable" or "practical" requires scrutiny:

**The hybrid attack's classical outer loop is astronomically infeasible:**
- 2^{127} classical iterations, each requiring ~2^{20} operations for S-box generation
- At 10^9 operations/second: 2^{127} × 2^{20} / 10^9 ≈ 2^{117} seconds ≈ 5 × 10^{26} years
- This is ~3.6 × 10^{16} times the age of the universe
- Even with 2^{30} classical processors (~1 billion): still ~5 × 10^{17} years

**The total work comparison:**
- Hybrid: O(2^{190.5}) total operations (Driscoll's estimate) or O(2^{216.5}) (Turing's)
- Full Grover: O(2^{163})
- AES Grover: O(2^{143})

The hybrid attack trades qubits for dramatically more total work - so much more that it is less practical than full Grover, which is itself completely impractical. Calling it a "viable lower-qubit attack" is technically accurate but misleading about practical implications.

**What the paper SHOULD do:** Acknowledge the hybrid attack exists and honestly state that it reduces qubits to ~3,000–5,000 at the cost of dramatically more total work (O(2^{190+})). This is good scientific practice. But claiming the hybrid "demolishes the qubit-advantage narrative" (Turing) overstates the case - both the hybrid and full Grover are so far beyond feasibility that the distinction is academic.

**The finding is partially refuted because:**
- The omission is a legitimate criticism (the paper should discuss it)
- But the characterization as "viable" and "demolishing" the qubit narrative is overstated
- The qubit comparison remains relevant for engineering-timeline projections (when will N qubits exist?)

**Refutation points: 0** (finding has real merit, but its impact is overstated)

---

#### D-Cross: Bernstein cost model / MAXDEPTH omission

**Phase 1 Verdict (Driscoll):** UNSUPPORTED omission - changes the narrative.

**Cross-Review Verdict: PARTIALLY REFUTED**

Driscoll is correct that MAXDEPTH and DW-cost are important metrics the paper should discuss. However:

1. **MAXDEPTH constraints actually HELP SPM's case.** SPM's deeper oracle circuit means attackers hit depth limits faster, requiring more parallel instances. Under MAXDEPTH = 2^{96}, SPM's attackers need more parallelism than AES's attackers - strengthening, not weakening, the paper's argument.

2. **DW-cost preserves the ratio.** If both ciphers are analyzed under DW-cost, SPM's deeper oracle × wider qubit requirement gives it a larger DW-cost per iteration. The ratio may shift somewhat, but SPM remains more expensive.

3. **The omission is a missed opportunity, not an error.** Including MAXDEPTH analysis would strengthen the paper's claims, not undermine them. Driscoll acknowledges this ("it reinforces the point") but still scores it as a weakness.

The finding is partially refuted: the omission is real but does not "change the narrative" as claimed - it would actually strengthen it.

**Refutation points: 0** (omission is real, but impact assessment is wrong)

---

#### D-Cross: "Equal theoretical, dramatically different practical" framing

**Phase 1 Verdict (Driscoll):** MISLEADING - internally incoherent framing.

**Cross-Review Verdict: PARTIALLY REFUTED**

Driscoll argues the paper's distinction between "theoretical" (oracle-call count) and "practical" (total gate cost) security is incoherent. However:

1. **The distinction is actually standard in the quantum cryptanalysis literature.** NIST's security categories are defined by oracle-call complexity (Category 1 = 2^{128} for AES-128, etc.), while the practical cost of each oracle call is a separate engineering question. The paper follows this convention.

2. **"Theoretical" ≈ information-theoretic/asymptotic; "practical" ≈ concrete cost.** This is a reasonable and common distinction. AES-256 and SPM-256 have ~equal information-theoretic security under Grover (both ~127–128 bits). The concrete computational cost differs dramatically. This framing is defensible.

3. **Where Driscoll has a point:** The paper could be clearer about what it means. "Practical" in cryptography usually means "feasible with real hardware," and neither attack is practical in that sense. Better phrasing: "concrete quantum computational cost" rather than "practical security."

**Refutation points: 0** (finding has some merit in wording, but the underlying distinction is standard)

---

#### D-Cross: Qubit count as security metric

**Phase 1 Verdict (Driscoll):** MISLEADING - engineering constraint, not security parameter.

**Cross-Review Verdict: PARTIALLY REFUTED**

Driscoll argues qubits are an engineering constraint, not a security metric. This is partially correct but:

1. **Qubit count IS a meaningful security consideration** in the quantum era. NIST's evaluation framework considers both computational cost AND hardware requirements. A cipher requiring 2.1M logical qubits is meaningfully harder to attack than one requiring 320, even holding total work constant - because the attacker must build and maintain a coherent system 6,500× larger.

2. **The hybrid attack does NOT "collapse the ratio entirely."** As analyzed above, the hybrid is itself astronomically infeasible (10^{26} years classical work). The qubit advantage under full Grover remains a valid metric for comparing the two ciphers under the same attack strategy.

3. **Moore's Law for qubits is speculative.** Driscoll's argument that "IBM targets 100K+ qubits by 2033" is about *physical* qubits, not logical qubits. With ~1,000–10,000 physical qubits per logical qubit, IBM's 2033 roadmap gives ~10–100 logical qubits - nowhere near either 320 or 2.1M.

4. **However**, Driscoll is right that total computational cost is the more fundamental metric. The paper over-emphasizes qubits relative to total gate count.

**Refutation points: 0** (finding has partial merit)

---

#### D-Cross: Error correction overhead (valid concern, ratio constant)

**Phase 1 Verdict (Driscoll):** Valid concern, 0 points claimed.

**Cross-Review Verdict: UPHELD (no change needed - Driscoll correctly assessed this as 0 points)**

No refutation applicable.

---

### REJEWSKI REVIEWS TURING'S FINDINGS

#### T-Q1: Grover reduces to O(2^{n/2}) - omits nuances

**Phase 1 Verdict (Turing):** MISLEADING - omits π/4 constant, multi-target, parallel Grover, success probability.

**Cross-Review Verdict: PARTIALLY REFUTED**

1. The π/4 constant is absorbed into O(·) notation. The paper uses O(·) notation consistently. Faulting it for not stating the exact constant while using O(·) is contradictory.
2. Multi-target and parallel Grover apply equally to AES and SPM - they don't affect the comparative analysis.
3. Success probability ≈ 1 − 1/N is so close to 1 for N = 2^{254} that mentioning it adds nothing.
4. The parallel Grover penalty (S² processors for S× speedup) is a valid nuance but affects both ciphers equally.

The paper is a comparative analysis, not a quantum computing textbook. These omissions don't affect the SPM-vs-AES comparison.

**Refutation points: 0** (finding has some merit but is pedantic for a comparative paper)

---

#### T-Q2: Total cost = O(2^{n/2}) × C_oracle - non-standard metric

**Phase 1 Verdict (Turing):** MISLEADING - DW-cost is the standard; cherry-picks width-optimized AES vs. inflated SPM.

**Cross-Review Verdict: PARTIALLY REFUTED**

1. Total gate count is a valid (if incomplete) metric. DW-cost is preferred but total gate count is widely used.
2. The "cherry-picking" allegation (width-optimized AES vs. inflated SPM) is a fair point but partially addressed by the paper's consistent use of the same methodology for both ciphers.
3. DW-cost analysis would actually favor SPM (deeper oracle + wider qubits = larger DW-cost for SPM's attacker), so the omission hurts the paper's case, not helps it.

**Refutation points: 0** (valid concern about metric choice, though DW-cost would strengthen the paper)

---

#### T-Q3: Oracle cost "often overlooked" is a straw man

**Phase 1 Verdict (Turing):** FALSE - oracle cost is a central concern in the field.

**Cross-Review Verdict: UPHELD**

Turing is correct. The paper's claim that oracle cost is "often overlooked in theoretical analyses" is factually wrong. The entire subfield of quantum symmetric cryptanalysis (Grassl 2016, Jaques 2020, NIST PQC process) is specifically about oracle costs. The paper references these very works, undermining its own straw-man claim.

However, looking at the actual paper text (line 222, 271), the paper says "this metric treats oracle calls as unit cost, which profoundly understates SPM's advantage" - which is a statement about the *Grover halving metric* (counting oracle calls only), not about the field in general. The paper's phrasing in the executive summary ("often overlooked") is indeed overstated, but the body text is more careful.

**Refutation points: 0** (the executive summary's phrasing is a valid criticism)

---

#### T-Q9: S-box requires 1,048,576 qubits - ignores QRAM/QROM alternatives

**Phase 1 Verdict (Turing):** MISLEADING - ignores QRAM, QROM, in-place computation.

**Cross-Review Verdict: PARTIALLY REFUTED**

Turing's alternatives deserve scrutiny:

1. **Bucket-brigade QRAM:** As Rejewski himself notes (Q14), the community consensus for Grover-based symmetric cryptanalysis is *explicit circuits, not QRAM*. No published Grover-on-AES paper uses QRAM. Proposing QRAM for SPM while the AES literature doesn't use it is an inconsistent comparison.

2. **QROM (O(√N) qubits):** The CSWAP-QROM approach cited by Turing requires O(√N) qubits but O(N) gates per lookup - so you save qubits but pay in gates. For SPM: O(256) qubits but O(65,536) gates per lookup × 759 lookups = O(2^{26}) gates, which matches the paper's cascade cost estimate. The qubit savings is real but the gate cost doesn't change.

3. **In-place computation:** This is the hybrid attack argument. Computing the S-box on-the-fly from the PRNG is exactly what the paper's full-Grover analysis assumes - and it costs O(2^{36}) gates. Computing it classically and hardwiring is the hybrid attack.

4. **The critical distinction Turing misses:** AES's S-box can be computed with ~100 qubits because GF(2^8) inversion has a compact algebraic circuit. SPM's S-box is a PRNG-driven shuffle - there is no compact algebraic circuit for a random permutation. The only known way to implement it quantumly IS the expensive PRNG simulation.

The paper's estimate is conservative but not unreasonable given the explicit-circuit model used for all published quantum symmetric cryptanalysis.

**Refutation points: 0** (finding has some merit, but the alternatives are less viable than presented)

---

#### T-Q10: Reverse S-box requires additional 1,048,576 qubits

**Phase 1 Verdict (Turing):** FALSE - uncomputation makes reverse S-box free.

**Cross-Review Verdict: UPHELD**

Turing is correct. In reversible/quantum computation:
- The inverse of any unitary is obtained by running the circuit in reverse (adjoint/dagger).
- No separate storage for the inverse S-box is needed.
- This is standard practice in all published quantum cipher circuits (Grassl 2016, Jaques 2020).

The paper's allocation of 1,048,576 qubits for the reverse S-box is an error that inflates the total by ~2×.

**Correction needed:** Remove the reverse S-box entry from the qubit table. Total drops from ~2.1M to ~1.05M.

**Refutation points: 0** (finding is correct)

---

#### T-Q11: Total ~2.1M qubits

**Phase 1 Verdict (Turing):** MISLEADING - unreliable due to Q9 and Q10 errors.

**Cross-Review Verdict: PARTIALLY REFUTED**

The finding depends on Q9 and Q10:
- Q10 (reverse S-box) is UPHELD → drops total to ~1.05M
- Q9 (QRAM alternatives) is PARTIALLY REFUTED → the 1.05M figure for the forward S-box table is reasonable under explicit-circuit assumptions

Turing's estimate of "3,500–5,000 qubits" relies on QROM techniques that are not used in any published Grover-on-cipher paper. The corrected figure is ~1.05M (removing only the reverse S-box), not 3,500.

**Correction needed:** Total should be ~1.05M, not 2.1M. But Turing's alternative of ~3,500 is too aggressive.

**Refutation points: 0** (finding has partial merit - the 2× inflation from Q10 is real)

---

#### T-Q12: Hybrid attack - paper's most critical error

**Phase 1 Verdict (Turing):** FALSE - hybrid attack reduces qubits to ~3,000–5,000.

**Cross-Review Verdict: PARTIALLY REFUTED**

The hybrid attack is valid as a theoretical construction (see Driscoll cross-review above). However:

1. **Turing's cost estimate is O(2^{216.5})**, which is 2^{53.5} times MORE work than full Grover. This is ~10^{16} times harder.

2. **The classical outer loop (2^{127} iterations)** alone requires ~10^{26} years even at 10^9 ops/sec. This makes the hybrid **less practical** than full Grover in every sense except qubit count.

3. **Turing's claim that "a machine capable of attacking AES-256 could also attack SPM-256" is misleading.** Yes, the same *quantum hardware* suffices for the inner loop, but you also need a classical computer running for 10^{26} years. The hybrid attack is not "feasible" by any standard.

4. **The paper's omission is still a weakness** - it should discuss and dismiss the hybrid attack to demonstrate awareness. But the claim that this is the paper's "most critical error" (Turing) and that it "demolishes the qubit narrative" is overstated.

**Refutation points: 0** (the omission is real; the impact assessment is overstated)

---

#### T-Q20: AES machine "entirely inadequate" for SPM

**Phase 1 Verdict (Turing):** FALSE - hybrid attack shows same quantum hardware suffices.

**Cross-Review Verdict: PARTIALLY REFUTED**

Under the hybrid attack, the same quantum hardware (qubits) suffices - but paired with 10^{26} years of classical computation. Saying the AES machine is "entirely inadequate" is technically wrong (it's the right *quantum* hardware), but saying it "suffices" is equally misleading (you need an absurd amount of classical computation on top).

The paper's claim would be more precise as: "A quantum computer capable of attacking AES-256 via full Grover would need to be ~3,300× larger in qubit count to attack SPM-256 via full Grover. A hybrid attack can use the same qubit count but requires O(2^{190+}) total work, far exceeding the full Grover cost."

**Refutation points: 0** (finding has merit but overstates practical implications)

---

#### T-Q21: "Each doubling quadruples qubit requirement"

**Phase 1 Verdict (Turing):** FALSE - mathematical error in scaling claim.

**Cross-Review Verdict: UPHELD**

Turing's math is correct:
- Q(b) = b × 2^b
- Q(b+1)/Q(b) = 2(b+1)/b → approaches 2, not 4
- For the 8→16 jump: ratio = 512×, not 4^8 = 65,536×

The paper's claim that "each additional bit quadruples the quantum register size" is mathematically false. The correct scaling is approximately 2× per additional bit for large b.

**Correction needed:** Fix the scaling claim. State the actual 512× ratio for the 8→16 jump.

**Refutation points: 0** (finding is correct)

---

#### T-Q22: 512× table qubits / 6,500× total qubits comparison

**Phase 1 Verdict (Turing):** MISLEADING - inconsistent methodology (table storage for SPM, algebraic for AES).

**Cross-Review Verdict: PARTIALLY REFUTED**

Turing argues the comparison is unfair because AES uses algebraic computation (not table storage) while SPM assumes table storage. However:

1. **AES's S-box CAN be computed algebraically because it has algebraic structure** (GF(2^8) inversion). This is precisely the design difference the paper highlights.

2. **SPM's S-box CANNOT be computed algebraically** because it's a PRNG-generated random permutation. There is no compact circuit - the only way to evaluate it is to either store the table or re-run the PRNG shuffle. The asymmetry in implementation is a real architectural consequence, not a methodological inconsistency.

3. **The inconsistency IS the point.** AES's compact quantum circuit is possible *because* of its algebraic S-box. SPM's expensive quantum circuit is a direct consequence of its random S-box. Comparing them differently reflects the actual cryptographic difference.

4. **Turing is right about Q10:** The 6,500× ratio should be ~3,300× after removing the reverse S-box. But the comparison methodology (algebraic for AES, table for SPM) is justified by the architectural difference.

**Refutation points: 0** (finding has partial merit re: Q10 inflation, but the methodology critique is wrong)

---

### FRIEDMAN REVIEWS REJEWSKI'S FINDINGS

#### R-Q4: AES S-box admits compact quantum circuit via tower field decomposition

**Phase 1 Verdict (Rejewski):** VALID - no points claimed.

**Cross-Review Verdict: UPHELD (no change - Rejewski correctly validated this claim)**

---

#### R-Q5: AES qubit counts 264–320 (citing Zou 2025, Huang 2025)

**Phase 1 Verdict (Rejewski):** FALSE - papers are 2020–2023, numbers are AES-128 not AES-256.

**Cross-Review Verdict: PARTIALLY REFUTED**

Rejewski's analysis requires correction:

1. **The citations may be valid.** Turing's reference list (Phase 1 report, references 9–10) identifies:
   - Zou et al. 2025: "Quantum circuit synthesis for AES with low DW-cost," IACR ePrint 2025/1494
   - Huang & Sun 2025: "Constructing resource-efficient quantum circuits for AES," Frontiers in Physics, 2025

   These appear to be **newer 2025 publications** by the same author groups, distinct from the 2020/2022 papers Rejewski identified. Rejewski checked for the 2020-era publications and concluded the 2025 citations don't exist, but they may be genuine 2025 follow-up papers with improved results. The research paper's bibliography ([17], [18]) lists specific 2025 titles and venues.

2. **The AES-128 vs AES-256 qubit confusion remains a valid concern.** Even if the 2025 papers exist, the 264-qubit figure historically corresponds to AES-128. Whether the 2025 papers achieve 264 qubits for AES-256 would need verification. The paper should clarify which AES variant the numbers apply to.

3. **The impact is reduced.** If the citations are valid 2025 papers, the "fabricated dates" accusation is wrong. But the AES-128/256 confusion may persist.

**Correction needed:** Verify the 2025 papers exist. If they do, the citation date criticism is invalid. The AES-128/256 distinction should still be clarified.

**Refutation points: 0** (finding has partial merit regarding AES-128/256 confusion, but the citation date accusation may be wrong)

---

#### R-Q6: AES T-gates: 26,000–53,000 (paper) vs ~186M (Rejewski)

**Phase 1 Verdict (Rejewski):** FALSE - off by ~4 orders of magnitude.

**Cross-Review Verdict: PARTIALLY REFUTED**

This is the most important dispute in the cross-review. The resolution hinges on a crucial distinction Rejewski fails to make:

1. **Grassl et al. 2016's 186M T-gates is for the FULL Grover iteration**, including:
   - Oracle construction (forward AES evaluation)
   - Diffusion operator
   - Oracle uncomputation (reverse AES evaluation)
   - Ancilla management and error correction overhead
   
   The full Grover iteration cost ≈ 2× cipher evaluation + overhead.

2. **The paper appears to be reporting cipher-evaluation-only gate cost.** The claim "gates per oracle call" likely refers to the gates needed to evaluate AES once (forward direction), not the full Grover iteration. In Grassl et al.:
   - Full Grover iteration: ~186M T-gates (2^{27.5})
   - Forward AES-128 evaluation: significantly less (roughly half, minus overhead)
   - Furthermore, Langenberg 2020 reduced Toffoli count by 88%, and subsequent papers (2022-2025) likely reduced further.

3. **The actual cipher-evaluation-only T-gate count for AES-256** in recent optimized implementations is likely in the range of **2^{17}–2^{20}** T-gates, not 2^{15} and not 2^{27.5}. The paper's "26,000–53,000" (≈ 2^{14.7}–2^{15.7}) is on the low end but not "4 orders of magnitude" off.

4. **The critical point:** The paper applies the SAME methodology to both ciphers - cipher-evaluation-only gates × Grover iterations. If you instead use full-Grover-iteration gates, you must apply that to SPM too, and the ratio remains approximately the same.

**Rejewski's finding is overstated.** The paper's AES figure is likely low by a factor of ~2^{2}–2^{4} (4–16×), not 2^{12.5} (~6,000×). The "2 million×" headline is probably overstated by a similar factor, giving a corrected ratio of ~125,000–500,000× - still enormous, and nowhere near Rejewski's claim of "~360×."

**Refutation points: 0** (the paper's number is too low, but Rejewski overstates the error by conflating cipher-only and full-iteration costs)

---

#### R-Q7: Total AES cost O(2^{143})

**Phase 1 Verdict (Rejewski):** FALSE - should be O(2^{155.5}) with corrected T-gates.

**Cross-Review Verdict: PARTIALLY REFUTED**

Since Q6 is partially refuted (the true cipher-evaluation figure is likely 2^{17}–2^{20}, not 2^{27.5}), the corrected total becomes:
- O(2^{128}) × 2^{17–20} ≈ O(2^{145–148})

This is close to the paper's O(2^{143}), not Rejewski's O(2^{155.5}). The paper is off by ~2^{2}–2^{5}, not 2^{12.5}.

**Refutation points: 0** (finding has some merit but magnitude is overstated)

---

#### R-Q8: "~2^{15} gates per call" characterization

**Phase 1 Verdict (Rejewski):** FALSE - conflates metrics, understates by ~2^{12.5}.

**Cross-Review Verdict: PARTIALLY REFUTED**

Per the Q6 analysis, the actual understatement is likely ~2^{2}–2^{4}, not 2^{12.5}. The paper's figure is on the low end but not absurdly wrong. The ambiguity between "T-gates," "Toffoli gates," and "total gates" is a valid criticism - the paper should specify which metric it uses.

**Refutation points: 0** (valid concern about metric clarity and slight understatement)

---

#### R-Q14: QRAM access costs O(2^{16}) gates - ignores bucket-brigade

**Phase 1 Verdict (Rejewski):** MISLEADING - uses worst-case model, ignores alternatives.

**Cross-Review Verdict: PARTIALLY REFUTED**

Rejewski presents bucket-brigade QRAM as a well-established alternative, but then acknowledges (in his own Q14 analysis, paragraph on "community consensus") that **explicit circuits, not QRAM, are the realistic model** for Grover-based symmetric cryptanalysis. This internal contradiction undermines his own finding:

1. **No published Grover-on-AES paper uses QRAM.** All use explicit quantum circuits. This is the standard assumption.

2. **Bucket-brigade QRAM requires qutrit-based quantum routers** that don't exist and may not be physically realizable at scale. Proposing it as a cost reduction for SPM is speculative.

3. **Even with bucket-brigade QRAM, the O(n) hardware requirement persists.** You need 65,536 quantum routers - they're just not all simultaneously active. The hardware cost doesn't vanish; it's recharacterized.

4. **Under the explicit-circuit model (community consensus), the S-box must be computed on-the-fly** via the PRNG shuffle circuit. This is exactly what the paper assumes, and it IS expensive - O(2^{16}) gates per swap operation in a multiplexer circuit is a reasonable estimate for a 16-bit address space.

5. **Rejewski's own admission** that "without QRAM, SPM's S-box table cannot be stored as a quantum register at all - it must be computed on-the-fly" SUPPORTS the paper's position.

The finding is partially refuted: the paper should acknowledge the QRAM model choice for transparency, but its choice of the fanout/explicit-circuit model is the standard one.

**Refutation points: 0** (paper should note model choice, but the choice is standard)

---

#### R-Q15: S-box generation O(2^{36}) gates

**Phase 1 Verdict (Rejewski):** MISLEADING - depends on Q14.

**Cross-Review Verdict: PARTIALLY REFUTED**

Since Q14's bucket-brigade alternative is itself partially refuted, Q15's dependence on it is weakened. Under the standard explicit-circuit model, O(2^{36}) is a reasonable estimate. The finding reduces to: "the paper should state its QRAM model assumption explicitly."

**Refutation points: 0**

---

#### R-Q16: Cascade encryption O(2^{26}) gates

**Phase 1 Verdict (Rejewski):** MISLEADING - same QRAM dependency.

**Cross-Review Verdict: PARTIALLY REFUTED**

Same reasoning as Q15. Under explicit circuits, O(2^{26}) for 759 lookups into a 16-bit table is reasonable.

**Refutation points: 0**

---

#### R-Q17: Total SPM oracle O(2^{36}) gates

**Phase 1 Verdict (Rejewski):** MISLEADING - sensitivity to QRAM not disclosed.

**Cross-Review Verdict: PARTIALLY REFUTED**

The estimate is reasonable under the standard model. The paper should state the model assumption, but the conclusion is sound.

Rejewski's dramatic claim that "under bucket-brigade QRAM, SPM's oracle is cheaper than AES's" (Q17 table) is misleading - it assumes a QRAM model for SPM while the AES comparison uses explicit circuits. An apples-to-apples comparison under the same model preserves SPM's cost advantage.

**Refutation points: 0**

---

#### R-Q18: "2 million times more gates" headline

**Phase 1 Verdict (Rejewski):** FALSE - headline unsupportable.

**Cross-Review Verdict: PARTIALLY REFUTED**

Rejewski's conclusion that the ratio drops to ~360× (or even inverts) depends on two corrections, both of which are themselves partially refuted:
1. AES cost is 2^{27.5} (partially refuted - likely 2^{17}–2^{20} for cipher-only)
2. SPM cost is 2^{24} under bucket-brigade QRAM (partially refuted - community standard is explicit circuits)

With our corrected figures:
- AES cipher-evaluation: ~2^{17}–2^{20}
- SPM oracle: ~2^{36} (standard model)
- Ratio: 2^{16}–2^{19} ≈ 65,000–500,000×

The "2 million×" headline (2^{21}) is still likely overstated but by a factor of ~4–32×, not by Rejewski's claimed 6,000×. A more defensible headline would be "~100,000–500,000× more gates per oracle evaluation."

**Refutation points: 0** (headline is overstated, but Rejewski's correction overcorrects dramatically)

---

### DRISCOLL REVIEWS FRIEDMAN'S FINDINGS

#### F-Q19: Total gate cost O(2^{163}) - non-standard metric

**Phase 1 Verdict (Friedman):** MISLEADING - MAXDEPTH constraints ignored.

**Cross-Review Verdict: PARTIALLY REFUTED**

Friedman is correct that MAXDEPTH and DW-cost are important, but:

1. Total gate count is a valid (if incomplete) metric used widely in the literature.
2. MAXDEPTH analysis would strengthen SPM's case (see Driscoll cross-review of Bernstein omission).
3. The omission hurts the paper's argument (by not presenting the stronger MAXDEPTH-constrained case), making it a missed opportunity rather than an error that inflates claims.

The finding is partially refuted because the omission works against the paper, not for it.

**Refutation points: 0** (valid concern, but impact assessment should note it favors the paper)

---

#### F-Q23: Simon's algorithm prerequisites

**Phase 1 Verdict (Friedman):** MISLEADING - states Even-Mansour requirements, not Simon's general requirements.

**Cross-Review Verdict: UPHELD**

Friedman is correct that Simon's algorithm requires a function with hidden XOR-period, not specifically a "public permutation." The paper conflates application-specific conditions (Even-Mansour structure) with algorithm-level requirements.

However, the paper's conclusion is correct - SPM does not expose hidden periodicity exploitable by Simon's. The issue is imprecise reasoning leading to a correct conclusion.

**Correction needed:** Restate requirements in terms of hidden XOR-period. Explain why SPM doesn't expose one.

**Refutation points: 0** (finding is correct)

---

#### F-Q24: Kuwakado & Morii citation (2010 vs 2012)

**Phase 1 Verdict (Friedman):** FALSE - wrong year and target cipher.

**Cross-Review Verdict: PARTIALLY REFUTED**

Friedman himself acknowledges: "The paper's text in §7.5 does not include an explicit year citation, so the '2010' may be an error in the task description rather than the paper."

Checking the paper's references:
- The research paper ([21]) cites "Kuwakado and Morii, 'Quantum Distinguisher Between the 3-Round Feistel Cipher and the Random Permutation,' ISIT 2010" - this is the **Feistel** paper, not the Even-Mansour paper.
- The paper's §7.5 discusses Even-Mansour context but references [21], which is the Feistel paper.

So the citation is technically wrong (Feistel paper cited in Even-Mansour context), but the error is in the reference list mapping, not a fabricated date. Friedman's finding about the Q2 threat model omission remains valid.

**Refutation points: 0** (citation mapping error is real, but less severe than "FALSE")

---

#### F-Q25: SPM "immune" to Simon's

**Phase 1 Verdict (Friedman):** MISLEADING - "immune" is epistemologically too strong.

**Cross-Review Verdict: REFUTED (+10 points)**

While formal proof purists may prefer "resistant," the term "immune" is defensible in context:

1. **"Immune" means the attack's prerequisites are absent**, not that a formal proof exists. When a cipher lacks the structural features an attack requires (no public permutation, no additive key structure, no hidden periodicity), saying it is "immune" to that specific attack is standard informal usage.

2. **The AES literature uses similar language.** Full AES is routinely described as "immune to" or "not vulnerable to" Simon's algorithm because it lacks Even-Mansour structure. This is the same claim the paper makes about SPM.

3. **Kuperberg's algorithm** (mentioned by Friedman) targets the dihedral hidden subgroup problem for lattice-based cryptography, not symmetric ciphers. It has no known application to block cipher key recovery. Mentioning it as a gap in SPM's analysis is a stretch.

4. **The distinction between "immune" and "resistant under current analysis"** is a matter of linguistic preference, not a factual error. The paper's use of "immune" in the context of a specific attack (Simon's) whose prerequisites are demonstrably absent is reasonable.

**Refutation points: +10** (the finding is a stylistic preference, not a substantive error)

---

#### F-Q26: Bonnetain et al. 2019 characterization

**Phase 1 Verdict (Friedman):** MISLEADING - Bonnetain et al. did not demonstrate Simon-type attacks on simplified AES variants.

**Cross-Review Verdict: UPHELD**

Friedman is correct. The paper's claim that "Simon-type attacks on simplified AES variants have been demonstrated" mischaracterizes the literature:
- Bonnetain et al. 2019 focused on Grover-based and meet-in-the-middle quantum attacks.
- Simon-type attacks target Even-Mansour/FX *constructions* (generic wrappers), not "simplified AES variants" (reduced-round AES).
- The distinction matters: the vulnerability is in the wrapping construction, not in AES's internal design.

**Correction needed:** Rewrite to: "Simon-type attacks have been demonstrated against Even-Mansour and FX constructions when instantiated with any permutation, including AES."

**Refutation points: 0** (finding is correct)

---

#### F-Q29: Quantum differential/linear speedup "on data collection only"

**Phase 1 Verdict (Friedman):** MISLEADING - oversimplifies Kaplan et al.'s results.

**Cross-Review Verdict: PARTIALLY REFUTED**

Friedman is technically correct that quantum speedups can apply to characteristic search and key recovery phases, not just data collection. However:

1. **The paper's conclusion is correct**: unknown DDT/LAT blocks all phases of quantum differential/linear cryptanalysis, not just data collection. If you can't characterize the S-box, you can't find good characteristics (blocking the search phase) and you can't identify useful statistical biases (blocking data collection).

2. **The oversimplification doesn't affect the comparison.** Even if SPM's paper incorrectly limits the speedup to data collection, the conclusion (SPM resists quantum differential/linear attacks) is correct because the S-box is unknown.

3. **The Q1/Q2 model distinction is a valid concern** but primarily relevant for attacks where the adversary has quantum query access, which is not the standard threat model for stored-data encryption.

**Refutation points: 0** (finding is pedantically correct but doesn't affect conclusions)

---

#### F-Q30: DDT/LAT invariance in quantum settings

**Phase 1 Verdict (Friedman):** UNSUPPORTED - no published proof for quantum model.

**Cross-Review Verdict: REFUTED (+10 points)**

Friedman acknowledges the claim is "likely correct" and "obviously true" but marks it as unsupported because no formal proof exists in the quantum query model. This standard is unreasonable:

1. **DDT/LAT invariance is a property of the function's truth table**, not of the computational model used to evaluate it. The DDT counts the number of input pairs with a given input/output difference - this is a combinatorial property of the function, independent of how the function is queried.

2. **The algebraic identity is trivial**: S(x ⊕ m) with a = x ⊕ m means iterating over x is a bijection to iterating over a. This holds regardless of whether x is classical or in quantum superposition - the function's truth table is the same.

3. **Friedman's own analysis confirms this**: "The counting argument *does* transfer to the quantum setting (it's a property of the function, not of the query model)." He then scores it as unsupported despite answering his own question.

4. **No published proof exists because none is needed.** The invariance is definitional. Demanding a published quantum-specific proof for a combinatorial identity is like demanding a published proof that 2+2=4 holds on quantum computers.

**Refutation points: +10** (the finding demands an unnecessary proof for a trivially true mathematical identity)

---

## Consensus Table

| Claim | Phase 1 Analyst | Phase 1 Verdict | Phase 2 Cross-Reviewer | Phase 2 Verdict | Paper Correction Needed? |
|-------|----------------|-----------------|----------------------|-----------------|--------------------------|
| **Q1:** Grover → O(2^{n/2}) | Turing | MISLEADING | Rejewski | **PARTIALLY REFUTED** | Minor: note π/4 constant if giving concrete estimates |
| **Q2:** Total cost = calls × C_oracle | Turing | MISLEADING | Rejewski | **PARTIALLY REFUTED** | Moderate: acknowledge DW-cost as alternative metric |
| **Q3:** Oracle cost "often overlooked" | Turing | FALSE | Rejewski | **UPHELD** | Yes: remove straw-man phrasing |
| **Q4:** Tower field decomposition | Rejewski | VALID | Friedman | **UPHELD (valid)** | None |
| **Q5:** 264–320 qubits (Zou/Huang 2025) | Rejewski | FALSE | Friedman | **PARTIALLY REFUTED** | Moderate: verify 2025 papers; clarify AES-128 vs AES-256 |
| **Q6:** AES T-gates ~2^{15} | Rejewski | FALSE | Friedman | **PARTIALLY REFUTED** | Yes: likely ~2^{17}–2^{20}; specify "cipher-evaluation-only" |
| **Q7:** AES total cost O(2^{143}) | Rejewski | FALSE | Friedman | **PARTIALLY REFUTED** | Moderate: adjust to ~O(2^{145}–2^{148}) |
| **Q8:** "~2^{15} gates per call" | Rejewski | FALSE | Friedman | **PARTIALLY REFUTED** | Yes: specify metric (T-gates vs Toffoli vs total) |
| **Q9:** S-box needs 1,048,576 qubits | Turing | MISLEADING | Rejewski | **PARTIALLY REFUTED** | Minor: acknowledge model assumption |
| **Q10:** Reverse S-box needs 1,048,576 | Turing | FALSE | Rejewski | **UPHELD** | Yes: remove reverse S-box from qubit table |
| **Q11:** Total ~2.1M qubits | Turing | MISLEADING | Rejewski | **PARTIALLY REFUTED** | Yes: correct to ~1.05M after removing reverse S-box |
| **Q12:** Hybrid attack omission | Turing | FALSE | Rejewski | **PARTIALLY REFUTED** | Yes: discuss hybrid attack; note O(2^{190+}) total cost |
| **Q14:** QRAM = O(2^{16}) gates/access | Rejewski | MISLEADING | Friedman | **PARTIALLY REFUTED** | Minor: state QRAM model assumption |
| **Q15:** S-box gen = O(2^{36}) | Rejewski | MISLEADING | Friedman | **PARTIALLY REFUTED** | Minor: note model dependency |
| **Q16:** Cascade = O(2^{26}) | Rejewski | MISLEADING | Friedman | **PARTIALLY REFUTED** | Minor: note model dependency |
| **Q17:** Total oracle = O(2^{36}) | Rejewski | MISLEADING | Friedman | **PARTIALLY REFUTED** | Minor: present sensitivity range |
| **Q18:** "2 million×" headline | Rejewski | FALSE | Friedman | **PARTIALLY REFUTED** | Yes: revise to ~100K–500K× with corrected AES figures |
| **Q19:** O(2^{163}) total gates | Friedman | MISLEADING | Driscoll | **PARTIALLY REFUTED** | Moderate: add DW-cost or MAXDEPTH discussion |
| **Q20:** AES machine "inadequate" | Turing | FALSE | Rejewski | **PARTIALLY REFUTED** | Yes: acknowledge hybrid attack trade-off |
| **Q21:** "Quadruples per bit" | Turing | FALSE | Rejewski | **UPHELD** | Yes: fix mathematical error |
| **Q22:** 512× / 6,500× comparison | Turing | MISLEADING | Rejewski | **PARTIALLY REFUTED** | Moderate: correct to ~3,300× after Q10 fix |
| **Q23:** Simon's prerequisites | Friedman | MISLEADING | Driscoll | **UPHELD** | Yes: restate in terms of hidden XOR-period |
| **Q24:** Kuwakado & Morii citation | Friedman | FALSE | Driscoll | **PARTIALLY REFUTED** | Yes: fix reference mapping (cite 2012 paper for Even-Mansour) |
| **Q25:** SPM "immune" to Simon's | Friedman | MISLEADING | Driscoll | **REFUTED** ✓ | None - "immune" is acceptable informal usage |
| **Q26:** Bonnetain et al. characterization | Friedman | MISLEADING | Driscoll | **UPHELD** | Yes: correct characterization of Even-Mansour vs AES variants |
| **Q27:** 23 quadratic equations attribution | Driscoll | MISLEADING | Turing | **PARTIALLY REFUTED** | Minor: fix attribution to Courtois & Pieprzyk |
| **Q28:** Algebraic degree ~2^{16}−1 | Driscoll | FALSE | Turing | **UPHELD** | Yes: correct to 15 (multivariate ANF degree) |
| **Q29:** Quantum speedup "data collection only" | Friedman | MISLEADING | Driscoll | **PARTIALLY REFUTED** | Minor: broaden speedup description |
| **Q30:** DDT/LAT quantum invariance | Friedman | UNSUPPORTED | Driscoll | **REFUTED** ✓ | None - combinatorial identity needs no quantum proof |
| **Cross: Multi-target Grover** | Driscoll | UNSUPPORTED | Turing | **REFUTED** ✓ | None - not differentially relevant to comparison |
| **Cross: Hybrid attack** | Driscoll | MISLEADING | Turing | **PARTIALLY REFUTED** | Yes: discuss but note 10^{26}-year classical cost |
| **Cross: Bernstein/MAXDEPTH** | Driscoll | UNSUPPORTED | Turing | **PARTIALLY REFUTED** | Moderate: add MAXDEPTH discussion (it helps the case) |
| **Cross: Coherence framing** | Driscoll | MISLEADING | Turing | **PARTIALLY REFUTED** | Minor: clarify "theoretical" vs "concrete cost" |
| **Cross: Qubit as security metric** | Driscoll | MISLEADING | Turing | **PARTIALLY REFUTED** | Minor: add total-work emphasis alongside qubits |

---

## Scoring Summary

| Verdict | Count | Refutation Points |
|---------|-------|-------------------|
| UPHELD | 8 | 0 |
| PARTIALLY REFUTED | 19 | 0 |
| REFUTED | 3 | +30 |
| N/A (Q4 valid, error correction 0pts) | 2 | 0 |
| **Total** | **32** | **+30** |

**Successful refutations (+10 each):**
1. Q25: SPM "immune" to Simon's → acceptable usage (+10)
2. Q30: DDT/LAT quantum invariance → trivially true, no proof needed (+10)
3. Multi-target Grover omission → not relevant to comparison (+10)

---

## Key Dispute Resolutions

### 1. The Hybrid Attack

**Resolution: The attack exists but is not "viable" in any practical sense.**

Both Turing and Driscoll correctly identify the hybrid classical-quantum attack. However, their characterization of it as "viable" or "practical" is misleading:

- The classical outer loop requires 2^{127} iterations × ~2^{20} operations each ≈ 2^{147} classical operations
- At 10^9 ops/sec: ~2^{117} seconds ≈ 5 × 10^{26} years
- Even with 10^9 parallel processors: ~5 × 10^{17} years (~4 × 10^{7} × age of universe)
- Total work: O(2^{190+}) - vastly more than full Grover's O(2^{163})

**Consensus:** The paper should acknowledge and dismiss the hybrid attack. It reduces qubits to ~3,000–5,000 but at the cost of 2^{27+} times more total work and a classical bottleneck lasting trillions of times the age of the universe. It does not make SPM "attackable by the same class of quantum computers that could attack AES" in any meaningful operational sense - it makes SPM attackable by the same quantum computers PLUS an astronomically infeasible classical computation.

**Recommended paper text:** "A hybrid attack can classically enumerate K_S values and use Grover only for K_M, reducing the quantum circuit to ~3,000–5,000 qubits. However, this requires 2^{127} classical iterations (each generating a full S-box), with total work O(2^{190+}) - far exceeding the full-Grover cost of O(2^{163}). The hybrid attack trades qubit count for dramatically more total computation."

### 2. The AES Gate Cost Dispute

**Resolution: The paper understates AES gates, but Rejewski overcorrects by conflating cipher-only and full-iteration costs.**

- Grassl 2016's ~186M T-gates (2^{27.5}) is the **full Grover iteration** cost, not the cipher-evaluation-only cost.
- The cipher-evaluation-only cost is lower - likely ~2^{17}–2^{20} for optimized AES-256.
- The paper's 2^{15} is on the low end; a more defensible figure would be ~2^{18}.
- With corrected AES costs (~2^{18}), the gate ratio becomes 2^{36}/2^{18} = 2^{18} ≈ 262,144× - still enormous, but ~8× less than the claimed 2^{21}.

**Recommended correction:** "AES-256 cipher evaluation requires approximately 2^{17}–2^{19} T-gates (optimized, cipher evaluation only; Langenberg 2020, Huang & Sun 2025). SPM's oracle requires ~2^{36} gates under the explicit-circuit model. The ratio is approximately 2^{17}–2^{19} (130,000–500,000×)."

### 3. The QRAM Model Dispute

**Resolution: The paper's explicit-circuit (fanout) model is the standard assumption; bucket-brigade QRAM is speculative.**

- All published Grover-on-AES papers use explicit circuits, not QRAM.
- Bucket-brigade QRAM requires qutrit-based quantum routers that don't exist at scale.
- The community consensus (including Rejewski's own admission) is explicit circuits for symmetric cryptanalysis.
- Under explicit circuits, SPM's O(2^{16}) gates per table access and O(2^{36}) total oracle cost are reasonable estimates.

**Recommendation:** The paper should add a footnote: "We use the explicit quantum circuit model (fanout QRAM) standard in the Grover-on-cipher literature (Grassl 2016, Jaques 2020). Under speculative bucket-brigade QRAM (O(log n) active gates per access), the S-box evaluation cost would decrease, but this model is not used in any published symmetric cipher quantum analysis."

### 4. The Algebraic Degree Error

**Resolution: Driscoll is correct. The number is wrong but the argument is sound.**

- The paper claims "expected algebraic degree ~2^{16} − 1 = 65,535."
- The correct value is **15** (multivariate ANF degree, bounded by n−1 for n-bit permutations).
- This is a 4,369× numerical error caused by confusing univariate GF(2^16) degree with multivariate GF(2) degree.
- However, degree 15 is near-maximal for a 16-bit permutation, vs. AES's degree 7 for an 8-bit permutation.
- The qualitative argument (SPM's S-box resists algebraic attacks) is correct - the quantitative claim needs fixing.

**Recommended correction:** "SPM's S-box has expected multivariate algebraic degree 15 - the maximum for any 16-bit permutation (bounded by n−1). By contrast, AES's 8-bit S-box has degree 7 (also maximal for its width, but over a much smaller space). The relevant comparison for algebraic attack resistance is the number and degree of equations relating input and output bits: AES has 39 quadratic equations per S-box, while a random 16-bit S-box requires equations of degree approaching 15."

### 5. Citation Errors

**Resolution: Mixed - some citations may be valid, others need correction.**

- **Zou et al. 2025 / Huang & Sun 2025:** Turing's references identify plausible 2025 publications (ePrint 2025/1494 for Zou; Frontiers in Physics 2025 for Huang & Sun). These may be genuine follow-up papers to the 2020/2022 originals. Rejewski's assertion that they "don't exist" may be based on checking only for the older papers. **Recommendation:** Verify the 2025 publications exist. If so, the citation dates are correct and Rejewski's finding is invalid on this point.

- **Kuwakado & Morii:** The paper's reference [21] cites their 2010 Feistel paper in a context discussing Even-Mansour (2012). The reference should be updated to cite the 2012 ISITA paper for Even-Mansour specifically.

- **AES-128 vs AES-256 qubit confusion:** Even if the 2025 papers exist, the paper should verify that 264 qubits applies to AES-256, not AES-128. Historical context suggests 264 was an AES-128 result.

---

## Recommended Corrections (Priority-Ordered)

### Critical (factual errors)

1. **Q10:** Remove reverse S-box from qubit table. Correct total from ~2.1M to ~1.05M.
2. **Q28:** Change "~2^{16} − 1" to "15" for algebraic degree. Fix in both `cryptanalysis.md` and `SpmbcVAes.md`.
3. **Q21:** Fix "quadruples per bit" scaling claim. The actual ratio is ~2× per bit for large b.
4. **Q6/Q8:** Revise AES gate cost from "2^{15}" to "~2^{17}–2^{19}" and specify "cipher-evaluation T-gates."

### Important (missing analysis)

5. **Hybrid attack:** Add a subsection discussing the hybrid classical-quantum attack, its qubit savings (~3,000–5,000), and its dramatically higher total cost (O(2^{190+})).
6. **Q18:** Revise headline from "2 million×" to "~100,000–500,000× more gates per oracle evaluation" (after AES cost correction).
7. **Q5:** Verify 2025 citations. Clarify AES-128 vs AES-256 qubit figures.

### Moderate (imprecise claims)

8. **Q3:** Soften "often overlooked" to "treated as unit-cost in the asymptotic Grover metric."
9. **Q23:** Restate Simon's prerequisites correctly.
10. **Q26:** Correct Bonnetain characterization (Even-Mansour constructions, not simplified AES variants).
11. **Q24:** Fix Kuwakado & Morii reference to 2012 ISITA for Even-Mansour.
12. **Q27:** Correct attribution to Courtois & Pieprzyk 2002.

### Minor (transparency improvements)

13. Add a sentence noting the QRAM model assumption (explicit circuits).
14. Add DW-cost or MAXDEPTH discussion as supplementary metric (this helps the paper's case).
15. Clarify "theoretical" vs "concrete computational cost" distinction.

---

## Final Assessment

**The paper's central thesis - that SPM is significantly harder to attack quantumly than AES-256 - survives the adversarial review, but the magnitude of the advantage is overstated and several supporting claims contain errors.**

After all corrections:
- **Qubit advantage:** ~3,300× (down from 6,500× after removing reverse S-box), or ~10–15× under the hybrid attack (but at 2^{27}× more total work)
- **Gate cost advantage:** ~100,000–500,000× per oracle evaluation (down from 2,000,000×)
- **Total work advantage:** ~2^{17}–2^{20} (down from 2^{20}) under full Grover
- **SPM is still meaningfully harder to attack quantumly**, but the headline numbers need correction

The paper's fundamental insight - that a 16-bit key-dependent S-box imposes massive quantum circuit costs - is sound. The execution contains several quantitative errors and omissions that, while not invalidating the conclusion, significantly weaken the paper's credibility and overstate the advantage by roughly one order of magnitude.

---

*Phase 2 Cross-Review completed. 3 refutations scored (+30 points). 8 findings upheld. 19 findings partially refuted (reduced in scope but not eliminated). 2 findings not applicable to scoring.*
