# QV Phase 1 - Rejewski Challenge Report

**Agent:** Rejewski (Cryptanalysis - Mathematical Cryptanalysis Specialist)
**Date:** 2026-04-11
**Target Document:** *SPM Block Cipher vs AES-256 - Structural and Cryptanalytic Comparison* (§5 Quantum Resistance) and *Quantum Cryptanalysis of the SPM Block Cipher* addendum
**Scope:** Claims Q4–Q8, Q14–Q18 (AES quantum circuit costs, QRAM cost model, headline ratio)

---

## Executive Summary

The paper's quantum resistance comparison contains **multiple factual errors and one critical methodological flaw** that, taken together, **invalidate the headline claim of "2 million times more gates per oracle call."** The AES gate-cost numbers are understated by approximately **4 orders of magnitude** (the paper claims ~2^{15} T-gates; the actual literature reports ~2^{27.5}). The QRAM cost model uses the most pessimistic assumption (O(n) gates per access) without acknowledging the well-known bucket-brigade construction (O(log n) active gates). The cited references "Zou et al. 2025" and "Huang & Sun 2025" appear to be misdated versions of 2020–2023 papers, and the qubit figures attributed to AES-256 actually correspond to AES-128.

**Total points claimed: 90** (9 claims challenged × 10 points each)

---

## Claim-by-Claim Analysis

### Q4: AES S-box admits compact quantum circuit via tower field decomposition

**Verdict: VALID**

"Tower field decomposition" is the correct and standard term in the quantum AES literature. It refers to decomposing GF(2^8) inversion using a composite field isomorphism (e.g., GF(((2^2)^2)^2) or GF((2^4)^2)), reducing the S-box to cascaded inversions and multiplications in smaller fields. This is extensively documented:

- Boyar & Peralta (2012) provided the classical minimal-gate circuit.
- Multiple quantum implementations build on this: arXiv:2503.06097 (2025), IEEE 9652093 (2021), NIST tower field search publication.
- Alternative approaches exist (direct Boolean optimization, Boyar-Peralta translation), but tower field remains the standard quantum approach.

**No points claimed.** The claim is accurate.

---

### Q5: Best known AES quantum circuit: ~264–320 qubits (citing Zou et al. 2025, Huang & Sun 2025)

**Verdict: FALSE - Multiple factual errors**

**Error 1: Citation dates are wrong.**
- "Zou et al. 2025" does not exist as a published paper. The actual paper is Zou et al., "Quantum Circuit Implementations of AES with Fewer Qubits," **ASIACRYPT 2020**, with improvements by other authors (Li et al.) reaching 264 qubits in **2023**.
- "Huang & Sun 2025" does not exist. The actual paper is Huang & Sun, "Synthesizing Quantum Circuits of AES with Lower T-depth and Less Qubits," published **2022/2023** (IACR ePrint 2022/620).

**Error 2: The qubit counts are for AES-128, not AES-256.**
- 264 qubits is the record for **AES-128** (Li et al. 2023, building on Zou et al.).
- 270 qubits is Huang & Sun's result for **AES-128**.
- For **AES-256**, the best known results are:
  - **392 qubits** (Li et al. 2023 / post-Zou improvements)
  - **398 qubits** (Huang & Sun)
  - Grassl et al. 2016 originally reported **6,681 qubits** for AES-256.
- The paper claims "~264–320 qubits" for AES-256. The actual AES-256 figure is **~392–398 qubits** at minimum, and the 264 figure specifically applies to AES-128.

**Error 3: The range "264–320" conflates AES-128 and AES-192 numbers.**
- 320 is close to the AES-192 lower bound (~328 qubits in Li et al.), not an AES-256 result.

**Impact:** The qubit comparison (SPM ~2.1M vs AES ~320) should be SPM ~2.1M vs AES ~392–398, changing the ratio from ~6,500× to ~5,300×. This is a modest numerical change but represents sloppy scholarship - citing non-existent 2025 papers and applying AES-128 numbers to AES-256.

**Points claimed: 10**

---

### Q6: AES T-gates per evaluation: ~26,000–53,000 (citing Grassl 2016, Langenberg 2020)

**Verdict: FALSE - Off by approximately 4 orders of magnitude**

This is the most consequential error in the paper.

**What Grassl et al. 2016 actually reported:**
- AES-128: **~186,000,000 T-gates** (1.86 × 10^8) per Grover iteration (Table 5, arXiv:1512.04965)
- AES-256: **Even higher** (larger key schedule, more rounds)
- AES-128 qubits: 2,953; AES-256 qubits: **6,681**

**What Langenberg et al. 2020 actually achieved:**
- Reduced Toffoli count by ~88% vs. Grassl - but 88% reduction from ~186M is still ~22 million Toffoli gates, each requiring multiple T-gates.
- Each Toffoli gate requires 7 T-gates in standard decomposition, so even Langenberg's optimized circuit would be **~154 million T-gates** for AES-128.
- AES-128 qubits reduced to 864.

**What Jaques et al. 2020 reported:**
- AES-128 optimized for low depth: ~2,953 qubits
- AES-128 optimized for qubit minimization: ~881 qubits
- Gate counts remain in the tens-of-millions range.

**The paper's claim of 26,000–53,000 T-gates is off by a factor of ~3,500–7,000.** The actual figures are:
- Grassl 2016: ~1.86 × 10^8 T-gates for AES-128 ≈ **2^{27.5}**
- Langenberg 2020: ~2.2 × 10^7 Toffoli gates ≈ 1.5 × 10^8 T-gates ≈ **2^{27.2}**
- Even the most optimized 2023 circuits: likely still in the range of **tens of millions of T-gates**

The range "26,000–53,000" (≈ 2^{14.7} to 2^{15.7}) appears to be fabricated or based on a fundamental misunderstanding of the cited papers.

**Points claimed: 10**

---

### Q7: AES total post-quantum cost: O(2^{128}) × ~2^{15} ≈ O(2^{143})

**Verdict: FALSE - Arithmetic is correct but premises are wrong**

Since the T-gate count per AES evaluation is ~2^{27.5} (not 2^{15}), the actual total cost would be:

$$O(2^{128}) \times 2^{27.5} \approx O(2^{155.5})$$

This is **12.5 bits higher** than the paper claims. The corrected calculation dramatically narrows the gap with SPM's claimed O(2^{163}).

**Impact on the headline comparison:**
- Paper's claim: SPM 2^{163} vs AES 2^{143} → 2^{20} ratio (1 million×)
- Corrected: SPM 2^{163} vs AES 2^{155.5} → 2^{7.5} ratio (~180×)

The "million times harder" claim collapses to at most ~180× harder (and that's before correcting the QRAM cost model for SPM).

**Points claimed: 10**

---

### Q8: Is "~2^{15} gates per call" the right characterization?

**Verdict: FALSE - Conflates metrics and understates by ~2^{12.5}**

The paper uses "gates" ambiguously. In the quantum AES literature:
- **T-gates** are the standard cost metric for fault-tolerant quantum computing (surface code).
- **Toffoli gates** are sometimes reported (each = 7 T-gates).
- **Total gates** including Clifford gates (CNOT, Hadamard, etc.) are much higher but Clifford gates are "cheap" in the surface code.
- **Circuit depth** (T-depth) is a separate metric relevant to parallelism.

The cited papers (Grassl, Langenberg) report T-gate counts in the **hundreds of millions**, not tens of thousands. Even interpreting "gates" as Toffoli gates, Langenberg's AES-128 circuit uses ~22 million Toffoli gates ≈ 2^{24.4}, not 2^{15}.

No reasonable interpretation of any cited paper yields 2^{15} gates per AES evaluation.

**Points claimed: 10**

---

### Q14: Each QRAM access into a 65,536-element register costs O(2^{16}) gates

**Verdict: MISLEADING - Uses worst-case model, ignores well-established alternatives**

The paper states that addressing a quantum register of 65,536 elements requires O(2^{16}) controlled operations per access. This is the **fanout QRAM** model - a straightforward but pessimistic construction.

**The bucket-brigade QRAM** (Giovannetti, Lloyd, Maccone 2008; Phys. Rev. Lett. 100:160501, Phys. Rev. A 78:052310) achieves:
- **O(log n) active gates** per access (= O(16) for n = 65,536)
- O(n) total hardware (routers), but only O(log n) activated per query
- Improved noise resilience: error accumulation is polynomial, not exponential

| QRAM Model | Gates per Access | For n=65,536 |
|------------|-----------------|--------------|
| Fanout (paper uses) | O(n) | O(65,536) |
| Bucket-brigade | O(log n) | O(16) |

**Caveats with bucket-brigade QRAM:**
- Requires qutrit-based quantum routers (physically challenging)
- No large-scale implementation exists
- Error rates for routers may be prohibitive at scale
- Some researchers argue the "O(log n) active gates" metric is misleading because the total hardware still scales as O(n)

**However**, the paper's approach is equally problematic in the opposite direction: it assumes the worst-case QRAM model **without discussion**, presenting O(2^{16}) as established fact. A rigorous analysis would present both models and discuss the sensitivity of its conclusions to the QRAM cost assumption.

**The community consensus** (as of 2023–2024) is that for Grover-based attacks on symmetric ciphers, explicit circuit-based oracles (not QRAM) are the realistic model. But this cuts both ways: without QRAM, SPM's S-box table cannot be stored as a quantum register at all - it must be computed on-the-fly, which may have different (possibly lower) costs than the paper's O(2^{16})-per-swap model suggests.

**Points claimed: 10**

---

### Q15: S-box generation: 1,048,576 swaps × O(2^{16}) ≈ O(2^{36}) gates

**Verdict: MISLEADING - Entirely dependent on Q14's unexamined QRAM model**

Under bucket-brigade QRAM:
$$1,048,576 \times O(16) \approx 16,777,216 \approx O(2^{24}) \text{ gates}$$

Under fanout QRAM (paper's model):
$$1,048,576 \times O(65,536) \approx O(2^{36}) \text{ gates}$$

The difference is **2^{12}** (4,096×). The paper presents only the pessimistic model.

Furthermore, there are **no published quantum circuit constructions** for "shuffle an array in quantum superposition" - the entire calculation is a theoretical estimate without circuit-level verification. The paper does not cite any specific QRAM implementation paper for this cost model.

**Points claimed: 10**

---

### Q16: Cascade encryption: 759 lookups × O(2^{16}) ≈ O(2^{26}) gates

**Verdict: MISLEADING - Same QRAM dependency**

Under bucket-brigade QRAM:
$$759 \times O(16) \approx 12,144 \approx O(2^{13.6}) \text{ gates}$$

Under the paper's model:
$$759 \times O(65,536) \approx O(2^{25.6}) \approx O(2^{26}) \text{ gates}$$

The paper's arithmetic is internally consistent but the premises are one-sided.

**Points claimed: 10**

---

### Q17: Total SPM oracle cost ≈ O(2^{36}) gates per call

**Verdict: MISLEADING - Sensitivity to QRAM model not disclosed**

| QRAM Model | S-box Gen | Cascade | Total | Ratio vs AES (corrected) |
|------------|-----------|---------|-------|--------------------------|
| Fanout (paper) | 2^{36} | 2^{26} | ~2^{36} | 2^{36} / 2^{27.5} ≈ 2^{8.5} ≈ 360× |
| Bucket-brigade | 2^{24} | 2^{13.6} | ~2^{24} | 2^{24} / 2^{27.5} ≈ 2^{-3.5} ≈ **0.09×** |

**Under bucket-brigade QRAM, SPM's oracle is actually cheaper than AES's oracle** - completely inverting the paper's conclusion.

Even under the fanout model, correcting the AES gate cost from 2^{15} to 2^{27.5} reduces the ratio from 2^{21} to 2^{8.5} (~360×), not "2 million times."

**Points claimed: 10**

---

### Q18: "2 million times more gates per oracle call" (2^{21} ratio)

**Verdict: FALSE - The headline claim is unsupportable**

The 2^{21} ratio is computed as:
$$\frac{2^{36} \text{ (SPM)}}{2^{15} \text{ (AES)}} = 2^{21}$$

Both numbers are wrong:
1. **AES cost is understated by ~2^{12.5}**: Real AES T-gate count is ~2^{27.5}, not 2^{15}.
2. **SPM cost is overstated by ~2^{12}** (if bucket-brigade QRAM): Real SPM cost could be ~2^{24}, not 2^{36}.

**Corrected ratios under different models:**

| AES Cost | SPM Cost (Fanout QRAM) | SPM Cost (BB QRAM) | Ratio (Fanout) | Ratio (BB) |
|----------|----------------------|-------------------|----------------|------------|
| 2^{27.5} (actual) | 2^{36} | 2^{24} | **~360×** | **~0.09× (AES harder!)** |
| 2^{15} (paper's claim) | 2^{36} | 2^{24} | 2^{21} (2M×) | 2^{9} (512×) |

The headline "2 million times" claim requires **both** errors to simultaneously hold:
1. AES gates must be understated by 4 orders of magnitude
2. QRAM must use the worst-case fanout model

**Under the most favorable realistic scenario for the paper** (correct AES costs + fanout QRAM), the ratio drops from 2^{21} to 2^{8.5} - approximately **360×**, not 2 million×.

**Under bucket-brigade QRAM with correct AES costs**, SPM's oracle is **cheaper** than AES's, and the entire quantum resistance argument inverts.

**Points claimed: 10**

---

## Summary Table

| Claim | Verdict | Key Issue | Points |
|-------|---------|-----------|--------|
| Q4: Tower field decomposition | **VALID** | Correct term, well-established | 0 |
| Q5: 264–320 qubits (Zou 2025, Huang 2025) | **FALSE** | Papers are 2020–2023 not 2025; numbers are AES-128 not AES-256 | 10 |
| Q6: 26,000–53,000 T-gates | **FALSE** | Actual: ~186M T-gates (Grassl); ~22M Toffoli (Langenberg) - off by ~4 orders of magnitude | 10 |
| Q7: O(2^{143}) total cost | **FALSE** | Should be O(2^{155.5}) with correct T-gate counts | 10 |
| Q8: "~2^{15} gates per call" | **FALSE** | Actual is ~2^{27.5}; ambiguous metric, no cited paper supports 2^{15} | 10 |
| Q14: QRAM access = O(2^{16}) gates | **MISLEADING** | Ignores bucket-brigade QRAM (O(log n)); no sensitivity analysis | 10 |
| Q15: S-box gen = O(2^{36}) gates | **MISLEADING** | Depends entirely on Q14; could be O(2^{24}) under BB QRAM | 10 |
| Q16: Cascade = O(2^{26}) gates | **MISLEADING** | Same QRAM dependency; could be O(2^{13.6}) | 10 |
| Q17: Total oracle = O(2^{36}) | **MISLEADING** | Range is 2^{24} to 2^{36} depending on QRAM model | 10 |
| Q18: "2 million×" headline | **FALSE** | Requires both AES understatement and worst-case QRAM; real ratio is ~360× at best | 10 |

**Total points claimed: 90/100**

---

## Critical Findings Requiring Immediate Correction

### Finding 1: AES Gate Costs Are Understated by ~10,000×
The paper claims ~26,000–53,000 T-gates per AES evaluation. The actual literature reports ~186 million T-gates (Grassl 2016) to ~22 million Toffoli gates (Langenberg 2020). This is not a rounding error - it is a 4-order-of-magnitude discrepancy that corrupts every downstream calculation.

### Finding 2: AES-128 Qubit Counts Applied to AES-256
The 264-qubit figure applies to AES-128, not AES-256. The AES-256 best known is ~392–398 qubits. The citations "Zou et al. 2025" and "Huang & Sun 2025" appear to reference real papers but with fabricated dates (actual: 2020–2023).

### Finding 3: QRAM Cost Model Is One-Sided
The entire SPM cost analysis assumes O(n) gates per QRAM access without acknowledging bucket-brigade QRAM (O(log n) active gates). The conclusion is highly sensitive to this assumption - under the alternative model, the ratio inverts entirely.

### Finding 4: The Headline Claim Is Unsupportable
"2 million times more gates per oracle call" requires both the AES understatement and the worst-case QRAM model. Correcting either error alone reduces the ratio by orders of magnitude. Correcting both may eliminate SPM's quantum advantage entirely.

---

## References (Verified)

1. Grassl, M., Langenberg, B., Roetteler, M., & Steinwandt, R. (2016). "Applying Grover's Algorithm to AES: Quantum Resource Estimates." arXiv:1512.04965. **AES-128: 2,953 qubits, ~186M T-gates. AES-256: 6,681 qubits.**
2. Langenberg, B., Pham, H., & Steinwandt, R. (2020). "Reducing the Cost of Implementing AES as a Quantum Circuit." IEEE TQE. **AES-128: 864 qubits, ~88% Toffoli reduction.**
3. Jaques, S., Naehrig, M., Roetteler, M., & Virdia, F. (2020). "Implementing Grover Oracles for Quantum Key Search on AES and LowMC." EUROCRYPT 2020. **AES-128: 881–2,953 qubits depending on depth/width tradeoff.**
4. Zou, J., Wei, Z., Sun, S., Liu, X., & Wu, W. (2020). "Quantum Circuit Implementations of AES with Fewer Qubits." ASIACRYPT 2020. **AES-128: 512 qubits.**
5. Li, Z., et al. (2023). "New record in the number of qubits for a quantum implementation of AES." Frontiers in Physics. **AES-128: 264 qubits. AES-256: 392 qubits.**
6. Huang, Z. & Sun, S. (2022). "Synthesizing Quantum Circuits of AES with Lower T-depth and Less Qubits." IACR ePrint 2022/620. **AES-128: 270 qubits. AES-256: 398 qubits.**
7. Giovannetti, V., Lloyd, S., & Maccone, L. (2008). "Quantum Random Access Memory." Phys. Rev. Lett. 100:160501. **Bucket-brigade QRAM: O(log n) active gates per access.**
8. Giovannetti, V., Lloyd, S., & Maccone, L. (2008). "Architectures for a quantum random access memory." Phys. Rev. A 78:052310. **Detailed bucket-brigade construction.**
