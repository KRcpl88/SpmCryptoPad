# QV Phase 1 - Driscoll Challenge Report
## Cryptanalysis Expert: Practical Attack Assessment

**Analyst:** Driscoll (adversarial cryptanalysis role)
**Date:** 2025-07-15
**Scope:** Claims Q27, Q28, cross-cutting quantum attacks, argument coherence

---

## Q27: "AES S-box has 23 quadratic equations in GF(2)" (citing Murphy & Robshaw 2002)

### Verdict: **MISLEADING** (+10 points)

The paper states the AES S-box "can be expressed as a system of 23 quadratic equations in 16 variables over GF(2)" and attributes this to Murphy & Robshaw 2002. This conflates two distinct results from two different papers and elides a critical distinction.

**What the literature actually says:**

1. **Courtois & Pieprzyk (2002)** - "Cryptanalysis of Block Ciphers with Overdefined Systems of Equations" (ASIACRYPT 2002) - are the ones who first characterized the AES S-box algebraically for attack purposes. They identified:
   - **23 bi-affine equations** in 16 variables (8 input bits + 8 output bits) - these arise from the relation x·y = 1 in GF(2^8). "Bi-affine" means each equation is affine in either the input or output variables separately, but quadratic when both are considered together.
   - **39 fully quadratic equations** in 16 variables - a superset that includes 16 additional equations derived from identities like x⁴y = x³ and y⁴x = y³. These are general quadratic equations (products of any two variables).

2. **Murphy & Robshaw (2002)** - "Essential Algebraic Structure within the AES" (CRYPTO 2002) - discussed the algebraic structure of AES using operations in GF(2^8) directly. They referenced and built upon the Courtois & Pieprzyk framework, discussing the "23 or 24" equation characterization, but their primary contribution was analyzing the cipher's structure at the GF(2^8) level, not originating the GF(2) equation count.

**The specific problems with the paper's claim:**

- The "23 quadratic equations" number comes from Courtois & Pieprzyk, not Murphy & Robshaw. Murphy & Robshaw discussed this result but did not originate it.
- The 23 equations are specifically **bi-affine**, not general quadratic. This is a meaningful distinction - bi-affine equations are a restricted subclass of quadratic equations. The full set of 39 general quadratic equations is the more commonly cited figure in algebraic cryptanalysis literature.
- The paper presents "23 quadratic equations in 16 variables" as if it were a single authoritative number. In reality, the algebraic characterization depends on what class of equations you allow: 23 bi-affine, 39 general quadratic, or even larger systems with linearized variables.

**Why this matters:** The paper uses this number to argue that AES has a "compact algebraic description" vulnerable to algebraic attacks. While the general point is valid (AES does have exploitable algebraic structure), misattributing and oversimplifying the characterization weakens the comparison's credibility. A reader checking the Murphy & Robshaw paper would find a different emphasis than what the paper implies.

**References:**
- Courtois & Pieprzyk, ASIACRYPT 2002, LNCS 2501, pp. 267–287
- Murphy & Robshaw, CRYPTO 2002, LNCS 2442, pp. 1–16
- Crypto StackExchange: "What is the difference between the 23 bi-affine and the 39 fully quadratic equations?"

---

## Q28: SPM S-box has "no compact algebraic description" - expected degree ~2^{16}−1

### Verdict: **FALSE** (+10 points)

The paper claims the SPM S-box's "algebraic degree is expected to be maximal (close to 2^16)" (SpmbcVAes.md line 115) and later refers to "expected algebraic degree ~2^{16} − 1" (line 230). **This is wrong.** The paper is conflating two completely different notions of "algebraic degree," and the number it states is the wrong one for both.

**The two representations and their actual degrees:**

### Representation 1: Univariate polynomial over GF(2^16)

Any permutation on GF(2^n) can be represented as a unique polynomial of degree at most 2^n − 1. For n = 16, this gives a maximum univariate degree of 2^16 − 1 = 65,535. A random permutation will indeed have degree close to 2^16 − 1 with overwhelming probability.

**But this metric is cryptographically irrelevant.** Every permutation - including perfectly linear ones and the identity function - has a univariate representation. The univariate degree over GF(2^n) does not measure cryptographic nonlinearity or algebraic attack resistance. A permutation with univariate degree 65,535 could still have low multivariate algebraic degree (which is what matters for algebraic attacks).

### Representation 2: Multivariate ANF over GF(2) - THE RELEVANT METRIC

This is what matters for algebraic cryptanalysis. Each of the 16 output bits is expressed as a Boolean function of the 16 input bits in Algebraic Normal Form (ANF). The degree of the permutation is the maximum degree across all coordinate functions.

**Key fact:** No n-bit permutation can have multivariate algebraic degree n. The maximum possible degree for any n-bit permutation is **n − 1**. This is a well-known theorem in Boolean function theory (see Carlet, "Boolean Functions for Cryptography and Coding Theory," Cambridge 2021; Nikova et al., IACR ePrint 2018/103).

For a random 16-bit permutation:
- **Maximum possible degree: 15** (not 65,535)
- **Expected degree: 15** (almost all random permutations achieve the maximum n − 1)

**The paper states ~2^{16} − 1 = 65,535. The correct answer is 15.**

This is a factor of **4,369× error** in the stated algebraic degree. The paper appears to have confused the univariate degree over the extension field GF(2^16) with the multivariate ANF degree over GF(2), which is the metric relevant to algebraic attacks (XL, XSL, Gröbner basis methods).

**Does this undermine the paper's broader argument?** Partially. The qualitative claim that SPM's S-box has high algebraic degree and resists algebraic attacks is still defensible - degree 15 over GF(2) with 16 input variables is indeed near-maximal, making algebraic attacks difficult. But:

1. AES's S-box has algebraic degree 7 over GF(2) (which is n − 1 for an 8-bit permutation), so AES also has maximal algebraic degree for its width. The degree comparison is 15 vs. 7, not 65,535 vs. something small.
2. The relevant comparison for algebraic attack resistance is the **number and degree of equations relating input and output bits**, not the raw algebraic degree. AES has 39 quadratic equations in 16 variables per S-box; a random 16-bit S-box would require equations of much higher degree (likely close to degree 15), making algebraic attacks harder. This is a legitimate advantage - but the paper quantifies it incorrectly.

**References:**
- Carlet, "Boolean Functions for Cryptography and Coding Theory," Cambridge, 2021
- Nikova et al., "Decomposition of Permutations in a Finite Field," IACR ePrint 2018/103
- Bard, "Algebraic Cryptanalysis," Springer, 2009

---

## Cross-Cutting: Quantum Attacks NOT Considered

### 1. Quantum Collision Finding (BHT Algorithm)

### Verdict: **VALID OMISSION - low relevance**

The Brassard–Høyer–Tapp (BHT) algorithm finds collisions in O(2^{n/3}) quantum queries vs. O(2^{n/2}) classical birthday attack. However:

- **BHT targets hash functions, not block ciphers.** It finds collisions in a public function f. For SPM, there is no public function to query - the S-box is secret and key-dependent.
- **Applicability to S-box analysis:** An attacker who somehow had oracle access to the S-box (side-channel model) could use BHT to find S-box collisions in O(2^{16/3}) ≈ O(2^{5.3}) queries. But S-box collisions alone do not enable key recovery - they would only partially characterize the DDT.
- **QRAM requirement:** BHT requires quantum random access memory, which is an even more demanding assumption than standard quantum computation. This is a severe practical limitation.

**The paper's omission of BHT is reasonable** - the algorithm does not provide a meaningful attack vector against SPM's key recovery problem.

### 2. Quantum Walks

### Verdict: **VALID OMISSION - speculative applicability**

Quantum walk-based algorithms (e.g., Ambainis' element distinctness, Magniez et al. quantum walk framework) provide speedups for graph search and collision-finding problems. Their application to block cipher cryptanalysis is largely theoretical and unexplored for ciphers of SPM's structure. No published quantum walk attack on any practical cipher's cascade structure exists. The omission is defensible given the current state of knowledge.

### 3. Quantum Multi-Target Search

### Verdict: **UNSUPPORTED OMISSION - should have been discussed** (+10 points)

Multi-target Grover search is a well-known variant where having T target keys reduces the search from O(2^{n/2}) to O(2^{n/2}/√T). For key recovery with multiple known plaintext-ciphertext pairs, this doesn't directly apply (you're searching for one specific key), but **multi-target preimage search** could matter in related attack scenarios.

More importantly, the paper's quantum analysis only considers the single-target Grover scenario. It does not discuss:
- Whether multiple known P/C pairs can reduce the quantum circuit depth (by allowing earlier rejection of wrong key candidates)
- Whether the 1024-bit block size helps or hurts in quantum multi-target scenarios
- Whether multi-instance attacks (attacking many SPM users simultaneously) change the economics

While multi-target Grover doesn't fundamentally break the O(2^{n/2}) barrier for a single key, the paper should have at least acknowledged and dismissed this vector explicitly.

### 4. Hybrid Classical-Quantum Attack

### Verdict: **MISLEADING - paper ignores a viable lower-qubit attack** (+10 points)

This is the most significant omission. The paper only considers "pure Grover" over the full 254-bit key space, requiring ~2.1 million qubits. A hybrid attack deserves explicit analysis:

**Hybrid attack construction:**
1. **Classical outer loop:** Iterate over all 2^{127} candidate S-box PRNG seeds. For each:
   a. Classically generate the S-box (~1M operations)
   b. Hardwire this fixed S-box into a quantum circuit
2. **Quantum inner loop:** Use Grover to search the 2^{127} candidate mask PRNG seeds
   - With a *fixed* S-box, the quantum oracle only needs to implement 759 table lookups + XORs - no PRNG-driven S-box generation
   - Qubits needed: ~320–1000 (the S-box is a classical lookup table, not held in quantum superposition)
   - Oracle cost: ~759 × 16-bit lookups ≈ O(2^{14}) gates per call
   - Grover iterations: O(2^{63.5})
3. **Total cost:** 2^{127} classical iterations × O(2^{63.5}) quantum work = O(2^{190.5}) total gates

**This hybrid attack requires only ~320–1000 qubits**, compared to the paper's claimed 2.1 million. The total work is higher (O(2^{190.5}) vs O(2^{163})), but the qubit requirement is reduced by **2,000–6,500×**.

**Why this matters:**
- The paper's central quantum resistance claim is built on the "2.1 million qubit" figure.
- The hybrid attack shows that a quantum computer with only ~320–1000 qubits could contribute meaningfully to attacking SPM - the same qubit budget as attacking AES.
- The paper's comparison table (320 qubits for AES vs. 2.1M for SPM) is misleading because it only considers one specific attack strategy.
- The hybrid attack's O(2^{190.5}) total cost is still completely infeasible, but so is AES's O(2^{143}) - neither is remotely practical. The relevant comparison should be about the minimum qubit threshold, where SPM's advantage largely evaporates under the hybrid approach.

**Counterargument the paper could make:** The total gate count is the dominant cost metric, and O(2^{190.5}) > O(2^{163}) > O(2^{143}), so SPM is still more expensive to attack. This is true but it's a different argument than "6,500× more qubits." The paper should present both attack strategies honestly.

### 5. Quantum Amplitude Estimation

### Verdict: **VALID OMISSION - marginal relevance**

Quantum amplitude estimation (QAE) can provide quadratic speedups for estimating probabilities, which could theoretically accelerate statistical distinguishers (differential/linear cryptanalysis). However:

- SPM's S-box is secret, so the attacker cannot construct a quantum oracle for the DDT/LAT without first recovering the S-box
- Even with a known S-box, QAE applied to a 759-step cascade differential would require coherent quantum simulation of the full cascade - an enormous circuit
- No published QAE-based attack on any practical block cipher exists

The omission is reasonable.

### 6. Bernstein's Cost Model

### Verdict: **UNSUPPORTED OMISSION - changes the narrative** (+10 points)

Daniel Bernstein has argued extensively that the correct cost metric for quantum attacks is not raw gate count but rather the **quantum circuit area × time product** (sometimes called "quantum cost" or "DW cost"), incorporating:

- Error correction overhead (1,000–10,000 physical qubits per logical qubit)
- Circuit depth constraints (MAXDEPTH)
- Parallelization limitations (Grover's algorithm offers only limited parallelism: using P processors gives √P speedup, not P)
- Energy and time costs

Under Bernstein's model:
- The comparison of "2^{15} gates for AES vs 2^{36} gates for SPM" per oracle call would be multiplied by roughly the same error correction factor, preserving the ratio.
- However, the MAXDEPTH constraint is critical: if the quantum computation must complete within a maximum circuit depth D, then Grover's O(2^{n/2}) iterations each of depth d require total depth O(2^{n/2} × d). For SPM's deeper oracle circuit, the MAXDEPTH constraint bites harder.
- NIST's post-quantum evaluation explicitly considers MAXDEPTH limits (2^40, 2^64, 2^96 gates). Under MAXDEPTH = 2^96, both AES and SPM Grover attacks are infeasible. Under MAXDEPTH = 2^64, the comparison changes - SPM's deeper oracle may exceed the depth budget while AES's does not.

The paper makes no mention of depth constraints, MAXDEPTH, or Bernstein's cost model. This is a significant omission for a paper making strong claims about quantum resistance.

**References:**
- Bernstein, "Cost analysis of hash collisions: Will quantum computers make SHARCS obsolete?" SHARCS 2009
- Jaques et al., "Implementing Grover oracles for quantum key search on AES and LowMC," EUROCRYPT 2020
- NIST, "On the Practical Cost of Grover for AES Key Recovery," 5th PQC Standardization Conference, 2024

---

## Cross-Cutting: Argument Coherence

### 7. "~Equal theoretical security" AND "dramatically harder in practice"

### Verdict: **MISLEADING** (+10 points)

The paper simultaneously claims:
- "Post-quantum security (theoretical): 128 bits vs 127 bits - ~Equal"
- "Post-quantum security (practical): SPM dramatically harder"

**This position is internally incoherent as presented.** Here's why:

"Theoretical security" in the Grover context means the number of oracle calls: O(2^{128}) for AES vs O(2^{127}) for SPM. These are essentially equal. The paper then argues that "practical security" is dramatically different because each oracle call costs more for SPM.

The problem: **oracle cost IS part of the theoretical security analysis.** The total work (oracle calls × cost per call) is the relevant measure, not just oracle call count. If you separate these, you could make any cipher look the same "theoretically" by only counting oracle calls and ignoring per-call cost.

What the paper is actually claiming - but not stating clearly - is that **total quantum computational cost** differs by ~2^{20} (a million-fold). This is a legitimate observation. But framing it as "equal theoretical, dramatically different practical" is misleading because:

1. It implies theoretical equality when total theoretical work differs by 2^{20}
2. It uses "practical" to mean "resource cost" when cryptographers use "practical" to mean "feasible with real hardware"
3. Neither attack is "practical" in any engineering sense - both require technology far beyond current capabilities

A more honest framing: "SPM requires approximately 2^{20}× more total quantum gate operations than AES for a Grover key recovery attack. Both attacks are astronomically beyond current quantum computing capabilities."

### 8. Qubit Count as a Security Metric

### Verdict: **MISLEADING** (+10 points)

The paper heavily emphasizes the "6,500× more qubits" comparison as a security advantage. This is problematic:

1. **Qubit count is an engineering constraint, not a security parameter.** Security is measured in bits of work (computational complexity). The number of qubits required is a hardware constraint that reflects the current state of quantum engineering, not a fundamental cryptographic property.

2. **Moore's Law for qubits:** Quantum computing qubit counts are growing exponentially. IBM's roadmap targets 100,000+ qubits by 2033. While 2.1 million is beyond near-term projections, it's within the range of conceivable future machines (decades, not centuries). When such machines exist, SPM's qubit advantage evaporates entirely.

3. **The hybrid attack (§4 above) reduces the qubit requirement to ~320–1000**, comparable to AES. So even today, the "6,500× qubit advantage" is a feature of one specific attack strategy, not an inherent property of the cipher.

4. **The meaningful metric is total computational cost** - O(2^{163}) vs O(2^{143}) total gate operations. The 2^{20}× difference is real but modest in cryptographic terms (both are astronomically infeasible). In contrast, the gap between AES-128 (64-bit post-quantum security) and AES-256 (128-bit) is 2^{64}× - that's a meaningful difference.

### 9. Error Correction Overhead

### Verdict: **VALID CONCERN - ratio roughly constant but absolute numbers change narrative**

The paper reports ~320 logical qubits for AES and ~2.1M logical qubits for SPM. Under quantum error correction with surface codes:

| Metric | AES-256 | SPM-256 | Ratio |
|--------|---------|---------|-------|
| Logical qubits | ~320 | ~2,100,000 | 6,500× |
| Physical qubits (×1,000) | ~320,000 | ~2.1 billion | 6,500× |
| Physical qubits (×10,000) | ~3.2 million | ~21 billion | 6,500× |

The ratio is preserved under error correction (it's a constant multiplicative factor applied to both). However, the absolute numbers change the narrative significantly:

- AES-256 already requires 320K–3.2M physical qubits - well beyond current technology (~1,000 qubits in 2024)
- SPM-256 requires 2.1B–21B physical qubits - far beyond even optimistic long-term projections

**The paper's omission of error correction doesn't change the ratio but strengthens its argument.** The paper should have included this analysis because it reinforces the point: even AES is safe from near-term Grover attacks when error correction is considered, and SPM is safer still. The omission is a missed opportunity, not a flaw.

However, it also reveals that both ciphers are so far beyond practical quantum attack that the comparison is somewhat academic. The "6,500× advantage" sounds dramatic until you realize both numbers are billions of years away from feasibility.

---

## Score Summary

| Claim | Verdict | Points |
|-------|---------|--------|
| Q27: 23 quadratic equations (Murphy & Robshaw) | **MISLEADING** - wrong attribution, bi-affine vs quadratic distinction omitted | +10 |
| Q28: Expected degree ~2^{16}−1 | **FALSE** - confuses univariate GF(2^16) degree with multivariate ANF degree; correct answer is 15, not 65,535 | +10 |
| Omission: BHT collision finding | VALID omission | 0 |
| Omission: Quantum walks | VALID omission | 0 |
| Omission: Multi-target Grover | **UNSUPPORTED** omission | +10 |
| Omission: Hybrid classical-quantum attack | **MISLEADING** - ignores viable ~320-qubit attack | +10 |
| Omission: Quantum amplitude estimation | VALID omission | 0 |
| Omission: Bernstein cost model / MAXDEPTH | **UNSUPPORTED** omission | +10 |
| "Equal theoretical, dramatically different practical" | **MISLEADING** - incoherent framing | +10 |
| Qubit count as security metric | **MISLEADING** - engineering constraint, not security parameter | +10 |
| Error correction overhead | VALID concern but ratio constant | 0 |

**Total: 70 points**

---

## Recommendations

1. **Fix Q27:** Attribute the 23-equation result to Courtois & Pieprzyk 2002, clarify they are bi-affine (not general quadratic), and note the 39 general quadratic equations characterization. Reference Murphy & Robshaw for the GF(2^8)-level algebraic structure analysis.

2. **Fix Q28:** Replace "expected algebraic degree ~2^{16} − 1" with "expected multivariate algebraic degree 15 (the maximum for any 16-bit permutation)." Explain that the relevant metric is the ANF degree over GF(2), which is bounded by n − 1 = 15 for n-bit permutations. Note that this is still near-maximal and makes algebraic attacks difficult - the qualitative argument is sound even though the quantitative claim is wrong.

3. **Add hybrid attack analysis:** Explicitly analyze the classical-outer/quantum-inner hybrid attack. Show that it requires only ~320 qubits but O(2^{190.5}) total work. Be honest that the qubit advantage is strategy-dependent.

4. **Add Bernstein cost model discussion:** Acknowledge MAXDEPTH constraints and depth-aware cost metrics. This actually helps SPM's case (deeper oracles are worse for attackers under depth constraints) but needs to be presented rigorously.

5. **Reframe the comparison:** Drop "equal theoretical security" framing. Instead: "SPM requires O(2^{163}) total quantum gate operations for Grover key recovery vs O(2^{143}) for AES-256 - a 2^{20}× advantage. Both are astronomically infeasible with current or projected quantum hardware."

6. **Add error correction analysis:** Include physical qubit estimates. This strengthens the argument.

---

*Report generated by Driscoll (adversarial cryptanalysis role), QV Phase 1*
