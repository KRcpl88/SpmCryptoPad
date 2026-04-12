# QV Phase 1 — Friedman Challenge Report

**Reviewer:** Friedman (Cryptanalysis / Statistical & Structural Analysis)
**Date:** 2025-07-15
**Subject:** Quantum cryptanalysis claims in `cryptanalysis.md` §7

---

## Q19: Total SPM quantum attack: O(2^{127}) × O(2^{36}) ≈ O(2^{163}) total gates

### Verdict: **MISLEADING**

**Claim under review:** The paper computes total quantum attack cost as oracle calls × gates per call = O(2^{127}) × O(2^{36}) ≈ O(2^{163}) total gate operations, and uses this figure to compare SPM favorably against AES-256.

**Challenges:**

1. **The multiplication is arithmetically correct but the resulting metric is non-standard.** Simply multiplying oracle calls by gates per call yields a raw gate count, which is only *one* of several quantum cost metrics used in the literature. Published quantum cost metrics include:
   - **Total gate count** (what the paper uses)
   - **T-depth** (the sequential depth of T-gates, which dominate error correction cost)
   - **DW-cost** (depth × width, i.e., circuit depth × qubit count)
   - **MAXDEPTH-constrained cost** (NIST's preferred model)

2. **NIST's MAXDEPTH constraint is completely ignored.** In NIST's "Submission Requirements and Evaluation Criteria for Post-Quantum Cryptography" (December 2016), NIST explicitly introduced MAXDEPTH constraints of 2^{40}, 2^{64}, and 2^{96} sequential gate depth to model practical quantum computing limits. Under a MAXDEPTH model, you *cannot* simply run 2^{127} sequential Grover iterations — you must parallelize them. Parallelizing Grover iterations incurs a *quadratic* overhead in qubit count: reducing depth by a factor S requires S² parallel instances. This means:
   - Under MAXDEPTH = 2^{96}: depth reduction factor S = 2^{127}/2^{96} = 2^{31}, requiring (2^{31})² = 2^{62} parallel circuits, each needing ~2.1M qubits → total ~2^{83} qubits.
   - Under MAXDEPTH = 2^{64}: S = 2^{63}, requiring 2^{126} parallel circuits → astronomically more qubits.
   - The raw gate count 2^{163} hides these parallelization costs entirely.

3. **The comparison with AES-256 is therefore asymmetric.** The paper applies the same naive "calls × gates" formula to both ciphers (2^{143} for AES vs. 2^{163} for SPM). If MAXDEPTH constraints were applied to both, the *relative* advantage might hold (SPM's oracle is more expensive), but the *absolute* numbers would change dramatically. The paper should acknowledge this or present DW-cost comparisons.

4. **The paper does acknowledge that oracle cost matters** ("this metric treats oracle calls as unit cost, which profoundly understates SPM's advantage"), which is laudable. But it then replaces one simplification with another equally non-standard simplification.

**Score: +10 points** — The metric is non-standard and the omission of MAXDEPTH constraints makes the comparison incomplete and potentially misleading, even though the *relative* advantage of SPM over AES is likely directionally correct.

**References:**
- NIST, "Submission Requirements and Evaluation Criteria for Post-Quantum Cryptography," Dec 2016. Section 4.A.5, pp. 18–19. https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/call-for-proposals-final-dec-2016.pdf
- Grassl, Langenberg, Roetteler, Steinwandt, "Applying Grover's algorithm to AES," 2016.
- Jaques, Naehrig, Roetteler, Virdia, "Implementing Grover Oracles for Quantum Key Search on AES and LowMC," EUROCRYPT 2020 — explicitly reports T-depth, DW-cost, and MAXDEPTH-constrained costs.

---

## Q23: Simon's algorithm requires a public permutation and additive key structure

### Verdict: **MISLEADING**

**Claim under review:** The paper states three prerequisites for Simon's algorithm: (1) a public permutation, (2) additive key structure, (3) key-dependent nonlinearity eliminates exploitable periodicity.

**Challenges:**

1. **The actual mathematical requirement is more general.** Simon's algorithm (Simon 1997) requires a function f: {0,1}^n → {0,1}^m satisfying the *promise* that there exists s ∈ {0,1}^n such that f(x) = f(y) iff y = x or y = x ⊕ s. The algorithm finds s in O(n) quantum queries. The requirements are:
   - A function with a hidden XOR-period (2-to-1 with unique collisions paired by s)
   - Quantum oracle access to evaluate f in superposition
   - No additional "accidental" collisions beyond those caused by s

2. **"Public permutation" is not a formal requirement of Simon's algorithm.** It is a requirement of *specific applications* of Simon's to the Even-Mansour construction, where the public permutation P allows the attacker to construct a function g(x) = E_k(x) ⊕ P(x) = P(x ⊕ k₁) ⊕ k₂ ⊕ P(x), which has period k₁. The paper conflates the requirements of a *specific application* with the requirements of the *algorithm itself*.

3. **The paper's three conditions are sufficient but not necessary.** It is correct that SPM lacks the Even-Mansour structure. However, saying Simon's requires a "public permutation" overstates what the algorithm needs — it requires *any* function with a hidden period, constructible from quantum oracle access. A clever reformulation *could* potentially expose periodicity in other ways, though no such reformulation is currently known for SPM.

4. **The conclusion is likely correct but for imprecise reasons.** SPM almost certainly resists Simon's algorithm, but the paper's argument should focus on the *absence of exploitable hidden periodicity* rather than listing structural features as formal prerequisites.

**Score: +10 points** — The stated prerequisites are those of the Even-Mansour application, not of Simon's algorithm in general. The paper presents application-specific conditions as algorithm-level requirements.

**References:**
- D. Simon, "On the Power of Quantum Computation," SIAM J. Comput. 26(5), 1997.
- Kuwakado & Morii, ISITA 2012 (Even-Mansour application).

---

## Q24: Simon's has been applied to break Even-Mansour (citing Kuwakado & Morii 2010)

### Verdict: **FALSE** (citation error)

**Claim under review:** The paper implies (§7.5) that Simon's algorithm was applied to Even-Mansour, citing the general body of Kuwakado & Morii's work. While no explicit "2010" citation appears in the paper text, the task assignment references this date.

**Findings from verification:**

1. **Kuwakado and Morii published TWO distinct papers:**
   - **ISIT 2010:** "Quantum distinguisher between the 3-round Feistel cipher and the random permutation" — this attacked a **3-round Feistel cipher (Luby-Rackoff construction)**, NOT Even-Mansour.
   - **ISITA 2012:** "Security on the quantum-type Even-Mansour cipher" — this is the paper that broke **Even-Mansour** using Simon's algorithm.

2. **The target cipher and year matter.** The 2010 paper attacked Feistel, not Even-Mansour. The Even-Mansour result was published in **2012**, not 2010.

3. **Threat model:** Both papers use the **Q2 model** (quantum superposition queries to the encryption oracle). This is a critical distinction — the attacks require the adversary to query the cipher in quantum superposition, which is a strong and arguably unrealistic threat model for most practical scenarios. The paper does not mention this restriction.

4. **The paper's text in §7.5 does not include an explicit year citation**, so the "2010" may be an error in the task description rather than the paper. However, the paper should cite the specific Kuwakado & Morii 2012 paper and note the Q2 threat model.

**Score: +10 points** — If the paper cites 2010 for Even-Mansour, the year and target cipher are wrong. Even if the year is not explicitly stated, the paper fails to note the Q2 threat model, which significantly limits the practical relevance of Simon's attacks.

**References:**
- Kuwakado, H. & Morii, M., "Quantum distinguisher between the 3-round Feistel cipher and the random permutation," ISIT 2010.
- Kuwakado, H. & Morii, M., "Security on the quantum-type Even-Mansour cipher," ISITA 2012.

---

## Q25: SPM is immune to Simon's because S-box is secret and key structure is nonlinear

### Verdict: **MISLEADING**

**Claim under review:** "SPM is immune to Simon's algorithm" (used in both the executive summary and §7.5).

**Challenges:**

1. **"Immune" is epistemologically too strong.** In cryptanalysis, no cipher is proven "immune" to an attack unless there is a formal proof of security in the relevant model. The correct phrasing would be "resistant under current understanding" or "no known application of Simon's algorithm applies." The paper uses "immune" as a certainty claim without formal proof.

2. **Kuperberg's algorithm for the dihedral hidden subgroup problem** is a generalization beyond Simon's that works on non-abelian groups. While Kuperberg's algorithm (subexponential time, O(exp(C·√log N))) is primarily relevant to lattice-based cryptosystems and does not currently threaten symmetric ciphers, the paper does not acknowledge the existence of generalizations of Simon's algorithm that relax its structural requirements. This is a gap in the analysis.

3. **Chosen-plaintext access and function construction.** If an attacker has quantum chosen-plaintext access (Q2 model), they can evaluate the cipher in superposition. Could they construct a derived function from SPM that exhibits hidden periodicity? The paper asserts this is impossible because "every nonlinear operation depends on the key," but this is an informal argument, not a proof. For a fixed (unknown) key, the cipher *is* a fixed permutation — the question is whether any function constructible from this permutation (e.g., by composing it with itself or with known transforms) exhibits exploitable periodicity.

4. **The argument is likely directionally correct.** SPM's key-dependent S-box does remove the specific structural features that enable known Simon's attacks. But "immune" should be replaced with "resistant" to avoid overclaiming.

**Score: +10 points** — "Immune" is an overclaim without formal proof. The paper should acknowledge the absence of proof of security and use more cautious language.

---

## Q26: "Simon-type attacks on simplified AES variants have been demonstrated" (citing Bonnetain et al. 2019)

### Verdict: **MISLEADING**

**Claim under review:** "AES also resists Simon's algorithm on the full cipher, but its public S-box means Simon-type attacks on simplified AES variants (reduced rounds, Even-Mansour-like constructions) have been demonstrated."

**Findings from verification of Bonnetain, Naya-Plasencia, Schrottenloher 2019:**

1. **What the paper actually demonstrated:** Bonnetain et al. 2019 ("Quantum Security Analysis of AES," ePrint 2019/272) performed a comprehensive quantum security analysis of AES, primarily examining:
   - Quantum versions of Demirci-Selçuk meet-in-the-middle attacks on reduced-round AES
   - A general framework for quantum symmetric cryptanalysis cost modeling
   - Their best quantum attack was on 8-round AES-256 requiring ~2^{138} quantum operations

2. **They did NOT demonstrate "Simon-type attacks on simplified AES variants."** The Bonnetain et al. 2019 paper is primarily about Grover-based and meet-in-the-middle quantum attacks, not Simon's algorithm. Simon-type attacks on Even-Mansour and FX constructions are discussed in the *context* of their framework, but these are attacks on **Even-Mansour/FX constructions that happen to use AES as the underlying permutation**, not on "simplified AES variants" per se.

3. **The distinction matters.** An attack on "AES used inside an Even-Mansour construction" is fundamentally different from an attack on "a reduced-round version of AES." The former exploits the Even-Mansour key-mixing structure (which has nothing to do with AES's internal design), while the latter would exploit AES's round structure. The paper's phrasing conflates these.

4. **The implicit citation is also imprecise.** If the intended citation for Simon-type attacks is Kuwakado & Morii 2012 (Even-Mansour) or Bonnetain et al., neither demonstrates attacks on "simplified AES variants" in the sense of reduced-round AES. The attacks are on *generic constructions* (Even-Mansour, FX) that are *instantiated with* AES.

**Score: +10 points** — The characterization of Bonnetain et al. 2019 is inaccurate. They did not demonstrate Simon-type attacks on simplified AES variants. The attacks in the literature target Even-Mansour/FX *constructions*, not AES's internal structure.

**References:**
- Bonnetain, X., Naya-Plasencia, M., Schrottenloher, A., "Quantum Security Analysis of AES," IACR ePrint 2019/272. https://eprint.iacr.org/2019/272

---

## Q29: Quantum differential/linear attacks get quadratic speedup on data collection only

### Verdict: **MISLEADING**

**Claim under review:** "Quantum differential/linear attacks use amplitude amplification for quadratic speedup. For AES, the fixed public DDT/LAT enables precomputation of optimal characteristics. For SPM, the DDT and LAT are key-dependent and unknown — the same barrier that blocks classical attacks blocks quantum-enhanced versions."

**Challenges:**

1. **The claim oversimplifies where quantum speedups apply.** Kaplan, Leurent, Leverrier, and Naya-Plasencia (2016, "Quantum Differential and Linear Cryptanalysis," ToSC 2016/1) showed that quantum speedups in differential/linear cryptanalysis are nuanced:
   - **Data collection phase:** Grover/amplitude amplification can provide quadratic speedup in finding right pairs or linear approximations.
   - **Characteristic search phase:** Quantum search can also accelerate the search for good differential characteristics or linear trails — this is a *separate* speedup that the paper ignores.
   - **Key recovery phase:** Quantum speedups may or may not apply, depending on the specific attack structure.

2. **Kaplan et al. explicitly note:** "The most effective quantum attack might not simply be a quantum-accelerated version of the best classical attack." Some attack structures do not permit full quadratic speedup across all phases, while others permit speedups in phases beyond data collection.

3. **The paper's core argument about SPM is sound but incomplete.** The claim that unknown DDT/LAT blocks quantum differential/linear attacks is reasonable — if the attacker cannot characterize the S-box, they cannot identify useful characteristics regardless of quantum speedups. However, the paper should acknowledge that quantum speedups apply to *more* than just data collection.

4. **The two-adversary-model distinction matters.** Kaplan et al. distinguish between:
   - Q1: Classical queries, quantum offline computation
   - Q2: Quantum superposition queries
   The paper does not specify which model applies to its claims about quantum differential/linear attacks on SPM.

**Score: +10 points** — The claim that quantum speedups apply "only to data collection" is an oversimplification of Kaplan et al.'s results, though the downstream conclusion about SPM's resistance is likely correct.

**References:**
- Kaplan, M., Leurent, G., Leverrier, A., Naya-Plasencia, M., "Quantum Differential and Linear Cryptanalysis," ToSC 2016(1), pp. 71–94. https://tosc.iacr.org/index.php/ToSC/article/view/536

---

## Q30: Mask transparency (DDT/LAT invariance under XOR) holds in quantum settings

### Verdict: **UNSUPPORTED**

**Claim under review:** The paper proves (§3.1, §3.3) that DDT and LAT are invariant under XOR masking:
```
DDT_{S(·⊕m)}(Δx, Δy) = DDT_S(Δx, Δy)   for all mask values m
|LAT_{S(·⊕m)}(a, b)| = |LAT_S(a, b)|     for all mask values m
```
The paper uses these properties throughout its quantum analysis (§7.6) to argue that masks do not affect the difficulty of quantum differential/linear attacks.

**Challenges:**

1. **The classical proofs are correct.** The DDT invariance proof uses algebraic substitution: if a = x ⊕ m, then iterating over x is equivalent to iterating over a (bijection), so the count of pairs with a given input/output difference is preserved. The LAT proof similarly uses the linearity of XOR. These are standard results in classical cryptanalysis.

2. **Transferring to the quantum setting requires additional justification.** When a Grover oracle evaluates the cipher in superposition, the XOR mask is applied to a *superposition of inputs*. The algebraic identity S(x ⊕ m) with x in superposition is implemented as a quantum gate sequence. The *computational equivalence* (same function, same truth table) holds trivially — a quantum computer computing S(x ⊕ m) produces the same input-output mapping as S(a) where a = x ⊕ m.

3. **However, the paper never explicitly addresses this.** The quantum setting introduces subtleties:
   - Are the DDT/LAT *statistical properties* (which are defined over classical probability distributions of input differences) well-defined when the attacker queries in superposition?
   - In the Q2 model, the attacker can create quantum superpositions of input differences — the "distribution" of differences is then a quantum amplitude distribution, not a classical probability distribution.
   - The classical DDT counts #{x : S(x ⊕ Δx) ⊕ S(x) = Δy}. This counting argument *does* transfer to the quantum setting (it's a property of the function, not of the query model), but the paper should state this explicitly.

4. **No published work directly addresses DDT/LAT invariance in quantum settings.** The literature on quantum symmetric cryptanalysis (Kaplan et al. 2016, Bonnetain et al. 2019) implicitly assumes classical DDT/LAT properties carry over, but does not provide explicit proofs. The paper's claim is therefore reasonable but formally unsupported by citation.

5. **The practical impact is minimal.** The invariance is a property of the function's truth table, which does not change regardless of how it is queried. The paper's conclusion is almost certainly correct, but the gap between "obviously true" and "formally proven in the quantum model" should be acknowledged.

**Score: +10 points** — The claim is likely correct but formally unsupported. No published proof exists for DDT/LAT invariance in the quantum query model, and the paper does not provide one. The paper should either provide a brief proof sketch or acknowledge this as an assumption.

---

## Summary Score

| Claim | Verdict | Points |
|-------|---------|--------|
| Q19: Total gate cost O(2^{163}) | MISLEADING | +10 |
| Q23: Simon's prerequisites | MISLEADING | +10 |
| Q24: Kuwakado & Morii citation | FALSE | +10 |
| Q25: SPM "immune" to Simon's | MISLEADING | +10 |
| Q26: Bonnetain et al. 2019 characterization | MISLEADING | +10 |
| Q29: Quantum speedup on data collection only | MISLEADING | +10 |
| Q30: DDT/LAT invariance in quantum settings | UNSUPPORTED | +10 |
| **Total** | | **70 points** |

---

## Recommendations for Paper Revision

1. **Q19:** Replace raw gate count with NIST-standard DW-cost or MAXDEPTH-constrained cost. At minimum, acknowledge MAXDEPTH constraints and note that the raw gate count is a lower bound on actual attack cost.

2. **Q23:** Restate Simon's prerequisites in terms of the algorithm's actual mathematical requirements (hidden XOR-period function with 2-to-1 promise), then explain why SPM does not expose such structure.

3. **Q24:** Correct the citation to Kuwakado & Morii, ISITA **2012** for Even-Mansour, and ISIT **2010** for 3-round Feistel. Note the Q2 (superposition query) threat model.

4. **Q25:** Replace "immune" with "resistant under current analysis" or "no known Simon-type attack applies." Acknowledge the absence of a formal proof of security against Simon's.

5. **Q26:** Correct the characterization: Bonnetain et al. 2019 analyzed quantum meet-in-the-middle attacks on reduced-round AES; Simon-type attacks in the literature target Even-Mansour/FX constructions instantiated with AES, not simplified AES variants per se.

6. **Q29:** Acknowledge that quantum speedups apply to multiple phases of differential/linear cryptanalysis (data collection, characteristic search, and potentially key recovery), not just data collection. Cite Kaplan et al. 2016 explicitly.

7. **Q30:** Add a brief justification for why DDT/LAT invariance (a property of the function's truth table) transfers to the quantum query model. A one-sentence argument suffices: "DDT/LAT invariance is a property of the function definition, independent of the computational model used to evaluate it."
