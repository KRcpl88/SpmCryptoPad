# Quantum Cryptanalysis of the SPM Block Cipher and Comparison with AES-256

**Date:** April 2026
**Authors:** Cryptanalysis Squad — Turing, Rejewski, Friedman, Driscoll
**Addendum to:** *The SPM Block Cipher: Algorithm Specification, Cryptanalysis, and Comparison with AES-256*

---

## Abstract

We analyze the resistance of the SPM block cipher to quantum cryptanalytic attacks, focusing on Grover's algorithm for key search, Simon's algorithm for structural exploitation, and quantum variants of differential and algebraic attacks. We find that SPM is **significantly more resistant** to quantum attack than AES-256, primarily because its key-dependent S-box imposes an enormous quantum circuit cost on Grover's oracle function, and its lack of algebraic structure eliminates the applicability of Simon's algorithm and quantum algebraic attacks. Under Grover's algorithm, AES-256 provides 128-bit post-quantum security; SPM-256 provides 127-bit post-quantum security in theory, but the practical quantum circuit cost per oracle call is orders of magnitude higher for SPM, making the effective quantum resistance substantially greater.

---

## 1. Background: Quantum Attacks on Symmetric Ciphers

### 1.1 Grover's Algorithm

Grover's algorithm [1] provides a quadratic speedup for unstructured search problems. Applied to brute-force key recovery for an n-bit key cipher, it reduces the search complexity from O(2^n) classical operations to O(2^{n/2}) quantum oracle calls. Each oracle call requires a reversible quantum circuit implementation of the cipher's encryption function.

For a 256-bit key cipher:
- **Classical brute force:** O(2^256)
- **Grover's search:** O(2^128) oracle calls

The critical nuance is that "oracle calls" are not free. Each call requires constructing the cipher as a reversible quantum circuit and executing it in superposition. The total quantum cost is:

$$\text{Total cost} = O(2^{n/2}) \times C_{\text{oracle}}$$

where C_oracle is the quantum circuit cost of one cipher evaluation. The circuit cost — measured in qubits, T-gates, and circuit depth — varies enormously between ciphers and is the decisive factor in practical quantum resistance.

### 1.2 Simon's Algorithm

Simon's algorithm [2] finds hidden periods in functions with exponential speedup (polynomial quantum complexity vs. exponential classical). It has been applied to break Even-Mansour constructions [3], certain Feistel networks, and MAC schemes in polynomial time under the Q2 model (quantum superposition queries to the encryption oracle).

Simon's algorithm requires the target cipher to have exploitable algebraic periodicity — specifically, the existence of a function f(x) = f(x ⊕ s) for a secret period s related to the key.

### 1.3 Quantum Algebraic and Differential Attacks

Quantum computers can provide polynomial speedups to classical algebraic attacks via quantum linear algebra (HHL algorithm) and to differential attacks via quantum amplitude amplification [4]. The applicability of these attacks depends on the cipher's algebraic structure.

---

## 2. Grover's Attack on AES-256

### 2.1 Quantum Circuit for AES

AES-256 has a fixed, publicly known S-box derived from GF(2^8) inversion. This algebraic structure enables highly optimized quantum circuit implementations:

| Resource | Best Known Estimate | Source |
|----------|-------------------|--------|
| Qubits | ~264–320 | Zou et al. 2025 [5]; Huang & Sun 2025 [6] |
| T-gates per evaluation | ~26,000–53,000 | Grassl et al. 2016 [7]; Langenberg et al. 2020 [8] |
| T-depth | ~800–1,600 | Various optimizations [5][6] |
| DW-cost (depth × width) | ~65,000–103,000 | Huang & Sun 2025 [6] |

The AES S-box's algebraic structure (GF(2^8) multiplicative inverse) enables compact quantum implementations using tower field decomposition or composite field arithmetic. The S-box can be expressed as a small number of AND/XOR gates, making each S-box evaluation lightweight in the quantum circuit.

### 2.2 AES-256 Quantum Security

- **Grover oracle calls:** O(2^128)
- **Cost per oracle call:** ~26,000–53,000 T-gates (well-optimized)
- **Total quantum cost:** O(2^128 × 2^{15}) ≈ O(2^{143}) T-gate operations
- **Post-quantum security level:** 128 bits (by Grover halving)

While O(2^128) quantum operations remains far beyond current and near-term quantum hardware, the circuit cost per AES evaluation is well-characterized and relatively compact, making AES the most favorable target for future Grover-based attacks among commonly used ciphers.

---

## 3. Grover's Attack on SPM-256

### 3.1 The Quantum Oracle Problem for SPM

Grover's algorithm requires implementing the cipher's encryption function as a reversible quantum circuit. For SPM, this circuit must include:

1. **S-box generation from the key** (executed in superposition over all candidate keys)
2. **759 cascade S-box lookups** using the generated S-box
3. **Comparison with known ciphertext**

Each component presents unique challenges that dramatically increase the quantum circuit cost compared to AES.

### 3.2 Quantum Cost of Key-Dependent S-box Generation

The most consequential difference between SPM and AES is that SPM's S-box is key-dependent and must be computed **inside the Grover oracle** for each key candidate tested in superposition.

**S-box generation requires:**
- 16 passes × 65,536 swap operations = 1,048,576 PRNG-driven swaps
- Each swap requires: PRNG state update, random index generation, and a conditional swap of two 16-bit entries in a 65,536-entry table
- The entire 65,536-entry permutation table (131,072 bytes) must be maintained in quantum registers

**Quantum register requirements for the S-box alone:**

| Component | Qubits Required |
|-----------|----------------|
| S-box table (65,536 × 16-bit entries) | 1,048,576 qubits |
| Reverse S-box table | 1,048,576 qubits |
| PRNG state registers | ~192 qubits |
| Swap operation ancillae | ~64 qubits |
| Block state (128 bytes) | 1,024 qubits |
| Mask values and intermediate state | ~2,048 qubits |
| **Minimum total** | **~2,099,904 qubits** |

Compare to AES's ~264–320 qubits. **SPM requires approximately 6,500× more qubits than AES** just to hold the S-box in quantum registers.

### 3.3 Quantum Circuit Depth for S-box Generation

Each of the 1,048,576 shuffle swaps requires:
1. A PRNG Rand() call (addition mod 2^64, slice extraction) — ~64 T-gates
2. A conditional swap of two 16-bit values at computed addresses in the S-box register — this requires quantum RAM (QRAM) addressing into a 65,536-entry table

**The QRAM problem:** Addressing a specific entry in a quantum register of 65,536 elements requires a quantum multiplexer circuit with O(65,536) = O(2^16) controlled operations. Each swap step thus costs O(2^16) gates for address decoding alone.

**Total gate cost for S-box generation:**
$$C_{\text{sbox}} \approx 1,048,576 \times O(2^{16}) \approx O(2^{36}) \text{ gates}$$

This is approximately **2^{21} times more expensive** than an entire AES evaluation (~2^{15} T-gates).

### 3.4 Quantum Circuit for Cascade Encryption

After S-box generation, the 759 cascade steps each require:
1. PRNG Rand() call for mask: ~64 T-gates
2. XOR mask with 2-byte window: ~16 CNOT gates
3. S-box lookup: QRAM access into the 65,536-entry quantum S-box register — O(2^16) gates per lookup

**Total gate cost for cascade encryption:**
$$C_{\text{encrypt}} \approx 759 \times O(2^{16}) \approx O(2^{26}) \text{ gates}$$

### 3.5 Total Grover Oracle Cost for SPM

$$C_{\text{oracle}}^{\text{SPM}} \approx C_{\text{sbox}} + C_{\text{encrypt}} \approx O(2^{36}) + O(2^{26}) \approx O(2^{36})$$

The S-box generation dominates the oracle cost.

### 3.6 SPM-256 Quantum Security

- **Grover oracle calls:** O(2^{254/2}) = O(2^{127})
- **Cost per oracle call:** O(2^{36}) gates (dominated by S-box generation)
- **Total quantum cost:** O(2^{127} × 2^{36}) = **O(2^{163})** gate operations
- **Qubit requirement:** ~2.1 million qubits (vs. ~320 for AES)

### 3.7 Comparison: Grover's Attack Quantum Resources

| Resource | AES-256 | SPM-256 | Ratio (SPM/AES) |
|----------|---------|---------|-----------------|
| Grover oracle calls | O(2^{128}) | O(2^{127}) | ~0.5× |
| Qubits required | ~320 | ~2,100,000 | **~6,500×** |
| Gates per oracle call | ~2^{15} | ~2^{36} | **~2^{21}×** |
| Total gate operations | ~2^{143} | ~2^{163} | **~2^{20}×** |
| Post-quantum security (theoretical) | 128 bits | 127 bits | ~Equal |
| Post-quantum security (practical) | 128 bits | **>>127 bits** | **SPM much harder** |

**The theoretical post-quantum security levels are nearly identical** (128 vs 127 bits by the Grover halving metric). However, the **practical quantum resistance of SPM is dramatically higher** due to the ~2^{21}× greater gate cost per oracle call and ~6,500× greater qubit requirement. A quantum computer capable of attacking AES-256 would need to be approximately **6,500 times larger** (in qubit count) and perform **2 million times more gate operations** (per oracle call) to attack SPM-256.

---

## 4. Simon's Algorithm: Not Applicable to SPM

Simon's algorithm provides exponential speedup against ciphers with exploitable algebraic periodicity. The canonical target is the Even-Mansour construction: E_K(x) = P(x ⊕ K_1) ⊕ K_2, where P is a public permutation. Defining f(x) = E_K(x) ⊕ P(x), the function has period K_1, which Simon's algorithm recovers in polynomial time [3].

**Requirements for Simon's attack:**
1. A public permutation P that the attacker can evaluate independently
2. The key enters as an XOR with the input or output (additive key mixing)
3. Quantum superposition access to the encryption oracle (Q2 model)

**Why Simon's algorithm does not apply to SPM:**

1. **No public permutation.** SPM's S-box is key-dependent and entirely secret. The attacker has no access to the underlying permutation without the key. There is no "P" to query independently.

2. **No additive key structure.** While SPM uses XOR masks, the masks are consumed inside a 759-step cascade where each step's output feeds into the next step's input. The key's effect on the ciphertext is not a simple XOR — it is the composition of 759 nonlinear substitutions with key-dependent input modifications. There is no function f(x) = f(x ⊕ s) with a key-related period s.

3. **Key-dependent nonlinearity.** In Even-Mansour, the permutation P is key-independent — the key affects only the input/output whitening. In SPM, the key determines the S-box itself. Every nonlinear operation inside the cipher is key-dependent, eliminating the separation between "public structure" and "secret key" that Simon's attack exploits.

**Comparison with AES:** AES also resists Simon's algorithm because its key enters through the key schedule (not simple XOR whitening) and the S-box is applied in combination with multiple round key additions. However, AES's S-box is public, which means Simon-type attacks on simplified AES variants (reduced rounds, Even-Mansour-like constructions) have been demonstrated in the literature [3][9]. For SPM, even simplified variants resist Simon's attack because the S-box is secret.

---

## 5. Quantum Algebraic Attacks

Classical algebraic attacks on AES exploit the S-box's compact polynomial representation (degree-254 in GF(2^8), or 23 quadratic equations per S-box in GF(2)) [10]. Quantum computers can accelerate the solution of such systems via:

- **Quantum Gröbner basis computation:** Polynomial speedup over classical Buchberger/F4/F5 algorithms
- **HHL algorithm for linear subsystems:** Exponential speedup for linear algebra components
- **Quantum SAT solving:** Quadratic speedup via Grover-enhanced backtracking

**For AES:** The algebraic system (23 quadratic equations per S-box × 224 S-boxes = 5,152 equations) is well-characterized. While no practical algebraic attack on full AES exists classically, the compact algebraic description means quantum algebraic algorithms have a well-defined target system to work with.

**For SPM:** The S-box has **no compact algebraic description**. A random 16-bit permutation requires specification of all 65,536 input-output pairs — there is no low-degree polynomial representation. The algebraic system for SPM encryption would consist of 759 applications of this high-degree permutation, each coupled through the cascade. This system is intractable for classical algebraic solvers, and quantum speedups (which are polynomial or quadratic) applied to an already-intractable base complexity yield no practical improvement.

**Verdict:** Quantum algebraic attacks are inapplicable to SPM. The absence of algebraic structure is a **quantum advantage** for SPM over AES.

---

## 6. Quantum Differential and Linear Attacks

Quantum computers can enhance differential and linear cryptanalysis through:

- **Amplitude amplification:** Quadratic speedup for finding conforming pairs (differential) or estimating biases (linear)
- **Quantum counting:** More efficient estimation of differential probabilities

**For AES:** The fixed, public DDT and LAT enable precomputation of optimal characteristics. Quantum amplitude amplification could theoretically improve the data complexity of differential attacks by a square root factor. However, since no practical classical differential attack on full AES exists, the quantum speedup applies to an already-infeasible attack.

**For SPM:** The DDT and LAT are key-dependent and unknown to the attacker. Quantum differential attacks face the same barrier as classical ones: the attacker must first recover the S-box to compute differential characteristics, which requires the key. Amplitude amplification provides no benefit when the base attack requires key knowledge.

Additionally, we proved in the main paper (Theorems 1 and 2) that XOR masks are transparent to differential and linear analysis. This transparency is a structural property that holds in both classical and quantum settings — no quantum algorithm can extract information from the masks that is invisible to classical analysis.

**Verdict:** SPM's key-dependent S-box makes quantum-enhanced differential and linear attacks no more effective than their classical counterparts (which are already infeasible).

---

## 7. Quantum Side-Channel Hybrid Attacks

In a hybrid scenario where the S-box is leaked via classical side-channel attack (cache-timing), the remaining search space is the 127-bit mask PRNG key.

**Grover on the remaining 127-bit mask key:**
- Oracle calls: O(2^{63.5})
- Cost per oracle call: 759 S-box lookups (S-box is now known, not in quantum registers) ≈ O(759) ≈ O(2^{10})
- Total quantum cost: O(2^{73.5}) gate operations
- Qubits required: ~1,200 (block state + PRNG state + ancillae — no S-box table in registers)

This is a significantly more tractable quantum attack than the full-key Grover search, though O(2^{63.5}) quantum oracle calls still far exceeds current quantum computing capabilities.

**Comparison:** AES-256 under Grover's attack requires ~320 qubits and O(2^{143}) gates. SPM-256 under the side-channel hybrid requires ~1,200 qubits and O(2^{73.5}) gates. The hybrid attack on SPM is computationally easier than Grover on AES, but requires a successful prior side-channel attack — a much stronger threat model.

---

## 8. Summary Comparison: Quantum Resistance

| Attack | AES-256 Quantum Cost | SPM-256 Quantum Cost | Advantage |
|--------|---------------------|---------------------|-----------|
| **Grover key search** | O(2^{143}) gates, ~320 qubits | O(2^{163}) gates, ~2.1M qubits | **SPM** (2^{20}× harder, 6,500× more qubits) |
| **Simon's algorithm** | Not applicable (no Even-Mansour structure) | Not applicable (key-dependent S-box) | **Tie** |
| **Quantum algebraic** | Theoretically applicable (compact S-box algebra) | Not applicable (no algebraic structure) | **SPM** |
| **Quantum differential** | Quadratic speedup on infeasible base | Same barrier + unknown DDT | **SPM** |
| **Quantum linear** | Quadratic speedup on infeasible base | Same barrier + unknown LAT | **SPM** |
| **Side-channel + Grover** | N/A (no key partition) | O(2^{73.5}) gates, ~1,200 qubits | **AES** (no side-channel partition) |

### Overall Quantum Resistance Ranking

**SPM-256 is more resistant to quantum attacks than AES-256** across every pure cryptanalytic dimension:

1. **Grover's algorithm:** Both provide ~127–128 bits of theoretical post-quantum security (by the halving metric), but SPM's oracle cost is ~2^{21}× higher per call, making the practical quantum attack enormously more expensive. A quantum computer designed to break AES-256 would be entirely inadequate for SPM-256 — it would need ~6,500× more qubits.

2. **Beyond-Grover attacks:** Simon's algorithm and quantum algebraic attacks, which could theoretically threaten simplified AES variants, are fundamentally inapplicable to SPM due to its key-dependent S-box and absence of algebraic structure.

3. **Quantum differential/linear:** SPM's unknown DDT/LAT provides a strictly stronger barrier than AES's public tables.

The one dimension where AES has an advantage is the **absence of a key partition exploitable by side-channel + Grover hybrid attacks**. SPM's clean key split means that a side-channel leak of the S-box reduces the quantum search space to 2^{63.5} oracle calls (127-bit mask key under Grover), while AES has no analogous partition. However, this requires a successful side-channel attack as a prerequisite — a stronger threat model than pure quantum cryptanalysis.

---

## 9. The Key-Dependent S-box as a Quantum Defense Mechanism

The most significant finding of this analysis is that SPM's 16-bit key-dependent S-box — **designed explicitly as a countermeasure against quantum attacks** by maximizing the degree of nonlinearity — provides quantum resistance through two reinforcing mechanisms:

### 9.1 Oracle Cost Amplification

A fixed S-box (like AES's) can be hardwired into a quantum circuit using a modest number of gates. A key-dependent S-box must be **computed inside the oracle** in superposition — the S-box generation becomes part of the quantum circuit for each Grover iteration. For SPM, this computation involves 1,048,576 PRNG-driven swaps over a 65,536-entry table, requiring ~2 million qubits and ~2^{36} gates. This transforms a "lightweight" oracle call into a "heavyweight" one, multiplying the total quantum work by a factor of ~2^{21} compared to AES.

### 9.2 Algebraic Structure Elimination

Quantum algorithms beyond Grover (Simon, HHL, quantum algebraic solvers) exploit algebraic structure in the target function. AES's GF(2^8) S-box has a compact polynomial description that enables algebraic formulations. SPM's PRNG-generated S-box has no such description — it is (for practical purposes) a random permutation drawn from a key-dependent distribution. This eliminates the algebraic "handles" that beyond-Grover quantum algorithms require, confining the quantum attacker to generic search (Grover) as the only applicable strategy.

Together, these properties make SPM an inherently more quantum-resistant design than fixed-S-box ciphers. The 16-bit S-box width was chosen specifically to maximize nonlinearity and impose extraordinary quantum circuit costs — a design decision that produces a 6,500× qubit advantage and a 2-million-fold gate cost advantage over AES's 8-bit fixed S-box.

---

## 10. Conclusion

SPM-256 provides **stronger quantum resistance than AES-256** by every pure cryptanalytic measure. The theoretical post-quantum security levels are comparable (~127 vs. 128 bits under Grover halving), but the practical quantum attack cost is dramatically higher for SPM:

- **~2 million qubits** vs. ~320 for AES (6,500× more)
- **~2^{163} total gate operations** vs. ~2^{143} for AES (2^{20}× more)
- **No applicability** of Simon's algorithm, quantum algebraic attacks, or quantum-enhanced differential/linear attacks

The key-dependent 16-bit S-box, designed explicitly to maximize nonlinearity as a quantum countermeasure, dramatically increases the quantum oracle cost and eliminates the algebraic structure that beyond-Grover attacks exploit. SPM's unlimited key scalability further ensures that post-quantum security margins can be increased without architectural changes — a capability AES does not possess.

---

## References

[1] L. K. Grover, "A Fast Quantum Mechanical Algorithm for Database Search," in *Proceedings of the 28th Annual ACM Symposium on Theory of Computing (STOC)*, 1996, pp. 212–219.

[2] D. R. Simon, "On the Power of Quantum Computation," *SIAM Journal on Computing*, vol. 26, no. 5, pp. 1474–1483, 1997.

[3] H. Kuwakado and M. Morii, "Quantum Distinguisher Between the 3-Round Feistel Cipher and the Random Permutation," in *IEEE International Symposium on Information Theory (ISIT)*, 2010, pp. 2682–2685.

[4] G. Brassard, P. Høyer, and A. Tapp, "Quantum Cryptanalysis of Hash and Claw-Free Functions," in *LATIN '98*, Springer, 1998, pp. 163–169.

[5] J. Zou, L. Li, and Z. Wei, "Quantum Circuit for Implementing AES S-box with Low Costs," *Quantum Information Processing*, vol. 25, 2025.

[6] Z. Huang and S. Sun, "Quantum Circuit Synthesis for AES with Low DW-Cost," in *Advances in Cryptology*, Springer, 2025.

[7] M. Grassl, B. Langenberg, M. Roetteler, and R. Steinwandt, "Applying Grover's Algorithm to AES: Quantum Resource Estimates," in *Post-Quantum Cryptography — PQCrypto 2016*, Springer, 2016, pp. 29–43.

[8] B. Langenberg, H. Pham, and R. Steinwandt, "Reducing the Cost of Implementing the Advanced Encryption Standard as a Quantum Circuit," *IEEE Transactions on Quantum Engineering*, vol. 1, pp. 1–12, 2020.

[9] A. Bonnetain, M. Naya-Plasencia, and A. Schrottenloher, "Beyond Quadratic Speedups in Quantum Attacks on Symmetric Schemes," *IACR ePrint*, 2023.

[10] S. Murphy and M. Robshaw, "Essential Algebraic Structure within the AES," in *Advances in Cryptology — CRYPTO 2002*, Springer, 2002, pp. 1–16.

[11] A. Bogdanov, D. Khovratovich, and C. Rechberger, "Biclique Cryptanalysis of the Full AES," in *Advances in Cryptology — ASIACRYPT 2011*, Springer, 2011, pp. 344–371.

[12] D. J. Bernstein, "Cost Analysis of Hash Collisions: Will Quantum Computers Make SHARCS Obsolete?" in *SHARCS '09*, 2009.

---

*Addendum prepared April 2026. To be read in conjunction with the main paper: "The SPM Block Cipher: Algorithm Specification, Cryptanalysis, and Comparison with AES-256."*
