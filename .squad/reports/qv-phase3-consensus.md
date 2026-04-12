# QV Phase 3 — Consensus Report

**Date:** 2025-07-15
**Coordinator:** Phase 3 Consensus Panel
**Input:** Phase 2 Cross-Review Report (qv-phase2-crossreview.md)

---

## Executive Summary

Phase 2 cross-review resolved all disputes across 32 findings. This Phase 3 report ratifies the consensus and authorizes paper corrections.

**Verdict breakdown:** 8 UPHELD, 19 PARTIALLY REFUTED, 3 REFUTED (+30 points).

**Core thesis status:** SURVIVES. SPM is significantly harder to attack quantumly than AES-256. Headline numbers require downward correction (~1 order of magnitude), but the qualitative advantage remains overwhelming.

---

## Ratified Corrections

### Critical (factual errors — must fix)

| # | Finding | Correction | Consensus Basis |
|---|---------|-----------|----------------|
| 1 | Q10: Reverse S-box in qubit table | Remove — uncomputation makes it free. Total: ~2.1M → ~1.05M qubits | UPHELD unanimously. Standard quantum computing practice (adjoint/dagger). |
| 2 | Q28: Algebraic degree "~2^{16}−1" | Change to "15 (the maximum n−1 for any n-bit permutation)." Qualitative argument preserved. | UPHELD. Multivariate ANF degree bounded by n−1. |
| 3 | Q21: "Quadruples per bit" scaling | Replace with: 512× increase for 8→16 bit jump. Q(b)=b×2^b; ratio approaches 2× per bit for large b. | UPHELD. Mathematical error. |
| 4 | Q6/Q8: AES gate cost "~2^{15}" | Revise to "~2^{17}–2^{19}" cipher-evaluation T-gates. Grassl's 2^{27.5} is full Grover iteration, not cipher-only. | PARTIALLY REFUTED — paper low by ~2^{2}–2^{4}, not Rejewski's claimed 2^{12.5}. |

### Important (missing analysis — must add)

| # | Finding | Correction |
|---|---------|-----------|
| 5 | Hybrid attack omission | Add subsection: hybrid reduces qubits to ~3,000–5,000 but total work O(2^{190+}) — far worse than full Grover's O(2^{163}). Classical loop: ~10^{26} years. |
| 6 | Q18: "2 million×" headline | Revise to "~100,000–500,000× more gates per oracle evaluation." |
| 7 | Q5: AES qubit AES-128/256 confusion | Add note: ~264 qubits applies to AES-128; AES-256 requires ~320–400 qubits. |

### Moderate (imprecise claims — should fix)

| # | Finding | Correction |
|---|---------|-----------|
| 8 | Q3: "Often overlooked" straw man | Soften to "absorbed when treating the oracle as a unit-cost black box in the standard Grover halving metric." |
| 9 | Q23: Simon's prerequisites | Restate in terms of hidden XOR-period, not Even-Mansour-specific conditions. |
| 10 | Q26: Bonnetain characterization | Correct: Simon-type attacks target Even-Mansour/FX constructions, not "simplified AES variants." |
| 11 | Q24: Kuwakado & Morii reference | Add [25] for 2012 ISITA Even-Mansour paper. Update §5.5 citation. |
| 12 | Q27: "23 equations" attribution | Change citation from [8] to [7] (Courtois & Pieprzyk 2002). |

### Minor (transparency — recommended)

| # | Finding | Correction |
|---|---------|-----------|
| 13 | QRAM model footnote | State that analysis uses the explicit quantum circuit model. |
| 14 | MAXDEPTH note | Mention that NIST MAXDEPTH constraints make SPM's deeper oracle even more disadvantageous for attackers. |
| 15 | "Theoretical" vs "concrete" | Clarify distinction in §5.4. |

---

## Preserved Claims (validated — do NOT change)

- "The 16-bit S-box was designed explicitly as a quantum countermeasure" — correct and well-supported
- "SPM is immune to Simon's algorithm" — Phase 2 REFUTED the challenge (Q25, +10 points); acceptable informal usage
- DDT/LAT quantum invariance — Phase 2 REFUTED the challenge (Q30, +10 points); trivially true mathematical identity
- Multi-target Grover omission — Phase 2 REFUTED (not differentially relevant to comparison)
- §4.4 Performance and §4.6 Key Scalability — user-edited sections, preserve as-is

---

## Updated Headline Numbers

| Metric | Old (paper) | Corrected | Change |
|--------|------------|-----------|--------|
| SPM qubits | ~2.1 million | ~1.05 million | −50% (reverse S-box removed) |
| Qubit ratio (SPM/AES) | ~6,500× | ~3,300× | −49% |
| AES gates/oracle | ~2^{15} | ~2^{17}–2^{19} | +4–16× |
| Gate ratio (SPM/AES) | ~2^{21} (2M×) | ~2^{17}–2^{19} (130K–500K×) | Reduced ~4–16× |
| Total gate ratio | ~2^{20} (1M×) | ~2^{16}–2^{18} (65K–260K×) | Reduced ~4–16× |
| AES total gates | ~O(2^{143}) | ~O(2^{145}–2^{147}) | +2^{2}–2^{4} |

---

## Authorization

All corrections listed above are authorized for application to the research paper (spm-cipher-research-paper-2026-04-11.md), §5 (Quantum Cryptanalysis) and §7 (Conclusion).

Phase 3 consensus is COMPLETE. Proceed to Phase 4 (paper update).

---

*Phase 3 Consensus Report completed. Authorized by the cross-review panel.*
