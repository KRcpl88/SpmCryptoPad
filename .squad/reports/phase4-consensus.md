# Phase 4: Consensus Synthesis

**Date:** 2026-04-11

## Resolved Disagreements

1. **Key decomposition**: O(2^254), NOT O(2^128). Cascade prevents poly-time S-box verification. Both Turing and Driscoll independently confirmed in Phase 3.
2. **S-box severity**: MEDIUM (Rejewski wins). Absence of indistinguishability proof warrants MEDIUM. Friedman's δ≈2 corrected to δ≈4–6.
3. **Cascade survival**: 61% (Friedman wins). Two errors in Rejewski's model corrected. Diffusion still adequate.
4. **CPA partition attack**: Fails against full cipher (Turing wins). Works only on single-pass model. Also wrong byte (high, not low, on LE).

## Strongest Attack

O(2^254) brute force. No cryptanalytic shortcut found. Side-channel: O(2^127) conditional on S-box leak.

## Most Practical Attack

Ciphertext manipulation — O(1), no key knowledge required. No authentication.

## Consensus Complete — Proceeding to Phase 5 Final Report.
