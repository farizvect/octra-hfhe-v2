# HFHE v2 Challenge — Cryptanalysis Repository

**Target**: Recover plaintext from `secret.ct` — contains private key for Octra wallet `octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ` (500,000 OCT, nonce 0).

**Status**: LPN samples released 2026-07-11 (commit `d9d29d5`). Active work on LPN recovery + wrap ratio attack.

---

## Repository Structure

```
.
├── README.md                  # This file
├── Makefile                   # Build all tools
├── challenge_source/          # Original challenge generator source
├── data/                      # Manifest, params, SHA256SUMS, pvac_commit
├── docs/                      # Analysis reports
├── tools/
│   ├── analysis/              # Structure parsers, verifiers
│   ├── attack/                # Algebraic, bias, PC, LPN attacks
│   └── lpn/                   # LPN sample analysis + ratio tests
├── solver/                    # Earlier solver attempts (pre-LPN)
├── hist/                      # Historical challenge versions
├── challenge/                 # Legacy challenge directory
└── pvac_hfhe_cpp/             # Pinned library (commit 071b0e9)
```

## Challenge Structure

### Ciphertext (`secret.ct`)
- **22 ciphers**, wire format **v3** (no `R_com`)
- Each cipher: **1 slot**, **2 BASE layers** (wrapping)
- **Total**: 44 base layers, 1829 edges
- Plaintext: 301-315 bytes (1 length cipher + 21 data blocks × 15 bytes)
- Encoding: `pvac-text-wrapped`

### Encryption per cipher (`enc_fp_wrapped_depth`)
```
T0_i = (v_i + m_i) · R0_i      (layer 0)
T1_i = (-m_i) · R1_i           (layer 1)
```
Where `R0_i`, `R1_i` are PRF outputs: `R = prf_R_core(R1) · prf_R_core(R2) · prf_R_core(R3)`.

### Public key (`pk.bin`)
- Field: `F_p` with `p = 2^127 - 1`
- Base: `B = 337` (prime divisor of p-1)
- LPN: `n = 4096`, `t = 16384`, `τ = 1/8`
- `canon_tag = 0x760802093a19931`
- Pedersen PC per layer: `PC = g^{sc(R^{-1})} · h^{ρ(prf_k)}`

## v1 vs v2 Hardening

| Feature | v1 (broken) | v2 |
|---------|-------------|-----|
| **R_com oracle** | Hash includes R → plaintext oracle | Hash excludes R → no oracle |
| **Text encoding** | Unwrapped (single layer) | Wrapped (`Enc(v+m) ‖ Enc(-m)`) |
| **Wire format** | v2 (R_com on wire) | v3 (R_com absent) |
| **Pedersen PC** | Not present | Present (hiding R behind ρ) |

## Attack Surface — What We've Tried

### ✅ Confirmed: No Defects
- Wire format: clean, no `R_com`, no extra data
- All 44 nonces unique, no reuse
- All PCs valid, no zero-weight edges
- `c0` all zeros, no trailing bytes
- No native-source layers (all wrapped)

### ✅ Confirmed: Algebraic Barriers
- **Scale invariance**: T = v·R, PC = g^{sc(R⁻¹)}·h^ρ. Public data homogeneous in R.
- **Toeplitz bias**: Bit-0 bias (P=0.2476) washes out after F_p multiplication
- **Pedersen hiding**: Perfect hiding without `prf_k` (256 bits of blinding)
- **No linear invariants**: Public T values carry no extractable pattern

### 🔄 In Progress: LPN Sample Attack

**Octra released 44 JSONL files** (commit `d9d29d5`) containing:
- 16384 LPN samples per layer for **PRF_R1 domain only**
- Each sample: `(a_i, y_i)` where `y_i = ⟨a_i, s⟩ ⊕ e_i`, τ=1/8
- Total: 720,896 samples sharing the same `s` (lpn_s_bits, 4096 bits)
- All match challenge nonces/T values → authentic for this ciphertext

**Status**: Multiple LPN solvers attempted (Gaussian elimination with majority voting, belief propagation, bit-flip gradient descent) — none converge for n=4096/τ=1/8 on laptop hardware.

### 🔄 In Progress: Wrap Ratio + LPN Bridge

Per Octra documentation, the intended attack path:

1. **PRF_R1 ybits from LPN samples** confirm which component is shared
2. **Wrap ratio** `T0_i/T1_i = -(v_i+m_i)/m_i · (u0_i/u1_i)` where `u = r2·r3`
3. If `u0/u1 = 1` (shared R2/R3 or known constant), then:
   ```
   k = T0_i/T1_i = -(v+m)/m  →  v = m·(k - 1)
   ```
4. With `v` expressed in terms of `m`, brute-force/enumerate potential `m` values
5. Verify against wallet address + ciphertext structure

**Caveat**: In the actual implementation at `071b0e9`, the two wrapped layers use DIFFERENT seeds → different PRF_R1 values → no direct cancellation. The ratio approach may require a modified interpretation or the ratio of `u0/u1` (R2·R3 components) may have exploitable structure.

### Key Open Question

Does the `u0/u1 = r2_0·r3_0 / (r2_1·r3_1)` ratio simplify? The LPN samples are only for PRF_R1 — the R2/R3 ybits are NOT released. If R2/R3 cancel in some way (same seed, same output, or known constant ratio), the wrap attack becomes feasible. Otherwise, we need:
1. Solve LPN to recover `s`
2. Use `s` + LPN samples + wrap equations to determine `prf_k` or bypass the Toeplitz

## Key Constants

```
Wallet:     octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ
Address hash (decoded): a4a12fb15de6fd821f9415a2ae23c9483cd80b0256f787d6765b0c7f4d41aef2
canon_tag:  0x760802093a19931
Library:    071b0e909c119de815e284b347c4bd979cb59ef3
B:          337
p:          2^127 - 1
lpn_n:      4096
lpn_t:      16384
lpn_tau:    1/8
```

## Build

```bash
# Requires pvac_hfhe_cpp at ../pvac_hfhe_cpp
# Set PVAC_INCLUDE if different
make all
```

## Tool Index

| Tool | Purpose | Result |
|------|---------|--------|
| `tools/analysis/analyze.cpp` | Parse secret.ct structure | 22 ciphers, 44 BASE, v3 wire |
| `tools/analysis/verify_all.cpp` | Full validation | All 32 checks PASS |
| `tools/analysis/dump_real.cpp` | Dump nonces, edge counts | All unique, wrapped |
| `tools/analysis/native_scan.cpp` | Find native-source layers | 0 found |
| `tools/attack/algebra_lab.cpp` | Edge algebra analysis | Scale barrier confirmed |
| `tools/attack/scale_barrier.cpp` | Information-theoretic bound | ~2058-bit deficit |
| `tools/attack/pedersen_check.cpp` | Pedersen H = k·G? | No — H not small multiple |
| `tools/attack/check_rcom.cpp` | R_com on wire? | No — v3 omits it |
| `tools/attack/pc_combine.cpp` | PC homomorphic check | Not a public oracle |
| `tools/attack/pin_open.cpp` | All algebraic pins | None hold |
| `tools/attack/full_sweep.cpp` | R², zero-T, weight reuse | All negative |
| `tools/attack/defect_scan.cpp` | Implementation defects | Clean |
| `tools/attack/deep_lpn.cpp` | LPN-PRF analysis | No public sample access |
| `tools/attack/bias_deep.cpp` | Toeplitz bias chain | Washed out by F_p |
| `tools/attack/toep_analysis.cpp` | Bias quantification | No distinguisher |
| `tools/lpn/lpn_solve.cpp` | LPN Gaussian elimination | Rank deficient |
| `tools/lpn/lpn_solve2.cpp` | LPN bit-majority voting | 50% (random) |
| `tools/lpn/lpn_bp.cpp` | LPN belief propagation | No convergence |
| `tools/lpn/lpn_gd.cpp` | LPN gradient descent | 50.5% (stuck) |
| `tools/lpn/ratio_test.cpp` | r1 shared between layers? | **No** — seeds differ |
| `tools/lpn/challenge_ratio.cpp` | Challenge T0/T1 ratios | All different |
| `tools/lpn/try_ratio.cpp` | Ratio algebra attempt | Needs R0/R1 ratio |
