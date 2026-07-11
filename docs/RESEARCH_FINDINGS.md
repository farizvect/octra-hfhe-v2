# HFHE v2 — Pure Cryptanalysis Research Log

## Mathematical core

Encryption of a field element `v` produces public
```
T = Σ sgn(e) · w_e · g_{idx(e)} = v · R
```
with every edge weight `w_e = R · coef_e`.

### Theorem (scale homogeneity)

If `(w_e, T)` is consistent with mask `R` and plaintext `v`, then for every
`λ ∈ F_p^*`, the scaled public data `(λ w_e, λ T)` is consistent with mask
`λR` and the **same** plaintext `v`.

All N2 / N3 / signal linear relations are homogeneous of degree 1 in the
weights. Therefore they are invariant under rescaling and **cannot determine
the absolute scale `R`**.

**Lab confirmation** (`research_lab`):
- weight ratios invariant under scale: yes
- structure score(true R) = structure score(random R) for 200 trials
- integer-GCD of weights never recovers R

### Wrapping

```
T0 = (v+m)·R0
T1 = (−m)·R1
```
`m ← F_p^*` uniform (lab: 0/100 “small” under 2^40).  
2 equations, 4 unknowns → still free after fixing any candidate `v`.

### Pedersen PC

```
PC = g^{sc(R^{-1})} · h^{ρ},  ρ = SHA256(prf_k ‖ nonce ‖ j)
```
- Opening needs `ρ` (secret `prf_k`)
- `sc_from_fp` is a homomorphism on small integers, **never** on random field
  elements (0/500 hits) → `PC^{T}` is not a clean Pedersen of `v`
- Multi-layer identity `Q = PC / g^{sc(Rinv)} = h^ρ` holds with sk; without
  sk, discrete log base `h` is required

### LPN-PRF mask

```
R = r1·r2·r3,  ri = ToeplitzExtract(LPN_ybits(AES_k(seed, dom_i)))
k = SHA256(prf_k ‖ canon_tag ‖ H_digest ‖ seed ‖ dom)
```
Parameters: `n=4096`, `t=16384`, `τ=1/8`.

**Critical:** LPN samples `(A,y)` are **not public**. The AES key that
generates them depends on `sk.prf_k`. There is no LPN instance to feed an
ISD/BKW solver from the ciphertext alone.

### What v1 had and v2 removed

| | v1 | v2 |
|--|----|----|
| `R_com` contents | hash includes `R` | hash ignores `R` |
| `R_com` on wire | yes (v2 wire) | no (v3 wire) |
| text encoding | raw single-layer | wrapped two-layer |
| public pin for `R` | yes (oracle) | **none** |

## Exhaustive public-only attacks attempted

1. Edge-algebra / R² pair sums  
2. Integer GCD of weights  
3. Combinatorial N2/N3/signal partition scores  
4. Ghost-edge (w=0) leakage  
5. Zero-T / native `ru_src`  
6. PC opening with weak/zero `prf_k`  
7. `PC0^{T0}·PC1^{T1}` as commitment to `v`  
8. Wrap-mask `m` smallness  
9. Nonce/weight reuse  
10. Salt recovery (64-bit, useless for R even if done)

All negative.

## Information-theoretic statement

Public data determines the **projective** ray of the weight vector, not its
scale. The plaintext `v = T/R` is exactly the missing scale. Any attack must
introduce an **inhomogeneous** constraint on `R` from:
- a checkable commitment to `R` (removed),
- an opening of PC (needs sk),
- recovery of `sk` via LPN/PRF (samples hidden),
- or a new implementation bug not present in `071b0e9` + this artifact.

## Pin inventory (opening absolute scale R)

| Public object | Depends on R? | Pin usable? | Why |
|---|---|---|---|
| Edge weights / T | yes, **homogeneous** | NO | any λ-scale still consistent |
| `R_com` (v1) | yes (old hash) | **REMOVED** | hash no longer includes R; not on wire v3 |
| `PC` (Pedersen) | yes, **inhomogeneous** | **LOCKED** | `PC = g^{sc(R^{-1})} h^{ρ(prf_k)}`; ρ has 256-bit secret entropy |
| sigma / decoy | no | NO | independent of R |
| wrap mask m | free | blocks plaintext pin | uniform F_p^* |

Lab (`pin_open.cpp`):
- PC ≠ g^{Rinv}, g^R, g^T, ped(Rinv,R), ped(Rinv,Rinv), ped(Rinv,Rbytes)
- structured (L,m) + public-rho open attempts on challenge length cipher: **0 hits**

**Conclusion:** the only remaining public pin to R is PC, and it is
cryptographically locked by secret `prf_k` via ρ. Opening that pin without sk
is equivalent to breaking Pedersen hiding or recovering `prf_k`/LPN secret.

## Status

**Private key not recovered. Pin to R remains closed.**
