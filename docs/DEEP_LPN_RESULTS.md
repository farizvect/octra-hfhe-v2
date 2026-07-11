# Deep LPN-PRF / Related-Key Cryptanalysis — Results

## PRF chain (complete)

```
R = r1 · r2 · r3  (in F_p, p = 2^127-1)

rj = hash_to_fp_nonzero(toep_127(top_j, ybits_j))

ybits_j[i] = <a_i, s> ⊕ e_i     (i=0..16383)
  a_i = AES-CTR(prf_k-derived key, nonce)   — secret
  e_i ~ Ber(1/8)                              — secret noise
  s = sk.lpn_s_bits (4096 bits)               — secret

top_j = AES-CTR(prf_k-derived key, dom_j)    — secret
```

## Findings

### 1. Toeplitz output bit-0 bias (real but not exploitable)

**Measured:** toep output bit 0 = 1 with prob ~0.25 (not 0.5).

**Root cause:** `toep_127` computes GF(2) convolution. Output bit `j` has
exactly `j+1` terms. Bit 0 has 1 term: `ybits[0] * top[0]`. If `top[0]=0`
(prob 0.5), bit 0 is always 0. Average: 0.5 × 0 + 0.5 × 0.5 = 0.25.

**Not exploitable because:**
- `top` is secret (derived from `prf_k`)
- Even if observable, bit 0 = `top[0] * (<a_0,s> + e_0)` — hidden by noise

### 2. Bias washed out by Fp multiplication

`R = r1 · r2 · r3` in F_p (Mersenne p = 2^127-1).

**Mersenne reduction does NOT preserve parity:** `(p-1)·2 mod p = p-2` which
is odd, even though `p-1` is even. Reduction wraps bit 127 to bit 0.

**Measured:** `r1.lo & 1` = 0.254 (biased), but `R.lo & 1` = 0.4845 (uniform).
The product of 3 biased factors in F_p has **uniform** parity.

### 3. R = r1·r2·r3 is degree-3 GF(2) polynomial in s — nonlinear

**Confirmed:** flipping 1 bit of `s` changes r1 by a fixed GF(2) pattern
(linear). XOR of individual flips matches combined flip (linearity holds
for individual rj).

But R = r1·r2·r3 in F_p is **nonlinear** over GF(2) due to Fp multiplication.

### 4. Factoring R into r1·r2·r3 needs DLog

If individual rj were known, each gives 127 **linear** equations in s
(4096 bits). With 44 layers × 3 × 127 = 16,764 equations, s would be
overdetermined and solvable.

**Problem:** R = r1·r2·r3 in F_p. Factoring requires discrete log in F_p^*.
`p-1 = 2·(2^126-1)` — **not smooth**, Pohlig-Hellman infeasible.

### 5. Related-key: rho and R share prf_k but are independent

- `R` via AES-CTR(prf_k) → LPN → Toeplitz → Fp
- `rho` via SHA256(prf_k ‖ nonce)

1-bit flip of `prf_k`: both R and rho change completely (avalanche).
1-bit flip of `lpn_s_bits`: rho unchanged (independent of s).

No algebraic shortcut to combine PC and T constraints.

### 6. Cross-layer PC ratio still Pedersen-hidden

`PC_i / PC_j = g^{Δ(Rinv)} · h^{Δ(rho)}` — two unknowns, still hidden.

### 7. Information-theoretic deficit

| | Bits |
|--|--|
| Unknowns | prf_k(256) + s(4096) + m(2794) + v(~500) ≈ 7646 |
| Public T constraints | 44 × 127 = 5588 (each is v·R product) |
| Public PC constraints | 0 (Pedersen perfectly hiding) |
| **Deficit** | **~2058 bits** |

### 8. Challenge T parity: uniform (no bias)

Challenge T parity: 24/44 odd (54.5%) — consistent with uniform R.

## Conclusion

The Toeplitz bit-0 bias is real but **not exploitable**: it's washed out by
Mersenne Fp multiplication, and the underlying `top`/`s` are secret.

The construction is cryptographically sound under LPN + Pedersen hiding.
No break found through deep LPN-PRF or related-key analysis.

**Plaintext not recovered.**
