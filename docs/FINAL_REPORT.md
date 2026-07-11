# HFHE Challenge v2 — Final Report

## Target
- **Ciphertext**: `secret.ct` (22 ciphers, wire v3)
- **Plaintext**: wallet private key + metadata, 301-315 bytes
- **Wallet**: `octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ`  
- **Balance**: 500,000 OCT (nonce 0)
- **Address derivation**: `oct` + base58(SHA256(ed25519_pubkey))

## Exhaustive attack surface (all negative)

| Category | Approach | Result |
|----------|----------|--------|
| **v1 oracle** | R_com hash check | Removed — hash ignores R, not on wire v3 |
| **Packaging** | Leaked sk, plaintext, challenge_private | None in git leaks, forks, GH search |
| **Zero-T** | Unwrapped zero plaintext | All 22 ciphers wrapped, T never zero |
| **Edge algebra** | Compute R from weights, R² pairs, GCD | Scale barrier: all weights `×R`, structure homogeneous |
| **Pedersen PC** | Open PC without rho, zero-prf_k, public-rho try | rho has 256-bit secret entropy from prf_k |
| **Wrap bypass** | T0==T1, T0==-T1, small m | No equality; m is uniform F_p^* |
| **Nonce/PC reuse** | Reused nonces or PC values | 44/44 unique |
| **PK analysis** | sk magic in pk.bin, regenerable structure | None; only pubkey material present |
| **Git archaeology** | All commits, dangling blobs | No private files |
| **Intermediate artifacts** | 08bf/e464 hist files | Also v3 + wrapped, same hardening |
| **Toeplitz bit-0 bias** | Fp multiplication washout | Real bias in rj but washed by Mersenne reduction |
| **LPN-PRF cracking** | Factorization R=r1·r2·r3, linear s recovery | Needs DLog in F_p^* (p-1 not smooth) |
| **Related-key** | prf_k shared between R and rho | Independent paths (AES vs SHA256), no shortcut |
| **Multi-instance PC** | 44 PC equations, cross-layer ratios | Still Pedersen-hidden per layer |
| **On-chain** | Transaction data, messages | Simple transfer, no message/memo |
| **Webcli diff** | Old R_com still in webcli hash | Challenge uses hardened lib 071b0e9, not webcli |
| **Address crib** | Known address bytes in plaintext | No oracle to verify guesses |
| **keygen_from_seed** | HFHE keys derived from wallet key | Generator uses `keygen()` (random), independent |

## Root cause of v2 hardness

Encryption `T = v·R` is a **projective relation** in `F_p`. Without an
**inhomogeneous pin** for the absolute scale `R`, the public data determines
`v` only up to a scalar. v1 had `R_com` as the pin. v2 removed it and added
wrapping (`v+m ‖ -m`) which adds a free mask `m`.

The only remaining inhomogeneous public object is the **Pedersen commitment**
`PC = g^{sc(R^{-1})} · h^{ρ(prf_k)}`, which is perfectly hiding without `prf_k`.

## Information-theoretic assessment

- Unknowns: prf_k (256) + lpn_s (4096) + m_i (2794) + v_i (~500) ≈ 7646 bits
- Public T constraints: 44 × 127 = 5588 bits (each is `v·R` product)
- Public PC constraints: 0 bits (Pedersen perfectly hiding)
- **Deficit: ~2058 bits — information-theoretically underdetermined**

## Conclusion

**Plaintext not recovered.** The v2 design successfully closes the v1 oracle
and the scheme is cryptographically sound under LPN + Pedersen hiding
assumptions. No break found after exhaustive analysis of packaging,
implementation, algebra, LPN-PRF, related-key, and on-chain vectors.

Recovering the plaintext from public data alone requires a **novel
cryptanalytic break** — either of the LPN-PRF construction as composed here,
or of the Pedersen commitment with related keys. This is open research, not
a scriptable CTF.

## Remaining (non-trivial) research directions

1. **LPN-PRF factorization**: R = r1·r2·r3 in F_p. If individual rj could
   be recovered, each gives 127 linear equations in the 4096-bit LPN
   secret. Currently blocked by DLog hardness in F_p^* (unsmooth order).

2. **Multi-instance Pedersen with related openings**: 44 commitments
   sharing the same prf_k-derived blindings. Standard Pedersen hiding
   prevents extraction without prf_k, but the related-key structure might
   admit a specialized attack.

3. **Toeplitz channel**: The bit-0 bias in individual rj factors is real
   but washed out by Mersenne F_p multiplication. A deeper analysis of
   the convolution structure might reveal additional correlations.
