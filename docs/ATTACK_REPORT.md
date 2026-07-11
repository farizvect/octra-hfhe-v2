# HFHE Challenge v2 — Attack Report

Target wallet: `octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ` (500k OCT)
Repo: `octra-labs/hfhe-challenge` @ final secret.ct (sha256 prefix `5da7f827…`)
Library pin: `pvac_hfhe_cpp@071b0e9`

## Result

**Private key / plaintext NOT recovered.**

v2 is a hardened reissue after the public `R_com` plaintext oracle (v1) was fixed.
No remaining public-only oracle or packaging leak was found.

## Ciphertext facts (live artifact)

| Property | Value |
|----------|--------|
| Bundle | 22 ciphers, wire v3, no `R_com` |
| Encoding | `pvac-text-wrapped` |
| Layers/block | 2 BASE (wrap: Enc(v+m)‖Enc(-m)) |
| Base layers total | 44 |
| Edge weights unique | 1829 (0 collisions) |
| Nonce collisions | 0 |
| Public T = 0 | 0 |
| Native `ru_src` layers | 0 |
| Expected length | 301–315 bytes |
| PC (Pedersen) | 44 valid ristretto points |

## Attack matrix

| # | Approach | Status | Why it fails on v2 |
|---|----------|--------|---------------------|
| 1 | v1 `R_com` oracle (guess x → R=T/x → hash check) | **DEAD** | `R` removed from hash (`cdc6a52`); wire v3 drops `R_com` |
| 2 | Single-layer edge algebra for R | **DEAD** | Scale barrier: all `w_i = R·coef_i`, `T=v·R` — infinite (v,R) pairs |
| 3 | R² pair-sum leak (bounty2 class) | **DEAD** | 0 hits on live CT; regression test designed to stay clean |
| 4 | Zero-plaintext public T leak | **DEAD** | Wrapping forces both layers nonzero |
| 5 | Public-native recrypt (`ru_src`) | **DEAD** | 0/44 layers; ztags match normal PRG |
| 6 | Pedersen PC as oracle | **DEAD** | Needs secret `ρ = H(prf_k‖nonce)`; H≠small·G; no false opens |
| 7 | Nonce / weight / RNG reuse | **DEAD** | No collisions across 44 layers |
| 8 | `pk.bin` secret-key bleed | **DEAD** | Compressed pubkey only; no TAG_SECKEY |
| 9 | Git history / dangling blobs | **DEAD** | No sk.bin / plaintext.txt ever published |
| 10 | Intermediate artifacts (08bf/e464) | **N/A** | Same library pin + wrap; smaller different payload; still no R_com oracle |
| 11 | LPN recovery of mask R | **INFEASIBLE** | n=4096, τ=1/8; samples not public (AES-CTR keyed by sk) |
| 12 | Syndrome decode of σ decoys | **NOT SUFFICIENT** | Even if decoded, yields salt selection not R |
| 13 | Address as BIP39 filter alone | **INFEASIBLE** | ~2^128 without per-block oracle; len 301–315 ≫ 12-word mnemonic |

## Hardness (confirmed by design + formal notes)

Value channel: `T = v · R` with secret LPN-PRF mask `R`.
Security story (Lean formalization `lamafab/octra-hfhe-lean`): confidentiality reduces to LPN; decoy channel is separate syndrome-decoding hardness.

v1 broke **commitment binding of R**, not LPN. v2 removed that commitment content and added additive wrapping so free mask `m` kills residual guess-oracles even if a weak commitment returned.

## What would actually break v2

1. A new public relation that pins absolute scale of `R` (or of `v`) without sk.
2. A generation/packaging bug that reintroduces `R` into a public checkable tag.
3. Leak of `sk.bin` / `plaintext.txt` from the operator machine.
4. Classical break of LPN at these params (not realistic here).

## Tools left in `/home/fariz/codes/hfhe-challenge`

- `full_sweep`, `algebra_lab`, `scale_barrier`, `native_scan`, `pedersen_check`, `idx_scan`, `analyze`, `probe`
- Work copy: `/home/fariz/codes/octra-hfhe-v2/`

## Operator leak hunt (2026-07-09)

| Source | Result |
|--------|--------|
| GH forks of `hfhe-challenge` | Only v1 `seed.ct` trees; no sk/plaintext |
| GH Actions | No workflows |
| `challenge_private` / `sk.bin` code search | Source refs only; no private blobs |
| `octC5eR9…` global code search | README only |
| Org repos (wallet-gen, webcli, …) | No challenge secrets |

### Side finding: `octra-labs/webcli` still ships **v1-vulnerable** pvac

- `compute_R_com_base` still hashes `R.lo/R.hi`
- `enc_text` still uses **unwrapped** `enc_fp_depth`
- Wire **VERSION_V2** still serializes `R_com`

That does **not** help on the v2 challenge artifact (wire v3, wrapped, no R_com).
It does mean webcli itself remains oracle-broken for any text encrypted with its bundled headers.

### PC combine identity

`PC0^{T0} · PC1^{T1}` is **not** a clean Pedersen of `v` under `sc_from_fp`, because
`sc(T)·sc(R^{-1}) ≠ sc(T·R^{-1})` (non-homomorphism). No public `v`-oracle from this either.

## Conclusion

All practical public-artifact attacks that work on v1 or older bounties are closed on this v2 sample.
Recovering the private key from `secret.ct` + `pk.bin` alone currently requires a novel cryptanalytic break beyond known packaging bugs.

**Status: private key not recovered.**
