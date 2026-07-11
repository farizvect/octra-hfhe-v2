# Lane 2 — Implementation defect hunt (this artifact)

Target generation path (`source/hfhe_bounty_artifact.cpp` `generate()`):
1. `keygen(prm, pk, sk)` — CSPRNG
2. read `challenge_private/plaintext.txt`
3. `enc_text(pk, sk, plain)` — wrapped text path
4. write public `pk.bin` + `secret.ct`; private `sk.bin`

Pinned library: `071b0e9` (R_com de-oracle’d + wrap in tree).

## Checks run

| Check | Result |
|--------|--------|
| Nonce uniqueness (44 base layers) | **all unique**, 0 dups |
| ztag uniqueness | **all unique** |
| All ciphers wrapped (2 BASE) | **yes** (22/22) |
| T0==T1 or T0==-T1 | **0** |
| PC uniqueness | **44/44 unique** |
| R_com on wire / in memory after deserialize | **absent / zero** |
| c0 | size 1, **value 0** (normal) |
| Zero-weight edges | **0** |
| Low Hamming-weight weights (≤8/128) | **0/1829** |
| Weight bit bias | only forced `hi.bit63=0` (field MASK63) |
| powg_B roots integrity | **ok** |
| H / ubk regenerable from public canon_tag | **yes** |
| sk magic inside pk.bin raw | **not found** |
| secret.ct trailing bytes | **0** |
| Git objects for sk/plaintext/challenge_private | **none** (only source refs) |
| GH code search for address / challenge_private sk | **public README only** |
| Intermediate hist CTs (08bf/e464) | also **v3 + wrapped** |
| RNG path | `getrandom` / `/dev/urandom` (abort on fail) |
| Selector bias `csprng % 337` | slight modulo bias only; no R pin |
| Zero-plaintext raw leak (T=0) | fixed by wrap; challenge uses wrap |

## Generation code review notes

- `sk.bin` only written under `challenge_private/` with mode `0600` — not in public bundle / SHA256SUMS.
- `public_root()` when `source/` exists uses CWD as public dir; private is `../challenge_private` — private tree not in published repo.
- `enc_text` → length via `enc_value` (wrapped depth 0) + data blocks via `enc_fp_wrapped_depth` (depth 2,3,…).
- Fuse of wrap layers keeps independent seeds/R per layer.
- No alternate seeded encrypt path in `generate()`.

## Defect classes ruled out for *this* sample

1. Accidental R_com left on wire  
2. Unwrapped text / zero-T leak  
3. Nonce or PC reuse  
4. sk embedded in pk or ct  
5. Published private dir / git blob leak  
6. Degenerate roots / regenerable key material  
7. Obvious stego in weight high bits  
8. Structured wrap mask (T0±T1 identities)

## Residual (not observed as a bug)

The only public inhomogeneous binding of R is still:

```
PC = g^{sc(R^{-1})} · h^{ρ(prf_k)}
```

That is intentional Pedersen hiding, not a generation defect.

## Status

**No implementation defect found that opens the pin to R or recovers plaintext on this artifact.**
