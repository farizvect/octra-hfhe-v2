// Algebraic lab: known-key encryption → hunt public-only invariants for R or v.
#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <map>
#include <set>
#include <vector>

using namespace pvac;

static bool eq(const Fp& a, const Fp& b) { return a.lo == b.lo && a.hi == b.hi; }
static bool is0(const Fp& a) { return a.lo == 0 && a.hi == 0; }

static Fp layer_T(const PubKey& pk, const Cipher& C, uint32_t lid) {
    Fp acc = (lid == 0 && !C.c0.empty()) ? C.c0[0] : fp_from_u64(0);
    for (const auto& e : C.E) {
        if (e.layer_id != lid) continue;
        Fp t = fp_mul(e.w[0], pk.powg_B[e.idx]);
        if (sgn_val(e.ch) < 0) t = fp_neg(t);
        acc = fp_add(acc, t);
    }
    return acc;
}

struct EdgeView {
    size_t i;
    uint16_t idx;
    uint8_t ch;
    Fp w;
    Fp term; // signed w * g
};

static std::vector<EdgeView> layer_edges(const PubKey& pk, const Cipher& C, uint32_t lid) {
    std::vector<EdgeView> out;
    for (size_t i = 0; i < C.E.size(); ++i) {
        const auto& e = C.E[i];
        if (e.layer_id != lid) continue;
        Fp t = fp_mul(e.w[0], pk.powg_B[e.idx]);
        if (sgn_val(e.ch) < 0) t = fp_neg(t);
        out.push_back({i, e.idx, e.ch, e.w[0], t});
    }
    return out;
}

// How often is some simple combination of edge terms equal to R, R^2, v*R, etc?
static void hunt_R_forms(const PubKey& pk, const Cipher& C, uint32_t lid,
                         const Fp& R, const Fp& x /* plaintext on this layer */,
                         const char* tag) {
    auto E = layer_edges(pk, C, lid);
    Fp T = layer_T(pk, C, lid);
    Fp R2 = fp_mul(R, R);
    Fp xR = fp_mul(x, R);
    std::cout << "\n== " << tag << " lid=" << lid
              << " edges=" << E.size()
              << " T==xR:" << eq(T, xR)
              << " x=" << x.lo << " ==0:" << is0(x) << "\n";

    int hit_R = 0, hit_R2 = 0, hit_negR = 0, hit_negR2 = 0;
    int hit_pair_R2 = 0, hit_pair_R = 0;
    int hit_w_eq_R = 0;

    for (auto& e : E) {
        if (eq(e.w, R) || eq(e.w, fp_neg(R))) ++hit_w_eq_R;
        if (eq(e.term, R) || eq(e.term, fp_neg(R))) ++hit_R;
        if (eq(e.term, R2) || eq(e.term, fp_neg(R2))) ++hit_R2;
    }

    // opposite-sign pairs: term_i + term_j
    for (size_t i = 0; i < E.size(); ++i) {
        for (size_t j = i + 1; j < E.size(); ++j) {
            if (E[i].ch == E[j].ch) continue;
            Fp s = fp_add(E[i].term, E[j].term);
            if (eq(s, R2) || eq(s, fp_neg(R2))) ++hit_pair_R2;
            if (eq(s, R) || eq(s, fp_neg(R))) ++hit_pair_R;
            // also w_i*w_j related?
            Fp prod = fp_mul(E[i].w, E[j].w);
            if (eq(prod, R2) || eq(prod, fp_neg(R2))) {
                // rare
            }
        }
    }

    // triple sums (N3 cancel structure → R*d)
    int hit_trip_R = 0;
    size_t n = E.size();
    if (n <= 40) {
        for (size_t i = 0; i < n; ++i)
            for (size_t j = i + 1; j < n; ++j)
                for (size_t k = j + 1; k < n; ++k) {
                    Fp s = fp_add(fp_add(E[i].term, E[j].term), E[k].term);
                    if (eq(s, R) || eq(s, fp_neg(R)) || eq(s, R2) || eq(s, fp_neg(R2)))
                        ++hit_trip_R;
                }
    }

    // weight ratios: all should be R-free. Count distinct ratios from first nonzero weight.
    std::map<std::pair<uint64_t,uint64_t>, int> ratios;
    size_t base = 0;
    while (base < E.size() && is0(E[base].w)) ++base;
    if (base < E.size()) {
        Fp invb = fp_inv(E[base].w);
        for (size_t i = 0; i < E.size(); ++i) {
            if (is0(E[i].w)) continue;
            Fp r = fp_mul(E[i].w, invb);
            ratios[{r.lo, r.hi}]++;
        }
    }

    std::cout << "  w==±R: " << hit_w_eq_R
              << " term==±R: " << hit_R
              << " term==±R2: " << hit_R2
              << " opp-pair==±R2: " << hit_pair_R2
              << " opp-pair==±R: " << hit_pair_R
              << " trip hits: " << hit_trip_R
              << " distinct_w_ratios: " << ratios.size()
              << "\n";

    // Check: can we recover R as gcd-like of weights? In field, gcd is meaningless,
    // but if coefs are "small" integers, w/R would be small.
    int small_coef = 0;
    for (auto& e : E) {
        if (is0(e.w)) continue;
        Fp c = fp_mul(e.w, fp_inv(R));
        // "small" if hi==0 and lo < 2^32, or neg of that
        Fp cn = fp_neg(c);
        auto small = [](const Fp& x) {
            return x.hi == 0 && x.lo < (1ull << 32);
        };
        if (small(c) || small(cn)) ++small_coef;
    }
    std::cout << "  weights/R that look uint32-small: " << small_coef << "/" << E.size() << "\n";
}

// For wrapped: try public-only linear algebra over GF(2) on sigmas — any leak?
static void sigma_stats(const Cipher& C, uint32_t lid) {
    size_t ones = 0, bits = 0;
    for (const auto& e : C.E) {
        if (e.layer_id != lid) continue;
        ones += e.s.popcnt();
        bits += e.s.nbits;
    }
    std::cout << "  sigma density=" << (bits ? (double)ones / bits : 0.0) << "\n";
}

// Reconstruct layer plaintext from sk and compare to public T/R
static void verify_wrap_model(const PubKey& pk, const SecKey& sk) {
    Fp v = fp_from_u64(0x123456789abcdefull);
    // Manual wrap to know m
    Fp m = rand_fp_nonzero();
    Cipher A = enc_fp_raw_depth(pk, sk, fp_add(v, m), 2);
    Cipher B = enc_fp_raw_depth(pk, sk, fp_neg(m), 2);
    Cipher W = combine_ciphers(pk, A, B);

    Fp R0 = prf_R_slots(pk, sk, W.L[0].seed, 1)[0];
    Fp R1 = prf_R_slots(pk, sk, W.L[1].seed, 1)[0];
    Fp T0 = layer_T(pk, W, 0);
    Fp T1 = layer_T(pk, W, 1);
    Fp x0 = fp_mul(T0, fp_inv(R0));
    Fp x1 = fp_mul(T1, fp_inv(R1));
    std::cout << "wrap model: x0==(v+m):" << eq(x0, fp_add(v, m))
              << " x1==(-m):" << eq(x1, fp_neg(m))
              << " sum==v:" << eq(fp_add(x0, x1), v) << "\n";

    hunt_R_forms(pk, W, 0, R0, fp_add(v, m), "wrapped-L0");
    hunt_R_forms(pk, W, 1, R1, fp_neg(m), "wrapped-L1");
    sigma_stats(W, 0);
    sigma_stats(W, 1);

    // RAW single layer (pre-wrap style) for comparison
    Cipher raw = enc_fp_raw_depth(pk, sk, v, 2);
    Fp Rr = prf_R_slots(pk, sk, raw.L[0].seed, 1)[0];
    hunt_R_forms(pk, raw, 0, Rr, v, "raw-L0");
}

// Try: among all opposite-sign pairs, treat sum as candidate for R*delta;
// for signal, the residual after removing noise might isolate va*R.
// Without labels we look for algebraic consistency across two layers of a wrap:
// Is there a public relation F(T0,T1, edges0, edges1) == 0 that involves only v?
static void cross_layer_search(const PubKey& pk, const SecKey& sk, int trials) {
    int rel_hits = 0;
    for (int t = 0; t < trials; ++t) {
        Fp v = fp_from_u64(1000 + t);
        Cipher W = enc_fp_wrapped_depth(pk, sk, v, 2);
        Fp T0 = layer_T(pk, W, 0);
        Fp T1 = layer_T(pk, W, 1);
        // Trivial: no public relation T0+T1 = v*(something public)
        // Check if T0/T1 is independent of v (should depend on m,R0,R1)
        (void)T0; (void)T1;
        // Check weight-space: take all L0 weights as vector, L1 weights as vector —
        // do they share a common ratio cluster? (would mean shared coef structure — shouldn't)
        auto E0 = layer_edges(pk, W, 0);
        auto E1 = layer_edges(pk, W, 1);
        int shared = 0;
        for (auto& a : E0) {
            if (is0(a.w)) continue;
            for (auto& b : E1) {
                if (is0(b.w)) continue;
                // same absolute weight?
                if (eq(a.w, b.w) || eq(a.w, fp_neg(b.w))) ++shared;
            }
        }
        if (shared) ++rel_hits;
    }
    std::cout << "cross-layer shared |w| hits over " << trials << " trials: " << rel_hits << "\n";
}

// Recover R from raw layer IF we know v (oracle simulation) — baseline.
// Then try to find ANY function of public edges that equals R without v.
static void search_public_R_expression(const PubKey& pk, const SecKey& sk) {
    Cipher C = enc_fp_raw_depth(pk, sk, fp_from_u64(42), 3);
    Fp R = prf_R_slots(pk, sk, C.L[0].seed, 1)[0];
    auto E = layer_edges(pk, C, 0);
    // For each pair of edges, compute term_i * inv(term_j) — never R
    // For each edge, w * inv(g) — is it R * small?
    int found = 0;
    for (size_t i = 0; i < E.size(); ++i) {
        for (size_t j = 0; j < E.size(); ++j) {
            if (i == j || is0(E[j].term)) continue;
            Fp r = fp_mul(E[i].term, fp_inv(E[j].term));
            // r == R? would mean term_i = R * term_j which is weird
            if (eq(r, R) || eq(r, fp_neg(R))) ++found;
        }
    }
    std::cout << "pair term ratios == ±R: " << found << "\n";

    // Linear combination with ±1 coeffs of ALL edges: only full sum is T=vR.
    // Subsets: for n edges 2^n is large; for n<=24 try random subsets.
    int subset_R = 0;
    if (E.size() <= 28) {
        size_t n = E.size();
        uint64_t lim = 1ull << std::min(n, (size_t)20);
        for (uint64_t mask = 1; mask < lim; ++mask) {
            Fp s = fp_from_u64(0);
            for (size_t b = 0; b < n && b < 20; ++b)
                if (mask & (1ull << b)) s = fp_add(s, E[b].term);
            if (eq(s, R) || eq(s, fp_neg(R)) || eq(s, fp_mul(R, R)) || eq(s, fp_neg(fp_mul(R, R))))
                ++subset_R;
        }
    }
    std::cout << "subset sums hitting ±R or ±R2 (mask<=20 bits): " << subset_R << "\n";
}

int main() {
    Params prm;
    prm.noise_entropy_bits = 128.0;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);
    std::cout << "keygen ok B=" << pk.prm.B << "\n";

    verify_wrap_model(pk, sk);
    cross_layer_search(pk, sk, 50);
    search_public_R_expression(pk, sk);

    // Text path: real enc_text
    {
        std::string msg = "abcdefghijklmno"; // 15 bytes exactly one block + length
        auto cts = enc_text(pk, sk, msg);
        std::cout << "\nenc_text blocks=" << cts.size() << "\n";
        for (size_t i = 0; i < cts.size(); ++i) {
            for (uint32_t lid = 0; lid < cts[i].L.size(); ++lid) {
                if (cts[i].L[lid].rule != RRule::BASE) continue;
                Fp R = prf_R_slots(pk, sk, cts[i].L[lid].seed, 1)[0];
                Fp T = layer_T(pk, cts[i], lid);
                Fp x = fp_mul(T, fp_inv(R));
                std::cout << "ct[" << i << "] L" << lid << " x.lo=" << std::hex << x.lo << std::dec
                          << " edges=" << layer_edges(pk, cts[i], lid).size() << "\n";
            }
        }
        std::cout << "dec: [" << dec_text(pk, sk, cts) << "]\n";
    }
    return 0;
}
