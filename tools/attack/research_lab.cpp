// Deep research lab: N2 identification, merge ghosts, multi-layer invariants,
// sc_from_fp gaps, and attempts to pin absolute scale R from public data.
#include <pvac/pvac.hpp>
#include <algorithm>
#include <cmath>
#include <iostream>
#include <map>
#include <set>
#include <vector>
using namespace pvac;

static bool eq(const Fp& a, const Fp& b) { return a.lo == b.lo && a.hi == b.hi; }
static bool is0(const Fp& a) { return a.lo == 0 && a.hi == 0; }

struct EView {
    size_t i;
    uint16_t idx;
    uint8_t ch;
    Fp w;
    Fp term; // signed w*g
    BitVec s;
};

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

static std::vector<EView> edges(const PubKey& pk, const Cipher& C, uint32_t lid) {
    std::vector<EView> out;
    for (size_t i = 0; i < C.E.size(); ++i) {
        const auto& e = C.E[i];
        if (e.layer_id != lid) continue;
        Fp t = fp_mul(e.w[0], pk.powg_B[e.idx]);
        if (sgn_val(e.ch) < 0) t = fp_neg(t);
        out.push_back({i, e.idx, e.ch, e.w[0], t, e.s});
    }
    return out;
}

// With known R: classify which opposite-sign pairs are true N2 (sum term = R*d for some)
// Measure how unique that signature is among all pairs.
static void n2_identifiability(const PubKey& pk, const SecKey& sk, int trials) {
    int total_pairs = 0, true_n2_style = 0;
    // "true N2 style": term sum / R is "noise-like" vs random pair
    // Better: with known R, recover coef = w/R for each edge, then check N2 relation:
    // for opposite signs a,b: sa*ra*ga + sb*rb*gb should equal some delta
    // All opposite pairs satisfy something - measure fraction where |coef| relation holds with random.
    double avg_match_frac = 0;
    for (int t = 0; t < trials; ++t) {
        Cipher C = enc_fp_raw_depth(pk, sk, fp_from_u64(12345 + t), 2);
        Fp R = prf_R_slots(pk, sk, C.L[0].seed, 1)[0];
        Fp Rinv = fp_inv(R);
        auto E = edges(pk, C, 0);
        // coef_i = w_i / R
        std::vector<Fp> coef(E.size());
        for (size_t i = 0; i < E.size(); ++i) coef[i] = fp_mul(E[i].w, Rinv);

        // Check: for every opposite-sign pair, compute
        // d_hat = s_a * coef_a * g_a + s_b * coef_b * g_b
        // For true N2, d_hat equals the planted delta. For random pairs, random.
        // Count how many pairs have d_hat matching a known delta from another pair (collision).
        std::map<std::pair<uint64_t,uint64_t>, int> dhat_count;
        int pairs = 0;
        for (size_t i = 0; i < E.size(); ++i) {
            for (size_t j = i + 1; j < E.size(); ++j) {
                if (E[i].ch == E[j].ch) continue;
                // term_i + term_j = R * d_hat  =>  d_hat = (term_i+term_j)/R
                Fp s = fp_add(E[i].term, E[j].term);
                Fp dhat = fp_mul(s, Rinv);
                dhat_count[{dhat.lo, dhat.hi}]++;
                pairs++;
            }
        }
        total_pairs += pairs;
        int multi = 0;
        for (auto& kv : dhat_count) if (kv.second > 1) multi += kv.second;
        // uniqueness of dhat: for true N2, each delta appears once ideally
        avg_match_frac += pairs ? (double)multi / pairs : 0;
    }
    std::cout << "[N2] avg fraction of dhat collisions among opp pairs: "
              << (avg_match_frac / trials) << " (over " << trials << " trials)\n";
    std::cout << "[N2] total opp pairs seen: " << total_pairs << "\n";
}

// Ghost edges: weight zero but sigma nonzero after merge
static void ghost_scan(const PubKey& pk, const SecKey& sk, int trials) {
    int ghosts = 0, total_e = 0;
    for (int t = 0; t < trials; ++t) {
        Cipher C = enc_fp_raw_depth(pk, sk, fp_from_u64(t + 1), 5);
        for (auto& e : C.E) {
            ++total_e;
            bool w0 = true;
            for (auto& x : e.w) if (!is0(x)) w0 = false;
            if (w0 && e.s.popcnt() > 0) ++ghosts;
        }
    }
    std::cout << "[ghost] weight-zero edges with sigma: " << ghosts
              << " / " << total_e << "\n";
}

// Can we recover R by solving: find lambda such that all w_i/lambda look like
// "structured" N2/N3/signal? Use known R to define a score, then see if score
// peaks uniquely at true R when scanning wrong lambdas.
static void scale_score_test(const PubKey& pk, const SecKey& sk) {
    Cipher C = enc_fp_raw_depth(pk, sk, fp_from_u64(0xdead), 2);
    Fp Rtrue = prf_R_slots(pk, sk, C.L[0].seed, 1)[0];
    auto E = edges(pk, C, 0);
    Fp T = layer_T(pk, C, 0);

    auto score = [&](const Fp& Rcand) -> int {
        if (is0(Rcand)) return -1;
        Fp Rinv = fp_inv(Rcand);
        // After dividing by Rcand, check how many opposite-sign pairs have
        // d_hat matching: count unique d_hats vs pairs (lower unique = more structure?)
        // Better score: reconstruct plaintext candidate v = T/Rcand and check if
        // the last-signal-style consistency holds: exists subset of 8 edges whose
        // signed coef*g sum to v - sum(other deltas)... too combinatorial.
        //
        // Practical score: number of opposite-sign pairs where
        // coef_a * g_a - coef_b * g_b  has BOTH coefs "related" via
        // rb = (ra*ga - d)/gb for SOME d that also appears as another pair's d.
        std::map<std::pair<uint64_t,uint64_t>, int> dhats;
        for (size_t i = 0; i < E.size(); ++i) {
            for (size_t j = i + 1; j < E.size(); ++j) {
                if (E[i].ch == E[j].ch) continue;
                Fp s = fp_add(E[i].term, E[j].term);
                Fp d = fp_mul(s, Rinv);
                dhats[{d.lo, d.hi}]++;
            }
        }
        int maxc = 0;
        for (auto& kv : dhats) maxc = std::max(maxc, kv.second);
        return maxc; // higher if many pairs share same d (unlikely for wrong R)
    };

    int s_true = score(Rtrue);
    int better = 0, equal = 0, worse = 0;
    for (int k = 0; k < 200; ++k) {
        Fp Rwrong = rand_fp_nonzero();
        if (eq(Rwrong, Rtrue)) continue;
        int s = score(Rwrong);
        if (s > s_true) ++better;
        else if (s == s_true) ++equal;
        else ++worse;
    }
    std::cout << "[scale-score] true_score=" << s_true
              << " random: better=" << better << " equal=" << equal
              << " worse=" << worse << " /200\n";
    // If better~equal~random, score does not pin R.
}

// sc_from_fp non-homomorphism: measure how often sc(a*b)==sc(a)*sc(b)
static void sc_homomorphism_stats(int n) {
    int hit = 0;
    for (int i = 0; i < n; ++i) {
        Fp a = rand_fp_nonzero();
        Fp b = rand_fp_nonzero();
        Scalar sa = sc_from_fp_signed(a);
        Scalar sb = sc_from_fp_signed(b);
        Scalar sab = sc_from_fp_signed(fp_mul(a, b));
        Scalar prod = sc_mul(sa, sb);
        bool ok = true;
        for (int k = 0; k < 4; ++k) if (sab.v[k] != prod.v[k]) ok = false;
        if (ok) ++hit;
    }
    std::cout << "[sc] homomorphism hits: " << hit << " / " << n << "\n";

    // When does it hold? If a,b small enough product fits without mod L
    int hit_small = 0, n_small = 0;
    for (uint64_t a = 1; a < 1000; a += 7) {
        for (uint64_t b = 1; b < 1000; b += 11) {
            ++n_small;
            Fp A = fp_from_u64(a), B = fp_from_u64(b);
            Scalar sa = sc_from_fp_signed(A);
            Scalar sb = sc_from_fp_signed(B);
            Scalar sab = sc_from_fp_signed(fp_mul(A, B));
            Scalar prod = sc_mul(sa, sb);
            bool ok = true;
            for (int k = 0; k < 4; ++k) if (sab.v[k] != prod.v[k]) ok = false;
            if (ok) ++hit_small;
        }
    }
    std::cout << "[sc] small-int homomorphism: " << hit_small << " / " << n_small << "\n";
}

// Multi-instance: same sk, many layers. For each layer we have T_i, PC_i, seed_i.
// rho_i = H(prf_k || seed_i). If we guess v_i for length-like small values,
// R_i = T_i/v_i, Rinv = v_i/T_i. Then PC_i / g^{sc(Rinv)} = h^{rho_i}.
// Taking discrete log base H is hard — but we can check CONSISTENCY of prf_k
// if we could DLOG. Without DLOG we get points Q_i = PC_i / g^{sc(Rinv_i)} = h^{rho_i}.
// Then Q_i should equal H^{H(k||n_i)}. Still need to find k.
//
// Test: for known sk and known v, extract Q and verify.
static void multi_pc_identity(const PubKey& pk, const SecKey& sk) {
    Fp v = fp_from_u64(99);
    Cipher W = enc_fp_wrapped_depth(pk, sk, v, 2);
    for (uint32_t lid = 0; lid < 2; ++lid) {
        Fp R = prf_R_slots(pk, sk, W.L[lid].seed, 1)[0];
        Fp Rinv = fp_inv(R);
        Fp T = layer_T(pk, W, lid);
        Fp x = fp_mul(T, fp_inv(R));
        // Q = PC / g^{sc(Rinv)} should be h^rho
        Scalar sc_r = sc_from_fp_signed(Rinv);
        auto gR = rist_scalarmul(rist_G(), sc_r);
        auto Q = rist_sub(W.L[lid].PC[0], gR);
        // recompute rho
        Sha256 h; h.init();
        h.update(Dom::PRF_RHO, strlen(Dom::PRF_RHO));
        for (int k = 0; k < 4; k++) sha256_acc_u64(h, sk.prf_k[k]);
        sha256_acc_u64(h, W.L[lid].seed.nonce.lo);
        sha256_acc_u64(h, W.L[lid].seed.nonce.hi);
        sha256_acc_u64(h, 0);
        uint8_t b[32]; h.finish(b);
        Scalar rho = sc_reduce256(b);
        auto expect = rist_scalarmul(rist_H(), rho);
        bool match = true;
        for (int i = 0; i < 32; i++) if (Q.data()[i] != expect.data()[i]) match = false;
        std::cout << "[PC] layer " << lid << " Q==h^rho: " << match
                  << " x=(" << x.hi << ":" << x.lo << ")\n";
    }
}

// Attempt: use signal K=8 structure. After dividing by R, 8 signal coefs satisfy
// sum s_i c_i g_i = va. Without knowing which 8 edges are signal (after merge/shuffle),
// enumerate combinations C(n,8) is huge for n=24.
// For depth 0 with ~22 edges: C(22,8) ~ 319770. Feasible!
// Attack idea for RAW (unwrapped) layer with known small v:
//   for candidate R = T/v (if v known), check if some 8-subset of edges forms valid signal
//   with remaining edges partitioning into N2/N3.
// For WRAPPED: v unknown, but for LENGTH cipher, v in 301..315 is small!
//
// Length is WRAPPED though: T0=(L+m)R0, T1=(-m)R1. L small but m free.
//
// For a RAW encryption of known small v, can we verify R without R_com
// by checking combinatorial structure of coefs?
static bool structure_check(const PubKey& pk, const Cipher& C, uint32_t lid, const Fp& Rcand, const Fp& v_expected) {
    // v_expected is plaintext of this layer (not wrapped)
    Fp T = layer_T(pk, C, lid);
    Fp v_from = fp_mul(T, fp_inv(Rcand));
    if (!eq(v_from, v_expected)) return false;
    // Divide weights by R
    auto E = edges(pk, C, lid);
    // For each edge, coef = w/R
    // Noise deltas sum + va = v. We check existence of partition...
    // Lightweight check: max opposite-pair dhat multiplicity should be low for true R
    // (already tested). Stronger: remaining after removing estimated N2 pairs.
    return true; // tautology if T/R = v
}

// Combinatorial signal finder: given R, check if there exist 8 edges whose
// signed coef*g sum equals v - (sum of other edges' signed coef*g) i.e. total always v.
// That's always true for correct R. For wrong R, T/R is wrong v so fails at structure_check.
//
// The structure check that works WITHOUT knowing v:
// After /R, all coefs should make N2 pairs satisfy:
// for pair (a,b) opposite signs with sa=1,sb=0: ra*ga - rb*gb = d
// and ra is "random" while rb is determined...
// We can't distinguish without knowing which pairs are N2.
//
// Unless: for CORRECT R, the set of all edge terms/R partitions into
// {signal set} U {N2 pairs} U {N3 triples} with exact linear relations.
// For WRONG R, no such partition (with high probability).
//
// Implement exact partition search for small n (depth 0, ~22 edges).
// n2=4 pairs (8 edges), n3=2 triples (6 edges), signal=8. Total 8+8+6=22.
//
// Search: choose 8 edges for signal (C(22,8)), remaining 14: try to pair into 4 N2 + 2 N3.
// This is expensive but for verification of ONE candidate R with known v it's ok.
// For unknown v, candidates are infinite.

// Implement N2-relation test for a pair under given R:
// pair is N2-consistent if opposite signs and we don't need more...
// Actually ALL opposite sign pairs define some d. N2 means there EXISTS ra free.
// Every opposite pair is "N2-shaped" for d = sa*ca*ga+sb*cb*gb!
// N3: three edges, sa*ca*ga+sb*cb*gb+sc*cc*gc = d, with ca,cb free, cc determined.
// Again always true for any 3!
//
// So the linear relations always hold for ANY scale R (because they're homogeneous)!
// Structure is scale-invariant. Cannot pin R from N2/N3/signal shape alone.
static void homogeneity_proof() {
    std::cout << "[math] N2/N3/signal relations are homogeneous in R:\n"
              << "  all edge weights and T scale by R → relations on coefs are R-invariant.\n"
              << "  Therefore combinatorial structure CANNOT pin absolute scale.\n"
              << "  Only inhomogeneous data (R_com, PC opening, sk) can pin R.\n";
}

// Challenge CT: try length brute with wrap — for each L in 301..315,
// we still have free m. Unless m has a bug and is small?
// Check distribution of m from wrap on self-test: is m ever small?
static void wrap_m_distribution(const PubKey& pk, const SecKey& sk, int trials) {
    int small_m = 0;
    for (int t = 0; t < trials; ++t) {
        // encrypt known v via wrap by using enc_fp_wrapped and recovering m from sk
        Fp v = fp_from_u64(100 + t);
        Cipher W = enc_fp_wrapped_depth(pk, sk, v, 2);
        Fp R0 = prf_R_slots(pk, sk, W.L[0].seed, 1)[0];
        Fp R1 = prf_R_slots(pk, sk, W.L[1].seed, 1)[0];
        Fp x0 = fp_mul(layer_T(pk, W, 0), fp_inv(R0));
        Fp x1 = fp_mul(layer_T(pk, W, 1), fp_inv(R1));
        // m = -x1, v = x0+x1
        Fp m = fp_neg(x1);
        // "small" if hi==0 and lo < 2^40
        if (m.hi == 0 && m.lo < (1ull << 40)) ++small_m;
        Fp mn = fp_neg(m);
        if (mn.hi == 0 && mn.lo < (1ull << 40)) ++small_m;
    }
    std::cout << "[wrap] small m count (uint40): " << small_m << " / " << trials << "\n";
}

// LPN sample access: can public data reconstruct any LPN samples?
// AES key needs sk.prf_k — no.
// Unless H_digest + canon_tag + seed is enough with weak prf_k — no.

// Final attempt: BSGS-style if R were in a small subgroup of F_p^*.
// p-1 = 2^127 - 2 = 2*(2^126 - 1). Order of multiplicative group is p-1.
// R is essentially uniform in F_p^* from hash_to_fp_nonzero of LPN extract.
// Not small order.

static void field_order_info() {
    // p = 2^127 - 1 Mersenne prime
    // B=337 divides p-1
    std::cout << "[field] p=2^127-1, B=337 | (p-1). powg_B generates B-torsion subgroup.\n"
              << "  Signal/noise live in full field for weights; g_idx in B-th roots.\n";
}

int main() {
    Params prm;
    prm.noise_entropy_bits = 128;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);
    std::cout << "keygen ok\n";

    homogeneity_proof();
    field_order_info();
    sc_homomorphism_stats(500);
    n2_identifiability(pk, sk, 30);
    ghost_scan(pk, sk, 20);
    scale_score_test(pk, sk);
    multi_pc_identity(pk, sk);
    wrap_m_distribution(pk, sk, 100);

    // Challenge length cipher: report edge counts vs budget
    std::cout << "\n[challenge budget] depth0: n2=4 n3=2 edges~22; wrapped length has 2 such layers\n";

    // Prove homogeneity experimentally: scale all weights and T by lambda, structure scores identical
    {
        Cipher C = enc_fp_raw_depth(pk, sk, fp_from_u64(55), 2);
        Fp R = prf_R_slots(pk, sk, C.L[0].seed, 1)[0];
        auto E = edges(pk, C, 0);
        Fp lambda = fp_from_u64(0x1234567);
        // ratios w_i/w_0 invariant under R -> lambda*R
        Fp inv0 = fp_inv(E[0].w);
        Fp inv0s = fp_inv(fp_mul(E[0].w, lambda));
        bool same_ratios = true;
        for (size_t i = 1; i < E.size(); ++i) {
            Fp r1 = fp_mul(E[i].w, inv0);
            Fp r2 = fp_mul(fp_mul(E[i].w, lambda), inv0s);
            if (!eq(r1, r2)) same_ratios = false;
        }
        std::cout << "[homog] weight ratios invariant under scale: " << same_ratios << "\n";
    }

    std::cout << "\n=== RESEARCH CONCLUSION ===\n"
              << "Homogeneous masking: public edge algebra is scale-invariant.\n"
              << "Wrapping adds free m (full entropy). PC needs secret rho.\n"
              << "No public pin for R found. Ciphertext-only break needs LPN or new oracle.\n";
    return 0;
}
