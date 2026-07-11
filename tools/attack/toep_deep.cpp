#include <pvac/pvac.hpp>
#include <iostream>
#include <vector>
#include <cmath>
using namespace pvac;

int main() {
    Params prm; prm.noise_entropy_bits = 128;
    PubKey pk; SecKey sk; keygen(prm, pk, sk);

    int trials = 10000;
    int ones[127] = {0};
    for (int tr = 0; tr < trials; tr++) {
        RSeed s;
        s.nonce = {csprng_u64(), csprng_u64()};
        s.ztag = prg_layer_ztag(pk.canon_tag, s.nonce);

        std::vector<uint64_t> ybits;
        lpn_make_ybits(pk, sk, s, Dom::PRF_R1, ybits);

        uint8_t tk[32]; uint64_t tn;
        derive_aes_key(pk, sk, s, Dom::TOEP, tk, tn);
        tn ^= fnv1a_domain(Dom::PRF_R1);
        AesCtr256 p; p.init(tk, tn);
        size_t top_words = ((size_t)pk.prm.lpn_t + 127u + 63u) / 64u;
        std::vector<uint64_t> tp(top_words);
        p.fill_u64(tp.data(), top_words);

        uint64_t lo, hi;
        toep_127(tp, ybits, lo, hi);
        for (int b = 0; b < 64; b++) if (lo >> b & 1) ones[b]++;
        for (int b = 0; b < 63; b++) if (hi >> b & 1) ones[64+b]++;
    }
    std::cout << "Bit frequencies (" << trials << " trials):\n";
    double max_dev = 0; int max_bit = -1;
    for (int b = 0; b < 127; b++) {
        double f = (double)ones[b] / trials;
        double dev = fabs(f - 0.5);
        if (dev > max_dev) { max_dev = dev; max_bit = b; }
        if (dev > 0.02) std::cout << "  bit " << b << ": freq=" << f << " dev=" << dev << "\n";
    }
    std::cout << "  max_dev=" << max_dev << " at bit " << max_bit << "\n";
    std::cout << "  expected max dev (uniform): ~0.016\n";

    // ybits bias
    int y_ones = 0, y_total = 0;
    for (int tr = 0; tr < 100; tr++) {
        RSeed s;
        s.nonce = {csprng_u64(), csprng_u64()};
        s.ztag = prg_layer_ztag(pk.canon_tag, s.nonce);
        std::vector<uint64_t> ybits;
        lpn_make_ybits(pk, sk, s, Dom::PRF_R1, ybits);
        for (auto w : ybits) {
            y_ones += __builtin_popcountll(w);
            y_total += 64;
        }
    }
    std::cout << "ybits freq: " << (double)y_ones/y_total << " (expect 0.5)\n";

    // R bias (Fp value distribution)
    int r_low_zero = 0, r_hi_zero = 0;
    for (int tr = 0; tr < 1000; tr++) {
        RSeed s;
        s.nonce = {csprng_u64(), csprng_u64()};
        s.ztag = prg_layer_ztag(pk.canon_tag, s.nonce);
        Fp R = prf_R(pk, sk, s);
        if (R.lo == 0) r_low_zero++;
        if (R.hi == 0) r_hi_zero++;
    }
    std::cout << "R.lo==0: " << r_low_zero << "/1000 (expect ~0)\n";
    std::cout << "R.hi==0: " << r_hi_zero << "/1000 (expect ~0)\n";

    return 0;
}
