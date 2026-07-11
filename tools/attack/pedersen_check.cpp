#include <pvac/pvac.hpp>
#include <iostream>
using namespace pvac;

// Is H a known small multiple of G? (would break Pedersen hiding)
int main() {
    auto G = rist_G();
    auto H = rist_H();
    std::cout << "G: ";
    for (int i = 0; i < 8; i++) printf("%02x", G.data()[i]);
    std::cout << "\nH: ";
    for (int i = 0; i < 8; i++) printf("%02x", H.data()[i]);
    std::cout << "\n";

    // Check H == [k]G for small k
    for (uint64_t k = 1; k < 10000; ++k) {
        Scalar s{{k, 0, 0, 0}};
        auto p = rist_basemul(s);
        bool same = true;
        for (int i = 0; i < 32; i++) if (p.data()[i] != H.data()[i]) { same = false; break; }
        if (same) {
            std::cout << "H = [" << k << "]G  *** BROKEN PEDERSEN ***\n";
            return 0;
        }
    }
    std::cout << "H not small multiple of G (k<10000)\n";

    // Random open/close
    Params prm; prm.noise_entropy_bits = 128;
    PubKey pk; SecKey sk; keygen(prm, pk, sk);
    Fp R = prf_R(pk, sk, RSeed{1, {2, 3}});
    Fp Rinv = fp_inv(R);
    // forge wrong openings with random rho — should not match stored PC from real encrypt
    Cipher c = enc_fp_raw_depth(pk, sk, fp_from_u64(99), 2);
    auto real_pc = c.L[0].PC[0];
    int false_open = 0;
    for (int i = 0; i < 1000; i++) {
        Scalar rho = sc_random();
        // try open with wrong value
        auto fake = pedersen_commit(sc_from_fp_signed(fp_from_u64(i + 1)), rho);
        bool match = true;
        for (int j = 0; j < 32; j++) if (fake.data()[j] != real_pc.data()[j]) match = false;
        if (match) ++false_open;
    }
    std::cout << "false PC opens in 1000 random tries: " << false_open << "\n";
    return 0;
}
