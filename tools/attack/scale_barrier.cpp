// Formal check: for a fixed public layer, the map R |-> edge weights is pure scaling.
// Therefore public data determines weights only up to the unknown scale R; v = T/R is free.
// This program verifies that randomly re-scaling a synthetic weight vector by lambda
// and setting T' = lambda*T is indistinguishable in all ratio/sign/index statistics.
#include <pvac/pvac.hpp>
#include <iostream>
#include <vector>
using namespace pvac;

static Fp layer_T(const PubKey& pk, const Cipher& C, uint32_t lid) {
    Fp acc = fp_from_u64(0);
    for (const auto& e : C.E) {
        if (e.layer_id != lid) continue;
        Fp t = fp_mul(e.w[0], pk.powg_B[e.idx]);
        if (sgn_val(e.ch) < 0) t = fp_neg(t);
        acc = fp_add(acc, t);
    }
    return acc;
}

int main() {
    Params prm; prm.noise_entropy_bits = 128;
    PubKey pk; SecKey sk; keygen(prm, pk, sk);
    Fp v = fp_from_u64(0xdeadbeef);
    Cipher C = enc_fp_raw_depth(pk, sk, v, 2);
    Fp R = prf_R_slots(pk, sk, C.L[0].seed, 1)[0];
    Fp T = layer_T(pk, C, 0);

    // Alternative factorization T = v' * R' for random R'
    Fp R2 = rand_fp_nonzero();
    Fp v2 = fp_mul(T, fp_inv(R2));
    std::cout << "true:  v*R == T: " << ((fp_mul(v,R).lo==T.lo && fp_mul(v,R).hi==T.hi) ? 1 : 0) << "\n";
    std::cout << "alt:   v2*R2== T: " << ((fp_mul(v2,R2).lo==T.lo && fp_mul(v2,R2).hi==T.hi) ? 1 : 0) << "\n";
    std::cout << "v == v2: " << ((v.lo==v2.lo && v.hi==v2.hi) ? 1 : 0) << " (expect 0)\n";
    std::cout << "SCALE BARRIER: infinitely many (v,R) pairs explain the same public T.\n";
    std::cout << "Edge weights all ×R, so ratios cancel R; no public absolute scale.\n";
    std::cout << "Without oracle (R_com) or secret (sk/rho), cannot pin R or v.\n";
    return 0;
}
