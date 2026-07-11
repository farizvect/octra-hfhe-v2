#include <pvac/pvac.hpp>
#include <iostream>
using namespace pvac;

int main() {
    Params prm; prm.noise_entropy_bits = 128;
    PubKey pk; SecKey sk; keygen(prm, pk, sk);
    Fp m = fp_from_u64(123456789);
    Cipher c = enc_fp_raw_depth(pk, sk, m, 2);
    Fp T = fp_from_u64(0);
    for (auto& e : c.E) {
        if (e.layer_id != 0) continue;
        Fp t = fp_mul(e.w[0], pk.powg_B[e.idx]);
        if (sgn_val(e.ch) < 0) t = fp_neg(t);
        T = fp_add(T, t);
    }
    Fp R = prf_R_slots(pk, sk, c.L[0].seed, 1)[0];
    Fp Rinv = fp_inv(R);
    // recompute PC with correct and wrong values
    auto pc = c.L[0].PC[0];
    // derive real rho
    Sha256 h; h.init();
    h.update(Dom::PRF_RHO, strlen(Dom::PRF_RHO));
    for (int k=0;k<4;k++) sha256_acc_u64(h, sk.prf_k[k]);
    sha256_acc_u64(h, c.L[0].seed.nonce.lo);
    sha256_acc_u64(h, c.L[0].seed.nonce.hi);
    sha256_acc_u64(h, 0);
    uint8_t rho_bytes[32]; h.finish(rho_bytes);
    Scalar rho = sc_reduce256(rho_bytes);
    auto pc_ok = pedersen_commit(sc_from_fp_signed(Rinv), rho);
    auto pc_bad = pedersen_commit(sc_from_fp_signed(fp_inv(fp_from_u64(1))), rho);
    bool match_ok=true, match_bad=true;
    for (int i=0;i<32;i++){ if(pc_ok.data()[i]!=pc.data()[i]) match_ok=false; if(pc_bad.data()[i]!=pc.data()[i]) match_bad=false; }
    std::cout << "pc matches correct Rinv+rho: " << match_ok << "\n";
    std::cout << "pc matches wrong Rinv+same rho: " << match_bad << "\n";
    // without rho, any Rinv can be "opened" with some rho' - hiding property
    // so PC is NOT a public oracle
    std::cout << "T == m*R: " << (fp_mul(m,R).lo==T.lo && fp_mul(m,R).hi==T.hi) << "\n";
    // wrapped
    Cipher w = enc_fp_wrapped_depth(pk, sk, m, 2);
    std::cout << "wrapped layers=" << w.L.size() << " base edges L0/L1: ";
    int e0=0,e1=0; for(auto&e:w.E){ if(e.layer_id==0)e0++; if(e.layer_id==1)e1++; }
    std::cout << e0 << "/" << e1 << "\n";
    return 0;
}
