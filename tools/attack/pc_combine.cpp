// Test: PC0^T0 * PC1^T1 = g^v * h^(...)  — Pedersen of plaintext under secret blinding.
// Confirms mathematical identity with known sk; proves it does NOT yield a public oracle.
#include <pvac/pvac.hpp>
#include <iostream>
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
    Fp v = fp_from_u64(0x41424344454647ull); // "ABCDEFG" packed-ish
    Cipher W = enc_fp_wrapped_depth(pk, sk, v, 2);
    Fp T0 = layer_T(pk, W, 0);
    Fp T1 = layer_T(pk, W, 1);
    auto PC0 = W.L[0].PC[0];
    auto PC1 = W.L[1].PC[0];

    // C = PC0^{sc(T0)} * PC1^{sc(T1)}
    Scalar s0 = sc_from_fp_signed(T0);
    Scalar s1 = sc_from_fp_signed(T1);
    auto C = rist_add(rist_scalarmul(PC0, s0), rist_scalarmul(PC1, s1));

    // Expected: g^v * h^{T0*rho0 + T1*rho1}
    // Compute with sk
    Fp R0 = prf_R_slots(pk, sk, W.L[0].seed, 1)[0];
    Fp R1 = prf_R_slots(pk, sk, W.L[1].seed, 1)[0];
    Fp x0 = fp_mul(T0, fp_inv(R0));
    Fp x1 = fp_mul(T1, fp_inv(R1));
    std::cout << "x0+x1==v: " << ((fp_add(x0,x1).lo==v.lo && fp_add(x0,x1).hi==v.hi)?1:0) << "\n";

    // Derive rhos
    auto rho = [&](const Layer& L) {
        Sha256 h; h.init();
        h.update(Dom::PRF_RHO, strlen(Dom::PRF_RHO));
        for (int k=0;k<4;k++) sha256_acc_u64(h, sk.prf_k[k]);
        sha256_acc_u64(h, L.seed.nonce.lo);
        sha256_acc_u64(h, L.seed.nonce.hi);
        sha256_acc_u64(h, 0);
        uint8_t b[32]; h.finish(b);
        return sc_reduce256(b);
    };
    Scalar rho0 = rho(W.L[0]);
    Scalar rho1 = rho(W.L[1]);
    // blind = T0*rho0 + T1*rho1 in scalar field — careful: T is Fp, mapped via sc_from_fp_signed
    // pedersen: PC = g^{Rinv} h^rho, so PC^T = g^{T*Rinv} h^{T*rho} = g^{x} h^{T*rho} only if T*Rinv = x in scalar
    // The scalar mapping sc_from_fp_signed may not commute with field mul! That's a potential bug.
    auto g = rist_G();
    auto H = rist_H();
    // Direct: g^v * h^{?}
    auto expect_g = rist_scalarmul(g, sc_from_fp_signed(v));
    // C / g^v should be in <H>
    auto C_div = rist_sub(C, expect_g);
    // Check if C_div is H^{something} by seeing if we can verify with known blind
    // blind_scalar = sc_from_fp_signed(T0)*rho0 + sc_from_fp_signed(T1)*rho1  (approx)
    // Actually PC^s uses s as scalar; PC = g^{sc_rinv} h^rho; PC^s = g^{s*sc_rinv} h^{s*rho}
    // We need s*sc_rinv == sc_from_fp_signed(x) for equality with g^x
    // If sc_from_fp is a field homomorphism into Z/L, then yes when values small.

    bool match_g_only = true;
    for (int i=0;i<32;i++) if (C.data()[i] != expect_g.data()[i]) match_g_only = false;
    std::cout << "C == g^v (no blinding)? " << match_g_only << " (expect 0)\n";

    // Try opening check with combined blind using scalar mul of mapped T
    Scalar blind = sc_add(sc_mul(s0, rho0), sc_mul(s1, rho1));
    auto expect = rist_add(rist_scalarmul(g, sc_from_fp_signed(v)), rist_scalarmul(H, blind));
    bool match = true;
    for (int i=0;i<32;i++) if (C.data()[i] != expect.data()[i]) match = false;
    std::cout << "C == g^v h^{s0*rho0+s1*rho1}? " << match << "\n";

    // If match==0, sc_from_fp doesn't commute — possible algebraic gap
    // Check alternative: sc_from_fp(x) vs sc_from_fp(T)*sc_from_fp(Rinv)
    Fp Rinv0 = fp_inv(R0);
    Scalar a = sc_from_fp_signed(x0);
    Scalar b = sc_mul(sc_from_fp_signed(T0), sc_from_fp_signed(Rinv0));
    bool commute = true;
    for (int i=0;i<4;i++) if (a.v[i]!=b.v[i]) commute = false;
    std::cout << "sc_from_fp_signed(T*Rinv) == sc(T)*sc(Rinv)? " << commute << "\n";
    // print limbs
    std::cout << "sc(x) limbs: " << a.v[0] << " " << a.v[1] << "\n";
    std::cout << "sc(T)*sc(Rinv) limbs: " << b.v[0] << " " << b.v[1] << "\n";

    return 0;
}
