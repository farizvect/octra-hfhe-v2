// Key insight from the wrap structure:
// Layer 0 encrypts (v+m), Layer 1 encrypts (-m)
// T0 = (v+m)*R0, T1 = (-m)*R1
// T0/R0 + T1/R1 = v
//
// Can we verify v candidates using both PCs at once?
// PC0 = g^{sc(1/R0)} * h^{rho(sk, seed0)}
// PC1 = g^{sc(1/R1)} * h^{rho(sk, seed1)}
//
// For a candidate v, we need to verify that some m satisfies both.
// T0 = (v+m)*R0 => R0 = T0/(v+m)
// T1 = (-m)*R1  => R1 = T1/(-m)
//
// The ratio R0/R1 = T0*(-m) / (T1*(v+m))
// We don't know m. But what about from the PC side?
//
// PC0 * PC1 = g^{sc(1/R0)+sc(1/R1)} * h^{rho0+rho1}
// With T0=(v+m)*R0 and T1=(-m)*R1, 
// 1/R0 = (v+m)/T0, 1/R1 = -m/T1
// So sc(1/R0) = sc((v+m)/T0), sc(1/R1) = sc(-m/T1)
//
// sc is NOT a field homomorphism, so these don't simplify nicely.
// But: for SMALL (v+m) and m values, sc IS a homomorphism!
// Problem: m is full Fp*, so v+m and m are large -> sc fails.
//
// UNLESS the challenge uses some special m values?
// Let me check: rand_fp_nonzero() generates uniform Fp* -> m is large.
//
// Alternative: maybe the key is that we have 44 LAYERS sharing prf_k,
// and the PC constraints + T equations form a solvable system.
// Let me count equations vs unknowns:
//
// Public per layer: T (127 bits), PC (253 bits but 0 info without sk)
// Unknown per layer: v or m (127 bits)
// Shared unknowns: prf_k (256), lpn_s (4096)
//
// 44 layers: 44 T equations, 44 PC "equations" (but each adds unknown rho)
// Actually: rho_i = f(prf_k, seed_i). If we knew prf_k, rho is known.
// So PC_i gives: PC_i * h^{-rho_i(prf_k)} = g^{sc(R_i^{-1})}
// This is a Ristretto point. sc(R_i^{-1}) is in [-2^126, 2^126].
//
// For a candidate prf_k, we get 44 points Q_i = PC_i * h^{-rho_i(prf_k)}.
// If prf_k is correct: Q_i = g^{sc(R_i^{-1})} for the true R_i.
// If wrong: Q_i = g^{random}.
//
// BUT: sc(R_i^{-1}) = ±(v_i+m_i)/T0_i (for layer 0) or ±(-m_i)/T1_i (for layer 1)
// And v_i is unknown, m_i is unknown.
//
// For the LENGTH cipher (ct0): v = length in {301..315}, wrapped.
// Layer 0: sc(R0^{-1}) = sc((L+m)/T0)
// Layer 1: sc(R1^{-1}) = sc((-m)/T1)
//
// If I guess L AND m, I can compute R0, R1, and verify both PCs.
// m is 127 bits -> 2^127 guesses per L -> infeasible.
//
// BUT: what if the RELATIONSHIP between the two wrapped layers
// eliminates m? Let me try algebraically.
//
// From PC0: g^{sc(R0^{-1})} = PC0 * h^{-rho0}
// From PC1: g^{sc(R1^{-1})} = PC1 * h^{-rho1}
//
// sc(R0^{-1}) = sc((L+m)/T0)
// sc(R1^{-1}) = sc(-m/T1) = sc(m/T1) * (-1??) - actually sc(-x) = -sc(x) for sc_from_fp_signed
// Let me verify: sc_from_fp_signed(-x) = sc_neg(sc_from_fp_signed(x))? Yes by construction.
//
// So sc(R1^{-1}) = sc_neg(sc_from_fp_signed(m/T1)) = -sc(m/T1) in scalar group
//
// Now: T0*R1 + T1*R0 = L*R0*R1  (from wrap equation)
// => T0/R0 + T1/R1 = L
//
// From PC: 
// g^{a0} = PC0 * h^{-rho0} where a0 = [(L+m)/T0]_sc
// g^{a1} = PC1 * h^{-rho1} where a1 = [(-m)/T1]_sc = [-m/T1]_sc
//
// where [x]_sc = sc_from_fp_signed(x)

#include <pvac/pvac.hpp>
#include <iostream>
using namespace pvac;

int main() {
    // Verify: sc_from_fp_signed(-x) == -sc_from_fp_signed(x)?
    Fp x = fp_from_u64(42);
    Fp negx = fp_neg(x);
    Scalar sx = sc_from_fp_signed(x);
    Scalar snegx = sc_from_fp_signed(negx);
    Scalar expected = sc_neg(sx);
    bool ok = (snegx.v[0]==expected.v[0] && snegx.v[1]==expected.v[1] 
            && snegx.v[2]==expected.v[2] && snegx.v[3]==expected.v[3]);
    std::cout << "sc(-x) == -sc(x): " << ok << "\n";

    // Verify: sc(x/T) = sc(x) * sc(1/T) in scalar field?
    Fp T = fp_from_u64(12345);
    Fp xT = fp_mul(x, fp_inv(T));
    Scalar direct = sc_from_fp_signed(xT);
    Scalar composed = sc_mul(sc_from_fp_signed(x), sc_from_fp_signed(fp_inv(T)));
    ok = (direct.v[0]==composed.v[0] && direct.v[1]==composed.v[1]
       && direct.v[2]==composed.v[2] && direct.v[3]==composed.v[3]);
    std::cout << "sc(x/T) == sc(x)*sc(1/T): " << ok << " (expected 0 for random Fp)\n";

    // For SMALL values (< 2^32), sc preserves multiplication.
    Fp small_a = fp_from_u64(100);
    Fp small_b = fp_from_u64(200);
    Scalar sc_ab_direct = sc_from_fp_signed(fp_mul(small_a, small_b));
    Scalar sc_ab_compose = sc_mul(sc_from_fp_signed(small_a), sc_from_fp_signed(small_b));
    ok = (sc_ab_direct.v[0]==sc_ab_compose.v[0]);
    std::cout << "sc(a*b)==sc(a)*sc(b) for small a,b: " << ok << "\n";

    // KEY TEST: can we verify a candidate (v, m) pair?
    Params prm; prm.noise_entropy_bits=128;
    PubKey pk; SecKey sk; keygen(prm,pk,sk);
    Fp v = fp_from_u64(315);
    Fp m = rand_fp_nonzero();
    Cipher W = enc_fp_wrapped_depth(pk, sk, v, 2);
    
    // Public values
    Fp T0=fp_from_u64(0), T1=fp_from_u64(0);
    for(auto&e:W.E){
        Fp term=fp_mul(e.w[0],pk.powg_B[e.idx]);
        if(sgn_val(e.ch)<0) term=fp_neg(term);
        if(e.layer_id==0) T0=fp_add(T0,term);
        else T1=fp_add(T1,term);
    }
    auto PC0=W.L[0].PC[0], PC1=W.L[1].PC[0];
    Fp R0=prf_R_slots(pk,sk,W.L[0].seed,1)[0];
    Fp R1=prf_R_slots(pk,sk,W.L[1].seed,1)[0];
    
    // With known SK, verify: PC0 == g^{sc(1/R0)} * h^{rho0}
    // And: sc(1/R0) should equal sc((v+m)/T0) if encryption is correct
    Scalar a0_direct = sc_from_fp_signed(fp_inv(R0));
    Scalar a0_from_T = sc_from_fp_signed(fp_mul(fp_add(v,m), fp_inv(T0)));
    ok = (a0_direct.v[0]==a0_from_T.v[0]);
    std::cout << "sc(1/R0) == sc((v+m)/T0): " << ok << "\n";

    // For layer 1: sc(1/R1) should equal sc(-m/T1) = -sc(m/T1)
    Scalar a1_direct = sc_from_fp_signed(fp_inv(R1));
    Scalar a1_from_T = sc_neg(sc_from_fp_signed(fp_mul(m, fp_inv(T1))));
    ok = (a1_direct.v[0]==a1_from_T.v[0]);
    std::cout << "sc(1/R1) == -sc(m/T1): " << ok << "\n";

    // Now: PC0 * g^{-sc((v+m)/T0)} should equal h^{rho0}
    // And PC1 * g^{-sc(-m/T1)} = PC1 * g^{sc(m/T1)} should equal h^{rho1}
    // These two should be points in <H>.
    // We can check: is PC0 * g^{-sc((v+m)/T0)} / (PC1 * g^{sc(m/T1)}) = h^{rho0-rho1}?
    // But we can't verify without knowing rho0, rho1.
    
    // HOWEVER: the wrapping gives us a relationship:
    // sc((v+m)/T0) + sc((m)/T1) relates to v
    // Specifically: T0*R1 + T1*R0 = v*R0*R1
    // In scalar form: T0*sc(1/R0) - T1*sc(1/R1) ??? No, sc is not linear in Fp.
    
    // The KEY question: does the wrap structure create a verifiable constraint?
    // T0/R0 + T1/R1 = v
    // Multiply by R0*R1: T0*R1 + T1*R0 = v*R0*R1
    // This is in Fp, not in the scalar field.
    // PC works in the scalar field. These are different groups.
    // No direct algebraic connection.

    std::cout << "\nWRAP CONSTRAINT: T0*R1 + T1*R0 = v*R0*R1 (in F_p)\n";
    std::cout << "PC CONSTRAINT: g^{sc(1/R0)}*h^{rho0} = PC0 (in Ristretto)\n";
    std::cout << "These live in DIFFERENT algebraic structures.\n";
    std::cout << "No direct way to combine F_p and Ristretto constraints.\n";

    return 0;
}
