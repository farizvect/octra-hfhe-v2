// Test the ratio claim: does R0/R1 have the structure r1 * u0 / (r1 * u1) = u0/u1?
// i.e., is r1 shared between the two wrapped layers?
#include <pvac/pvac.hpp>
#include <iostream>
using namespace pvac;

static Fp layer_T(const PubKey& pk, const Cipher& C, uint32_t lid) {
    Fp a = (lid==0 && !C.c0.empty()) ? C.c0[0] : fp_from_u64(0);
    for(auto&e:C.E) {
        if(e.layer_id!=lid) continue;
        Fp t=fp_mul(e.w[0],pk.powg_B[e.idx]);
        if(sgn_val(e.ch)<0) t=fp_neg(t);
        a=fp_add(a,t);
    }
    return a;
}

static bool eq(const Fp&a,const Fp&b){return a.lo==b.lo&&a.hi==b.hi;}

int main() {
    Params prm; prm.noise_entropy_bits=128;
    PubKey pk; SecKey sk;
    keygen(prm,pk,sk);

    // Self-test: generate wrapped ciphertexts
    int same_r1=0, diff_r1=0;
    int same_r2r3_ratio=0;
    
    for(int t=0; t<10; t++) {
        Fp v = fp_from_u64(300+t);
        Cipher W = enc_fp_wrapped_depth(pk, sk, v, 2);
        
        // Get the real values
        Fp R0 = prf_R_slots(pk, sk, W.L[0].seed, 1)[0];
        Fp R1 = prf_R_slots(pk, sk, W.L[1].seed, 1)[0];
        
        Fp r1_0 = prf_R_core(pk, sk, W.L[0].seed, Dom::PRF_R1);
        Fp r1_1 = prf_R_core(pk, sk, W.L[1].seed, Dom::PRF_R1);  // DIFFERENT seed!
        Fp r2_0 = prf_R_core(pk, sk, W.L[0].seed, Dom::PRF_R2);
        Fp r3_0 = prf_R_core(pk, sk, W.L[0].seed, Dom::PRF_R3);
        Fp r2_1 = prf_R_core(pk, sk, W.L[1].seed, Dom::PRF_R2);
        Fp r3_1 = prf_R_core(pk, sk, W.L[1].seed, Dom::PRF_R3);
        
        Fp u0 = fp_mul(r2_0, r3_0);
        Fp u1 = fp_mul(r2_1, r3_1);
        
        std::cout << "Trial " << t << ":\n";
        std::cout << "  r1_0 == r1_1? " << eq(r1_0, r1_1) 
                  << " (seeds " << ((W.L[0].seed.nonce.lo==W.L[1].seed.nonce.lo && W.L[0].seed.nonce.hi==W.L[1].seed.nonce.hi)?"same":"diff") << ")\n";
        std::cout << "  R0/R1 = " << (fp_mul(R0, fp_inv(R1)).lo & 0xFFFF) << "...\n";
        std::cout << "  u0/u1 = " << (fp_mul(u0, fp_inv(u1)).lo & 0xFFFF) << "...\n";
        
        if(eq(r1_0, r1_1)) same_r1++;
        else diff_r1++;
        
        Fp T0 = layer_T(pk, W, 0);
        Fp T1 = layer_T(pk, W, 1);
        Fp ratio_T = fp_mul(T0, fp_inv(T1));
        // If r1 cancels: ratio_T = -(v+m)/m = -v/m - 1
        // For v << m: ratio_T ≈ -1
        std::cout << "  T0/T1 = (" << (ratio_T.hi & 0xFFF) << ":" << (ratio_T.lo & 0xFFFF) << ")\n";
        
        // For m ≈ 2^127, v ≈ 300: ratio_T should be close to -1
        Fp neg_one = fp_neg(fp_from_u64(1));
        std::cout << "  T0/T1 ≈ -1? " << (eq(ratio_T, neg_one)? "exact":"no") << "\n";
        
        // Check: is T0/T1 ≈ -R0/R1 (if v << m)?
        Fp ratio_R = fp_mul(fp_neg(R0), fp_inv(R1));
        std::cout << "  -R0/R1 = (" << (ratio_R.hi & 0xFFF) << ":" << (ratio_R.lo & 0xFFFF) << ")\n";
    }
    
    std::cout << "\nr1 same: " << same_r1 << ", different: " << diff_r1 << "\n";
    
    // NOW: test with the SAME seed for both layers
    std::cout << "\n=== Forcing same seed ===\n";
    Fp v2 = fp_from_u64(315);
    // Manually create two layers with SAME seed
    Fp m = rand_fp_nonzero();
    RSeed same_seed;
    same_seed.nonce = make_nonce128();
    same_seed.ztag = prg_layer_ztag(pk.canon_tag, same_seed.nonce);
    
    Fp r1_same = prf_R_core(pk, sk, same_seed, Dom::PRF_R1);
    Fp r2_same = prf_R_core(pk, sk, same_seed, Dom::PRF_R2);
    Fp r3_same = prf_R_core(pk, sk, same_seed, Dom::PRF_R3);
    Fp R_same = fp_mul(fp_mul(r1_same, r2_same), r3_same);
    
    // Layer 0 encrypts v+m, Layer 1 encrypts -m
    // T0 = (v+m)*R_same, T1 = (-m)*R_same
    // T0/T1 = (v+m)/(-m) = -v/m - 1
    std::cout << "With same seed: T0/T1 = -v/m - 1 (exact, r1 cancels)\n";
    std::cout << "For v=315: ratio should be simple function of m\n";
    
    return 0;
}
