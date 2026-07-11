#include <pvac/pvac.hpp>
#include <iostream>
#include <vector>
#include <map>
#include <set>
using namespace pvac;

static bool eq(const Fp&a,const Fp&b){return a.lo==b.lo&&a.hi==b.hi;}
static bool is0(const Fp&a){return a.lo==0&&a.hi==0;}
static Fp Tof(const PubKey&pk,const Cipher&C,uint32_t lid){
  Fp acc=fp_from_u64(0);
  for(auto&e:C.E){if(e.layer_id!=lid)continue; Fp t=fp_mul(e.w[0],pk.powg_B[e.idx]); if(sgn_val(e.ch)<0)t=fp_neg(t); acc=fp_add(acc,t);} return acc;
}

// Represent Fp as integer 0..p-1
static unsigned __int128 as_int(const Fp&x){ return (unsigned __int128)x.lo + (((unsigned __int128)x.hi)<<64); }
static Fp from_int(unsigned __int128 z){ return fp_from_words((uint64_t)z, (uint64_t)(z>>64)); }

// Euclidean GCD in field doesn't help; try GCD of integer lifts of weights as integers < p
// If coefs are "random full field", GCD of R*c_i as integers is ~1. If coefs were small, GCD ~ R.
static unsigned __int128 ugcd(unsigned __int128 a, unsigned __int128 b){
  while(b){ auto t=a%b; a=b; b=t; } return a;
}

int main(){
  Params prm; prm.noise_entropy_bits=128;
  int hits_gcd_R=0, hits_gcd_R2=0, trials=20;
  for(int t=0;t<trials;t++){
    PubKey pk; SecKey sk; keygen(prm,pk,sk);
    Fp v=fp_from_u64(1000+t);
    Cipher C=enc_fp_raw_depth(pk,sk,v,2);
    Fp R=prf_R_slots(pk,sk,C.L[0].seed,1)[0];
    unsigned __int128 Ri=as_int(R);
    // integer GCD of all weights
    unsigned __int128 g=0;
    for(auto&e:C.E){ if(e.layer_id!=0||e.w.empty())continue;
      unsigned __int128 w=as_int(e.w[0]);
      if(w==0) continue;
      g = g==0?w:ugcd(g,w);
    }
    if(g==Ri || g==as_int(fp_neg(R))) hits_gcd_R++;
    // also try GCD of terms
    unsigned __int128 gt=0;
    for(auto&e:C.E){ if(e.layer_id!=0)continue;
      Fp term=fp_mul(e.w[0],pk.powg_B[e.idx]);
      unsigned __int128 ti=as_int(term);
      if(ti==0)continue;
      gt=gt==0?ti:ugcd(gt,ti);
    }
    if(gt==Ri) hits_gcd_R++;
    // check if g is a small multiple of R: g/R small integer
    if(g>1 && Ri>0 && g%Ri==0){
      unsigned __int128 m=g/Ri;
      if(m < 1000000) { hits_gcd_R2++; std::cout<<"gcd is "<<(uint64_t)m<<"*R\n"; }
    }
  }
  std::cout<<"integer-GCD equals R hits: "<<hits_gcd_R<<" / "<<trials<<"\n";
  std::cout<<"GCD = small*R hits: "<<hits_gcd_R2<<"\n";

  // Another idea: for wrapped, T0 and T1, is there relation with PC points via bilinear?
  // Ristretto has no pairing.

  // Salt brute on ONE edge of self-test - verify 64-bit salt is searchable in principle
  {
    PubKey pk; SecKey sk; keygen(prm,pk,sk);
    Cipher C=enc_fp_raw_depth(pk,sk,fp_from_u64(1),0); // low depth fewer edges
    // Find an edge and brute a few random salts won't work; just recompute with known... we don't know salt.
    // Instead: measure if salt appears anywhere public - no.
    std::cout<<"edges depth0="<<C.E.size()<<"\n";
  }

  // CRITICAL: does PC use R or R_inv? and can we recover R from PC if rho is derived from PUBLIC only by mistake?
  // Test: recompute PC with only public inputs (rho from zeros prf_k)
  {
    PubKey pk; SecKey sk; keygen(prm,pk,sk);
    Cipher C=enc_fp_raw_depth(pk,sk,fp_from_u64(42),2);
    Fp R=prf_R_slots(pk,sk,C.L[0].seed,1)[0];
    Fp Rinv=fp_inv(R);
    // try rho with prf_k=0
    SecKey zsk=sk; for(int i=0;i<4;i++) zsk.prf_k[i]=0;
    Sha256 h; h.init(); h.update(Dom::PRF_RHO,strlen(Dom::PRF_RHO));
    for(int k=0;k<4;k++) sha256_acc_u64(h,0);
    sha256_acc_u64(h,C.L[0].seed.nonce.lo);
    sha256_acc_u64(h,C.L[0].seed.nonce.hi);
    sha256_acc_u64(h,0);
    uint8_t b[32]; h.finish(b);
    Scalar rho=sc_reduce256(b);
    auto fake=pedersen_commit(sc_from_fp_signed(Rinv), rho);
    bool match=true; for(int i=0;i<32;i++) if(fake.data()[i]!=C.L[0].PC[0].data()[i]) match=false;
    std::cout<<"PC opens with zero prf_k? "<<match<<" (expect 0)\n";
  }

  // Hunt: among edge weights, is R equal to w_i * inv(some_public)?
  {
    int found=0;
    for(int t=0;t<10;t++){
      PubKey pk; SecKey sk; keygen(prm,pk,sk);
      Cipher C=enc_fp_raw_depth(pk,sk,fp_from_u64(7),2);
      Fp R=prf_R_slots(pk,sk,C.L[0].seed,1)[0];
      for(auto&e:C.E){
        if(e.layer_id!=0) continue;
        // w = R * coef, coef random - not public
        // w * inv(g) = R * coef * inv(g) - not R
        Fp cand=fp_mul(e.w[0], fp_inv(pk.powg_B[e.idx]));
        if(eq(cand,R)||eq(cand,fp_neg(R))) found++;
        if(eq(e.w[0],R)||eq(e.w[0],fp_neg(R))) found++;
      }
    }
    std::cout<<"weight-based R hits: "<<found<<"\n";
  }

  // Wrap: can we find m,R0,R1 from algebraic ideal membership?
  // T0*(something) = ...
  // Overdetermined? 2 equations 4 unknowns - no.

  // NEW: depth 0 length cipher has fewer noise edges. Still scales.

  // NEW: check if prf_R with only public-derived AES key (no sk) ever matches
  {
    PubKey pk; SecKey sk; keygen(prm,pk,sk);
    Cipher C=enc_fp_raw_depth(pk,sk,fp_from_u64(1),2);
    Fp real=prf_R(pk,sk,C.L[0].seed);
    SecKey z=sk; for(auto&x:z.prf_k)x=0; for(auto&x:z.lpn_s_bits)x=0;
    Fp fake=prf_R(pk,z,C.L[0].seed);
    std::cout<<"R with zero sk equals real? "<<eq(real,fake)<<"\n";
  }

  return 0;
}
