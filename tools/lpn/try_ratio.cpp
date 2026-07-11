// Try the ratio approach: assume T0/T1 ≈ -(v+m)/m ≈ -v/m - 1 (for v << m)
// For length cipher ct0: v = L ∈ {301..315}
// From T0/T1 we get m ≈ -v/(T0/T1 + 1) approximate
// Then R0 ≈ T0/(L+m) and R1 ≈ T1/(-m)
// Use LPN samples to verify: ybits should match prf_R1 evaluation
#include <pvac/pvac.hpp>
#include "source/pvac_artifact_serialize.hpp"
#include <fstream>
#include <iostream>
#include <vector>
#include <array>
using namespace pvac;
static std::vector<uint8_t> rf(const char*p){std::ifstream in(p,std::ios::binary);in.seekg(0,std::ios::end);auto n=in.tellg();in.seekg(0);std::vector<uint8_t>d((size_t)n);if(n>0)in.read((char*)d.data(),n);return d;}
static uint64_t tu(const std::vector<uint8_t>&in,size_t&p){uint64_t v=0;for(int i=0;i<8;i++)v|=(uint64_t)in[p++]<<(8*i);return v;}
static Fp layer_T(const PubKey& pk,const Cipher&C,uint32_t lid){
  Fp a=fp_from_u64(0);for(auto&e:C.E){if(e.layer_id!=lid)continue;Fp t=fp_mul(e.w[0],pk.powg_B[e.idx]);if(sgn_val(e.ch)<0)t=fp_neg(t);a=fp_add(a,t);}return a;
}
int main(){
  auto pk=pvac_ser::deserialize_pubkey(rf("pk.bin").data(),rf("pk.bin").size());
  auto in=rf("secret.ct");size_t p=16;uint64_t c=tu(in,p);
  // Get ct0 (length cipher)
  uint64_t n=tu(in,p);
  Cipher C=pvac_ser::deserialize_cipher(in.data()+p,(size_t)n);
  Fp T0=layer_T(pk,C,0), T1=layer_T(pk,C,1);
  
  std::cout<<"Length cipher ct0:\n";
  std::cout<<"  T0=("<<std::hex<<T0.hi<<":"<<T0.lo<<std::dec<<")\n";
  std::cout<<"  T1=("<<std::hex<<T1.hi<<":"<<T1.lo<<std::dec<<")\n";
  
  // Try each length candidate
  Fp neg_one = fp_neg(fp_from_u64(1));
  Fp ratio = fp_mul(T0, fp_inv(T1));
  std::cout<<"  T0/T1=("<<std::hex<<ratio.hi<<":"<<ratio.lo<<std::dec<<")\n";
  
  for(uint64_t L=301; L<=315; L++){
    Fp v = fp_from_u64(L);
    // From: ratio = -(v+m)/m * (R0/R1)
    // If R0/R1 = 1: ratio = -(v+m)/m → m = -v/(ratio+1)
    Fp rp1 = fp_add(ratio, fp_from_u64(1));
    Fp m = fp_mul(fp_neg(v), fp_inv(rp1));
    Fp R0_cand = fp_mul(T0, fp_inv(fp_add(v, m)));
    Fp R1_cand = fp_mul(T1, fp_inv(fp_neg(m)));
    
    std::cout<<"  L="<<L<<": m_lo="<<std::hex<<(m.lo&0xFFFF)<<std::dec;
    // Check if m is "small" (unlikely - should be random Fp)
    bool m_small = (m.hi==0 && m.lo < (1ULL<<40));
    std::cout<<" m_small="<<m_small;
    
    // Self-verify: does T0 = (L+m)*R0?
    Fp check0 = fp_mul(fp_add(v,m), R0_cand);
    std::cout<<" T0_check="<<(check0.lo==T0.lo&&check0.hi==T0.hi);
    std::cout<<" R0=("<<std::hex<<(R0_cand.hi&0xFFF)<<":"<<(R0_cand.lo&0xFFFF)<<std::dec<<")";
    std::cout<<"\n";
  }
  
  // Key insight: the LPN samples contain ybits for PRF_R1 for both layers
  // ybits are derived from AES key = SHA256(prf_k || seed || dom)
  // Without prf_k, we can't verify R candidates
  // BUT: the ratio approach gives us R0 = T0/(L+m) for each L guess
  // and the ratio is ONLY valid if R0/R1 = 1 (which it isn't in the actual code)
  std::cout<<"\nR0/R1 is NOT 1 in the actual implementation.\n";
  std::cout<<"The ratio T0/T1 = -(v+m)/m * (R0/R1) has unknown R0/R1.\n";
  
  return 0;
}
