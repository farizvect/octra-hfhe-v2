#include <pvac/pvac.hpp>
#include <iostream>
#include <cmath>
using namespace pvac;

int main(){
  Params prm; prm.noise_entropy_bits=128;
  PubKey pk; SecKey sk; keygen(prm,pk,sk);

  int r1_odd=0, R_odd=0;
  for(int tr=0;tr<2000;tr++){
    RSeed s; s.nonce={csprng_u64(),csprng_u64()};
    s.ztag=prg_layer_ztag(pk.canon_tag,s.nonce);
    Fp r1=prf_R_core(pk,sk,s,Dom::PRF_R1);
    Fp R=prf_R(pk,sk,s);
    if(r1.lo&1) r1_odd++;
    if(R.lo&1) R_odd++;
  }
  std::cout<<"r1.lo&1=1: "<<(double)r1_odd/2000<<" (expect ~0.25)\n";
  std::cout<<"R.lo&1=1:  "<<(double)R_odd/2000<<"\n";

  // Parity preservation test
  Fp a=fp_from_words(3,0), b=fp_from_words(5,0);
  Fp c=fp_mul(a,b);
  std::cout<<"3*5 mod p: lo&1="<<(c.lo&1)<<" (expect 1)\n";

  Fp big1=fp_from_words(UINT64_MAX, MASK63);
  Fp big2=fp_from_words(2,0);
  Fp bigprod=fp_mul(big1,big2);
  std::cout<<"(p-1)*2 mod p: lo&1="<<(bigprod.lo&1)<<"\n";
  // (p-1)*2 = 2p-2, mod p = p-2 = 2^127-3 (odd)
  // p-1 is even, but result is odd -> parity NOT preserved

  // So Fp multiplication does NOT preserve bit 0 when reduction occurs.
  // For random r1,r2,r3 ~ Fp, the product r1*r2*r3 mod p has uniform parity.
  // The toep bit-0 bias is WASHED OUT by Fp multiplication + reduction.
  // That's why R.lo&1 ~ 0.5 despite rj.lo&1 ~ 0.25.

  // Verify: r1*r2 parity vs expected
  int prod_odd=0;
  for(int tr=0;tr<2000;tr++){
    RSeed s; s.nonce={csprng_u64(),csprng_u64()};
    s.ztag=prg_layer_ztag(pk.canon_tag,s.nonce);
    Fp r1=prf_R_core(pk,sk,s,Dom::PRF_R1);
    Fp r2=prf_R_core(pk,sk,s,Dom::PRF_R2);
    Fp p12=fp_mul(r1,r2);
    if(p12.lo&1) prod_odd++;
  }
  std::cout<<"r1*r2 mod p odd: "<<(double)prod_odd/2000<<"\n";

  return 0;
}
