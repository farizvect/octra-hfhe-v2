// Focused: R parity bias consistency + challenge exploitability
#include <pvac/pvac.hpp>
#include "source/pvac_artifact_serialize.hpp"
#include <fstream>
#include <iostream>
#include <vector>
using namespace pvac;
static std::vector<uint8_t> rf(const char*p){
  std::ifstream in(p,std::ios::binary); in.seekg(0,std::ios::end); auto n=in.tellg(); in.seekg(0);
  std::vector<uint8_t> d((size_t)n); if(n>0) in.read((char*)d.data(),n); return d;
}
static uint64_t tu(const std::vector<uint8_t>&in,size_t&p){
  uint64_t v=0; for(int i=0;i<8;i++) v|=(uint64_t)in[p++]<<(8*i); return v;
}
static Fp layer_T(const PubKey& pk, const Cipher& C, uint32_t lid){
  Fp a=(lid==0&&!C.c0.empty())?C.c0[0]:fp_from_u64(0);
  for(auto&e:C.E){if(e.layer_id!=lid)continue; Fp t=fp_mul(e.w[0],pk.powg_B[e.idx]); if(sgn_val(e.ch)<0)t=fp_neg(t); a=fp_add(a,t);}
  return a;
}
int main(){
  Params prm; prm.noise_entropy_bits=128;

  // Test 1: R parity for 3 different keys, 1000 trials each
  for(int key=0; key<3; key++){
    PubKey pk; SecKey sk; keygen(prm,pk,sk);
    int odd=0;
    for(int tr=0;tr<1000;tr++){
      RSeed s; s.nonce={csprng_u64(),csprng_u64()};
      s.ztag=prg_layer_ztag(pk.canon_tag,s.nonce);
      Fp R=prf_R(pk,sk,s);
      if(R.lo&1) odd++;
    }
    std::cout<<"key"<<key<<" R odd="<<(double)odd/1000<<"\n";
  }

  // Test 2: r1*r2*r3 parity vs prf_R parity (should be same)
  {
    PubKey pk; SecKey sk; keygen(prm,pk,sk);
    int odd_manual=0, odd_prf=0;
    for(int tr=0;tr<500;tr++){
      RSeed s; s.nonce={csprng_u64(),csprng_u64()};
      s.ztag=prg_layer_ztag(pk.canon_tag,s.nonce);
      Fp r1=prf_R_core(pk,sk,s,Dom::PRF_R1);
      Fp r2=prf_R_core(pk,sk,s,Dom::PRF_R2);
      Fp r3=prf_R_core(pk,sk,s,Dom::PRF_R3);
      Fp Rm=fp_mul(fp_mul(r1,r2),r3);
      Fp R=prf_R(pk,sk,s);
      if(Rm.lo&1) odd_manual++;
      if(R.lo&1) odd_prf++;
    }
    std::cout<<"manual r1*r2*r3 odd="<<(double)odd_manual/500<<" prf_R odd="<<(double)odd_prf/500<<"\n";
  }

  // Test 3: rj parity individually
  {
    PubKey pk; SecKey sk; keygen(prm,pk,sk);
    int r1o=0,r2o=0,r3o=0;
    for(int tr=0;tr<500;tr++){
      RSeed s; s.nonce={csprng_u64(),csprng_u64()};
      s.ztag=prg_layer_ztag(pk.canon_tag,s.nonce);
      Fp r1=prf_R_core(pk,sk,s,Dom::PRF_R1);
      Fp r2=prf_R_core(pk,sk,s,Dom::PRF_R2);
      Fp r3=prf_R_core(pk,sk,s,Dom::PRF_R3);
      if(r1.lo&1) r1o++;
      if(r2.lo&1) r2o++;
      if(r3.lo&1) r3o++;
    }
    std::cout<<"r1 odd="<<(double)r1o/500<<" r2 odd="<<(double)r2o/500<<" r3 odd="<<(double)r3o/500<<"\n";
    std::cout<<"expected R odd if independent: "<<(double)r1o/500*(double)r2o/500*(double)r3o/500<<"\n";
  }

  // Test 4: Challenge T parity per cipher, per layer
  auto pkb=rf("pk.bin");
  auto pk=pvac_ser::deserialize_pubkey(pkb.data(),pkb.size());
  auto in=rf("secret.ct"); size_t p=16; uint64_t c=tu(in,p);
  std::cout<<"\nChallenge per-cipher T parity:\n";
  for(uint64_t i=0;i<c;i++){
    uint64_t n=tu(in,p);
    Cipher C=pvac_ser::deserialize_cipher(in.data()+p,(size_t)n); p+=(size_t)n;
    Fp T0=layer_T(pk,C,0), T1=layer_T(pk,C,1);
    std::cout<<"  ct"<<std::setw(2)<<i<<" T0:"<<(T0.lo&1)<<" T1:"<<(T1.lo&1)
             <<" T0mod4="<<((T0.lo)&3)<<" T1mod4="<<((T1.lo)&3)
             <<" T0mod8="<<((T0.lo)&7)<<" T1mod8="<<((T1.lo)&7)<<"\n";
  }

  // Test 5: R mod 2,4,8 distribution
  std::cout<<"\nR mod small powers distribution (1000 trials):\n";
  {
    PubKey pk2; SecKey sk2; keygen(prm,pk2,sk2);
    int mod2[2]={0,0}, mod4[4]={0,0,0,0}, mod8[8]={0,0,0,0,0,0,0,0};
    for(int tr=0;tr<1000;tr++){
      RSeed s; s.nonce={csprng_u64(),csprng_u64()};
      s.ztag=prg_layer_ztag(pk2.canon_tag,s.nonce);
      Fp R=prf_R(pk2,sk2,s);
      mod2[R.lo&1]++;
      mod4[R.lo&3]++;
      mod8[R.lo&7]++;
    }
    std::cout<<"  R mod 2: "<<mod2[0]<<" even, "<<mod2[1]<<" odd\n";
    std::cout<<"  R mod 4:";
    for(int i=0;i<4;i++) std::cout<<" "<<i<<":"<<mod4[i];
    std::cout<<"\n  R mod 8:";
    for(int i=0;i<8;i++) std::cout<<" "<<i<<":"<<mod8[i];
    std::cout<<"\n";
  }

  return 0;
}
