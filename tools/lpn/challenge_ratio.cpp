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
  std::cout<<"Challenge T0/T1 ratios:\n";
  for(uint64_t i=0;i<c;i++){
    uint64_t n=tu(in,p);
    Cipher C=pvac_ser::deserialize_cipher(in.data()+p,(size_t)n);p+=(size_t)n;
    Fp T0=layer_T(pk,C,0), T1=layer_T(pk,C,1);
    Fp ratio=fp_mul(T0,fp_inv(T1));
    Fp prod=fp_mul(T0,T1);
    std::cout<<"ct"<<i<<" T0/T1=("<<std::hex<<ratio.hi<<":"<<ratio.lo<<std::dec<<")";
    std::cout<<" T0*T1=("<<std::hex<<prod.hi<<":"<<prod.lo<<std::dec<<")";
    // Also: check if T0*T1 ratio is constant across ciphers
    // T0*T1 = (v+m)*(-m)*R0*R1 = -m(v+m)*R0*R1
    // If v is small, T0*T1 ≈ -m^2 * R0*R1
    std::cout<<"\n";
  }
  // Check: are ALL T0/T1 ratios the same?
  // Re-parse to check
  in=rf("secret.ct");p=16;c=tu(in,p);
  Fp first_ratio=fp_from_u64(0);
  int same_ratio=1;
  for(uint64_t i=0;i<c;i++){
    uint64_t n=tu(in,p);
    Cipher C=pvac_ser::deserialize_cipher(in.data()+p,(size_t)n);p+=(size_t)n;
    Fp T0=layer_T(pk,C,0), T1=layer_T(pk,C,1);
    Fp ratio=fp_mul(T0,fp_inv(T1));
    if(i==0) first_ratio=ratio;
    else if(ratio.lo!=first_ratio.lo||ratio.hi!=first_ratio.hi) same_ratio=0;
  }
  std::cout<<"\nAll T0/T1 ratios identical? "<<same_ratio<<"\n";
  return 0;
}
