#include <pvac/pvac.hpp>
#include "source/pvac_artifact_serialize.hpp"
#include <fstream>
#include <iostream>
#include <vector>
#include <array>
using namespace pvac;
static constexpr std::array<uint8_t,16> MAGIC={'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'};
static std::vector<uint8_t> rf(const char*p){std::ifstream in(p,std::ios::binary);in.seekg(0,std::ios::end);auto n=in.tellg();in.seekg(0);std::vector<uint8_t>d((size_t)n);if(n>0)in.read((char*)d.data(),n);return d;}
static uint64_t tu(const std::vector<uint8_t>&in,size_t&p){uint64_t v=0;for(int i=0;i<8;i++)v|=(uint64_t)in[p++]<<(8*i);return v;}
int main(){
  auto pk=pvac_ser::deserialize_pubkey(rf("pk.bin").data(),rf("pk.bin").size());
  auto in=rf("secret.ct"); size_t p=16; uint64_t c=tu(in,p);
  for(uint64_t i=0;i<c;i++){
    uint64_t n=tu(in,p);
    Cipher C=pvac_ser::deserialize_cipher(in.data()+p,(size_t)n); p+=(size_t)n;
    std::cout<<"ct"<<i<<" c0.size="<<C.c0.size();
    if(!C.c0.empty()){
      std::cout<<" c0=("<<std::hex<<C.c0[0].hi<<":"<<C.c0[0].lo<<std::dec<<")"
               <<" zero="<<(C.c0[0].lo==0&&C.c0[0].hi==0);
    }
    // edge weight zero count
    int wz=0;
    for(auto&e:C.E) if(e.w.empty()||(e.w[0].lo==0&&e.w[0].hi==0)) wz++;
    std::cout<<" zero_weight_edges="<<wz<<"/"<<C.E.size()<<"\n";
  }
  // Self: what is c0 after enc?
  Params prm; prm.noise_entropy_bits=128;
  PubKey pk2; SecKey sk; keygen(prm,pk2,sk);
  auto C1=enc_fp_raw_depth(pk2,sk,fp_from_u64(42),2);
  auto C2=enc_fp_wrapped_depth(pk2,sk,fp_from_u64(42),2);
  auto C3=enc_value(pk2,sk,42);
  std::cout<<"self raw c0.size="<<C1.c0.size(); if(!C1.c0.empty()) std::cout<<" zero="<<(C1.c0[0].lo==0&&C1.c0[0].hi==0);
  std::cout<<"\nself wrap c0.size="<<C2.c0.size(); if(!C2.c0.empty()) std::cout<<" zero="<<(C2.c0[0].lo==0&&C2.c0[0].hi==0);
  std::cout<<"\nself value c0.size="<<C3.c0.size(); if(!C3.c0.empty()) std::cout<<" zero="<<(C3.c0[0].lo==0&&C3.c0[0].hi==0);
  std::cout<<"\n";
}
