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
  auto pkb=rf("pk.bin");
  auto pk=pvac_ser::deserialize_pubkey(pkb.data(),pkb.size());
  std::cout<<"pk B="<<pk.prm.B<<" m_bits="<<pk.prm.m_bits<<" n_bits="<<pk.prm.n_bits
           <<" lpn_n="<<pk.prm.lpn_n<<" lpn_t="<<pk.prm.lpn_t<<" noise_ent="<<pk.prm.noise_entropy_bits
           <<" canon="<<std::hex<<pk.canon_tag<<std::dec<<"\n";
  auto in=rf("secret.ct");
  size_t p=16; uint64_t c=tu(in,p);
  std::cout<<"ciphers="<<c<<"\n";
  size_t total_edges=0, total_layers=0;
  for(uint64_t i=0;i<c;i++){
    uint64_t n=tu(in,p);
    Cipher C=pvac_ser::deserialize_cipher(in.data()+p,(size_t)n); p+=(size_t)n;
    total_edges+=C.E.size(); total_layers+=C.L.size();
    // T per layer
    std::cout<<"ct"<<i<<" slots="<<C.slots<<" nL="<<C.L.size()<<" nE="<<C.E.size()<<" c0="<<C.c0.size();
    for(size_t lid=0;lid<C.L.size();lid++){
      auto&L=C.L[lid];
      Fp T=fp_from_u64(0);
      int ne=0;
      for(auto&e:C.E) if(e.layer_id==(uint32_t)lid){
        ne++;
        Fp t=fp_mul(e.w[0], pk.powg_B[e.idx]);
        if(sgn_val(e.ch)<0) t=fp_neg(t);
        T=fp_add(T,t);
      }
      std::cout<<" | L"<<lid<<" rule="<<(int)L.rule<<" edges="<<ne
               <<" T_zero="<<(T.lo==0&&T.hi==0)
               <<" PC="<<(!L.PC.empty())
               <<" Rcom_zero=";
      bool z=true; for(auto b:L.R_com) if(b) z=false;
      std::cout<<z;
      if(L.rule==RRule::BASE) std::cout<<" nonce=("<<std::hex<<L.seed.nonce.hi<<":"<<L.seed.nonce.lo<<std::dec<<")";
    }
    std::cout<<"\n";
  }
  std::cout<<"total_layers="<<total_layers<<" total_edges="<<total_edges<<"\n";
}
