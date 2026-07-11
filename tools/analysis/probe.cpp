#include <pvac/pvac.hpp>
#include "source/pvac_artifact_serialize.hpp"
#include <array>
#include <fstream>
#include <iostream>
#include <map>
#include <vector>
using namespace pvac;
static constexpr std::array<uint8_t,16> MAGIC={'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'};
static std::vector<uint8_t> rf(const std::string&p){std::ifstream in(p,std::ios::binary);in.seekg(0,std::ios::end);auto n=in.tellg();in.seekg(0);std::vector<uint8_t>d((size_t)n);if(n>0)in.read((char*)d.data(),n);return d;}
static uint64_t tu(const std::vector<uint8_t>&in,size_t&p){uint64_t v=0;for(int i=0;i<8;i++)v|=(uint64_t)in[p++]<<(8*i);return v;}
static std::vector<Cipher> load(const std::vector<uint8_t>&in){size_t p=16;uint64_t c=tu(in,p);std::vector<Cipher>o;for(uint64_t i=0;i<c;i++){uint64_t n=tu(in,p);o.push_back(pvac_ser::deserialize_cipher(in.data()+p,(size_t)n));p+=(size_t)n;}return o;}
static Fp LT(const PubKey&pk,const Cipher&C,uint32_t lid){Fp a=(lid==0&&!C.c0.empty())?C.c0[0]:fp_from_u64(0);for(auto&e:C.E){if(e.layer_id!=lid)continue;Fp t=fp_mul(e.w[0],pk.powg_B[e.idx]);if(sgn_val(e.ch)<0)t=fp_neg(t);a=fp_add(a,t);}return a;}
static bool z(const Fp&x){return x.lo==0&&x.hi==0;}
int main(){
  auto pk=pvac_ser::deserialize_pubkey(rf("pk.bin").data(),rf("pk.bin").size());
  auto cts=load(rf("secret.ct"));
  // check c0 values and T values
  for(size_t i=0;i<cts.size();i++){
    const auto&C=cts[i];
    std::cout<<"ct["<<i<<"] c0=";
    if(C.c0.empty()) std::cout<<"empty";
    else std::cout<<std::hex<<C.c0[0].hi<<":"<<C.c0[0].lo<<std::dec<<" zero="<<z(C.c0[0]);
    std::cout<<"\n";
    for(uint32_t lid=0;lid<C.L.size();lid++){
      Fp T=LT(pk,C,lid);
      std::cout<<"  T"<<lid<<"="<<std::hex<<T.hi<<":"<<T.lo<<std::dec<<"\n";
    }
    // check weight ratios clusters within layer
    for(uint32_t lid=0;lid<C.L.size();lid++){
      std::vector<size_t> ei; for(size_t k=0;k<C.E.size();k++) if(C.E[k].layer_id==lid) ei.push_back(k);
      // look for pairs of opposite-sign edges whose signed g-terms sum to 0 (noise cancel pair without R factor visible)
      int z2=0;
      for(size_t a=0;a<ei.size();a++) for(size_t b=a+1;b<ei.size();b++){
        auto&e1=C.E[ei[a]]; auto&e2=C.E[ei[b]];
        Fp t1=fp_mul(e1.w[0],pk.powg_B[e1.idx]); if(sgn_val(e1.ch)<0)t1=fp_neg(t1);
        Fp t2=fp_mul(e2.w[0],pk.powg_B[e2.idx]); if(sgn_val(e2.ch)<0)t2=fp_neg(t2);
        if(z(fp_add(t1,t2))) z2++;
      }
      if(z2) std::cout<<"  L"<<lid<<" zero-sum pairs="<<z2<<"\n";
    }
  }
  // Try selftest: generate local wrapped text and see if any public invariant leaks plaintext length
  {
    Params prm; prm.noise_entropy_bits=128;
    PubKey tpk; SecKey sk; keygen(prm,tpk,sk);
    std::string msg="hello world test!!"; // 18 bytes
    auto tcts=enc_text(tpk,sk,msg);
    std::cout<<"\nself enc: cts="<<tcts.size()<<" len_ct layers="<<tcts[0].L.size()<<"\n";
    Fp flen=dec_value(tpk,sk,tcts[0]);
    std::cout<<"decrypted len="<<flen.lo<<"\n";
    // public T0,T1 for length cipher
    Fp T0=LT(tpk,tcts[0],0), T1=LT(tpk,tcts[0],1);
    Fp R0=prf_R_slots(tpk,sk,tcts[0].L[0].seed,1)[0];
    Fp R1=prf_R_slots(tpk,sk,tcts[0].L[1].seed,1)[0];
    Fp m_part=fp_mul(T1,fp_inv(R1)); // should be -m
    Fp vp=fp_mul(T0,fp_inv(R0)); // v+m
    std::cout<<"v+m + (-m) = "<<std::hex<<fp_add(vp,m_part).lo<<std::dec<<" (expect len)\n";
    // without sk: is there relation between T0,T1 and PC?
    std::cout<<"PC0 present="<<(!tcts[0].L[0].PC.empty())<<"\n";
  }
  return 0;
}
