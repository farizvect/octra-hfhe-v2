#include <pvac/pvac.hpp>
#include "../challenge/source/pvac_artifact_serialize.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <array>
#include <iomanip>
#include <sstream>
using namespace pvac;
static constexpr std::array<uint8_t,16> MAGIC={'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'};
static std::vector<uint8_t> rf(const std::string&p){std::ifstream in(p,std::ios::binary);in.seekg(0,std::ios::end);auto n=in.tellg();in.seekg(0);std::vector<uint8_t>d((size_t)n);if(n>0)in.read((char*)d.data(),n);return d;}
static uint64_t tu64(const std::vector<uint8_t>&in,size_t&pos){uint64_t v=0;for(int i=0;i<8;i++)v|=(uint64_t)in[pos++]<<(8*i);return v;}
static std::vector<Cipher> load(const std::vector<uint8_t>&in){
  if(in.size()<16||!std::equal(MAGIC.begin(),MAGIC.end(),in.begin())) throw std::runtime_error("magic");
  size_t pos=16; uint64_t c=tu64(in,pos); std::vector<Cipher>o;
  for(uint64_t i=0;i<c;i++){uint64_t n=tu64(in,pos); o.push_back(pvac_ser::deserialize_cipher(in.data()+pos,(size_t)n)); pos+=n;}
  return o;
}
static std::string hex(const std::array<uint8_t,32>&a){std::ostringstream o;for(auto x:a)o<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)x;return o.str();}
int main(int argc,char**argv){
  std::string dir=argc>1?argv[1]:".";
  auto pkb=rf(dir+"/pk.bin"); auto pk=pvac_ser::deserialize_pubkey(pkb.data(),pkb.size());
  auto cts=load(rf(dir+"/secret.ct"));
  std::cout<<"cts="<<cts.size()<<"\n";
  size_t nPC=0, nPC_id=0;
  for(size_t i=0;i<cts.size();++i){
    for(size_t l=0;l<cts[i].L.size();++l){
      auto&L=cts[i].L[l];
      std::cout<<"ct"<<i<<" L"<<l<<" PC.size="<<L.PC.size();
      if(!L.PC.empty()){
        nPC++;
        bool id=true; for(auto b:L.PC[0]) if(b) id=false;
        if(id) nPC_id++;
        std::cout<<" PC0="<<hex(L.PC[0]);
        // check if valid ristretto
        ExtPoint ep; bool ok=rist_decode(ep, L.PC[0]);
        std::cout<<" valid_rist="<<ok;
      }
      std::cout<<"\n";
    }
  }
  std::cout<<"layers_with_PC="<<nPC<<" identity_PC="<<nPC_id<<"\n";
  // Also check if H is regenerable from gen_H
  PubKey pk2; pk2.prm=pk.prm; pk2.canon_tag=pk.canon_tag; gen_H(pk2);
  bool Hmatch=true;
  if(pk2.H.size()!=pk.H.size()) Hmatch=false;
  else for(size_t i=0;i<pk.H.size();++i){
    if(pk2.H[i].w!=pk.H[i].w){Hmatch=false;break;}
  }
  std::cout<<"H regenerable from canon_tag: "<<Hmatch<<"\n";
  std::cout<<"H_digest match: "<<(pk2.H_digest==pk.H_digest)<<"\n";
  auto ubk=gen_ubk_public(pk.canon_tag, pk.prm.m_bits);
  std::cout<<"ubk regenerable: "<<(ubk.perm==pk.ubk.perm && ubk.inv==pk.ubk.inv)<<"\n";
}
