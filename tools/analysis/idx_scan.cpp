#include <pvac/pvac.hpp>
#include "source/pvac_artifact_serialize.hpp"
#include <array>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <vector>
using namespace pvac;
static constexpr std::array<uint8_t,16> MAGIC={'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'};
static std::vector<uint8_t> rf(const std::string&p){std::ifstream in(p,std::ios::binary);in.seekg(0,std::ios::end);auto n=in.tellg();in.seekg(0);std::vector<uint8_t>d((size_t)n);if(n>0)in.read((char*)d.data(),n);return d;}
static uint64_t tu(const std::vector<uint8_t>&in,size_t&p){uint64_t v=0;for(int i=0;i<8;i++)v|=(uint64_t)in[p++]<<(8*i);return v;}
static std::vector<Cipher> load(const std::vector<uint8_t>&in){size_t p=16;uint64_t c=tu(in,p);std::vector<Cipher>o;for(uint64_t i=0;i<c;i++){uint64_t n=tu(in,p);o.push_back(pvac_ser::deserialize_cipher(in.data()+p,(size_t)n));p+=(size_t)n;}return o;}
int main(){
  auto pk=pvac_ser::deserialize_pubkey(rf("pk.bin").data(),rf("pk.bin").size());
  auto cts=load(rf("secret.ct"));
  for(size_t i=0;i<cts.size();i++){
    const auto&C=cts[i];
    for(uint32_t lid=0;lid<C.L.size();lid++){
      std::map<int,int> both; // idx -> count across signs
      std::map<std::pair<int,int>,int> signedc; // (idx,ch)
      for(auto&e:C.E){ if(e.layer_id!=lid)continue; both[e.idx]++; signedc[{e.idx,e.ch}]++; }
      int multi=0, both_signs=0;
      for(auto&[k,v]:both) if(v>1) multi++;
      for(auto&[k,v]:signedc) if(v>1){}
      // check same idx with both signs present
      std::set<int> pos,neg;
      for(auto&e:C.E){ if(e.layer_id!=lid)continue; if(e.ch==SGN_P)pos.insert(e.idx); else neg.insert(e.idx); }
      int dual=0; for(int x:pos) if(neg.count(x)) dual++;
      if(multi||dual)
        std::cout<<"ct["<<i<<"] L"<<lid<<" edges_unique_idx="<<both.size()<<" multi_idx="<<multi<<" both_signs="<<dual<<"\n";
    }
  }
  return 0;
}
