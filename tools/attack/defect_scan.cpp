#include <pvac/pvac.hpp>
#include "source/pvac_artifact_serialize.hpp"
#include <fstream>
#include <iostream>
#include <set>
#include <map>
#include <vector>
#include <array>
#include <iomanip>
using namespace pvac;
static constexpr std::array<uint8_t,16> MAGIC={'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'};
static std::vector<uint8_t> rf(const char*p){std::ifstream in(p,std::ios::binary);in.seekg(0,std::ios::end);auto n=in.tellg();in.seekg(0);std::vector<uint8_t>d((size_t)n);if(n>0)in.read((char*)d.data(),n);return d;}
static uint64_t tu(const std::vector<uint8_t>&in,size_t&p){uint64_t v=0;for(int i=0;i<8;i++)v|=(uint64_t)in[p++]<<(8*i);return v;}
static Fp Tof(const PubKey&pk,const Cipher&C,uint32_t lid){Fp a=fp_from_u64(0);for(auto&e:C.E){if(e.layer_id!=lid)continue;Fp t=fp_mul(e.w[0],pk.powg_B[e.idx]);if(sgn_val(e.ch)<0)t=fp_neg(t);a=fp_add(a,t);}return a;}
int main(){
  auto pkb=rf("pk.bin");
  auto pk=pvac_ser::deserialize_pubkey(pkb.data(),pkb.size());
  auto in=rf("secret.ct"); size_t p=16; uint64_t c=tu(in,p);
  std::set<std::tuple<uint64_t,uint64_t,uint64_t>> nonces;
  std::set<uint64_t> ztags;
  int nonce_dups=0, ztag_dups=0;
  int wrap_T_equal=0, wrap_T_neg=0;
  // weight ratio between layers of same wrap - if R0==R1 and related plaintexts
  for(uint64_t i=0;i<c;i++){
    uint64_t n=tu(in,p);
    Cipher C=pvac_ser::deserialize_cipher(in.data()+p,(size_t)n); p+=(size_t)n;
    for(auto&L:C.L){
      if(L.rule!=RRule::BASE) continue;
      auto key=std::make_tuple(L.seed.ztag,L.seed.nonce.lo,L.seed.nonce.hi);
      if(!nonces.insert(key).second) {nonce_dups++; std::cout<<"DUP nonce ct"<<i<<"\n";}
      if(!ztags.insert(L.seed.ztag).second) ztag_dups++;
    }
    if(C.L.size()>=2){
      Fp T0=Tof(pk,C,0), T1=Tof(pk,C,1);
      if(T0.lo==T1.lo&&T0.hi==T1.hi) wrap_T_equal++;
      if(T0.lo==fp_neg(T1).lo&&T0.hi==fp_neg(T1).hi) wrap_T_neg++;
      // ratio T0/T1 public
    }
  }
  std::cout<<"unique_nonces="<<nonces.size()<<" dups="<<nonce_dups<<" ztag_dups="<<ztag_dups<<"\n";
  std::cout<<"wrap T0==T1: "<<wrap_T_equal<<" T0==-T1: "<<wrap_T_neg<<"\n";

  // Uncompress pk and scan for seckey magic / high entropy blobs that look like sk
  auto raw = pvac::compress::is_packed(pkb.data(),pkb.size()) ? pvac::compress::unpack(pkb) : pkb;
  std::cout<<"pk raw size="<<raw.size()<<" compressed="<<(pkb[0]==0xEC)<<"\n";
  // seckey magic from bounty2: 99696666 little = 0x66696999?
  // Search for SK magic patterns
  uint32_t sk_magic_candidates[] = {0x66666999, 0x99666666, 0x66699666, 0x06660666};
  for(uint32_t m: sk_magic_candidates){
    for(size_t i=0;i+4<=raw.size();i++){
      uint32_t v=raw[i]|(raw[i+1]<<8)|(raw[i+2]<<16)|(raw[i+3]<<24);
      if(v==m) std::cout<<"found magic "<<std::hex<<m<<" at off "<<std::dec<<i<<"\n";
    }
  }

  // Check powg_B integrity and omega
  bool roots_ok=true;
  Fp acc=fp_from_u64(1);
  for(int i=0;i<pk.prm.B;i++){
    if(pk.powg_B[i].lo!=acc.lo||pk.powg_B[i].hi!=acc.hi) roots_ok=false;
    acc=fp_mul(acc, pk.powg_B[1]);
  }
  std::cout<<"powg_B roots ok="<<roots_ok<<" omega_B=("<<std::hex<<pk.omega_B.hi<<":"<<pk.omega_B.lo<<std::dec<<")\n";

  // Index collision across opposite signs within same layer (dual-sign)
  in=rf("secret.ct"); p=16; c=tu(in,p);
  int dual_sign_pairs=0;
  for(uint64_t i=0;i<c;i++){
    uint64_t n=tu(in,p);
    Cipher C=pvac_ser::deserialize_cipher(in.data()+p,(size_t)n); p+=(size_t)n;
    for(uint32_t lid=0;lid<C.L.size();lid++){
      std::map<int,int> pos,neg;
      for(size_t ei=0;ei<C.E.size();ei++){
        auto&e=C.E[ei]; if(e.layer_id!=lid) continue;
        if(e.ch==SGN_P) pos[e.idx]++; else neg[e.idx]++;
      }
      for(auto&kv:pos) if(neg.count(kv.first)) dual_sign_pairs++;
    }
  }
  std::cout<<"dual_sign idx collisions (normal after merge): "<<dual_sign_pairs<<"\n";

  // Edge weight Hamming / low-weight?
  in=rf("secret.ct"); p=16; c=tu(in,p);
  int low_hw=0, total_w=0;
  for(uint64_t i=0;i<c;i++){
    uint64_t n=tu(in,p);
    Cipher C=pvac_ser::deserialize_cipher(in.data()+p,(size_t)n); p+=(size_t)n;
    for(auto&e:C.E){
      total_w++;
      int hw=__builtin_popcountll(e.w[0].lo)+__builtin_popcountll(e.w[0].hi);
      if(hw<=8) low_hw++;
    }
  }
  std::cout<<"low hamming weight edges (<=8/128): "<<low_hw<<"/"<<total_w<<"\n";

  // PC equality across layers?
  in=rf("secret.ct"); p=16; c=tu(in,p);
  std::set<std::string> pcs; int pc_dup=0;
  for(uint64_t i=0;i<c;i++){
    uint64_t n=tu(in,p);
    Cipher C=pvac_ser::deserialize_cipher(in.data()+p,(size_t)n); p+=(size_t)n;
    for(auto&L:C.L){
      if(L.PC.empty()) continue;
      std::string s((char*)L.PC[0].data(),32);
      if(!pcs.insert(s).second) pc_dup++;
    }
  }
  std::cout<<"unique PCs="<<pcs.size()<<" dups="<<pc_dup<<"\n";

  // Check serialize_pubkey_raw fields only public
  // Compare regenerable parts
  PubKey pk2; pk2.prm=pk.prm; pk2.canon_tag=pk.canon_tag; gen_H(pk2);
  bool Hok=pk2.H_digest==pk.H_digest;
  auto ubk=gen_ubk_public(pk.canon_tag, pk.prm.m_bits);
  bool ubkok=(ubk.perm==pk.ubk.perm);
  std::cout<<"H regenerable="<<Hok<<" ubk regenerable="<<ubkok<<"\n";

  // Defect: length ct depth 0 has fewer edges - try if length is unwrapped by mistake on any
  in=rf("secret.ct"); p=16; c=tu(in,p);
  for(uint64_t i=0;i<c;i++){
    uint64_t n=tu(in,p);
    Cipher C=pvac_ser::deserialize_cipher(in.data()+p,(size_t)n); p+=(size_t)n;
    size_t bases=0; for(auto&L:C.L) if(L.rule==RRule::BASE) bases++;
    if(bases!=2) std::cout<<"UNEXPECTED base layers ct"<<i<<" ="<<bases<<"\n";
  }
  std::cout<<"all ciphers wrapped (2 base)\n";
}
