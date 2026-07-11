#include <pvac/pvac.hpp>
#include "source/pvac_artifact_serialize.hpp"
#include <array>
#include <fstream>
#include <iostream>
#include <map>
#include <vector>
#include <cmath>
using namespace pvac;
static constexpr std::array<uint8_t,16> MAGIC={'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'};
static std::vector<uint8_t> rf(const std::string&p){std::ifstream in(p,std::ios::binary);in.seekg(0,std::ios::end);auto n=in.tellg();in.seekg(0);std::vector<uint8_t>d((size_t)n);if(n>0)in.read((char*)d.data(),n);return d;}
static uint64_t tu(const std::vector<uint8_t>&in,size_t&p){uint64_t v=0;for(int i=0;i<8;i++)v|=(uint64_t)in[p++]<<(8*i);return v;}
static std::vector<Cipher> load(const std::vector<uint8_t>&in){size_t p=16;uint64_t c=tu(in,p);std::vector<Cipher>o;for(uint64_t i=0;i<c;i++){uint64_t n=tu(in,p);o.push_back(pvac_ser::deserialize_cipher(in.data()+p,(size_t)n));p+=(size_t)n;}return o;}
static Fp layer_T(const PubKey& pk, const Cipher& C, uint32_t lid) {
    Fp acc = (lid==0 && !C.c0.empty()) ? C.c0[0] : fp_from_u64(0);
    for (const auto& e : C.E) {
        if (e.layer_id != lid) continue;
        Fp t = fp_mul(e.w[0], pk.powg_B[e.idx]);
        if (sgn_val(e.ch) < 0) t = fp_neg(t);
        acc = fp_add(acc, t);
    }
    return acc;
}
static bool same(const Fp&a,const Fp&b){return a.lo==b.lo&&a.hi==b.hi;}
static bool is0(const Fp&a){return a.lo==0&&a.hi==0;}

int main(){
    auto pk = pvac_ser::deserialize_pubkey(rf("pk.bin").data(), rf("pk.bin").size());
    auto cts = load(rf("secret.ct"));
    std::cout << "cts="<<cts.size()<<" B="<<pk.prm.B<<" lpn_n="<<pk.prm.lpn_n<<" lpn_t="<<pk.prm.lpn_t<<"\n";
    std::cout << "canon_tag=0x"<<std::hex<<pk.canon_tag<<std::dec<<"\n";

    // 1) Zero T check (should never for wrapped)
    int zero_T=0;
    for(size_t i=0;i<cts.size();i++)
      for(uint32_t l=0;l<cts[i].L.size();l++)
        if(cts[i].L[l].rule==RRule::BASE && is0(layer_T(pk,cts[i],l))) {zero_T++; std::cout<<"ZERO T ct"<<i<<" L"<<l<<"\n";}
    std::cout<<"zero_T_count="<<zero_T<<"\n";

    // 2) R2-style: for each layer, any opposite-sign pair sum equal across layers? 
    //    or equal to square of something public?
    //    Check if any opposite-sign pair term sum equals T (would mean R*(d) = R*v => d=v for that pair alone)
    int pair_eq_T=0, pair_eq_T2=0;
    for(size_t i=0;i<cts.size();i++){
      for(uint32_t lid=0;lid<cts[i].L.size();lid++){
        if(cts[i].L[lid].rule!=RRule::BASE) continue;
        Fp T=layer_T(pk,cts[i],lid);
        Fp T2=fp_mul(T,T);
        std::vector<Fp> terms;
        for(auto&e:cts[i].E){
          if(e.layer_id!=lid) continue;
          Fp t=fp_mul(e.w[0],pk.powg_B[e.idx]);
          if(sgn_val(e.ch)<0) t=fp_neg(t);
          terms.push_back(t);
        }
        for(size_t a=0;a<terms.size();a++)
          for(size_t b=a+1;b<terms.size();b++){
            Fp s=fp_add(terms[a],terms[b]);
            if(same(s,T)||same(s,fp_neg(T))) pair_eq_T++;
            if(same(s,T2)||same(s,fp_neg(T2))) pair_eq_T2++;
          }
      }
    }
    std::cout<<"opp-pair sum == ±T: "<<pair_eq_T<<" == ±T^2: "<<pair_eq_T2<<"\n";

    // 3) Length candidates: try L in 301..315; without oracle can't verify, but check if T0+T1 related
    //    For wrap: T0/R0 + T1/R1 = L. Without R, check T0+T1 (only if R0=R1=1 impossible)
    Fp T0=layer_T(pk,cts[0],0), T1=layer_T(pk,cts[0],1);
    std::cout<<"len T0+T1 zero? "<<is0(fp_add(T0,T1))<<"\n";
    std::cout<<"len T0/T1 ratio exists (non-zero both): "<<(!is0(T0)&&!is0(T1))<<"\n";

    // 4) PC validity: decode as ristretto
    int bad_pc=0, good_pc=0;
    for(auto&C:cts) for(auto&L:C.L) for(auto&pc:L.PC){
      try { (void)rist_decode_or_throw(pc); good_pc++; }
      catch(...) { bad_pc++; }
    }
    std::cout<<"PC good="<<good_pc<<" bad="<<bad_pc<<"\n";

    // 5) Cross-layer weight equality across ALL layers (RNG reuse)
    std::map<std::pair<uint64_t,uint64_t>,int> wfreq;
    for(auto&C:cts) for(auto&e:C.E) if(!e.w.empty()) wfreq[{e.w[0].lo,e.w[0].hi}]++;
    int reused=0; for(auto&kv:wfreq) if(kv.second>1) reused++;
    std::cout<<"unique edge weights="<<wfreq.size()<<" reused_values="<<reused<<"\n";

    // 6) Nonce uniqueness
    std::map<std::pair<uint64_t,uint64_t>,int> nonces;
    for(auto&C:cts) for(auto&L:C.L) if(L.rule==RRule::BASE) nonces[{L.seed.nonce.lo,L.seed.nonce.hi}]++;
    int nonce_re=0; for(auto&kv:nonces) if(kv.second>1) nonce_re++;
    std::cout<<"base layers="<<nonces.size()<<" nonce_collisions="<<nonce_re<<"\n";

    // 7) ztag consistency with public formula
    int zbad=0;
    for(auto&C:cts) for(auto&L:C.L) if(L.rule==RRule::BASE){
      if(L.seed.ztag != prg_layer_ztag(pk.canon_tag, L.seed.nonce)) zbad++;
    }
    std::cout<<"ztag_mismatch="<<zbad<<"\n";

    // 8) Try: for length L, brute small L, compute candidate R from T if single-layer (not)
    //    With wrap: for each L, for random m samples - useless at 2^127.
    //    Just print expected length range
    std::cout<<"expected_len_range="<<(cts.size()-2)*15+1<<".."<<(cts.size()-1)*15<<"\n";

    // 9) Edge weight / g ratios - look for small integers (signal last coef structure)
    int smallish=0;
    for(size_t i=0;i<std::min(cts.size(),(size_t)3);i++){
      for(uint32_t lid=0;lid<cts[i].L.size();lid++){
        if(cts[i].L[lid].rule!=RRule::BASE) continue;
        for(auto&e:cts[i].E){
          if(e.layer_id!=lid || e.w.empty()) continue;
          // w / g - random-looking?
          Fp q = fp_mul(e.w[0], fp_inv(pk.powg_B[e.idx]));
          if(q.hi==0 && q.lo < (1ull<<40)) smallish++;
          Fp qn=fp_neg(q);
          if(qn.hi==0 && qn.lo < (1ull<<40)) smallish++;
        }
      }
    }
    std::cout<<"smallish w/g in first 3 cts: "<<smallish<<"\n";

    return 0;
}
