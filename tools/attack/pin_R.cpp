#include <pvac/pvac.hpp>
#include "source/pvac_artifact_serialize.hpp"
#include <array>
#include <fstream>
#include <iostream>
#include <vector>
using namespace pvac;
static constexpr std::array<uint8_t,16> MAGIC={'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'};
static std::vector<uint8_t> rf(const std::string&p){std::ifstream in(p,std::ios::binary);in.seekg(0,std::ios::end);auto n=in.tellg();in.seekg(0);std::vector<uint8_t>d((size_t)n);if(n>0)in.read((char*)d.data(),n);return d;}
static uint64_t tu(const std::vector<uint8_t>&in,size_t&p){uint64_t v=0;for(int i=0;i<8;i++)v|=(uint64_t)in[p++]<<(8*i);return v;}
static std::vector<Cipher> load(const std::vector<uint8_t>&in){size_t p=16;uint64_t c=tu(in,p);std::vector<Cipher>o;for(uint64_t i=0;i<c;i++){uint64_t n=tu(in,p);o.push_back(pvac_ser::deserialize_cipher(in.data()+p,(size_t)n));p+=(size_t)n;}return o;}
static Fp layer_T(const PubKey& pk,const Cipher&C,uint32_t lid){Fp acc=(lid==0&&!C.c0.empty())?C.c0[0]:fp_from_u64(0);for(auto&e:C.E){if(e.layer_id!=lid)continue;Fp t=fp_mul(e.w[0],pk.powg_B[e.idx]);if(sgn_val(e.ch)<0)t=fp_neg(t);acc=fp_add(acc,t);}return acc;}

// OLD R_com with R included
static std::array<uint8_t,32> old_rcom(uint64_t canon,uint64_t ztag,uint64_t nlo,uint64_t nhi,const Fp&R){
  Sha256 s;s.init();s.update("pvac.dom.r_com",14);
  sha256_acc_u64(s,canon);sha256_acc_u64(s,ztag);sha256_acc_u64(s,nlo);sha256_acc_u64(s,nhi);
  sha256_acc_u64(s,1);sha256_acc_u64(s,R.lo);sha256_acc_u64(s,R.hi&MASK63);
  std::array<uint8_t,32>o{};s.finish(o.data());return o;
}

int main(){
  auto pkb=rf("pk.bin"); auto pk=pvac_ser::deserialize_pubkey(pkb.data(),pkb.size());
  auto cts=load(rf("secret.ct"));
  // After deserialize, is R_com zero or public formula?
  int zero=0, match_pub=0, n=0;
  for(auto&C:cts) for(auto&L:C.L){
    if(L.rule!=RRule::BASE) continue;
    ++n;
    bool z=true; for(auto b:L.R_com) if(b) z=false;
    if(z) ++zero;
    auto pub=compute_R_com_base(pk.canon_tag,L.seed.ztag,L.seed.nonce.lo,L.seed.nonce.hi,{fp_from_u64(0)});
    if(pub==L.R_com) ++match_pub;
  }
  std::cout<<"base layers="<<n<<" R_com_zero="<<zero<<" match_public_formula="<<match_pub<<"\n";

  // THE PIN: PC is the only R-dependent public object.
  // For length cipher L in 301..315, if UNWRAPPED: R=T/L, check if PC opens with rho brute - impossible.
  // With wrap: try to see if m is related to L or seed publicly
  //
  // Experimental pin attempt: assume rho is sc_from_fp of something public
  // and try to open PC for length candidates under raw (single layer) model — won't work for wrap.
  //
  // Try: for each layer, treat candidate R from T/x for small x, compute
  // Q = PC / g^{sc(Rinv)}, check if Q equals H^{hash(public only)} for various public formulas
  int pub_rho_hits=0;
  for(size_t i=0;i<cts.size();i++){
    for(uint32_t lid=0;lid<cts[i].L.size();lid++){
      if(cts[i].L[lid].rule!=RRule::BASE) continue;
      if(cts[i].L[lid].PC.empty()) continue;
      Fp T=layer_T(pk,cts[i],lid);
      if(T.lo==0&&T.hi==0) continue;
      // try x = 1..500 as layer plaintext (raw model)
      for(uint64_t x=1;x<=500;x++){
        Fp X=fp_from_u64(x);
        Fp R=fp_mul(T,fp_inv(X));
        Fp Rinv=fp_inv(R);
        Scalar sc=sc_from_fp_signed(Rinv);
        auto gpart=rist_scalarmul(rist_G(),sc);
        auto Q=rist_sub(cts[i].L[lid].PC[0], gpart);
        // try public rho candidates
        auto try_rho=[&](Scalar rho){
          auto expect=rist_scalarmul(rist_H(),rho);
          bool m=true; for(int k=0;k<32;k++) if(Q.data()[k]!=expect.data()[k]) m=false;
          return m;
        };
        // rho = sc_from_fp(nonce stuff)
        uint8_t buf[32]={};
        // 1) SHA of public seed only
        {
          Sha256 h;h.init();h.update(Dom::PRF_RHO,strlen(Dom::PRF_RHO));
          sha256_acc_u64(h,0);sha256_acc_u64(h,0);sha256_acc_u64(h,0);sha256_acc_u64(h,0);
          sha256_acc_u64(h,cts[i].L[lid].seed.nonce.lo);
          sha256_acc_u64(h,cts[i].L[lid].seed.nonce.hi);
          sha256_acc_u64(h,0);
          h.finish(buf);
          if(try_rho(sc_reduce256(buf))) {std::cout<<"HIT public rho zero-key ct"<<i<<" L"<<lid<<" x="<<x<<"\n"; pub_rho_hits++;}
        }
        // 2) SHA of seed without prf domain
        {
          Sha256 h;h.init();
          sha256_acc_u64(h,pk.canon_tag);
          sha256_acc_u64(h,cts[i].L[lid].seed.ztag);
          sha256_acc_u64(h,cts[i].L[lid].seed.nonce.lo);
          sha256_acc_u64(h,cts[i].L[lid].seed.nonce.hi);
          h.finish(buf);
          if(try_rho(sc_reduce256(buf))) {std::cout<<"HIT seed-only rho ct"<<i<<" L"<<lid<<" x="<<x<<"\n"; pub_rho_hits++;}
        }
        // 3) rho = 0
        if(try_rho(sc_zero())) {std::cout<<"HIT rho=0 ct"<<i<<" L"<<lid<<" x="<<x<<"\n"; pub_rho_hits++;}
      }
    }
  }
  std::cout<<"public-rho open hits: "<<pub_rho_hits<<"\n";

  // Self-test: with real sk, opening works for true x
  Params prm; prm.noise_entropy_bits=128; PubKey pk2; SecKey sk; keygen(prm,pk2,sk);
  Fp v=fp_from_u64(42);
  Cipher C=enc_fp_raw_depth(pk2,sk,v,2);
  Fp R=prf_R_slots(pk2,sk,C.L[0].seed,1)[0];
  Fp Rinv=fp_inv(R);
  // derive real rho
  Sha256 h;h.init();h.update(Dom::PRF_RHO,strlen(Dom::PRF_RHO));
  for(int k=0;k<4;k++) sha256_acc_u64(h,sk.prf_k[k]);
  sha256_acc_u64(h,C.L[0].seed.nonce.lo);sha256_acc_u64(h,C.L[0].seed.nonce.hi);sha256_acc_u64(h,0);
  uint8_t b[32];h.finish(b); Scalar rho=sc_reduce256(b);
  auto gpart=rist_scalarmul(rist_G(),sc_from_fp_signed(Rinv));
  auto Q=rist_sub(C.L[0].PC[0],gpart);
  auto expect=rist_scalarmul(rist_H(),rho);
  bool ok=true; for(int i=0;i<32;i++) if(Q.data()[i]!=expect.data()[i]) ok=false;
  std::cout<<"selftest PC open with sk: "<<ok<<"\n";

  // Can we use OLD r_com on challenge if they generated with old lib but stripped wire?
  // Would need R_com on wire - we don't have it.
  // But: if PC somehow equals something with old binding... no.

  // INHOMOGENEOUS pin search: PC depends on Rinv non-linearly in F_p sense via curve.
  // Without rho, information-theoretically hidden.
  // Unless rho is correlated with Rinv (same prf_k stream)!
  // Both R and rho depend on sk!
  // R = LPN_PRF(prf_k, lpn_s, seed)
  // rho = SHA(prf_k, seed)
  // Related-key: rho is independent of LPN (different derivation) - random oracle independent of R given public seed.
  // Related only through prf_k. Attacking needs to find prf_k such that:
  //   exists lpn_s: R = PRF(prf_k,lpn_s,seed) AND PC = g^{sc(1/R)} h^{H(prf_k||seed)}
  // That's the full sk recovery problem.

  std::cout<<"\nPIN STATUS: only inhomogeneous public object is PC=g^{Rinv}h^rho.\n"
           <<"rho has full 256-bit secret entropy from prf_k.\n"
           <<"No public-only opening found.\n";
  return 0;
}
