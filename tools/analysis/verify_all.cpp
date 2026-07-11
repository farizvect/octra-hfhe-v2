#include <pvac/pvac.hpp>
#include "source/pvac_artifact_serialize.hpp"
#include <fstream>
#include <iostream>
#include <vector>
#include <array>
#include <set>
#include <string>
using namespace pvac;
static constexpr std::array<uint8_t,16> MAGIC={'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'};
static std::vector<uint8_t> rf(const char*p){
  std::ifstream in(p,std::ios::binary);
  in.seekg(0,std::ios::end); auto n=in.tellg(); in.seekg(0);
  std::vector<uint8_t> d((size_t)n);
  if(n>0) in.read((char*)d.data(),n);
  return d;
}
static uint64_t tu(const std::vector<uint8_t>&in,size_t&p){
  uint64_t v=0; for(int i=0;i<8;i++) v|=(uint64_t)in[p++]<<(8*i); return v;
}
static Fp layer_T(const PubKey& pk, const Cipher& C, uint32_t lid){
  Fp a = (lid==0 && !C.c0.empty()) ? C.c0[0] : fp_from_u64(0);
  for(auto&e:C.E){
    if(e.layer_id!=lid) continue;
    Fp t=fp_mul(e.w[0],pk.powg_B[e.idx]);
    if(sgn_val(e.ch)<0) t=fp_neg(t);
    a=fp_add(a,t);
  }
  return a;
}
static bool eqP(const RistrettoPoint&a,const RistrettoPoint&b){
  for(int i=0;i<32;i++) if(a.data()[i]!=b.data()[i]) return false;
  return true;
}

int main(){
  int pass=0, fail=0;
  auto check=[&](const char*name, bool ok){
    std::cout<<(ok?"PASS":"FAIL")<<": "<<name<<"\n";
    if(ok) pass++; else fail++;
  };

  // 1. File integrity
  auto pkb_raw=rf("pk.bin");
  auto ctb_raw=rf("secret.ct");
  check("secret.ct magic == OCTRA-HFHE-BTY02",
    ctb_raw.size()>=16 && std::equal(MAGIC.begin(),MAGIC.end(),ctb_raw.begin()));
  check("pk.bin compressed tag 0xEC", pkb_raw.size()>0 && pkb_raw[0]==0xEC);

  // 2. Deserialize
  auto pk=pvac_ser::deserialize_pubkey(pkb_raw.data(),pkb_raw.size());
  size_t p=16; uint64_t c=tu(ctb_raw,p);
  std::vector<Cipher> cts;
  for(uint64_t i=0;i<c;i++){
    uint64_t n=tu(ctb_raw,p);
    cts.push_back(pvac_ser::deserialize_cipher(ctb_raw.data()+p,(size_t)n));
    p+=(size_t)n;
  }
  check("no trailing bytes after parse", p==ctb_raw.size());
  check("cipher count == 22", cts.size()==22);

  // 3. Params
  check("B==337", pk.prm.B==337);
  check("m_bits==8192", pk.prm.m_bits==8192);
  check("n_bits==16384", pk.prm.n_bits==16384);
  check("lpn_n==4096", pk.prm.lpn_n==4096);
  check("lpn_t==16384", pk.prm.lpn_t==16384);
  check("noise_entropy_bits==128", pk.prm.noise_entropy_bits==128.0);

  // 4. Wire version
  // Each cipher blob starts with PVAC + ver + tag
  // Re-serialize and check version byte
  // Direct: parse raw header of first cipher
  {
    size_t pp=16; uint64_t cc=tu(ctb_raw,pp);
    uint64_t n=tu(ctb_raw,pp);
    // header: PVAC[4] ver[1] tag[1]
    check("wire version v3", ctb_raw[pp+4]==3);
    check("wire tag 0", ctb_raw[pp+5]==0);
  }

  // 5. R_com absent on wire (v3 layer format has no R_com field)
  // Already confirmed by successful deserialize with v3 reader.
  // Verify R_com is zero in memory after deserialize.
  int rcom_nonzero=0;
  for(auto&C:cts) for(auto&L:C.L){
    for(auto b:L.R_com) if(b) {rcom_nonzero++; break;}
  }
  check("R_com all zero in memory (not on wire)", rcom_nonzero==0);

  // 6. All wrapped (2 BASE layers per cipher)
  int all_wrapped=1;
  for(auto&C:cts){
    int bases=0;
    for(auto&L:C.L) if(L.rule==RRule::BASE) bases++;
    if(bases!=2) all_wrapped=0;
  }
  check("all 22 ciphers wrapped (2 BASE)", all_wrapped==1);

  // 7. PC present and valid ristretto on every layer
  int pc_ok=0, pc_total=0;
  for(auto&C:cts) for(auto&L:C.L){
    if(L.PC.empty()) continue;
    pc_total++;
    ExtPoint ep;
    if(rist_decode(ep, L.PC[0])) pc_ok++;
  }
  check("PC present on all layers", pc_total==44);
  check("all PC valid ristretto points", pc_ok==44);

  // 8. PC uniqueness
  std::set<std::string> pcs;
  for(auto&C:cts) for(auto&L:C.L){
    if(!L.PC.empty()) pcs.insert(std::string((char*)L.PC[0].data(),32));
  }
  check("all 44 PCs unique", pcs.size()==44);

  // 9. Nonce uniqueness
  std::set<std::tuple<uint64_t,uint64_t,uint64_t>> nonces;
  for(auto&C:cts) for(auto&L:C.L){
    if(L.rule==RRule::BASE)
      nonces.insert({L.seed.ztag,L.seed.nonce.lo,L.seed.nonce.hi});
  }
  check("all 44 nonces unique", nonces.size()==44);

  // 10. c0 all zero
  int c0_zero=0, c0_total=0;
  for(auto&C:cts){
    if(!C.c0.empty()){
      c0_total++;
      if(C.c0[0].lo==0 && C.c0[0].hi==0) c0_zero++;
    }
  }
  check("c0 present on all 22", c0_total==22);
  check("c0 all zero", c0_zero==22);

  // 11. No zero-weight edges
  int zw=0;
  for(auto&C:cts) for(auto&e:C.E){
    if(e.w.empty()||(e.w[0].lo==0&&e.w[0].hi==0)) zw++;
  }
  check("no zero-weight edges", zw==0);

  // 12. powg_B roots integrity
  bool roots=true;
  Fp acc=fp_from_u64(1);
  for(int i=0;i<pk.prm.B;i++){
    if(pk.powg_B[i].lo!=acc.lo||pk.powg_B[i].hi!=acc.hi) roots=false;
    acc=fp_mul(acc,pk.powg_B[1]);
  }
  check("powg_B[0..336] = g^0..g^336", roots);
  check("g^337 == 1", acc.lo==1 && acc.hi==0);

  // 13. H regenerable from canon_tag
  PubKey pk2; pk2.prm=pk.prm; pk2.canon_tag=pk.canon_tag; gen_H(pk2);
  check("H regenerable from canon_tag", pk2.H_digest==pk.H_digest);

  // 14. ubk regenerable
  auto ubk=gen_ubk_public(pk.canon_tag, pk.prm.m_bits);
  check("ubk regenerable from canon_tag", ubk.perm==pk.ubk.perm);

  // 15. T nonzero on all layers (no zero-oracle leak)
  int t_zero=0;
  for(auto&C:cts) for(uint32_t lid=0;lid<C.L.size();lid++){
    Fp T=layer_T(pk,C,lid);
    if(T.lo==0&&T.hi==0) t_zero++;
  }
  check("no zero-T layers", t_zero==0);

  // 16. No T0==T1 or T0==-T1 (structured wrap mask)
  int t_eq=0, t_neg=0;
  for(auto&C:cts){
    if(C.L.size()>=2){
      Fp T0=layer_T(pk,C,0), T1=layer_T(pk,C,1);
      if(T0.lo==T1.lo&&T0.hi==T1.hi) t_eq++;
      if(T0.lo==fp_neg(T1).lo&&T0.hi==fp_neg(T1).hi) t_neg++;
    }
  }
  check("no T0==T1", t_eq==0);
  check("no T0==-T1", t_neg==0);

  // 17. No sk magic in pk.bin raw
  auto raw_pk = compress::is_packed(pkb_raw.data(),pkb_raw.size())
    ? compress::unpack(pkb_raw) : pkb_raw;
  bool sk_found=false;
  uint32_t sk_mags[]={0x66666999,0x99666666,0x66699666,0x06660666};
  for(uint32_t m: sk_mags){
    for(size_t i=0;i+4<=raw_pk.size();i++){
      uint32_t v=raw_pk[i]|(raw_pk[i+1]<<8)|(raw_pk[i+2]<<16)|(raw_pk[i+3]<<24);
      if(v==m){sk_found=true; break;}
    }
  }
  check("no seckey magic in pk.bin raw", !sk_found);

  // 18. Self-test: roundtrip with fresh key
  {
    Params prm; prm.noise_entropy_bits=128;
    PubKey tpk; SecKey tsk; keygen(prm,tpk,tsk);
    std::string msg="verify test 12345";
    auto tcts=enc_text(tpk,tsk,msg);
    bool rt=dec_text(tpk,tsk,tcts)==msg;
    check("enc_text/dec_text roundtrip (self-test)", rt);
  }

  // 19. Self-test: PC opens correctly with sk
  {
    Params prm; prm.noise_entropy_bits=128;
    PubKey tpk; SecKey tsk; keygen(prm,tpk,tsk);
    Cipher C=enc_fp_wrapped_depth(tpk,tsk,fp_from_u64(42),2);
    Fp R=prf_R_slots(tpk,tsk,C.L[0].seed,1)[0];
    Fp Rinv=fp_inv(R);
    Sha256 h; h.init(); h.update(Dom::PRF_RHO,strlen(Dom::PRF_RHO));
    for(int k=0;k<4;k++) sha256_acc_u64(h,tsk.prf_k[k]);
    sha256_acc_u64(h,C.L[0].seed.nonce.lo);
    sha256_acc_u64(h,C.L[0].seed.nonce.hi);
    sha256_acc_u64(h,0);
    uint8_t b[32]; h.finish(b);
    Scalar rho=sc_reduce256(b);
    auto expect=pedersen_commit(sc_from_fp_signed(Rinv),rho);
    check("PC = pedersen(Rinv, rho(prf_k)) [self-test]", eqP(expect,C.L[0].PC[0]));
  }

  // 20. Self-test: v1 oracle DEAD on v2 hash
  {
    Params prm; prm.noise_entropy_bits=128;
    PubKey tpk; SecKey tsk; keygen(prm,tpk,tsk);
    Fp v=fp_from_u64(999);
    Cipher C=enc_fp_raw_depth(tpk,tsk,v,2);
    Fp T=layer_T(tpk,C,0);
    Fp R_real=fp_mul(T, fp_inv(v));
    Fp R_wrong=fp_mul(T, fp_inv(fp_from_u64(888)));
    auto com_real=compute_R_com_base(tpk.canon_tag,C.L[0].seed.ztag,C.L[0].seed.nonce.lo,C.L[0].seed.nonce.hi,{R_real});
    auto com_wrong=compute_R_com_base(tpk.canon_tag,C.L[0].seed.ztag,C.L[0].seed.nonce.lo,C.L[0].seed.nonce.hi,{R_wrong});
    check("v2 R_com: real==wrong (oracle dead)", com_real==com_wrong);
  }

  std::cout<<"\n=== "<<pass<<" passed, "<<fail<<" failed ===\n";
  return fail?1:0;
}
