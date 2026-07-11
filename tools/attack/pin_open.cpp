// Attempt every remaining public pin for R
#include <pvac/pvac.hpp>
#include "source/pvac_artifact_serialize.hpp"
#include <fstream>
#include <iostream>
#include <vector>
#include <array>
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
static std::vector<Cipher> load(const std::vector<uint8_t>&in){
  size_t p=16; uint64_t c=tu(in,p); std::vector<Cipher> o;
  for(uint64_t i=0;i<c;i++){
    uint64_t n=tu(in,p);
    o.push_back(pvac_ser::deserialize_cipher(in.data()+p,(size_t)n));
    p+=(size_t)n;
  }
  return o;
}
static Fp Tof(const PubKey&pk,const Cipher&C,uint32_t lid){
  Fp a=fp_from_u64(0);
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

static void self_pc_vs_R(){
  Params prm; prm.noise_entropy_bits=128;
  PubKey pk; SecKey sk; keygen(prm,pk,sk);
  Cipher C=enc_fp_raw_depth(pk,sk,fp_from_u64(123),2);
  Fp R=prf_R_slots(pk,sk,C.L[0].seed,1)[0];
  Fp Rinv=fp_inv(R);
  auto PC=C.L[0].PC[0];
  auto gonly=rist_scalarmul(rist_G(),sc_from_fp_signed(Rinv));
  std::cout<<"PC==g^{Rinv}? "<<eqP(PC,gonly)<<"\n";
  auto gR=rist_scalarmul(rist_G(),sc_from_fp_signed(R));
  std::cout<<"PC==g^{R}? "<<eqP(PC,gR)<<"\n";
  auto gT=rist_scalarmul(rist_G(),sc_from_fp_signed(Tof(pk,C,0)));
  std::cout<<"PC==g^{T}? "<<eqP(PC,gT)<<"\n";
  auto p1=pedersen_commit(sc_from_fp_signed(Rinv), sc_from_fp_signed(R));
  std::cout<<"PC==ped(Rinv,R)? "<<eqP(PC,p1)<<"\n";
  auto p2=pedersen_commit(sc_from_fp_signed(Rinv), sc_from_fp_signed(Rinv));
  std::cout<<"PC==ped(Rinv,Rinv)? "<<eqP(PC,p2)<<"\n";
  uint8_t b[32]={};
  for(int i=0;i<8;i++) b[i]=(R.lo>>(8*i))&0xff;
  for(int i=0;i<8;i++) b[8+i]=(R.hi>>(8*i))&0xff;
  auto p3=pedersen_commit(sc_from_fp_signed(Rinv), sc_reduce256(b));
  std::cout<<"PC==ped(Rinv,sc(Rbytes))? "<<eqP(PC,p3)<<"\n";
}

static void try_structured_m(const PubKey& pk, const Cipher& C){
  if(C.L.size()<2){ std::cout<<"not wrap\n"; return; }
  Fp T0=Tof(pk,C,0), T1=Tof(pk,C,1);
  int hits=0;
  for(uint64_t L=301;L<=315;L++){
    std::vector<Fp> ms;
    ms.push_back(fp_from_u64(L));
    ms.push_back(fp_from_u64(1));
    ms.push_back(fp_from_u64(L+1));
    ms.push_back(fp_from_words(C.L[0].seed.nonce.lo, C.L[0].seed.nonce.hi & MASK63));
    ms.push_back(fp_from_words(C.L[1].seed.nonce.lo, C.L[1].seed.nonce.hi & MASK63));
    ms.push_back(fp_from_u64(C.L[0].seed.ztag));
    for(auto m: ms){
      if(m.lo==0 && m.hi==0) continue;
      Fp x0=fp_add(fp_from_u64(L), m);
      Fp x1=fp_neg(m);
      if(x0.lo==0 && x0.hi==0) continue;
      Fp R0=fp_mul(T0, fp_inv(x0));
      Fp R1=fp_mul(T1, fp_inv(x1));
      for(int lid=0; lid<2; lid++){
        Fp R = (lid==0) ? R0 : R1;
        Fp Rinv=fp_inv(R);
        auto gpart=rist_scalarmul(rist_G(), sc_from_fp_signed(Rinv));
        auto Q=rist_sub(C.L[lid].PC[0], gpart);
        if(eqP(Q, rist_scalarmul(rist_H(), sc_zero()))) {
          std::cout<<"HIT rho0 L="<<L<<" lid="<<lid<<"\n"; hits++;
        }
        Sha256 h; h.init(); h.update(Dom::PRF_RHO,strlen(Dom::PRF_RHO));
        for(int k=0;k<4;k++) sha256_acc_u64(h,0);
        sha256_acc_u64(h,C.L[lid].seed.nonce.lo);
        sha256_acc_u64(h,C.L[lid].seed.nonce.hi);
        sha256_acc_u64(h,0);
        uint8_t b[32]; h.finish(b);
        if(eqP(Q, rist_scalarmul(rist_H(), sc_reduce256(b)))) {
          std::cout<<"HIT zero-key rho L="<<L<<" lid="<<lid<<"\n"; hits++;
        }
      }
    }
  }
  std::cout<<"structured m+L hits: "<<hits<<"\n";
}

int main(){
  self_pc_vs_R();
  auto pkb=rf("pk.bin");
  auto pk=pvac_ser::deserialize_pubkey(pkb.data(), pkb.size());
  auto cts=load(rf("secret.ct"));
  std::cout<<"challenge cts="<<cts.size()<<" L0 layers="<<cts[0].L.size()<<"\n";
  try_structured_m(pk, cts[0]);

  std::cout<<"\n=== PIN INVENTORY (public) ===\n";
  std::cout<<"1. edges/T : homogeneous in R — NO pin\n";
  std::cout<<"2. R_com   : removed from hash + absent on wire — NO pin\n";
  std::cout<<"3. PC      : pedersen(Rinv, rho(prf_k)) — pin exists but rho secret — LOCKED\n";
  std::cout<<"4. sigma   : independent of R — NO pin\n";
  std::cout<<"5. wrap m  : full entropy — blocks plaintext pin\n";
  std::cout<<"Status: pin to R is LOCKED behind sk.prf_k (via rho) or LPN-PRF sk.\n";
  return 0;
}
