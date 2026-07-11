#include <pvac/pvac.hpp>
#include <iostream>
using namespace pvac;
static Fp public_T(const PubKey& pk, const Cipher& C, uint32_t lid){
  Fp acc = (lid==0 && !C.c0.empty()) ? C.c0[0] : fp_from_u64(0);
  for(const auto& e: C.E){
    if(e.layer_id!=lid) continue;
    Fp term = fp_mul(e.w[0], pk.powg_B[e.idx]);
    acc = sgn_val(e.ch)>0 ? fp_add(acc,term) : fp_sub(acc,term);
  }
  return acc;
}
int main(){
  Params prm; prm.noise_entropy_bits=128;
  PubKey pk; SecKey sk; keygen(prm,pk,sk);
  // raw single layer
  Fp v = fp_from_u64(0x414243); // 'ABC'
  Cipher c = enc_fp_raw_depth(pk,sk,v,2);
  std::vector<uint8_t> st(c.L.size(),0); std::vector<std::vector<Fp>> cache(c.L.size());
  Fp R = layer_R_cached(pk,sk,c,0,st,cache)[0];
  Fp T = public_T(pk,c,0);
  Fp check = fp_mul(T, fp_inv(R));
  std::cout<<"raw T/R == v? "<<(check.lo==v.lo && check.hi==v.hi)<<" T=("<<T.hi<<":"<<T.lo<<") R=("<<R.hi<<":"<<R.lo<<")\n";
  std::cout<<"dec="<<dec_value(pk,sk,c).lo<<"\n";
  // wrapped
  Cipher w = enc_fp_wrapped_depth(pk,sk,v,2);
  st.assign(w.L.size(),0); cache.assign(w.L.size(),{});
  Fp R0=layer_R_cached(pk,sk,w,0,st,cache)[0];
  Fp R1=layer_R_cached(pk,sk,w,1,st,cache)[0];
  Fp T0=public_T(pk,w,0), T1=public_T(pk,w,1);
  Fp rec = fp_add(fp_mul(T0,fp_inv(R0)), fp_mul(T1,fp_inv(R1)));
  std::cout<<"wrapped T0/R0+T1/R1 == v? "<<(rec.lo==v.lo && rec.hi==v.hi)<<"\n";
  std::cout<<"dec_wrapped="<<dec_value(pk,sk,w).lo<<" layers="<<w.L.size()<<" edges="<<w.E.size()<<"\n";
  // check PC opens: PC =? pedersen(Rinv, rho)
  for(size_t lid=0; lid<w.L.size(); ++lid){
    Fp R = layer_R_cached(pk,sk,w,(uint32_t)lid,st,cache)[0];
    Fp Rinv=fp_inv(R);
    // recompute rho
    Sha256 h; h.init(); h.update(Dom::PRF_RHO, strlen(Dom::PRF_RHO));
    for(int k=0;k<4;k++) sha256_acc_u64(h, sk.prf_k[k]);
    sha256_acc_u64(h, w.L[lid].seed.nonce.lo);
    sha256_acc_u64(h, w.L[lid].seed.nonce.hi);
    sha256_acc_u64(h, 0);
    uint8_t rho_bytes[32]; h.finish(rho_bytes);
    Scalar rho = sc_reduce256(rho_bytes);
    auto PC = pedersen_commit(sc_from_fp_signed(Rinv), rho);
    bool match = (PC==w.L[lid].PC[0]);
    std::cout<<"L"<<lid<<" PC opens correctly: "<<match<<"\n";
  }
}
