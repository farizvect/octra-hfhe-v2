#include <pvac/pvac.hpp>
#include "../challenge/source/pvac_artifact_serialize.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <array>
#include <cstring>
#include <iomanip>

using namespace pvac;

static constexpr std::array<uint8_t,16> BUNDLE_MAGIC = {
 'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'
};

static std::vector<uint8_t> rf(const std::string& p){
  std::ifstream in(p, std::ios::binary);
  in.seekg(0,std::ios::end); auto n=in.tellg(); in.seekg(0);
  std::vector<uint8_t> d((size_t)n);
  if(n>0) in.read((char*)d.data(), n);
  return d;
}
static uint64_t tu64(const std::vector<uint8_t>& in, size_t& pos){
  uint64_t v=0; for(int i=0;i<8;i++) v|=(uint64_t)in[pos++]<<(8*i); return v;
}
static std::vector<Cipher> load_bundle(const std::vector<uint8_t>& in){
  if(in.size()<16 || !std::equal(BUNDLE_MAGIC.begin(), BUNDLE_MAGIC.end(), in.begin()))
    throw std::runtime_error("bad magic");
  size_t pos=16;
  uint64_t c=tu64(in,pos);
  std::vector<Cipher> o;
  for(uint64_t i=0;i<c;i++){
    uint64_t n=tu64(in,pos);
    o.push_back(pvac_ser::deserialize_cipher(in.data()+pos,(size_t)n));
    pos+=(size_t)n;
  }
  return o;
}

static std::string hex32(const std::array<uint8_t,32>& a){
  std::ostringstream oss;
  for(int i=0;i<32;i++) oss<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)a[i];
  return oss.str();
}

static Fp public_layer_T(const PubKey& pk, const Cipher& C, uint32_t lid){
  Fp acc = (lid==0 && !C.c0.empty()) ? C.c0[0] : fp_from_u64(0);
  for(const auto& e: C.E){
    if(e.layer_id!=lid) continue;
    Fp term = fp_mul(e.w[0], pk.powg_B[e.idx]);
    acc = sgn_val(e.ch)>0 ? fp_add(acc,term) : fp_sub(acc,term);
  }
  return acc;
}

// recompute R_com with CURRENT (R-less) formula
static std::array<uint8_t,32> rcom_current(uint64_t canon, uint64_t ztag, uint64_t nlo, uint64_t nhi, size_t slots){
  return compute_R_com_base(canon, ztag, nlo, nhi, std::vector<Fp>(slots)); // size only matters
}

// old formula with dummy R=0
static std::array<uint8_t,32> rcom_old_zero(uint64_t canon, uint64_t ztag, uint64_t nlo, uint64_t nhi){
  Sha256 s; s.init(); s.update("pvac.dom.r_com",14);
  sha256_acc_u64(s,canon); sha256_acc_u64(s,ztag); sha256_acc_u64(s,nlo); sha256_acc_u64(s,nhi);
  sha256_acc_u64(s,1);
  sha256_acc_u64(s,0); sha256_acc_u64(s,0); // R.lo R.hi = 0
  std::array<uint8_t,32> out{}; s.finish(out.data()); return out;
}

int main(int argc, char** argv){
  std::string dir = argc>1?argv[1]:".";
  auto pkb = rf(dir+"/pk.bin");
  auto pk = pvac_ser::deserialize_pubkey(pkb.data(), pkb.size());
  auto cts = load_bundle(rf(dir+"/secret.ct"));

  std::cout<<"pk: B="<<pk.prm.B<<" m="<<pk.prm.m_bits<<" n="<<pk.prm.n_bits
           <<" h_col_wt="<<pk.prm.h_col_wt<<" x_col_wt="<<pk.prm.x_col_wt
           <<" err_wt="<<pk.prm.err_wt<<" noise_entropy="<<pk.prm.noise_entropy_bits
           <<" edge_budget="<<pk.prm.edge_budget<<"\n";
  std::cout<<"canon_tag=0x"<<std::hex<<pk.canon_tag<<std::dec<<"\n";
  std::cout<<"H size="<<pk.H.size()<<" powg_B size="<<pk.powg_B.size()<<"\n";
  std::cout<<"cts="<<cts.size()<<"\n\n";

  for(size_t i=0;i<cts.size();++i){
    const auto& C=cts[i];
    std::cout<<"=== ct["<<i<<"] slots="<<C.slots<<" layers="<<C.L.size()<<" edges="<<C.E.size()
             <<" c0_size="<<C.c0.size();
    if(!C.c0.empty()) std::cout<<" c0=("<<C.c0[0].hi<<":"<<C.c0[0].lo<<")";
    std::cout<<"\n";
    std::map<uint32_t,int> ecount;
    for(auto&e:C.E) ecount[e.layer_id]++;
    for(size_t l=0;l<C.L.size();++l){
      const auto& L=C.L[l];
      const char* rule = L.rule==RRule::BASE?"BASE":(L.rule==RRule::PROD?"PROD":"OTHER");
      std::cout<<"  L["<<l<<"] rule="<<rule;
      if(L.rule==RRule::PROD) std::cout<<" pa="<<L.pa<<" pb="<<L.pb;
      std::cout<<" ztag="<<L.seed.ztag<<" nonce=("<<L.seed.nonce.lo<<","<<L.seed.nonce.hi<<")"
               <<" edges="<<ecount[(uint32_t)l]
               <<" R_com="<<hex32(L.R_com)<<"\n";
      // verify R_com formula
      auto cur = compute_R_com_base(pk.canon_tag, L.seed.ztag, L.seed.nonce.lo, L.seed.nonce.hi, {fp_from_u64(0)});
      auto cur2 = compute_R_com_base(pk.canon_tag, L.seed.ztag, L.seed.nonce.lo, L.seed.nonce.hi, {fp_from_u64(1)});
      bool match_cur = (cur==L.R_com);
      bool r_independent = (cur==cur2);
      std::cout<<"    R_com matches R-less formula: "<<match_cur
               <<"  formula independent of R: "<<r_independent<<"\n";
      if(L.rule==RRule::BASE){
        Fp T = public_layer_T(pk,C,(uint32_t)l);
        std::cout<<"    public T=("<<T.hi<<":"<<T.lo<<") zero="<<(T.lo==0&&T.hi==0)<<"\n";
      }
    }
  }
  return 0;
}
