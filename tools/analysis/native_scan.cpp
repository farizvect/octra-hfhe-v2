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
static Fp layer_T(const PubKey& pk, const Cipher& C, uint32_t lid) {
    Fp acc = (lid == 0 && !C.c0.empty()) ? C.c0[0] : fp_from_u64(0);
    for (const auto& e : C.E) {
        if (e.layer_id != lid) continue;
        Fp t = fp_mul(e.w[0], pk.powg_B[e.idx]);
        if (sgn_val(e.ch) < 0) t = fp_neg(t);
        acc = fp_add(acc, t);
    }
    return acc;
}
int main(){
    auto pk_blob=rf("pk.bin"); auto ct_blob=rf("secret.ct");
    PubKey pk=pvac_ser::deserialize_pubkey(pk_blob.data(), pk_blob.size());
    auto cts=load(ct_blob);
    int native=0, total=0;
    for(size_t i=0;i<cts.size();i++){
        for(size_t lid=0;lid<cts[i].L.size();lid++){
            auto&L=cts[i].L[lid];
            if(L.rule!=RRule::BASE) continue;
            ++total;
            bool is_ru = ru_src(pk, L);
            uint64_t expect = prg_layer_ztag(pk.canon_tag, L.seed.nonce);
            bool ztag_ok = (L.seed.ztag == expect);
            if(is_ru || !ztag_ok){
                std::cout<<"ct["<<i<<"] L"<<lid<<" ru_src="<<is_ru
                         <<" ztag_matches_prg="<<ztag_ok
                         <<" ztag="<<std::hex<<L.seed.ztag
                         <<" expect_prg="<<expect
                         <<" ru_ztag="<<ru_ztag(pk.canon_tag,L.seed.nonce)<<std::dec<<"\n";
            }
            if(is_ru) ++native;
        }
    }
    std::cout<<"base layers="<<total<<" native="<<native<<"\n";

    // Also try: for each layer, T * inv(candidate_small_v) and see if resulting R
    // satisfies anything public — already know R_com useless.
    // Try length brute with address-unrelated check: none.

    // Dump expected length range and T values for length cipher
    Fp T0=layer_T(pk,cts[0],0), T1=layer_T(pk,cts[0],1);
    std::cout<<"len cipher T0="<<std::hex<<T0.hi<<":"<<T0.lo<<" T1="<<T1.hi<<":"<<T1.lo<<std::dec<<"\n";
    return 0;
}
