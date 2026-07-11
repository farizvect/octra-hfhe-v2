#include <pvac/pvac.hpp>
#include <array>
#include <fstream>
#include <iostream>
#include <vector>
using namespace pvac;

// Manual layer reader for VERSION with optional R_com
struct R {
  const uint8_t* p; const uint8_t* end;
  uint8_t u8(){ return *p++; }
  uint64_t u64(){ uint64_t v=0; for(int i=0;i<8;i++) v|=(uint64_t)p[i]<<(8*i); p+=8; return v; }
  uint32_t u32(){ uint32_t v=0; for(int i=0;i<4;i++) v|=(uint32_t)p[i]<<(8*i); p+=4; return v; }
  void raw(uint8_t*o,size_t n){ memcpy(o,p,n); p+=n; }
};

static std::vector<uint8_t> rf(const char*p){std::ifstream in(p,std::ios::binary);in.seekg(0,std::ios::end);auto n=in.tellg();in.seekg(0);std::vector<uint8_t>d(n);if(n>0)in.read((char*)d.data(),n);return d;}

int main(int argc, char**argv){
  auto ct=rf(argc>1?argv[1]:"secret.ct");
  // parse bundle header
  if(ct.size()<24){std::cerr<<"short\n";return 1;}
  size_t pos=16;
  auto takeu64=[&](){uint64_t v=0;for(int i=0;i<8;i++)v|=(uint64_t)ct[pos++]<<(8*i);return v;};
  uint64_t count=takeu64();
  std::cout<<"count="<<count<<"\n";
  for(uint64_t ci=0;ci<std::min(count,(uint64_t)3);ci++){
    uint64_t n=takeu64();
    const uint8_t* base=ct.data()+pos;
    // PVAC header
    if(memcmp(base,"PVAC",4)!=0){std::cout<<"bad magic\n";return 1;}
    uint8_t ver=base[4]; uint8_t tag=base[5];
    std::cout<<"ct["<<ci<<"] ver="<<(int)ver<<" tag="<<(int)tag<<" len="<<n<<"\n";
    R r{base+6, base+n};
    uint64_t slots=r.u64();
    uint64_t nL=r.u64();
    std::cout<<"  slots="<<slots<<" nL="<<nL<<"\n";
    for(uint64_t li=0;li<nL;li++){
      uint8_t rule=r.u8();
      uint64_t ztag=0,nlo=0,nhi=0; uint32_t pa=0,pb=0;
      if(rule==0){ ztag=r.u64(); nlo=r.u64(); nhi=r.u64(); }
      else { pa=r.u32(); pb=r.u32(); }
      std::array<uint8_t,32> rcom{};
      bool has_rcom = (ver < 3);
      if(has_rcom) r.raw(rcom.data(),32);
      uint64_t nPC = r.u64();
      std::cout<<"  L"<<li<<" rule="<<(int)rule<<" has_rcom="<<has_rcom<<" nPC="<<nPC;
      if(has_rcom){
        bool rz=true; for(auto b:rcom) if(b) rz=false;
        std::cout<<" rcom_zero="<<rz;
        // compute expected rcom WITHOUT R (current broken version)
        auto expect = compute_R_com_base(0, ztag, nlo, nhi, {fp_from_u64(1)}); // size=1 matters, R ignored
        // Need real canon_tag from pk - skip equality for now, just show hex
        std::cout<<" rcom=";
        for(int i=0;i<8;i++) printf("%02x", rcom[i]);
      }
      std::cout<<"\n";
      r.p += nPC*32; // skip PC
    }
    pos += n;
  }
  return 0;
}
