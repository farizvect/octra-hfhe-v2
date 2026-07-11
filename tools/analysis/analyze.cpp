#include <pvac/pvac.hpp>
#include "source/pvac_artifact_serialize.hpp"

#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace pvac;

static constexpr std::array<uint8_t, 16> BUNDLE_MAGIC = {
    'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'
};

static std::vector<uint8_t> read_file(const std::string& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) throw std::runtime_error("open " + p);
    in.seekg(0, std::ios::end);
    auto n = in.tellg();
    in.seekg(0);
    std::vector<uint8_t> d((size_t)n);
    if (n > 0) in.read((char*)d.data(), n);
    return d;
}

static uint64_t take_u64(const std::vector<uint8_t>& in, size_t& pos) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)in[pos++] << (8 * i);
    return v;
}

static std::vector<Cipher> deserialize_bundle(const std::vector<uint8_t>& in) {
    if (in.size() < BUNDLE_MAGIC.size() ||
        !std::equal(BUNDLE_MAGIC.begin(), BUNDLE_MAGIC.end(), in.begin()))
        throw std::runtime_error("bad magic");
    size_t pos = BUNDLE_MAGIC.size();
    uint64_t count = take_u64(in, pos);
    std::vector<Cipher> cts;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t n = take_u64(in, pos);
        cts.push_back(pvac_ser::deserialize_cipher(in.data() + pos, (size_t)n));
        pos += (size_t)n;
    }
    if (pos != in.size()) std::cerr << "trailing " << (in.size() - pos) << "\n";
    return cts;
}

static Fp layer_T(const PubKey& pk, const Cipher& C, uint32_t lid) {
    Fp acc = (lid == 0 && !C.c0.empty()) ? C.c0[0] : fp_from_u64(0);
    for (const auto& e : C.E) {
        if (e.layer_id != lid) continue;
        Fp term = fp_mul(e.w[0], pk.powg_B[e.idx]);
        if (sgn_val(e.ch) < 0) term = fp_neg(term);
        acc = fp_add(acc, term);
    }
    return acc;
}

static bool is_zero(const Fp& x) { return x.lo == 0 && x.hi == 0; }

static bool pc_zero(const std::array<uint8_t, 32>& pc) {
    for (auto b : pc) if (b) return false;
    return true;
}

int main(int argc, char** argv) {
    std::string dir = argc > 1 ? argv[1] : ".";
    auto pk_blob = read_file(dir + "/pk.bin");
    auto ct_blob = read_file(dir + "/secret.ct");
    std::cout << "pk.bin=" << pk_blob.size() << " secret.ct=" << ct_blob.size() << "\n";

    PubKey pk = pvac_ser::deserialize_pubkey(pk_blob.data(), pk_blob.size());
    std::cout << "B=" << pk.prm.B
              << " m=" << pk.prm.m_bits
              << " n=" << pk.prm.n_bits
              << " noise=" << pk.prm.noise_entropy_bits
              << " canon_tag=" << std::hex << pk.canon_tag << std::dec
              << " Hcols=" << pk.H.size()
              << " powg=" << pk.powg_B.size() << "\n";

    auto cts = deserialize_bundle(ct_blob);
    std::cout << "bundle count=" << cts.size() << "\n\n";

    size_t total_edges = 0;
    for (size_t i = 0; i < cts.size(); ++i) {
        const auto& C = cts[i];
        total_edges += C.E.size();
        std::cout << "ct[" << i << "] slots=" << C.slots
                  << " layers=" << C.L.size()
                  << " edges=" << C.E.size()
                  << " c0=" << C.c0.size();
        size_t base = 0, prod = 0;
        for (const auto& L : C.L) {
            if (L.rule == RRule::BASE) ++base;
            else ++prod;
        }
        std::cout << " base=" << base << " prod=" << prod << "\n";

        for (size_t lid = 0; lid < C.L.size(); ++lid) {
            const auto& L = C.L[lid];
            Fp T = layer_T(pk, C, (uint32_t)lid);
            size_t ecount = 0;
            for (const auto& e : C.E) if (e.layer_id == lid) ++ecount;
            std::cout << "  L" << lid
                      << " rule=" << (L.rule == RRule::BASE ? "BASE" : "PROD")
                      << " edges=" << ecount
                      << " PC=" << L.PC.size()
                      << " T_zero=" << is_zero(T)
                      << " R_com_zero=";
            bool rz = true;
            for (auto b : L.R_com) if (b) rz = false;
            std::cout << rz;
            if (L.rule == RRule::BASE) {
                std::cout << " ztag=" << std::hex << L.seed.ztag
                          << " nonce=" << L.seed.nonce.lo << ":" << L.seed.nonce.hi << std::dec;
                if (!L.PC.empty()) {
                    std::cout << " pc0_zero=" << pc_zero(L.PC[0]);
                }
            } else {
                std::cout << " pa=" << L.pa << " pb=" << L.pb;
            }
            std::cout << "\n";
        }
    }
    std::cout << "\ntotal_edges=" << total_edges << "\n";
    // rough plaintext length upper bound
    if (cts.size() >= 2)
        std::cout << "max_text_bytes=" << (cts.size() - 1) * 15 << "\n";
    return 0;
}
