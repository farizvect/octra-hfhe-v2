#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp> // ! wrapped
#include "pvac_artifact_serialize.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <sys/stat.h>

namespace fs = std::filesystem;
using namespace pvac;

namespace {
constexpr std::array<uint8_t, 16> BUNDLE_MAGIC = {
    'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'
};

const fs::path PUBLIC_DIR = "challenge_public";
const fs::path PRIVATE_DIR = "challenge_private";

void wipe(std::string& s) {
    volatile char* p = s.empty() ? nullptr : &s[0];
    for (size_t i = 0; i < s.size(); ++i) p[i] = 0;
    s.clear();
    s.shrink_to_fit();
}

void write_file(const fs::path& path, const std::vector<uint8_t>& data, mode_t mode) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("cannot open " + path.string());
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!out) throw std::runtime_error("cannot write " + path.string());
    out.close();
    if (::chmod(path.c_str(), mode) != 0) throw std::runtime_error("chmod failed for " + path.string());
}

std::vector<uint8_t> read_random_bytes(size_t n) {
    std::ifstream in("/dev/urandom", std::ios::binary);
    if (!in) throw std::runtime_error("cannot open random source");
    std::vector<uint8_t> data(n);
    in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!in) throw std::runtime_error("cannot read random source");
    return data;
}

std::string hex_encode(const std::vector<uint8_t>& data) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t x : data) {
        out.push_back(hex[x >> 4]);
        out.push_back(hex[x & 15]);
    }
    return out;
}

std::string decimal6(uint32_t x) {
    x %= 1000000;
    std::string out(6, '0');
    for (int i = 5; i >= 0; --i) {
        out[(size_t)i] = static_cast<char>('0' + (x % 10));
        x /= 10;
    }
    return out;
}

uint32_t random_u32() {
    auto b = read_random_bytes(4);
    uint32_t x = 0;
    for (int i = 0; i < 4; ++i)
        x |= static_cast<uint32_t>(b[(size_t)i]) << (8 * i);
    return x;
}

fs::path public_root() {
    if (fs::exists("source") && fs::is_directory("source")) return fs::current_path();
    return PUBLIC_DIR;
}

fs::path private_root(const fs::path& pub) {
    return pub.parent_path() / PRIVATE_DIR;
}

std::string bounty_plaintext() {
    std::string email = "bounty.data" + decimal6(random_u32()) + "@octra.org";
    std::string secret = hex_encode(read_random_bytes(32));
    return "email = " + email + "\nsecret = " + secret + "\n";
}

std::string trim_copy(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
    size_t pos = 0;
    while (pos < s.size() && (s[pos] == '\n' || s[pos] == '\r' || s[pos] == ' ')) ++pos;
    if (pos > 0) s.erase(0, pos);
    return s;
}

std::vector<uint8_t> read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open " + path.string());
    in.seekg(0, std::ios::end);
    const auto n = in.tellg();
    if (n < 0) throw std::runtime_error("cannot size " + path.string());
    if (n > static_cast<std::streamoff>(1ULL << 32)) throw std::runtime_error("file too large: " + path.string());
    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(static_cast<size_t>(n));
    if (!data.empty()) in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(n));
    if (!in) throw std::runtime_error("cannot read " + path.string());
    return data;
}

void append_u64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

uint64_t take_u64(const std::vector<uint8_t>& in, size_t& pos) {
    if (pos + 8 > in.size()) throw std::runtime_error("truncated secret.ct");
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(in[pos++]) << (8 * i);
    return v;
}

std::vector<uint8_t> serialize_bundle(const std::vector<Cipher>& cts) {
    std::vector<uint8_t> out(BUNDLE_MAGIC.begin(), BUNDLE_MAGIC.end());
    append_u64(out, cts.size());
    for (const auto& ct : cts) {
        auto blob = pvac_ser::serialize_cipher(ct);
        append_u64(out, blob.size());
        out.insert(out.end(), blob.begin(), blob.end());
    }
    return out;
}

std::vector<Cipher> deserialize_bundle(const std::vector<uint8_t>& in) {
    if (in.size() < BUNDLE_MAGIC.size() ||
        !std::equal(BUNDLE_MAGIC.begin(), BUNDLE_MAGIC.end(), in.begin()))
        throw std::runtime_error("bad secret.ct magic");
    size_t pos = BUNDLE_MAGIC.size();
    const uint64_t count = take_u64(in, pos);
    if (count == 0 || count > 1024) throw std::runtime_error("invalid cipher count");
    std::vector<Cipher> cts;
    cts.reserve(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; ++i) {
        const uint64_t n = take_u64(in, pos);
        if (n == 0 || n > in.size() - pos) throw std::runtime_error("invalid cipher length");
        cts.push_back(pvac_ser::deserialize_cipher(in.data() + pos, static_cast<size_t>(n)));
        pos += static_cast<size_t>(n);
    }
    if (pos != in.size()) throw std::runtime_error("trailing bytes in secret.ct");
    return cts;
}

bool layer_has_rcom(const Layer& layer) {
    return std::any_of(layer.R_com.begin(), layer.R_com.end(), [](uint8_t x) { return x != 0; });
}

bool bundle_is_rcomless(const std::vector<Cipher>& cts) {
    for (const auto& ct : cts) {
        for (const auto& layer : ct.L) {
            if (layer_has_rcom(layer)) return false;
        }
    }
    return true;
}

Fp public_layer_slot0(const PubKey& pk, const Cipher& c, uint32_t layer_id) {
    Fp acc = layer_id == 0 && !c.c0.empty() ? c.c0[0] : fp_from_u64(0);
    for (const auto& e : c.E) {
        if (e.layer_id != layer_id) continue;
        if (e.w.empty()) throw std::runtime_error("edge payload rejected");
        Fp term = fp_mul(e.w[0], pk.powg_B[e.idx]);
        acc = sgn_val(e.ch) > 0 ? fp_add(acc, term) : fp_sub(acc, term);
    }
    return acc;
}

bool fp_is_zero(const Fp& x) {
    return x.lo == 0 && x.hi == 0;
}

bool base_layers_are_public_nonzero(const PubKey& pk, const Cipher& c) {
    for (size_t i = 0; i < c.L.size(); ++i) {
        if (c.L[i].rule != RRule::BASE) continue;
        if (fp_is_zero(public_layer_slot0(pk, c, static_cast<uint32_t>(i)))) return false;
    }
    return true;
}

size_t base_layer_count(const Cipher& c) {
    size_t n = 0;
    for (const auto& layer : c.L) {
        if (layer.rule == RRule::BASE) ++n;
    }
    return n;
}

bool bundle_is_wrapped(const std::vector<Cipher>& cts) {
    for (const auto& ct : cts) {
        if (base_layer_count(ct) != 2) return false;
    }
    return true;
}

bool bundle_base_layers_are_public_nonzero(const PubKey& pk, const std::vector<Cipher>& cts) {
    for (const auto& ct : cts) {
        if (!base_layers_are_public_nonzero(pk, ct)) return false;
    }
    return true;
}

bool public_zero_regression() {
    Params prm;
    prm.noise_entropy_bits = 128.0;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);
    std::string zero_block(15, '\0');
    auto cts = enc_text(pk, sk, zero_block);
    return cts.size() == 2 &&
        base_layers_are_public_nonzero(pk, cts[1]) &&
        dec_text(pk, sk, cts) == zero_block;
}

int bit_parity(const BitVec& v) {
    int out = 0;
    for (uint64_t x : v.w)
        out ^= (__builtin_popcountll(x) & 1);
    return out;
}

int top_bit(const BitVec& v) {
    for (int i = (int)v.w.size() - 1; i >= 0; --i) {
        uint64_t x = v.w[(size_t)i];
        if (x)
            return i * 64 + 63 - __builtin_clzll(x);
    }
    return -1;
}

int gf2_rank(const std::vector<BitVec>& cols, size_t bits) {
    std::vector<BitVec> basis(bits);
    std::vector<uint8_t> used(bits, 0);
    int rank = 0;

    for (const auto& col : cols) {
        BitVec x = col;
        for (;;) {
            int p = top_bit(x);
            if (p < 0)
                break;
            if (!used[(size_t)p]) {
                basis[(size_t)p] = x;
                used[(size_t)p] = 1;
                ++rank;
                break;
            }
            x.xor_with(basis[(size_t)p]);
        }
    }

    return rank;
}

bool mixed_H_parity(const PubKey& pk) {
    bool even = false;
    bool odd = false;
    for (const auto& col : pk.H) {
        if (bit_parity(col))
            odd = true;
        else
            even = true;
    }
    return even && odd;
}

bool mixed_sigma_parity(const PubKey& pk) {
    bool even = false;
    bool odd = false;
    for (uint64_t i = 0; i < 128; ++i) {
        Nonce128 nonce{0x1000 + i, 0x2000 + i * 17};
        auto s = sigma_from_H(pk, 0x3000 + i, nonce, (uint16_t)i, (uint8_t)(i & 1), i * 257);
        if (bit_parity(s))
            odd = true;
        else
            even = true;
    }
    return even && odd;
}

bool small_H_rank_regression() {
    Params prm;
    prm.m_bits = 256;
    prm.n_bits = 512;
    prm.h_col_wt = 32;
    prm.x_col_wt = 32;
    prm.err_wt = 32;

    PubKey pk;
    pk.prm = prm;
    pk.canon_tag = 0x6f637472615f6c69ull;
    gen_H(pk);

    return gf2_rank(pk.H, (size_t)prm.m_bits) == prm.m_bits &&
        mixed_H_parity(pk) &&
        mixed_sigma_parity(pk);
}

void write_params(const Params& p, size_t plaintext_bytes, size_t cipher_objects, const fs::path& path) {
    std::ofstream o(path, std::ios::trunc);
    if (!o) throw std::runtime_error("cannot open " + path.string());
    o << "{\n"
      << "  \"format\": \"octra-hfhe-bounty-v2\",\n"
      << "  \"text_encoding\": \"length-cipher-plus-wrapped-15-byte-blocks\",\n"
      << "  \"pubkey_encoding\": \"pvac-v3-compressed\",\n"
      << "  \"cipher_encoding\": \"pvac-v3-length-prefixed-bundle\",\n"
      << "  \"plaintext_bytes\": " << plaintext_bytes << ",\n"
      << "  \"cipher_objects\": " << cipher_objects << ",\n"
      << "  \"h_dimensions\": {\n"
      << "    \"rows\": " << p.m_bits << ",\n"
      << "    \"columns\": " << p.n_bits << "\n"
      << "  },\n"
      << "  \"b\": " << p.B << ",\n"
      << "  \"m_bits\": " << p.m_bits << ",\n"
      << "  \"n_bits\": " << p.n_bits << ",\n"
      << "  \"h_col_wt\": " << p.h_col_wt << ",\n"
      << "  \"x_col_wt\": " << p.x_col_wt << ",\n"
      << "  \"err_wt\": " << p.err_wt << ",\n"
      << "  \"noise_entropy_bits\": " << p.noise_entropy_bits << ",\n"
      << "  \"tuple2_fraction\": " << p.tuple2_fraction << ",\n"
      << "  \"depth_slope_bits\": " << p.depth_slope_bits << ",\n"
      << "  \"edge_budget\": " << p.edge_budget << ",\n"
      << "  \"lpn_n\": " << p.lpn_n << ",\n"
      << "  \"lpn_t\": " << p.lpn_t << ",\n"
      << "  \"lpn_tau_num\": " << p.lpn_tau_num << ",\n"
      << "  \"lpn_tau_den\": " << p.lpn_tau_den << "\n"
      << "}\n";
    o.close();
    if (::chmod(path.c_str(), 0644) != 0) throw std::runtime_error("chmod failed for params.json");
}

std::string read_commit_value(const fs::path& pub) {
    const fs::path path = pub / "pvac_commit.txt";
    if (!fs::exists(path)) return "pending-fixed-pvac-commit";
    auto data = read_file(path);
    return trim_copy(std::string(data.begin(), data.end()));
}

void write_manifest(
    const Params& p,
    size_t plaintext_bytes,
    size_t cipher_objects,
    const std::string& commit,
    const fs::path& path
) {
    std::ofstream o(path, std::ios::trunc);
    if (!o) throw std::runtime_error("cannot open " + path.string());
    o << "{\n"
      << "  \"format\": \"octra-hfhe-bounty-v2\",\n"
      << "  \"status\": \"pre-release\",\n"
      << "  \"network\": \"octra-mainnet\",\n"
      << "  \"reward_oct\": 500000,\n"
      << "  \"encrypted_plaintext\": {\n"
      << "    \"type\": \"report-email-and-secret-string\",\n"
      << "    \"plaintext_bytes\": " << plaintext_bytes << ",\n"
      << "    \"cipher_objects\": " << cipher_objects << "\n"
      << "  },\n"
      << "  \"cryptography\": {\n"
      << "    \"implementation\": \"pvac-hfhe-cpp\",\n"
      << "    \"repository\": \"https://github.com/octra-labs/pvac_hfhe_cpp\",\n"
      << "    \"commit\": \"" << commit << "\",\n"
      << "    \"field\": \"2^127-1\",\n"
      << "    \"parameter_b\": " << p.B << ",\n"
      << "    \"h_dimensions\": {\n"
      << "      \"rows\": " << p.m_bits << ",\n"
      << "      \"columns\": " << p.n_bits << "\n"
      << "    },\n"
      << "    \"noise_entropy_bits\": " << p.noise_entropy_bits << "\n"
      << "  },\n"
      << "  \"public_artifacts\": {\n"
      << "    \"ciphertext\": \"secret.ct\",\n"
      << "    \"public_key\": \"pk.bin\",\n"
      << "    \"parameters\": \"params.json\"\n"
      << "  },\n"
      << "  \"private_artifacts_not_published\": [\n"
      << "    \"sk.bin\",\n"
      << "    \"plaintext.txt\",\n"
      << "    \"private decryption key\",\n"
      << "    \"private plaintext\"\n"
      << "  ],\n"
      << "  \"winning_condition\": \"recover plaintext from secret.ct using public files only; send the secret string and reproducible attack report to the recovered email\"\n"
      << "}\n";
    o.close();
    if (::chmod(path.c_str(), 0644) != 0) throw std::runtime_error("chmod failed for manifest.json");
}

void generate() {
    const fs::path pub = public_root();
    const fs::path priv = private_root(pub);
    if (!fs::exists(pub)) fs::create_directory(pub);
    if (fs::exists(pub / "pk.bin") || fs::exists(pub / "secret.ct") || fs::exists(priv))
        throw std::runtime_error("existing challenge artifacts rejected");
    fs::create_directory(priv);
    ::chmod(pub.c_str(), 0755);
    ::chmod(priv.c_str(), 0700);

    Params prm;
    prm.noise_entropy_bits = 128.0;
    PubKey pk;
    SecKey sk;
    std::cout << "event = keygen\n";
    keygen(prm, pk, sk);
    std::string plain = bounty_plaintext();
    std::cout << "event = encrypt bytes = " << plain.size() << "\n";
    auto cts = enc_text(pk, sk, plain);

    auto pk_blob = pvac_ser::serialize_pubkey(pk, true);
    auto sk_blob = pvac_ser::serialize_seckey(sk);
    auto ct_blob = serialize_bundle(cts);
    std::vector<uint8_t> plain_blob(plain.begin(), plain.end());

    write_file(pub / "pk.bin", pk_blob, 0644);
    write_file(pub / "secret.ct", ct_blob, 0644);
    write_file(priv / "sk.bin", sk_blob, 0600);
    write_file(priv / "plaintext.txt", plain_blob, 0600);
    write_params(prm, plain.size(), cts.size(), pub / "params.json");
    write_manifest(prm, plain.size(), cts.size(), read_commit_value(pub), pub / "manifest.json");

    auto pk2_blob = read_file(pub / "pk.bin");
    auto sk2_blob = read_file(priv / "sk.bin");
    auto ct2_blob = read_file(pub / "secret.ct");
    auto pk2 = pvac_ser::deserialize_pubkey(pk2_blob.data(), pk2_blob.size());
    auto sk2 = pvac_ser::deserialize_seckey(sk2_blob.data(), sk2_blob.size());
    auto cts2 = deserialize_bundle(ct2_blob);
    auto recovered = dec_text(pk2, sk2, cts2);
    const bool ok = recovered == plain;
    wipe(recovered); wipe(plain);
    if (!ok) throw std::runtime_error("disk round-trip verification failed");

    std::cout << "ok = roundtrip\n"
              << "cipher_objects = " << cts.size() << "\n"
              << "public_path = " << pub.string() << "\n"
              << "secret_path = " << (priv / "sk.bin").string() << "\n";
}

void verify() {
    const fs::path pub = public_root();
    const fs::path priv = private_root(pub);
    auto pk_blob = read_file(pub / "pk.bin");
    auto sk_blob = read_file(priv / "sk.bin");
    auto ct_blob = read_file(pub / "secret.ct");
    auto plain_blob = read_file(priv / "plaintext.txt");
    auto pk = pvac_ser::deserialize_pubkey(pk_blob.data(), pk_blob.size());
    auto sk = pvac_ser::deserialize_seckey(sk_blob.data(), sk_blob.size());
    auto cts = deserialize_bundle(ct_blob);
    auto recovered = dec_text(pk, sk, cts);
    std::string expected(plain_blob.begin(), plain_blob.end());
    const bool ok = recovered == expected;
    wipe(recovered); wipe(expected);
    if (!ok) throw std::runtime_error("verification failed: plaintext mismatch");
    std::cout << "ok = verify\n";
}

void public_audit() {
    const fs::path pub = public_root();
    auto pk_blob = read_file(pub / "pk.bin");
    auto ct_blob = read_file(pub / "secret.ct");
    auto pk = pvac_ser::deserialize_pubkey(pk_blob.data(), pk_blob.size());
    auto cts = deserialize_bundle(ct_blob);
    bool compatible = true;
    for (const auto& ct : cts)
        compatible = compatible && is_cipher_compatible_with_pubkey(pk, ct);
    bool rcomless = bundle_is_rcomless(cts);
    bool wrapped = bundle_is_wrapped(cts);
    bool public_nonzero = bundle_base_layers_are_public_nonzero(pk, cts);
    bool zero_regression = public_zero_regression();
    bool h_mixed = mixed_H_parity(pk);
    bool sigma_mixed = mixed_sigma_parity(pk);
    bool small_rank = small_H_rank_regression();
    std::cout << "compatible = " << compatible << "\n";
    std::cout << "rcomless = " << rcomless << "\n";
    std::cout << "wrapped = " << wrapped << "\n";
    std::cout << "public_nonzero = " << public_nonzero << "\n";
    std::cout << "zero_regression = " << zero_regression << "\n";
    std::cout << "h_mixed_parity = " << h_mixed << "\n";
    std::cout << "sigma_mixed_parity = " << sigma_mixed << "\n";
    std::cout << "small_h_rank_full = " << small_rank << "\n";
    if (!compatible || !rcomless || !wrapped || !public_nonzero || !zero_regression ||
        !h_mixed || !sigma_mixed || !small_rank)
        throw std::runtime_error("public audit failed");
}

void selftest() {
    Params prm;
    prm.noise_entropy_bits = 128.0;
    PubKey pk;
    SecKey sk;
    keygen(prm, pk, sk);
    std::string msg = "";
    auto cts = enc_text(pk, sk, msg);
    auto blob = serialize_bundle(cts);
    auto decoded = deserialize_bundle(blob);
    bool roundtrip = dec_text(pk, sk, decoded) == msg;
    bool compatible = true;
    for (const auto& ct : decoded)
        compatible = compatible && is_cipher_compatible_with_pubkey(pk, ct);
    bool rcomless = bundle_is_rcomless(decoded);
    bool wrapped = bundle_is_wrapped(decoded);
    bool public_nonzero = bundle_base_layers_are_public_nonzero(pk, decoded);
    bool zero_regression = public_zero_regression();
    bool h_mixed = mixed_H_parity(pk);
    bool sigma_mixed = mixed_sigma_parity(pk);
    bool small_rank = small_H_rank_regression();
    std::cout << "roundtrip = " << roundtrip << "\n";
    std::cout << "compatible = " << compatible << "\n";
    std::cout << "rcomless = " << rcomless << "\n";
    std::cout << "wrapped = " << wrapped << "\n";
    std::cout << "public_nonzero = " << public_nonzero << "\n";
    std::cout << "zero_regression = " << zero_regression << "\n";
    std::cout << "h_mixed_parity = " << h_mixed << "\n";
    std::cout << "sigma_mixed_parity = " << sigma_mixed << "\n";
    std::cout << "small_h_rank_full = " << small_rank << "\n";
    if (!roundtrip || !compatible || !rcomless || !wrapped || !public_nonzero ||
        !zero_regression || !h_mixed || !sigma_mixed || !small_rank)
        throw std::runtime_error("selftest failed");
}
}

int main(int argc, char** argv) {
    try {
        if (argc != 2) {
            std::cerr << "usage = " << argv[0] << " generate|verify|public-audit|selftest\n";
            return 2;
        }
        const std::string mode = argv[1];
        if (mode == "generate") generate();
        else if (mode == "verify") verify();
        else if (mode == "public-audit") public_audit();
        else if (mode == "selftest") selftest();
        else throw std::runtime_error("unknown mode");
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error = " << e.what() << "\n";
        return 1;
    }
}
