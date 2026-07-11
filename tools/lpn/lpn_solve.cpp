// LPN Solver: recover s (lpn_s_bits) from 44 sample files
// Each file: 16384 samples, (a_i, y_i) where y_i = <a_i, s> + e_i, e_i ~ Ber(1/8)
// 44 files × 16384 samples = 720,896 samples total
// n = 4096, tau = 1/8
//
// Approach: Gaussian elimination with majority voting
// 1. Sample random 4096×4096 submatrices
// 2. Solve each via Gaussian elimination (GF2)
// 3. For each secret bit, majority vote across estimates
//
// With noise rate 1/8, each equation has 1/8 error.
// After Gaussian elimination (back-substitution propagates noise),
// each estimate bit has error rate ~1/2. 
// Across many estimates, majority vote recovers correct bits.
//
// For reliable recovery, we need ~100-200 independent estimates.
// Each estimate uses 4096 equations. 720,896 / 4096 ≈ 176 estimates.

#include <pvac/pvac.hpp>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <random>
#include <algorithm>
using namespace pvac;

// GF2 Gaussian elimination
static std::vector<uint64_t> solve_gf2(const std::vector<std::vector<uint64_t>>& A,
                                        const std::vector<int>& y) {
    int n = 4096;
    int m = A.size();
    if (m < n) { std::cerr << "not enough equations\n"; return {}; }
    
    // Augmented matrix: A[0..n-1] rows, each row = 64 words of A coefficients + 1 word for y
    std::vector<std::vector<uint64_t>> mat(n);
    std::vector<int> y_sel(n);
    for (int i = 0; i < n; i++) {
        mat[i] = A[i];  // 64 words
        y_sel[i] = y[i];
    }
    
    // Forward elimination
    std::vector<int> pivot_cols(n, -1);
    int rank = 0;
    for (int col = 0; col < n && rank < n; col++) {
        int wi = col >> 6;
        int sh = col & 63;
        uint64_t mask = 1ULL << sh;
        
        // Find pivot row
        int pivot = -1;
        for (int row = rank; row < n; row++) {
            if (mat[row][wi] & mask) { pivot = row; break; }
        }
        if (pivot < 0) continue; // column is linearly dependent, skip
        
        // Swap
        std::swap(mat[rank], mat[pivot]);
        std::swap(y_sel[rank], y_sel[pivot]);
        pivot_cols[rank] = col;
        
        // Eliminate other rows
        for (int row = 0; row < n; row++) {
            if (row == rank) continue;
            if (mat[row][wi] & mask) {
                for (int w = 0; w < 64; w++) mat[row][w] ^= mat[rank][w];
                y_sel[row] ^= y_sel[rank];
            }
        }
        rank++;
    }
    
    if (rank < n) { std::cerr << "matrix rank deficient: " << rank << "/" << n << "\n"; return {}; }
    
    // Extract solution
    std::vector<uint64_t> s(64, 0);
    for (int i = 0; i < n; i++) {
        if (y_sel[i]) {
            int col = pivot_cols[i];
            if (col >= 0) {
                int wi = col >> 6;
                int sh = col & 63;
                s[wi] |= (1ULL << sh);
            }
        }
    }
    return s;
}

static int my_parity(uint64_t x) {
    return __builtin_parityll(x);
}

int main() {
    // Read samples from first layer to get y and a
    // For efficiency, use only the first file initially
    std::string path = "/tmp/hfhe-sample/lpn_samples/ct00_l0_s0_pvac_prf_r_1.jsonl";
    std::ifstream fin(path);
    if (!fin) { std::cerr << "cannot open " << path << "\n"; return 1; }
    
    std::string line;
    std::getline(fin, line); // skip metadata
    
    std::vector<std::vector<uint64_t>> all_A;
    std::vector<int> all_y;
    
    while (std::getline(fin, line)) {
        // Parse JSON: {"i":..., "y":..., "a":"hex..."}
        size_t py = line.find("\"y\":");
        if (py == std::string::npos) continue;
        py += 4;
        int ybit = (line[py] == '1') ? 1 : 0;
        
        size_t pa = line.find("\"a\":\"");
        if (pa == std::string::npos) continue;
        pa += 5;
        size_t pe = line.find('"', pa);
        std::string a_hex = line.substr(pa, pe - pa);
        
        // Decode hex: 1024 chars = 512 bytes = 64 words
        std::vector<uint64_t> row(64, 0);
        for (int i = 0; i < 64; i++) {
            for (int j = 0; j < 8; j++) {
                int pos = i * 16 + j * 2;
                if (pos + 1 >= (int)a_hex.size()) break;
                char h1 = a_hex[pos], h2 = a_hex[pos+1];
                auto hv = [](char c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    return 10 + (c - 'a');
                };
                row[i] |= ((uint64_t)(hv(h1) * 16 + hv(h2))) << (j * 8);
            }
        }
        
        all_A.push_back(row);
        all_y.push_back(ybit);
        
        if (all_A.size() >= 50000) break; // enough for many estimates
    }
    
    std::cout << "Loaded " << all_A.size() << " samples\n";
    
    // Verify: compute <a_i, s_guess> and check against y_i
    // Placeholder s (all zeros) - real s will be recovered
    std::vector<uint64_t> s_zero(64, 0);
    int matches = 0;
    for (size_t i = 0; i < std::min((size_t)100, all_A.size()); i++) {
        uint64_t dot = 0;
        for (int w = 0; w < 64; w++) dot ^= all_A[i][w] & s_zero[w];
        int computed_y = my_parity(dot) ^ 0;
        if (computed_y == all_y[i]) matches++;
    }
    // With s=0, <a_i,0>=0, so y_i should match when e_i=0 (prob 7/8)
    // matches should be ~7/8 * 100 ≈ 87
    std::cout << "Quick check (s=0): " << matches << "/100 match (expect ~87)\n";
    
    // Now: recover s via Gaussian elimination + majority voting
    std::vector<std::vector<uint64_t>> s_estimates;
    std::random_device rd;
    std::mt19937 rng(rd());
    
    int n_estimates = std::min(150, (int)all_A.size() / 4096);
    std::cout << "Running " << n_estimates << " Gaussian eliminations...\n";
    
    for (int est = 0; est < n_estimates; est++) {
        // Randomly select 4096 samples
        std::vector<int> indices(all_A.size());
        std::iota(indices.begin(), indices.end(), 0);
        std::shuffle(indices.begin(), indices.end(), rng);
        
        std::vector<std::vector<uint64_t>> A_eq(4096);
        std::vector<int> y_eq(4096);
        for (int i = 0; i < 4096; i++) {
            A_eq[i] = all_A[indices[i]];
            y_eq[i] = all_y[indices[i]];
        }
        
        auto s_est = solve_gf2(A_eq, y_eq);
        if (!s_est.empty()) {
            s_estimates.push_back(s_est);
        }
        if ((est + 1) % 10 == 0) std::cout << "  " << (est+1) << "/" << n_estimates << " done\n";
    }
    
    std::cout << "Got " << s_estimates.size() << " estimates\n";
    
    // Majority vote
    std::vector<uint64_t> s_final(64, 0);
    std::vector<int> vote_counts(4096, 0);
    for (int bit = 0; bit < 4096; bit++) {
        int votes = 0;
        for (auto& est : s_estimates) {
            int wi = bit >> 6;
            int sh = bit & 63;
            if (est[wi] & (1ULL << sh)) votes++;
        }
        if (votes > (int)s_estimates.size() / 2) {
            int wi = bit >> 6;
            int sh = bit & 63;
            s_final[wi] |= (1ULL << sh);
        }
        vote_counts[bit] = votes;
    }
    
    // Print votes distribution
    int low_votes = 0, high_votes = 0, mid = s_estimates.size() / 2;
    for (int bit = 0; bit < std::min(64, 4096); bit++) {
        std::cout << "  bit " << bit << ": " << vote_counts[bit] << "/" << s_estimates.size() << " votes\n";
        if (vote_counts[bit] < mid * 0.4 || vote_counts[bit] > mid * 1.6) {
            if (vote_counts[bit] < mid * 0.4) low_votes++;
            if (vote_counts[bit] > mid * 1.6) high_votes++;
        }
    }
    std::cout << "Low-confidence bits (<40% of majority): " << low_votes << "/64 shown\n";
    std::cout << "High-confidence bits (>60% of majority): " << high_votes << "/64 shown\n";
    
    // Verify s_final against ALL samples
    int correct = 0;
    for (size_t i = 0; i < all_A.size(); i++) {
        uint64_t dot = 0;
        for (int w = 0; w < 64; w++) dot ^= all_A[i][w] & s_final[w];
        int computed_y = my_parity(dot) ^ 0; // noise unknown
        if (computed_y == all_y[i]) correct++;
    }
    std::cout << "\nVerification (s recovered): " << correct << "/" << all_A.size() 
              << " = " << (100.0 * correct / all_A.size()) << "% (expect ~87.5% due to 1/8 noise)\n";
    
    return 0;
}
