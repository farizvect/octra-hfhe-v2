// LPN solver v4: Stochastic Gradient Descent with relaxation
// Convert to real optimization: minimize sum_i (y_i - <a_i, s> mod 2)
// Since mod 2 is hard, use continuous relaxation:
//   y_i - <a_i, s> is 0 or 1 mod 2. But <a_i, s> mod 2 = parity.
// Cannot differentiate parity. Instead use:
//   L = sum_i (actual y_i - expected y_i)^2
// where expected y_i = P(parity(<a_i, s>) = 1) = (1 - Prod_j (1-2*s_j)^{a_{i,j}})/2
// 
// Simpler: treat s as real in [0,1], use sigmoid-like:
//   h_i = sum_j a_{i,j} * s_j  (real sum, not parity)
//   p_i = 0.5 + 0.5 * sin(h_i * pi/2)  or p_i = (1 - cos(pi * h_i))/2
//   This gives p_i ~ 0 for even parity, ~1 for odd parity.
//   Actually: p_i = (1 - (-1)^{h_i}) / 2 if h_i were integer.
//   For real h_i: p_i = sin^2(h_i * pi/2) = (1 - cos(pi * h_i))/2
//
// Problem: sin/cos of linear combination of many reals doesn't give
// clean parity behavior. Better approach below.
//
// APPROACH: bit-flip gradient
// 1. Start with random s in {0,1}^4096
// 2. For each bit, compute improvement from flipping
// 3. Flip bits that improve the score
// 4. Iterate

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <random>
#include <filesystem>
namespace fs = std::filesystem;

static const int N = 4096;
static const int MAX_CHECKS = 100000;

struct Check {
    std::vector<int> vars;
    int y;
};

int main() {
    std::string sample_dir = "/tmp/hfhe-sample/lpn_samples/";
    
    // Load checks
    std::vector<Check> checks;
    int total_loaded = 0;
    
    for (const auto& entry : fs::directory_iterator(sample_dir)) {
        if (!entry.is_regular_file()) continue;
        std::string path = entry.path().string();
        if (path.find(".jsonl") == std::string::npos) continue;
        
        std::ifstream fin(path);
        std::string line;
        std::getline(fin, line);
        
        while (std::getline(fin, line) && total_loaded < MAX_CHECKS) {
            size_t py = line.find("\"y\":");
            py += 4;
            int ybit = (line[py] == '1') ? 1 : 0;
            
            size_t pa = line.find("\"a\":\"");
            pa += 5;
            size_t pe = line.find('"', pa);
            std::string a_hex = line.substr(pa, pe - pa);
            
            Check c;
            c.y = ybit;
            for (int i = 0; i < 512; i++) {
                int hex_pos = i * 2;
                if (hex_pos + 1 >= (int)a_hex.size()) break;
                char h1 = a_hex[hex_pos], h2 = a_hex[hex_pos+1];
                auto hv = [](char ch)->int{return(ch>='0'&&ch<='9')?ch-'0':10+(ch-'a');};
                uint8_t byte_val = (uint8_t)(hv(h1)*16+hv(h2));
                for (int b=0; b<8; b++) {
                    if (byte_val & (1<<b)) {
                        int bi = i*8+b;
                        if (bi>=N) break;
                        c.vars.push_back(bi);
                    }
                }
            }
            checks.push_back(c);
            total_loaded++;
        }
    }
    std::cout << "Loaded " << checks.size() << " checks\n";
    
    // Build inverse index: var -> list of check indices containing it
    std::vector<std::vector<int>> var_to_checks(N);
    for (int ci = 0; ci < (int)checks.size(); ci++) {
        for (int v : checks[ci].vars) {
            var_to_checks[v].push_back(ci);
        }
    }
    
    // Initialize s randomly
    std::vector<int> s(N, 0);
    std::mt19937 rng(42);
    for (int j = 0; j < N; j++) s[j] = rng() & 1;
    
    // Precompute parity for each check
    std::vector<int> check_parity(checks.size(), 0);
    for (int ci = 0; ci < (int)checks.size(); ci++) {
        int p = 0;
        for (int v : checks[ci].vars) p ^= s[v];
        check_parity[ci] = p;
    }
    
    // Score: number of satisfied checks
    auto compute_score = [&]() {
        int score = 0;
        for (int ci = 0; ci < (int)checks.size(); ci++) {
            if (check_parity[ci] == checks[ci].y) score++;
        }
        return score;
    };
    
    int initial_score = compute_score();
    std::cout << "Initial score: " << initial_score << "/" << checks.size() 
              << " = " << (100.0*initial_score/checks.size()) << "%\n";
    
    // Bit-flip descent
    for (int iter = 0; iter < 1000; iter++) {
        // For each bit, compute score improvement if flipped
        int best_bit = -1;
        int best_improvement = 0;
        
        // Random subset of bits for speed
        int check_count = std::min(200, N);
        std::vector<int> bit_indices(N);
        std::iota(bit_indices.begin(), bit_indices.end(), 0);
        std::shuffle(bit_indices.begin(), bit_indices.end(), rng);
        
        for (int bi = 0; bi < check_count; bi++) {
            int j = bit_indices[bi];
            
            // Compute improvement from flipping s[j]
            int improvement = 0;
            for (int ci : var_to_checks[j]) {
                int old_parity = check_parity[ci];
                int new_parity = old_parity ^ 1; // flip
                bool old_match = (old_parity == checks[ci].y);
                bool new_match = (new_parity == checks[ci].y);
                if (!old_match && new_match) improvement++;
                if (old_match && !new_match) improvement--;
            }
            
            if (improvement > best_improvement) {
                best_improvement = improvement;
                best_bit = j;
            }
        }
        
        if (best_bit < 0 || best_improvement <= 0) {
            std::cout << "iter " << iter << ": no improvement found\n";
            break;
        }
        
        // Flip the best bit
        s[best_bit] ^= 1;
        for (int ci : var_to_checks[best_bit]) {
            check_parity[ci] ^= 1;
        }
        
        if (iter % 50 == 0) {
            int score = compute_score();
            std::cout << "iter " << iter << ": score=" << score 
                      << " (" << (100.0*score/checks.size()) << "%)\n";
        }
    }
    
    int final_score = compute_score();
    std::cout << "Final score: " << final_score << "/" << checks.size() 
              << " = " << (100.0*final_score/checks.size()) << "%\n";
    std::cout << "Expected if correct: ~" << (100.0*7.0/8.0) << "%\n";
    
    return 0;
}
