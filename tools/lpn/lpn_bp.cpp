// LPN solver v3: Belief Propagation / Iterative Decoding
// Model: 720K check nodes, 4096 variable nodes
// Each check: <a_i, s> + e_i = y_i, where e_i ~ Ber(1/8)
// 
// Belief Propagation algorithm:
// 1. Initialize each variable node s[j] with P(s[j]=1) = 0.5
// 2. For each check node i:
//    a. Compute the XOR of all connected variables (from current beliefs)
//    b. Update beliefs based on y_i and noise probability
// 3. Iterate until convergence

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

static const int N = 4096;          // secret bits
static const int SUBSET_SIZE = 40000;  // use subset for speed (40000 checks)
static const double NOISE_PROB = 1.0/8.0;  // tau
static const int MAX_ITERS = 50;
static const double DAMPING = 0.3;  // damping factor for convergence

struct Check {
    std::vector<int> vars;  // indices of connected variable nodes
    int y;                   // observation bit
};

int main() {
    std::string sample_dir = "/tmp/hfhe-sample/lpn_samples/";
    
    // Load subset of samples
    std::vector<Check> checks;
    std::mt19937 rng(42);
    
    int total_loaded = 0;
    for (const auto& entry : fs::directory_iterator(sample_dir)) {
        if (!entry.is_regular_file()) continue;
        std::string path = entry.path().string();
        if (path.find(".jsonl") == std::string::npos) continue;
        
        std::ifstream fin(path);
        std::string line;
        std::getline(fin, line); // skip meta
        
        while (std::getline(fin, line)) {
            size_t py = line.find("\"y\":");
            if (py == std::string::npos) continue;
            py += 4;
            int ybit = (line[py] == '1') ? 1 : 0;
            
            size_t pa = line.find("\"a\":\"");
            if (pa == std::string::npos) continue;
            pa += 5;
            size_t pe = line.find('"', pa);
            std::string a_hex = line.substr(pa, pe - pa);
            
            Check c;
            c.y = ybit;
            for (int i = 0; i < 512; i++) {
                int hex_pos = i * 2;
                if (hex_pos + 1 >= (int)a_hex.size()) break;
                char h1 = a_hex[hex_pos], h2 = a_hex[hex_pos+1];
                auto hv = [](char ch) -> int {
                    if (ch >= '0' && ch <= '9') return ch - '0';
                    return 10 + (ch - 'a');
                };
                uint8_t byte_val = (uint8_t)(hv(h1) * 16 + hv(h2));
                for (int b = 0; b < 8; b++) {
                    if (byte_val & (1 << b)) {
                        int bit_idx = i * 8 + b;
                        if (bit_idx >= N) break;
                        c.vars.push_back(bit_idx);
                    }
                }
            }
            checks.push_back(c);
            total_loaded++;
            if (total_loaded >= SUBSET_SIZE) goto done_loading;
        }
    }
done_loading:
    std::cout << "Loaded " << checks.size() << " checks\n";
    
    // Initialize variable beliefs: P(s[j]=1) = 0.5
    std::vector<double> var_prob(N, 0.5);  // probability of bit = 1
    
    // Belief Propagation
    for (int iter = 0; iter < MAX_ITERS; iter++) {
        std::vector<double> new_prob = var_prob;  // start from prior
        
        for (auto& c : checks) {
            // Compute XOR of connected variables (from current beliefs)
            double xor_prob = 0.0;
            for (int v : c.vars) {
                // P(XOR with this bit = 1) = p(1-q) + q(1-p) = p+q-2pq
                // where p = var_prob[v], q = xor_prob
                double p = var_prob[v];
                xor_prob = p * (1 - xor_prob) + (1 - p) * xor_prob;
            }
            
            // Now: y = xor_prob + e (mod 2), where e ~ Ber(NOISE_PROB)
            // P(y=0 | xor) = (1-NOISE_PROB) if xor=0 else NOISE_PROB
            // P(y=1 | xor) = NOISE_PROB if xor=0 else (1-NOISE_PROB)
            
            // For each connected variable, compute the LLR update
            // LLR = log(P(y | s_j=0) / P(y | s_j=1))
            // Simplification: update each connected variable's probability
            
            double p_y_given_xor0 = c.y ? NOISE_PROB : (1 - NOISE_PROB);
            double p_y_given_xor1 = c.y ? (1 - NOISE_PROB) : NOISE_PROB;
            
            for (int v : c.vars) {
                // Remove this variable's contribution to xor
                double p_v = var_prob[v];
                double xor_without = xor_prob; // simplified: use full xor for update
                // More precise extrinsic computation is complex; use damping
                
                // Simple update: if XOR of others ≈ y, then s_j is supported
                // This is a crude but fast approximation
                double belief_update;
                if (c.y == 0) {
                    // y=0: support s_j based on xor_without
                    belief_update = 1.0 - xor_without;
                } else {
                    belief_update = xor_without;
                }
                // Apply noise: flip with prob NOISE_PROB
                belief_update = belief_update * (1 - NOISE_PROB) + (1 - belief_update) * NOISE_PROB;
                
                new_prob[v] = new_prob[v] * (1 - DAMPING) + belief_update * DAMPING;
            }
        }
        
        var_prob = new_prob;
        
        // Check convergence
        int ones = 0, confident = 0;
        for (int j = 0; j < N; j++) {
            if (var_prob[j] > 0.8 || var_prob[j] < 0.2) confident++;
            if (var_prob[j] > 0.5) ones++;
        }
        std::cout << "iter " << iter << ": confident=" << confident << "/" << N 
                  << " ones=" << ones << "\n";
        
        if (confident > N * 0.95) {
            std::cout << "Converged!\n";
            break;
        }
    }
    
    // Extract s
    std::vector<uint64_t> s(64, 0);
    for (int j = 0; j < N; j++) {
        if (var_prob[j] > 0.5) {
            int wi = j >> 6;
            int sh = j & 63;
            s[wi] |= (1ULL << sh);
        }
    }
    
    // Verify against samples
    std::cout << "\nVerifying recovered s...\n";
    int correct = 0, total = 0;
    for (auto& c : checks) {
        if (total >= 1000) break;
        uint64_t dot = 0;
        for (int v : c.vars) {
            int wi = v >> 6;
            int sh = v & 63;
            if (s[wi] & (1ULL << sh)) dot ^= 1;
        }
        if ((dot & 1) == c.y) correct++;
        total++;
    }
    std::cout << "Verification: " << correct << "/" << total 
              << " = " << (100.0*correct/total) << "% (expect ~87.5%)\n";
    
    return 0;
}
