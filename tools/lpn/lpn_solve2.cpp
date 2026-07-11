// LPN solver v2: use ALL 720K samples across 44 layers
// Approach: block-wise majority voting
// For each secret bit, take equations where that column=1
// and use majority of y values (with proper accounting for noise)
//
// Key insight: with 720K samples and tau=1/8:
// For each of the 4096 secret bits, ~360K samples have the column=1
// Among those, ~7/8 correctly reflect <a, s> = y_i (when noise free)
// This gives enough statistical power to recover each bit independently
//
// Simplified: for each bit j of s, compute:
//   votes_1 = count of samples where a[j]=1 AND y=1
//   votes_0 = count of samples where a[j]=1 AND y=0
// If s[j]=1: expected votes_1/(votes_0+votes_1) ≈ 7/8
// If s[j]=0: expected votes_0/(votes_0+votes_1) ≈ 7/8

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <cmath>
#include <filesystem>

namespace fs = std::filesystem;

struct SampleData {
    std::vector<std::vector<uint64_t>> A;  // rows of 64 words = 4096 bits
    std::vector<int> y;
    int layerInfo;
};

int main() {
    std::string sample_dir = "/tmp/hfhe-sample/lpn_samples/";
    
    // Phase 1: accumulate votes for each secret bit
    std::vector<uint64_t> votes_1(4096, 0);  // count of (a[j]=1 AND y=1)
    std::vector<uint64_t> votes_0(4096, 0);  // count of (a[j]=1 AND y=0)
    uint64_t total_samples = 0;
    
    int files_loaded = 0;
    for (const auto& entry : fs::directory_iterator(sample_dir)) {
        if (!entry.is_regular_file()) continue;
        std::string path = entry.path().string();
        if (path.find(".jsonl") == std::string::npos) continue;
        
        std::ifstream fin(path);
        if (!fin) continue;
        
        std::string line;
        std::getline(fin, line); // skip metadata
        
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
            
            // Count bits where a[j]=1 and accumulate votes
            for (int i = 0; i < 64; i++) {
                int hex_pos = i * 16;
                if (hex_pos + 15 >= (int)a_hex.size()) break;
                
                for (int j = 0; j < 8; j++) {
                    int byte_pos = hex_pos + j * 2;
                    if (byte_pos + 1 >= (int)a_hex.size()) break;
                    char h1 = a_hex[byte_pos], h2 = a_hex[byte_pos+1];
                    auto hv = [](char c) -> int {
                        if (c >= '0' && c <= '9') return c - '0';
                        return 10 + (c - 'a');
                    };
                    uint8_t byte_val = (uint8_t)(hv(h1) * 16 + hv(h2));
                    
                    // Process each bit in the byte
                    for (int b = 0; b < 8; b++) {
                        if (byte_val & (1 << b)) {
                            int bit_idx = i * 64 + j * 8 + b;
                            if (bit_idx >= 4096) break;
                            if (ybit) votes_1[bit_idx]++;
                            else votes_0[bit_idx]++;
                        }
                    }
                }
            }
            total_samples++;
            if (total_samples % 100000 == 0) {
                std::cout << "Processed " << total_samples << " samples...\n";
            }
        }
        files_loaded++;
    }
    
    std::cout << "Loaded " << total_samples << " samples from " << files_loaded << " files\n";
    
    // Phase 2: determine s bits via majority
    std::vector<uint64_t> s_recovered(64, 0);
    int confident_bits = 0;
    
    for (int j = 0; j < 4096; j++) {
        uint64_t v1 = votes_1[j];
        uint64_t v0 = votes_0[j];
        uint64_t total = v1 + v0;
        if (total < 100) continue; // not enough data
        
        double ratio = (double)v1 / total;
        
        // If s[j]=1: ratio ≈ 7/8 = 0.875
        // If s[j]=0: ratio ≈ 1/8 = 0.125
        // Noise: actual ratio will be near these values for the TRUE s
        
        int s_bit;
        if (ratio > 0.5) s_bit = 1;
        else s_bit = 0;
        
        if (s_bit) {
            int wi = j >> 6;
            int sh = j & 63;
            s_recovered[wi] |= (1ULL << sh);
        }
        
        // Confidence: how far from 0.5
        double dev = fabs(ratio - 0.5);
        if (dev > 0.3) confident_bits++;
    }
    
    std::cout << "Confident bits: " << confident_bits << "/4096\n";
    std::cout << "Votes per bit range: " << votes_1[0]+votes_0[0] 
              << " to " << votes_1[4095]+votes_0[4095] << "\n";
    
    // Phase 3: verify s_recovered against samples
    // Reload and compute actual match rate
    int correct = 0, total_checked = 0;
    int file_idx = 0;
    for (const auto& entry : fs::directory_iterator(sample_dir)) {
        if (!entry.is_regular_file()) continue;
        std::string path = entry.path().string();
        if (path.find(".jsonl") == std::string::npos) continue;
        if (file_idx++ > 2) break; // just check first 3 files
        
        std::ifstream fin(path);
        std::string line;
        std::getline(fin, line);
        
        while (std::getline(fin, line) && total_checked < 5000) {
            size_t py = line.find("\"y\":");
            py += 4;
            int ybit = (line[py] == '1') ? 1 : 0;
            
            size_t pa = line.find("\"a\":\"");
            pa += 5;
            size_t pe = line.find('"', pa);
            std::string a_hex = line.substr(pa, pe - pa);
            
            // Compute <a, s>
            uint64_t dot = 0;
            for (int i = 0; i < 64; i++) {
                int hex_pos = i * 16;
                if (hex_pos + 15 >= (int)a_hex.size()) break;
                
                uint64_t a_word = 0;
                for (int j = 0; j < 8; j++) {
                    int byte_pos = hex_pos + j * 2;
                    char h1 = a_hex[byte_pos], h2 = a_hex[byte_pos+1];
                    auto hv = [](char c)->int{return(c>='0'&&c<='9')?c-'0':10+(c-'a');};
                    a_word |= ((uint64_t)(hv(h1)*16+hv(h2))) << (j*8);
                }
                dot ^= a_word & s_recovered[i];
            }
            int computed = __builtin_parityll(dot);
            if (computed == ybit) correct++;
            total_checked++;
        }
    }
    
    std::cout << "\nVerification: " << correct << "/" << total_checked 
              << " = " << (100.0*correct/total_checked) 
              << "% (expect ~87.5% if correct)\n";
    
    if (correct > total_checked * 0.8) {
        std::cout << "\n*** LPN SECRET RECOVERED! ***\n";
        std::cout << "s[0..7] = ";
        for (int i = 0; i < 8; i++) printf("%016lx ", s_recovered[i]);
        std::cout << "\n";
    }
    
    return 0;
}
