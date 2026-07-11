# HFHE v2 Challenge — Cryptanalysis Makefile
# Requires: pvac_hfhe_cpp library (pinned at commit 071b0e9)
# Usage: make all

CXX = g++
CXXFLAGS = -std=c++17 -O2 -maes -msse4.1 -march=native
PVAC_INC = -I../pvac_hfhe_cpp/include
CHALLENGE_INC = -Isource -Ichallenge_source
INCLUDES = $(PVAC_INC)

# ===== Analysis Tools =====
ANALYSIS = \
	tools/analysis/analyze \
	tools/analysis/probe \
	tools/analysis/dump_real \
	tools/analysis/dump_c0 \
	tools/analysis/native_scan \
	tools/analysis/verify_all \
	tools/analysis/idx_scan

# ===== Attack Tools =====
ATTACK = \
	tools/attack/algebra_lab \
	tools/attack/scale_barrier \
	tools/attack/pedersen_check \
	tools/attack/pc_combine \
	tools/attack/pc_oracle_test \
	tools/attack/check_rcom \
	tools/attack/pin_open \
	tools/attack/pin_R \
	tools/attack/full_sweep \
	tools/attack/defect_scan \
	tools/attack/deep_lpn \
	tools/attack/deep_lab \
	tools/attack/research_lab \
	tools/attack/bias_deep \
	tools/attack/exploit_bias \
	tools/attack/toep_deep \
	tools/attack/toep_analysis

# ===== LPN Tools =====
LPN = \
	tools/lpn/lpn_solve \
	tools/lpn/lpn_solve2 \
	tools/lpn/lpn_bp \
	tools/lpn/lpn_gd \
	tools/lpn/ratio_test \
	tools/lpn/try_ratio \
	tools/lpn/challenge_ratio \
	tools/lpn/wrap_sum

ALL_TOOLS = $(ANALYSIS) $(ATTACK) $(LPN)

# ===== Special: tools that need challenge includes =====
tools/analysis/analyze: tools/analysis/analyze.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(CHALLENGE_INC) -o $@ $<

tools/analysis/probe: tools/analysis/probe.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(CHALLENGE_INC) -o $@ $<

tools/analysis/verify_all: tools/analysis/verify_all.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(CHALLENGE_INC) -o $@ $<

tools/attack/check_rcom: tools/attack/check_rcom.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(CHALLENGE_INC) -o $@ $<

tools/attack/pc_combine: tools/attack/pc_combine.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(CHALLENGE_INC) -o $@ $<

tools/lpn/challenge_ratio: tools/lpn/challenge_ratio.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(CHALLENGE_INC) -o $@ $<

tools/lpn/try_ratio: tools/lpn/try_ratio.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(CHALLENGE_INC) -o $@ $<

# ===== Generic build rule =====
%: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $<

# ===== Targets =====
.PHONY: all analysis attack lpn clean

all: $(ALL_TOOLS)

analysis: $(ANALYSIS)

attack: $(ATTACK)

lpn: $(LPN)

clean:
	rm -f $(ALL_TOOLS)

# ===== Run targets =====
run-verify: tools/analysis/verify_all
	cd /home/fariz/codes/hfhe-challenge && ../../octra-hfhe-v2/tools/analysis/verify_all pk.bin secret.ct

run-dump: tools/analysis/dump_real
	cd /home/fariz/codes/hfhe-challenge && ../../octra-hfhe-v2/tools/analysis/dump_real pk.bin secret.ct

run-ratio: tools/lpn/challenge_ratio
	cd /home/fariz/codes/hfhe-challenge && ../../octra-hfhe-v2/tools/lpn/challenge_ratio
