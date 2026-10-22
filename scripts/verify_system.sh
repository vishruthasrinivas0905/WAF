#!/usr/bin/env bash
# ==============================================================================
# APPAWARE-WAF: LOCAL REGRESSION AND BUILD CHECKS
# Script: scripts/verify_system.sh
# ==============================================================================
set -e

echo "================================================================================"
echo "    APPAWARE-WAF: LOCAL REGRESSION CHECKS                                      "
echo "================================================================================"
echo ""

# 1. Python Unit Tests
echo "[1/4] Running Python Core Unit Tests (tests/test_waf_pipeline.py)..."
python3 -m unittest discover tests -v
echo "==> Python Unit Tests: PASSED"
echo ""

# 2. Attack Matrix Verification
echo "[2/4] Running handcrafted attack regression vectors (scripts/live_attack_tester.py)..."
python3 scripts/live_attack_tester.py --pipeline
echo "==> Attack Matrix Verification: PASSED"
echo ""

# 3. Handcrafted smoke benchmark; timing repetitions are separate from sample count.
echo "[3/4] Running handcrafted smoke benchmark (29 unique requests; timing repetitions are separate)..."
python3 scripts/benchmark_waf.py
echo "==> Benchmark Suite: COMPLETED (Results saved to benchmark_results.json)"
echo ""

# 4. Frontend & Server Compilation Check
echo "[4/4] Verifying Applet Compilation (npm run build)..."
npm run build
echo "==> Applet Build: SUCCESS"
echo ""

echo "================================================================================"
echo "    LOCAL REGRESSION CHECKS PASSED; NO DATASET OR PRODUCTION AUDIT WAS RUN       "
echo "================================================================================"
