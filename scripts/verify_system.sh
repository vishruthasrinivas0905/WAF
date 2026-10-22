#!/usr/bin/env bash
# ==============================================================================
# APPAWARE-WAF: SYSTEM-WIDE VERIFICATION & HEALTH HARNESS
# Script: scripts/verify_system.sh
# ==============================================================================
set -e

echo "================================================================================"
echo "    APPAWARE-WAF: COMPREHENSIVE SYSTEM VERIFICATION & QUALITY AUDIT            "
echo "================================================================================"
echo ""

# 1. Python Unit Tests
echo "[1/4] Running Python Core Unit Tests (tests/test_waf_pipeline.py)..."
python3 -m unittest discover tests -v
echo "==> Python Unit Tests: PASSED"
echo ""

# 2. Attack Matrix Verification
echo "[2/4] Running 20-Vector Full HTTP Method Attack Matrix (scripts/live_attack_tester.py)..."
python3 scripts/live_attack_tester.py --pipeline
echo "==> Attack Matrix Verification: PASSED"
echo ""

# 3. Security & Latency Benchmark Engine (1,450 Payloads)
echo "[3/4] Running Large-Scale Benchmark Suite (scripts/benchmark_waf.py)..."
python3 scripts/benchmark_waf.py
echo "==> Benchmark Suite: COMPLETED (Results saved to benchmark_results.json)"
echo ""

# 4. Frontend & Server Compilation Check
echo "[4/4] Verifying Applet Compilation (npm run build)..."
npm run build
echo "==> Applet Build: SUCCESS"
echo ""

echo "================================================================================"
echo "    AUDIT SUMMARY: ALL SYSTEM COMPONENTS ARE GREEN AND OPERATIONAL              "
echo "================================================================================"
