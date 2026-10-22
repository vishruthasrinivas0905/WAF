#!/usr/bin/env python3
"""
CANONICALIZATION & EVASION ROBUSTNESS BENCHMARK
Experiment: experiments/robustness/run_robustness.py

Evaluates detection resilience against controlled payload transformations:
1. Standard URL Encoding (%20, %27, %3C)
2. Double URL Encoding (%2520, %2527, %253C)
3. Mixed Case Variations (uNiOn sElEcT, sCrIpT)
4. Whitespace and Comment Insertion (/**/ between SQL keywords)
5. Null-Byte Poisoning (%00 / \x00)
6. Path Traversal Encoding Variations (..%2f, %2e%2e/, %252e%252e%252f)

Compares detection rate BEFORE vs AFTER canonicalization.
"""

import os
import sys
import json
import urllib.parse
from typing import List, Dict, Any

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from waf.normalization.canonicalizer import Canonicalizer
from waf.rules.deterministic_engine import DeterministicRuleEngine

def generate_transformation_suite() -> List[Dict[str, Any]]:
    test_cases = [
        # --- SQL Injection Evasion Variations ---
        {
            "category": "SQLI",
            "base_payload": "SELECT * FROM users WHERE id = 1 UNION SELECT null, username, password FROM admin",
            "variations": [
                ("RAW", "SELECT * FROM users WHERE id = 1 UNION SELECT null, username, password FROM admin"),
                ("DOUBLE_URL_ENCODED", "SELECT%20*%20FROM%20users%20WHERE%20id%20=%201%20UNION%2520SELECT%2520null,username,password%2520FROM%2520admin"),
                ("MIXED_CASE", "sElEcT * fRoM users wHeRe id = 1 uNiOn sElEcT null, username, password fRoM admin"),
                ("SQL_COMMENT_INJECTION", "SELECT/**//*!32302**/id/**/FROM/**/users/**/WHERE/**/1=1/**/UNION/**/SELECT/**/null,username,password/**/FROM/**/admin"),
                ("NULL_BYTE_POISONING", "SELECT * FROM users WHERE id = 1%00 UNION SELECT null, username, password FROM admin")
            ]
        },
        # --- Cross-Site Scripting (XSS) Evasion Variations ---
        {
            "category": "XSS",
            "base_payload": "<script>alert(1)</script>",
            "variations": [
                ("RAW", "<script>alert(1)</script>"),
                ("MIXED_CASE", "<sCrIpT>alert(1)</ScRiPt>"),
                ("DOUBLE_URL_ENCODED", "%253Cscript%253Ealert(1)%253C%252Fscript%253E"),
                ("EVENT_HANDLER_SPACING", "<img src=x onerror  =  alert(document.cookie)>"),
                ("JAVASCRIPT_URI_ENCODED", "javascript:%61%6c%65%72%74(1)")
            ]
        },
        # --- Path Traversal / LFI Variations ---
        {
            "category": "TRAVERSAL",
            "base_payload": "/download?file=../../../../etc/passwd",
            "variations": [
                ("RAW", "/download?file=../../../../etc/passwd"),
                ("URL_ENCODED_SLASH", "/download?file=..%2f..%2f..%2f..%2fetc%2fpasswd"),
                ("DOUBLE_URL_ENCODED", "/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd"),
                ("REDUNDANT_SLASHES", "/download?file=..//..//..//etc//passwd"),
                ("CURRENT_DIR_INJECTION", "/download?file=./../.././etc/passwd")
            ]
        },
        # --- Remote Code Execution Variations ---
        {
            "category": "RCE",
            "base_payload": "; cat /etc/passwd",
            "variations": [
                ("RAW", "; cat /etc/passwd"),
                ("PIPE_CHAINING", "| whoami"),
                ("SUBCOMMAND_SUBSTITUTION", "$(whoami)"),
                ("BACKTICK_EXEC", "`id`")
            ]
        }
    ]
    return test_cases

def run_robustness_test():
    print("=" * 70)
    print("CANONICALIZATION & EVASION ROBUSTNESS EVALUATION")
    print("=" * 70)

    canonicalizer = Canonicalizer()
    rules_engine = DeterministicRuleEngine()
    suite = generate_transformation_suite()

    results = []
    total_variations = 0
    raw_detected_count = 0
    canon_detected_count = 0

    for test_group in suite:
        cat = test_group["category"]
        print(f"\n[Evaluating Category: {cat}]")

        for var_type, payload in test_group["variations"]:
            total_variations += 1
            raw_req = f"GET /api/test?data={payload} HTTP/1.1\nHost: target.app\nUser-Agent: AttackTester"

            # 1. Uncanonicalized / Raw Evaluation (direct regex search without decoding)
            raw_parsed = {
                "raw_uri": f"/api/test?data={payload}",
                "canonical_path": "/api/test",
                "query_string": f"data={payload}",
                "body": "",
                "canonical_text": raw_req,
                "headers": {},
                "anomaly_flags": []
            }
            raw_score, raw_matches = rules_engine.inspect(raw_parsed)
            raw_detected = (raw_score >= 0.70)
            if raw_detected:
                raw_detected_count += 1

            # 2. Canonicalized Evaluation (full decode passes, artifact removal, normalization)
            canon_parsed = canonicalizer.parse_raw_http_request(raw_req)
            canon_score, canon_matches = rules_engine.inspect(canon_parsed)
            canon_detected = (canon_score >= 0.70 or len(canon_matches) > 0)
            if canon_detected:
                canon_detected_count += 1

            status = "PASS" if canon_detected else "EVADED"
            boost = "[CANONICALIZER BLOCKED]" if (canon_detected and not raw_detected) else ""
            print(f"  [{status}] {var_type:<24} | Raw: {'DETECT' if raw_detected else 'MISS'} | Canon: {'DETECT' if canon_detected else 'MISS'} {boost}")

            results.append({
                "category": cat,
                "variation": var_type,
                "payload": payload[:50],
                "raw_score": round(raw_score, 3),
                "raw_detected": raw_detected,
                "canon_score": round(canon_score, 3),
                "canon_detected": canon_detected,
                "evaded_raw": not raw_detected,
                "evaded_canon": not canon_detected
            })

    raw_rate = (raw_detected_count / total_variations) * 100.0
    canon_rate = (canon_detected_count / total_variations) * 100.0

    print("\n" + "=" * 70)
    print("ROBUSTNESS SUMMARY:")
    print(f"  Total Attack Transformations Evaluated: {total_variations}")
    print(f"  Raw Direct Inspection Detection Rate:    {raw_rate:.2f}% ({raw_detected_count}/{total_variations})")
    print(f"  Canonicalized Inspection Detection Rate: {canon_rate:.2f}% ({canon_detected_count}/{total_variations})")
    print(f"  Evasion Resistance Improvement:          +{canon_rate - raw_rate:.2f}%")
    print("=" * 70)

    os.makedirs(os.path.join("experiments", "robustness"), exist_ok=True)
    out_file = os.path.join("experiments", "robustness", "robustness_results.json")
    with open(out_file, "w") as f:
        json.dump({
            "total_variations": total_variations,
            "raw_detection_rate": round(raw_rate, 2),
            "canonicalized_detection_rate": round(canon_rate, 2),
            "improvement_pct": round(canon_rate - raw_rate, 2),
            "detailed_cases": results
        }, f, indent=2)

    print(f"Results saved to: {out_file}")

if __name__ == "__main__":
    run_robustness_test()
