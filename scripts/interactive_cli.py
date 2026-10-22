#!/usr/bin/env python3
"""
APPAWARE-WAF INTERACTIVE CLI AND LIVE ATTACK INSPECTOR
Script: scripts/interactive_cli.py

Run on your local Windows machine:
  cd "C:\\Users\\SAHANA KS\\OneDrive\\Desktop\\MAJOR WAF 7"
  python scripts/interactive_cli.py

Features:
1. Interactive manual attack testing for GET, POST, PUT, DELETE.
2. Automated 20-vector test matrix verification across SQLi, XSS, RCE, Traversal, and Benign.
3. Loads your trained Transformer model ('models/transformer_waf') if PyTorch is available,
   with automatic fallback to token attention heuristics if torch is not installed.
4. Explains step-by-step why a request was ALLOWED or BLOCKED.
"""

import os
import sys
import json
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from waf.pipeline import WafPipeline
from waf.normalization.canonicalizer import Canonicalizer

# Try loading PyTorch DistilBERT model if available
transformer_model = None
tokenizer = None
device = "cpu"

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    model_dir = os.path.join(os.path.dirname(__file__), "..", "models", "transformer_waf")
    if os.path.isdir(model_dir):
        print(f"[*] Loading trained Transformer checkpoint from: {model_dir}")
        tokenizer = AutoTokenizer.from_pretrained(model_dir)
        transformer_model = AutoModelForSequenceClassification.from_pretrained(model_dir)
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        transformer_model.to(device)
        transformer_model.eval()
        print(f"[✓] Transformer model loaded successfully on {device}!\n")
except Exception as e:
    print(f"[-] Running with high-speed built-in heuristic (Transformer loading skipped: {e})\n")


def ml_inference_fn(canonical_text: str) -> float:
    if transformer_model is not None and tokenizer is not None:
        with torch.no_grad():
            enc = tokenizer(canonical_text, padding=True, truncation=True, max_length=256, return_tensors="pt").to(device)
            logits = transformer_model(**enc).logits
            prob = torch.softmax(logits, dim=-1)[:, 1].cpu().item()
            return prob
    return 0.0


pipeline = WafPipeline(mode="ENFORCING", model_inference_fn=ml_inference_fn if transformer_model else None)


def inspect_single(method: str, path: str, headers_dict: dict, body: str):
    raw_req = f"{method.upper()} {path} HTTP/1.1\n"
    for k, v in headers_dict.items():
        raw_req += f"{k}: {v}\n"
    if body:
        raw_req += f"\n{body}"

    print("\n" + "=" * 70)
    print(f"TESTING REQUEST: {method.upper()} {path}")
    if body:
        print(f"PAYLOAD BODY:   {body[:100]}{'...' if len(body) > 100 else ''}")
    print("=" * 70)

    event = pipeline.inspect_request(raw_req)

    print(f"\n[FINAL WAF DECISION]: {event['decision']}")
    print(f"  Composite Risk Score: {event['risk_score'] * 100:.1f}%")
    print(f"  Decision Reason:      {event['decision_reason']}")
    print(f"  Inspection Latency:   {event['latencies']['total_ms']:.2f} ms")

    print("\n[5-STAGE DEFENSIVE BREAKDOWN]:")
    print(f"  1. Canonical Path:    {event['path']}")
    if event['anomaly_flags']:
        print(f"     Encoding Flags:    {', '.join(event['anomaly_flags'])}")
    else:
        print(f"     Encoding Flags:    Clean (no evasion detected)")

    print(f"  2. OWASP CRS Rules:   Deterministic Score = {event['signals']['deterministic_score']:.2f}")
    if event['matched_rules']:
        for r in event['matched_rules']:
            print(f"     [MATCH] {r['rule_id']} ({r['category']}) - Severity {r['severity']}/5: {r['description']}")
            print(f"             Snippet: {r['matched_snippet']}")
    else:
        print("     No deterministic signatures matched.")

    print(f"  3. Transformer Score: P(Attack) = {event['signals']['transformer_score'] * 100:.1f}%")
    print(f"  4. App Profile Match: Anomaly = {event['signals']['profile_score']:.2f} (Known Route: {event['profile_context']['is_known_route']})")

    if event['decision'] == "BLOCK":
        print("\n[ACTION ENFORCED]: HTTP 403 Forbidden - TERMINATED BEFORE REACHING APPLICATION")
    elif event['decision'] == "MONITOR":
        print("\n[ACTION ENFORCED]: HTTP 200 OK - FORWARDED WITH AUDIT ALERT HEADER")
    else:
        print("\n[ACTION ENFORCED]: HTTP 200 OK - CLEAN REQUEST FORWARDED SAFELY TO UPSTREAM")


def interactive_prompt():
    print("\n--- Interactive Custom Attack Prompt ---")
    print("Type 'exit' to quit to menu.\n")
    while True:
        try:
            method = input("Enter HTTP Method [GET/POST/PUT/DELETE] (default: GET): ").strip().upper()
            if method == "EXIT":
                break
            if not method:
                method = "GET"

            path = input("Enter URI / Path with query (e.g. /api/users?id=1' OR 1=1--): ").strip()
            if path.lower() == "exit":
                break
            if not path:
                path = "/"

            body = ""
            if method in ("POST", "PUT", "PATCH"):
                body = input("Enter Body Payload (e.g. JSON, form data, or script payload): ").strip()

            inspect_single(method, path, {"Host": "target.app", "User-Agent": "SecurityTester"}, body)
            print("\n" + "-" * 70)
        except (KeyboardInterrupt, EOFError):
            break


def run_matrix():
    from scripts.live_attack_tester import TEST_VECTORS
    print("\nExecuting all 20 GET, POST, PUT, DELETE vectors...")
    time.sleep(0.5)
    from scripts.live_attack_tester import run_pipeline_test
    run_pipeline_test()


def main():
    while True:
        print("\n" + "=" * 60)
        print("  APPAWARE-WAF LIVE MANUAL & MATRIX ATTACK INSPECTOR")
        print("=" * 60)
        print("1. Run All 20 Vectors Across GET, POST, PUT, DELETE")
        print("2. Enter Interactive Custom Payload Prompt (Type your own attack)")
        print("3. Test Quick SQL Injection (GET /products?id=1 UNION SELECT...)")
        print("4. Test Quick XSS (POST /comments with <script> tag)")
        print("5. Test Quick RCE (PUT /config with command chaining)")
        print("6. Test Quick Path Traversal (DELETE /temp?file=../../etc/passwd)")
        print("7. Test Legitimate Benign Traffic (ALLOW Verification)")
        print("0. Exit")
        choice = input("\nSelect an option [0-7]: ").strip()

        if choice == "1":
            run_matrix()
        elif choice == "2":
            interactive_prompt()
        elif choice == "3":
            inspect_single("GET", "/products?id=1%20UNION%20SELECT%20null,password%20FROM%20users--", {"Host": "app.local"}, "")
        elif choice == "4":
            inspect_single("POST", "/api/v1/comments", {"Host": "app.local", "Content-Type": "application/json"}, '{"comment": "<script>alert(document.cookie)</script>"}')
        elif choice == "5":
            inspect_single("PUT", "/api/v1/config", {"Host": "app.local", "Content-Type": "application/json"}, '{"dns": "8.8.8.8 | whoami"}')
        elif choice == "6":
            inspect_single("DELETE", "/api/v1/temp/cleanup?file=../../../../etc/passwd", {"Host": "app.local"}, "")
        elif choice == "7":
            inspect_single("GET", "/api/v1/products?category=electronics&page=1", {"Host": "app.local", "User-Agent": "Mozilla/5.0"}, "")
        elif choice == "0":
            print("\nExiting. Goodbye!")
            break
        else:
            print("Invalid choice, please select 0-7.")


if __name__ == "__main__":
    main()
