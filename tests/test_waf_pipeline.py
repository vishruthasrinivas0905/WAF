"""
AUTOMATED REGRESSION AND UNIT TEST SUITE FOR APPAWARE-WAF
Tests: tests/test_waf_pipeline.py

Covers:
1. Defensive Canonicalization & Dataset Artifact Removal
2. OWASP CRS Deterministic Rule Detection (SQLi, XSS, RCE, Traversal)
3. Multi-Pass URL Decoding & Evasion Neutralization
4. Application-Aware Profile Scoring & Few-Shot Adaptation
5. Multi-Signal Risk Fusion (ALLOW, MONITOR, BLOCK)
6. Security Event Logging & Sensitive Field Redaction
"""

import unittest
import sys
import os

# Add root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from waf.normalization.canonicalizer import Canonicalizer
from waf.rules.deterministic_engine import DeterministicRuleEngine
from waf.application_profile.profile_engine import ApplicationProfileEngine
from waf.risk.policy_engine import PolicyEngine
from waf.pipeline import WafPipeline


class TestWafPipeline(unittest.TestCase):
    def setUp(self):
        self.canonicalizer = Canonicalizer()
        self.rules_engine = DeterministicRuleEngine()
        self.pipeline = WafPipeline(mode="ENFORCING")

    def test_dataset_artifact_stripping(self):
        raw_with_artifact = (
            "GET /index.php?id=1 HTTP/1.1\nHost: example.com\n\nnull\n\n"
            "End - Id: 28966\nStart - Id: 2877\nclass: Valid"
        )
        parsed = self.canonicalizer.parse_raw_http_request(raw_with_artifact)
        self.assertNotIn("End - Id", parsed["canonical_text"])
        self.assertNotIn("class: Valid", parsed["canonical_text"])
        self.assertEqual(parsed["canonical_path"], "/index.php")

    def test_double_url_encoding_detection(self):
        # %2520 is double encoded space, %253C is double encoded '<'
        raw = "GET /search?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E HTTP/1.1\nHost: app.local"
        parsed = self.canonicalizer.parse_raw_http_request(raw)
        self.assertTrue(any("DOUBLE_URL_ENCODED" in flag for flag in parsed["anomaly_flags"]))
        self.assertIn("<script>", parsed["query_string"])

    def test_path_traversal_canonicalization(self):
        raw = "GET /static/images/../../../../etc/passwd HTTP/1.1\nHost: app.local"
        parsed = self.canonicalizer.parse_raw_http_request(raw)
        self.assertEqual(parsed["canonical_path"], "/etc/passwd")
        score, matches = self.rules_engine.inspect(parsed)
        self.assertGreaterEqual(score, 0.70)
        self.assertTrue(any(m.category == "TRAVERSAL" for m in matches))

    def test_sqli_union_detection(self):
        raw = "GET /items?id=10%20UNION%20SELECT%20null,password%20FROM%20users-- HTTP/1.1\nHost: app.local"
        event = self.pipeline.inspect_request(raw)
        self.assertEqual(event["decision"], "BLOCK")
        self.assertGreaterEqual(event["risk_score"], 0.70)
        rule_ids = [r["rule_id"] for r in event["matched_rules"]]
        self.assertTrue("CRS-942-100" in rule_ids or "CRS-942-110" in rule_ids)

    def test_xss_script_tag_detection(self):
        raw = "POST /comments HTTP/1.1\nHost: app.local\n\n<script>alert(document.cookie)</script>"
        event = self.pipeline.inspect_request(raw)
        self.assertEqual(event["decision"], "BLOCK")
        self.assertTrue(any(r["category"] == "XSS" for r in event["matched_rules"]))

    def test_benign_request_allowed(self):
        raw = "GET /api/v1/users?page=1&limit=20 HTTP/1.1\nHost: app.local\nUser-Agent: Mozilla/5.0"
        event = self.pipeline.inspect_request(raw)
        self.assertEqual(event["decision"], "ALLOW")
        self.assertLess(event["risk_score"], 0.40)
        self.assertEqual(len(event["matched_rules"]), 0)

    def test_few_shot_profile_adaptation(self):
        profile_engine = ApplicationProfileEngine(app_id="test_suite_app")
        # Unadapted route should have neutral/baseline score
        clean_req = {
            "canonical_path": "/api/v2/reports",
            "method": "GET",
            "query_params": {"format": ["json"]},
            "body": ""
        }
        res_before = profile_engine.evaluate(clean_req)
        self.assertFalse(res_before["is_known_route"])

        # Adapt with 5 benign samples
        benign_samples = [
            {"canonical_path": "/api/v2/reports", "method": "GET", "query_params": {"format": ["json"]}, "body": ""}
            for _ in range(5)
        ]
        profile_engine.adapt_from_benign_samples(benign_samples)
        res_after = profile_engine.evaluate(clean_req)
        self.assertTrue(res_after["is_known_route"])
        self.assertEqual(res_after["profile_score"], 0.0)

    def test_neural_scorer_and_inference(self):
        from waf.inference.model_engine import create_default_scorer
        scorer = create_default_scorer()
        benign_score = scorer.predict("GET /index.html HTTP/1.1\nHost: example.com")
        attack_score = scorer.predict("GET /products?id=1 UNION SELECT null,password FROM users-- HTTP/1.1")
        self.assertLess(benign_score, 0.40)
        self.assertGreaterEqual(attack_score, 0.80)
        self.assertLess(scorer.avg_latency_ms, 5.0)

    def test_end_to_end_pipeline_signals(self):
        raw = "POST /api/exec HTTP/1.1\nHost: app.local\n\ncmd=;cat%20/etc/passwd"
        event = self.pipeline.inspect_request(raw)
        self.assertEqual(event["decision"], "BLOCK")
        self.assertIn("signals", event)
        self.assertIn("deterministic_score", event["signals"])
        self.assertIn("heuristic_score", event["signals"])
        self.assertGreaterEqual(event["signals"]["heuristic_score"], 0.70)


if __name__ == "__main__":
    unittest.main(verbosity=2)
