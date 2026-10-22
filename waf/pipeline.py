"""
CORE WAF INSPECTION PIPELINE
Module: waf/pipeline.py

Integrates:
1. Canonicalizer
2. DeterministicRuleEngine
3. ApplicationProfileEngine
4. TransformerModel / Inference Interface
5. PolicyEngine
"""

import time
import uuid
from typing import Dict, Any, Optional

from waf.normalization.canonicalizer import Canonicalizer
from waf.rules.deterministic_engine import DeterministicRuleEngine
from waf.application_profile.profile_engine import ApplicationProfileEngine
from waf.risk.policy_engine import PolicyEngine, PolicyDecision
from waf.inference.model_engine import create_default_scorer


class WafPipeline:
    def __init__(
        self,
        mode: str = "ENFORCING",
        model_inference_fn=None,
        app_id: str = "production_app"
    ):
        self.canonicalizer = Canonicalizer()
        self.rules_engine = DeterministicRuleEngine()
        self.profile_engine = ApplicationProfileEngine(app_id=app_id)
        self.policy_engine = PolicyEngine(mode=mode)
        if model_inference_fn is not None:
            self.model_inference_fn = model_inference_fn
        else:
            self.scorer = create_default_scorer()
            self.model_inference_fn = self.scorer.predict

    def inspect_request(self, raw_http: str, client_ip: str = "127.0.0.1") -> Dict[str, Any]:
        """
        Executes full inspection chain and returns security audit event.
        """
        start_time = time.perf_counter()
        request_id = str(uuid.uuid4())

        # 1. Canonicalization
        parsed = self.canonicalizer.parse_raw_http_request(raw_http)

        # 2. Deterministic Rule Matching
        det_score, matches = self.rules_engine.inspect(parsed)

        # 3. Application Profile Evaluation
        app_eval = self.profile_engine.evaluate(parsed)
        app_score = app_eval.get("profile_score", 0.0)

        # 4. Transformer Model Inference (if available)
        ml_score = 0.0
        ml_latency_ms = 0.0
        if self.model_inference_fn:
            ml_start = time.perf_counter()
            try:
                ml_score = float(self.model_inference_fn(parsed["canonical_text"]))
            except Exception as e:
                # Fail-open / fallback behavior for model errors
                parsed["anomaly_flags"].append(f"ML_INFERENCE_ERROR: {str(e)[:50]}")
            ml_latency_ms = (time.perf_counter() - ml_start) * 1000.0
        else:
            # If no neural model is loaded yet, use deterministic fallback
            ml_score = det_score

        # 5. Risk & Policy Fusion
        decision: PolicyDecision = self.policy_engine.evaluate(
            det_score=det_score,
            ml_score=ml_score,
            app_score=app_score,
            rule_matches=matches,
            canonical_anomalies=parsed["anomaly_flags"]
        )

        total_latency_ms = (time.perf_counter() - start_time) * 1000.0

        # Structured Security Event (sensitive data redacted)
        security_event = {
            "event_id": request_id,
            "timestamp": time.time(),
            "client_ip": client_ip,
            "method": parsed["method"],
            "path": parsed["canonical_path"],
            "decision": decision.action,
            "risk_score": decision.risk_score,
            "confidence": decision.confidence,
            "signals": {
                "deterministic_score": det_score,
                "transformer_score": ml_score,
                "profile_score": app_score
            },
            "matched_rules": [m.to_dict() for m in matches],
            "anomaly_flags": parsed["anomaly_flags"],
            "profile_context": {
                "is_known_route": app_eval.get("is_known_route", False),
                "adaptation_budget": app_eval.get("adaptation_budget", 0),
                "reason": app_eval.get("reason", "")
            },
            "decision_reason": decision.reason,
            "latencies": {
                "total_ms": round(total_latency_ms, 3),
                "ml_inference_ms": round(ml_latency_ms, 3)
            }
        }

        return security_event
