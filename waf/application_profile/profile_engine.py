"""
APPLICATION PROFILE & FEW-SHOT ADAPTATION ENGINE
Module: waf/application_profile/profile_engine.py

Represents legitimate application behavior to address the core research question:
"Can application-aware adaptation of a Transformer-based WAF reduce false positives
on previously unseen web applications using limited benign application-specific traffic?"

Features:
1. Static Application Specification (registered routes, allowed HTTP methods)
2. Statistical Profile Learning from Benign Samples (Budgets: 0, 100, 500, 1,000)
3. Endpoint parameter schema profiling (expected params, value types, length percentiles)
4. Contextual Anomaly Scoring (differentiating known vs novel endpoints vs schema violations)
"""

import math
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict


class EndpointProfile:
    def __init__(self, path: str, allowed_methods: Optional[Set[str]] = None):
        self.path = path
        self.allowed_methods = allowed_methods or {"GET", "POST"}
        self.observed_samples = 0
        self.known_params: Set[str] = set()
        self.param_lengths: Dict[str, List[int]] = defaultdict(list)
        self.payload_lengths: List[int] = []
        self.p95_payload_len: float = 2048.0
        self.avg_payload_len: float = 256.0

    def record_benign_sample(self, method: str, query_params: Dict[str, List[str]], body_len: int):
        self.observed_samples += 1
        self.allowed_methods.add(method.upper())
        self.payload_lengths.append(body_len)

        for param, values in query_params.items():
            self.known_params.add(param)
            total_val_len = sum(len(v) for v in values)
            self.param_lengths[param].append(total_val_len)

        if len(self.payload_lengths) >= 5:
            sorted_lens = sorted(self.payload_lengths)
            p95_idx = int(0.95 * len(sorted_lens))
            self.p95_payload_len = float(sorted_lens[p95_idx])
            self.avg_payload_len = sum(sorted_lens) / len(sorted_lens)

    def evaluate_request(self, method: str, query_params: Dict[str, List[str]], body: str) -> Dict[str, Any]:
        """
        Evaluates a request against this endpoint profile.
        Returns anomaly metrics without naively flagging every deviation as an attack.
        """
        violations = []
        anomaly_score = 0.0

        # Method check
        if method.upper() not in self.allowed_methods:
            violations.append(f"UNEXPECTED_METHOD_{method}")
            anomaly_score += 0.35

        # Unknown parameter check (only penalize if we have observed sufficient samples)
        if self.observed_samples >= 50:
            unknown_params = set(query_params.keys()) - self.known_params
            if unknown_params:
                violations.append(f"UNKNOWN_PARAMETERS_{list(unknown_params)[:3]}")
                # Mild anomaly score: legitimate applications evolve
                anomaly_score += min(0.30, 0.10 * len(unknown_params))

        # Payload size spike check
        body_len = len(body)
        if self.observed_samples >= 20 and body_len > (self.p95_payload_len * 3 + 128):
            violations.append(f"PAYLOAD_LENGTH_SPIKE_{body_len}_VS_P95_{int(self.p95_payload_len)}")
            anomaly_score += 0.25

        return {
            "endpoint_match": True,
            "observed_samples": self.observed_samples,
            "anomaly_score": min(1.0, anomaly_score),
            "violations": violations
        }


class ApplicationProfileEngine:
    def __init__(self, app_id: str = "default_app"):
        self.app_id = app_id
        self.adaptation_budget = 0
        self.endpoints: Dict[str, EndpointProfile] = {}
        self.global_benign_count = 0

    def adapt_from_benign_samples(self, samples: List[Dict[str, Any]]):
        """
        Ingests a budgeted number of benign requests (e.g. 0, 100, 500, 1000).
        Builds the baseline statistical profile.
        """
        self.adaptation_budget = len(samples)
        for sample in samples:
            path = sample.get("canonical_path", sample.get("path", "/"))
            method = sample.get("method", "GET")
            params = sample.get("query_params", {})
            body = sample.get("body", "")

            if path not in self.endpoints:
                self.endpoints[path] = EndpointProfile(path=path)

            self.endpoints[path].record_benign_sample(method, params, len(body))
            self.global_benign_count += 1

    def evaluate(self, parsed_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates a request against the learned application profile.
        Returns:
            profile_score: 0.0 (perfect conformance) to 1.0 (high profile deviation)
            is_known_route: bool
            adaptation_level: int
        """
        path = parsed_request.get("canonical_path", "/")
        method = parsed_request.get("method", "GET")
        params = parsed_request.get("query_params", {})
        body = parsed_request.get("body", "")

        # Exact match or normalized prefix match
        profile = self.endpoints.get(path)
        if not profile:
            # Fallback to general route match
            for ep_path, ep_profile in self.endpoints.items():
                if path.startswith(ep_path) and ep_path != "/":
                    profile = ep_profile
                    break

        if not profile:
            # Unseen route: if budget is 0 (unadapted), neutral score (0.0).
            # If application has been heavily profiled, slight unfamiliarity penalty (0.20)
            unfamiliarity = 0.20 if self.adaptation_budget >= 100 else 0.05
            return {
                "profile_score": unfamiliarity,
                "is_known_route": False,
                "adaptation_budget": self.adaptation_budget,
                "violations": ["UNSEEN_ROUTE"],
                "reason": "Route not present in baseline profile"
            }

        eval_res = profile.evaluate_request(method, params, body)
        return {
            "profile_score": eval_res["anomaly_score"],
            "is_known_route": True,
            "adaptation_budget": self.adaptation_budget,
            "observed_samples": eval_res["observed_samples"],
            "violations": eval_res["violations"],
            "reason": "; ".join(eval_res["violations"]) if eval_res["violations"] else "Conforms to profile"
        }
