"""
RISK AND POLICY DECISION ENGINE
Module: waf/risk/policy_engine.py

Fuses three independent defensive signals:
1. S_det: Deterministic Rule Severity (OWASP CRS matches)
2. P_ml: Transformer Deep Learning Inference Probability
3. S_app: Application Profile Anomaly / Context Score

Decisions:
- ALLOW: Low risk (forwarded to upstream application)
- MONITOR: Medium risk or ambiguous anomaly (forwarded with audit alert)
- BLOCK: High risk / malicious (terminated with HTTP 403 Forbidden)
"""

from typing import Dict, Any, List

class PolicyDecision:
    def __init__(
        self,
        action: str,
        risk_score: float,
        confidence: float,
        deterministic_score: float,
        transformer_score: float,
        profile_score: float,
        matched_rules: List[str],
        anomaly_flags: List[str],
        reason: str
    ):
        self.action = action  # "ALLOW", "MONITOR", "BLOCK"
        self.risk_score = risk_score
        self.confidence = confidence
        self.deterministic_score = deterministic_score
        self.transformer_score = transformer_score
        self.profile_score = profile_score
        self.matched_rules = matched_rules
        self.anomaly_flags = anomaly_flags
        self.reason = reason

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "risk_score": round(self.risk_score, 4),
            "confidence": round(self.confidence, 4),
            "signals": {
                "deterministic": round(self.deterministic_score, 4),
                "transformer": round(self.transformer_score, 4),
                "profile": round(self.profile_score, 4)
            },
            "matched_rules": self.matched_rules,
            "anomaly_flags": self.anomaly_flags,
            "reason": self.reason
        }


class PolicyEngine:
    def __init__(
        self,
        mode: str = "ENFORCING",  # "ENFORCING", "MONITORING", "BYPASS"
        block_threshold: float = 0.70,
        monitor_threshold: float = 0.40,
        w_det: float = 0.45,
        w_ml: float = 0.40,
        w_app: float = 0.15
    ):
        self.mode = mode
        self.block_threshold = block_threshold
        self.monitor_threshold = monitor_threshold
        # Signal weights (sum to 1.0)
        self.w_det = w_det
        self.w_ml = w_ml
        self.w_app = w_app

    def evaluate(
        self,
        det_score: float,
        ml_score: float,
        app_score: float,
        rule_matches: List[Any],
        canonical_anomalies: List[str]
    ) -> PolicyDecision:
        """
        Computes composite risk and determines the final enforcement decision.
        """
        rule_ids = [m.rule_id if hasattr(m, 'rule_id') else str(m) for m in rule_matches]
        
        # 1. Deterministic Rule Override (Defense in Depth)
        # Any verified critical signature (Severity 4/5: SQLi, RCE, XSS, LFI) directly blocks
        has_critical = any(
            getattr(m, 'severity', 1) >= 4 or getattr(m, 'category', '') in ("SQLI", "XSS", "RCE", "TRAVERSAL")
            for m in rule_matches
        )
        if det_score >= 0.85 or has_critical:
            composite_risk = max(det_score, 0.90)
            reason = f"High-confidence deterministic rule trigger: {', '.join(rule_ids[:2])}"
            action = "BLOCK" if self.mode == "ENFORCING" else "MONITOR"
            return PolicyDecision(
                action=action,
                risk_score=composite_risk,
                confidence=0.98,
                deterministic_score=det_score,
                transformer_score=ml_score,
                profile_score=app_score,
                matched_rules=rule_ids,
                anomaly_flags=canonical_anomalies,
                reason=reason
            )

        # 2. Weighted Signal Fusion
        composite_risk = (
            (self.w_det * det_score) +
            (self.w_ml * ml_score) +
            (self.w_app * app_score)
        )

        # 3. Contextual Adjustment (Application-Aware False Positive Suppression)
        # If Transformer is moderately uncertain (0.40 - 0.65) but:
        # - Deterministic rules are 0
        # - Route and parameters perfectly match learned application profile (app_score == 0)
        # -> Suppress false positive by moderating risk
        if det_score == 0.0 and app_score == 0.0 and (0.35 <= ml_score <= 0.65):
            composite_risk *= 0.65  # Contextual reduction

        # 4. Canonicalization Evasion Penalty
        if any("DOUBLE_URL_ENCODED" in flag or "NULL_BYTE" in flag for flag in canonical_anomalies):
            composite_risk = min(1.0, composite_risk + 0.20)

        # 5. Final Action Mapping
        if composite_risk >= self.block_threshold:
            action = "BLOCK"
            reason = f"Risk score ({composite_risk:.2f}) exceeds block threshold ({self.block_threshold})"
        elif composite_risk >= self.monitor_threshold:
            action = "MONITOR"
            reason = f"Elevated risk ({composite_risk:.2f}) flagged for audit"
        else:
            action = "ALLOW"
            reason = f"Risk score ({composite_risk:.2f}) within clean tolerance"

        if self.mode == "MONITORING" and action == "BLOCK":
            action = "MONITOR"
            reason += " [Enforcement suppressed by MONITORING mode]"

        confidence = 1.0 - abs(composite_risk - 0.5) * 0.5

        return PolicyDecision(
            action=action,
            risk_score=composite_risk,
            confidence=confidence,
            deterministic_score=det_score,
            transformer_score=ml_score,
            profile_score=app_score,
            matched_rules=rule_ids,
            anomaly_flags=canonical_anomalies,
            reason=reason
        )
