"""
DETERMINISTIC SECURITY RULE ENGINE
Module: waf/rules/deterministic_engine.py

Provides established, high-confidence deterministic attack pattern matching
aligned with OWASP CRS categories:
- SQL Injection (OWASP CRS 942)
- Cross-Site Scripting / XSS (OWASP CRS 941)
- Remote Code Execution / Command Injection (OWASP CRS 932)
- Path Traversal & LFI/RFI (OWASP CRS 930)
- Protocol Anomalies & Scanner Probes (OWASP CRS 913/920)
"""

import re
from typing import Dict, List, Any, Tuple

class RuleMatch:
    def __init__(self, rule_id: str, category: str, severity: int, description: str, matched_snippet: str):
        self.rule_id = rule_id
        self.category = category
        self.severity = severity  # 1 (Low) to 5 (Critical)
        self.description = description
        self.matched_snippet = matched_snippet

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "matched_snippet": self.matched_snippet[:80]  # truncate for safe logging
        }


class DeterministicRuleEngine:
    def __init__(self):
        self.rules = self._compile_rules()

    def _compile_rules(self) -> List[Dict[str, Any]]:
        raw_rules = [
            # ======================== SQL INJECTION (CRS 942) ========================
            {
                "id": "CRS-942-100",
                "category": "SQLI",
                "severity": 5,
                "desc": "Classic SQL comment or tautology bypass (OR 1=1, AND 1=1, --)",
                "pattern": re.compile(r"(\b(or|and)\b\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+|--|\/\*.*?\*\/|;\s*--|#)", re.IGNORECASE)
            },
            {
                "id": "CRS-942-110",
                "category": "SQLI",
                "severity": 5,
                "desc": "SQL UNION SELECT injection attempt",
                "pattern": re.compile(r"\bunion(\s+all)?\s+select\b", re.IGNORECASE)
            },
            {
                "id": "CRS-942-115",
                "category": "SQLI",
                "severity": 5,
                "desc": "SQL subquery or data extraction (SELECT ... FROM ...)",
                "pattern": re.compile(r"\bselect\b\s+[\w\*,\s\(\)]+\s+\bfrom\b", re.IGNORECASE)
            },
            {
                "id": "CRS-942-120",
                "category": "SQLI",
                "severity": 5,
                "desc": "SQL information schema or administrative table extraction",
                "pattern": re.compile(r"\b(information_schema|syscat|pg_catalog|sqlite_master|sysobjects)\b", re.IGNORECASE)
            },
            {
                "id": "CRS-942-130",
                "category": "SQLI",
                "severity": 5,
                "desc": "SQL time-based or error-based functions (sleep, benchmark, waitfor delay)",
                "pattern": re.compile(r"\b(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|waitfor\s+delay|pg_sleep)\b", re.IGNORECASE)
            },
            {
                "id": "CRS-942-140",
                "category": "SQLI",
                "severity": 5,
                "desc": "Dangerous stacked SQL commands (DROP, TRUNCATE, ALTER, EXEC xp_cmdshell)",
                "pattern": re.compile(r";\s*(drop|truncate|alter|grant|revoke)\s+\w+|\bxp_cmdshell\b", re.IGNORECASE)
            },

            # ======================== CROSS-SITE SCRIPTING (CRS 941) ========================
            {
                "id": "CRS-941-100",
                "category": "XSS",
                "severity": 5,
                "desc": "Standard script tag injection (<script>...</script>)",
                "pattern": re.compile(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL)
            },
            {
                "id": "CRS-941-110",
                "category": "XSS",
                "severity": 5,
                "desc": "HTML tag with JavaScript event handler (onload, onerror, onclick, onmouseover)",
                "pattern": re.compile(r"<\s*\w+[^>]+(on\w+)\s*=\s*[\'\"].*?[\'\"]", re.IGNORECASE)
            },
            {
                "id": "CRS-941-120",
                "category": "XSS",
                "severity": 5,
                "desc": "JavaScript pseudoprotocol URI (javascript:, vbscript:, data:text/html)",
                "pattern": re.compile(r"\b(javascript|vbscript|data\s*:\s*text\/html)\s*:", re.IGNORECASE)
            },
            {
                "id": "CRS-941-130",
                "category": "XSS",
                "severity": 5,
                "desc": "Unclosed script tag or vector payload (<script, <svg/onload, <img src=x onerror)",
                "pattern": re.compile(r"<\s*(script|iframe|svg|img|body|input)[^>]*(onerror|onload|onclick)", re.IGNORECASE)
            },

            # ======================== REMOTE CODE EXECUTION (CRS 932) ========================
            {
                "id": "CRS-932-100",
                "category": "RCE",
                "severity": 5,
                "desc": "Unix/Linux command execution via shell chaining (| , ;, &&, $(cmd), `cmd`)",
                "pattern": re.compile(r"(;|\||&&|\$\(|\`)\s*(cat|ls|pwd|whoami|id|uname|nc|bash|sh|curl|wget)\b", re.IGNORECASE)
            },
            {
                "id": "CRS-932-105",
                "category": "RCE",
                "severity": 5,
                "desc": "Shell invocation or reverse shell syntax (/bin/sh, nc -e, dev/tcp)",
                "pattern": re.compile(r"(\/bin\/(ba)?sh|\bnc\s+-[el]|/dev/tcp/\d|\bcmd\.exe|\bpowershell)\b", re.IGNORECASE)
            },
            {
                "id": "CRS-932-110",
                "category": "RCE",
                "severity": 5,
                "desc": "Windows cmd/powershell execution attempt",
                "pattern": re.compile(r"\b(powershell(\.exe)?|cmd(\.exe)?)\s+-[ecenopw]+\b|\b(certutil|bitsadmin)\b", re.IGNORECASE)
            },
            {
                "id": "CRS-932-120",
                "category": "RCE",
                "severity": 5,
                "desc": "PHP code evaluation injection (eval, assert, passthru, system, shell_exec)",
                "pattern": re.compile(r"\b(eval|assert|passthru|shell_exec|system|exec|proc_open)\s*\(", re.IGNORECASE)
            },
            {
                "id": "CRS-932-130",
                "category": "RCE",
                "severity": 5,
                "desc": "Java JNDI / Log4j / SSTI expression injection (${jndi:, #{...}, ${...})",
                "pattern": re.compile(r"\$\{\s*(jndi|ctx|env|sys):|#\{\s*[\w\.]+|__proto__|constructor\.prototype", re.IGNORECASE)
            },

            # ======================== PATH TRAVERSAL / LFI (CRS 930) ========================
            {
                "id": "CRS-930-100",
                "category": "TRAVERSAL",
                "severity": 5,
                "desc": "Directory traversal sequence (../ or ..\\ or encoded %2e%2e)",
                "pattern": re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)", re.IGNORECASE)
            },
            {
                "id": "CRS-930-110",
                "category": "TRAVERSAL",
                "severity": 5,
                "desc": "Attempted access to known sensitive OS configuration files (/etc/passwd, win.ini, boot.ini)",
                "pattern": re.compile(r"(/etc/(passwd|shadow|hosts|issue)|windows[/\\]win\.ini|boot\.ini)", re.IGNORECASE)
            },

            # ======================== SCANNER PROBES & RECON (CRS 913) ========================
            {
                "id": "CRS-913-100",
                "category": "SCANNER",
                "severity": 3,
                "desc": "Known vulnerability scanner or crawler signature (sqlmap, nikto, acunetix, nessus)",
                "pattern": re.compile(r"\b(sqlmap|nikto|acunetix|nessus|nmap|dirbuster|gobuster|wpscan)\b", re.IGNORECASE)
            }
        ]
        return raw_rules

    def inspect(self, parsed_request: Dict[str, Any]) -> Tuple[float, List[RuleMatch]]:
        """
        Evaluates the parsed and canonicalized request against the deterministic rule set.
        Returns:
            deterministic_score: Normalized severity score between 0.0 (clean) and 1.0 (malicious).
            matches: List of RuleMatch instances.
        """
        matches: List[RuleMatch] = []
        
        # Targets to inspect
        targets = [
            ("URI", parsed_request.get("raw_uri", "")),
            ("CANONICAL_PATH", parsed_request.get("canonical_path", "")),
            ("QUERY", parsed_request.get("query_string", "")),
            ("BODY", parsed_request.get("body", "")),
            ("CANONICAL_TEXT", parsed_request.get("canonical_text", ""))
        ]

        # Also inspect suspicious headers
        headers = parsed_request.get("headers", {})
        for h_key in ("user-agent", "referer", "cookie", "x-forwarded-for"):
            if h_key in headers:
                targets.append((f"HEADER_{h_key.upper()}", headers[h_key]))

        total_severity = 0
        matched_rule_ids = set()

        for rule in self.rules:
            pattern = rule["pattern"]
            for target_name, text in targets:
                if not text:
                    continue
                match = pattern.search(text)
                if match:
                    r_id = rule["id"]
                    if r_id not in matched_rule_ids:
                        matched_rule_ids.add(r_id)
                        snippet = match.group(0)
                        rule_match = RuleMatch(
                            rule_id=r_id,
                            category=rule["category"],
                            severity=rule["severity"],
                            description=rule["desc"],
                            matched_snippet=f"[{target_name}] {snippet}"
                        )
                        matches.append(rule_match)
                        total_severity += rule["severity"]
                        # Stop scanning other targets for this rule once matched
                        break

        # Calculate normalized score (0.0 to 1.0).
        # Any single Severity 5 rule yields >= 0.85 (immediate high risk)
        # Multiple lower severity rules accumulate.
        if not matches:
            deterministic_score = 0.0
        else:
            max_sev = max(m.severity for m in matches)
            if max_sev >= 5:
                deterministic_score = min(1.0, 0.85 + 0.05 * (len(matches) - 1))
            elif max_sev == 4:
                deterministic_score = min(0.95, 0.65 + 0.10 * (len(matches) - 1))
            else:
                deterministic_score = min(0.70, 0.25 * len(matches))

        return deterministic_score, matches
