"""
REQUEST NORMALIZER AND CANONICALIZATION ENGINE
Module: waf/normalization/canonicalizer.py

Implements defensive canonicalization:
1. Strips dataset parser artifacts (e.g. 'End - Id:', 'Start - Id:', 'class: Valid')
2. Bounded recursive URL decoding (max 3 passes to prevent decode evasion / zip bombs)
3. Path traversal canonicalization (/./, //, /foo/../bar -> /bar)
4. Null byte and control character sanitization
5. HTTP request decomposition into Method, Path, Query Params, Headers, and Body
"""

import re
import urllib.parse
from typing import Dict, Any, Tuple, Optional

# Regex to strip ECML/PKDD & CSIC benchmark metadata artifacts
DATASET_ARTIFACT_REGEX = re.compile(
    r'(\n|\r\n)*(null\s*)?(End\s*-\s*Id:.*|Start\s*-\s*Id:.*|class:\s*(Valid|Anomaly)).*$',
    re.IGNORECASE | re.DOTALL
)

# Common HTTP verbs
VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}


class Canonicalizer:
    def __init__(self, max_decode_passes: int = 3, max_payload_len: int = 16384):
        self.max_decode_passes = max_decode_passes
        self.max_payload_len = max_payload_len

    def strip_dataset_artifacts(self, raw_text: str) -> str:
        """Removes trailing benchmark dataset metadata tags."""
        if not raw_text:
            return ""
        cleaned = DATASET_ARTIFACT_REGEX.sub('', raw_text).rstrip()
        return cleaned

    def safe_url_decode(self, text: str) -> Tuple[str, int]:
        """
        Recursively decodes URL-encoded characters up to max_decode_passes.
        Tracks the number of decoding passes (multiple passes indicates evasion attempts).
        """
        if not text:
            return "", 0

        current = text
        passes = 0
        for i in range(self.max_decode_passes):
            decoded = urllib.parse.unquote_plus(current)
            if decoded == current:
                break
            current = decoded
            passes += 1

        return current, passes

    def normalize_path(self, path: str) -> str:
        """
        Canonicalizes URI path by resolving directory traversals and multiple slashes.
        Preserves leading slash.
        """
        if not path:
            return "/"

        # Replace multiple slashes with single slash
        path = re.sub(r'/+', '/', path)
        
        # Split and resolve . and ..
        segments = path.split('/')
        resolved = []
        for seg in segments:
            if seg in ('', '.'):
                continue
            elif seg == '..':
                if resolved:
                    resolved.pop()
            else:
                resolved.append(seg)
        
        canonical = '/' + '/'.join(resolved)
        return canonical

    def sanitize_control_characters(self, text: str) -> Tuple[str, bool]:
        """
        Detects and sanitizes null bytes (%00, \x00) and suspicious non-printable ASCII.
        Returns (sanitized_text, had_null_byte).
        """
        had_null = ('\x00' in text) or ('%00' in text.lower())
        sanitized = text.replace('\x00', '')
        return sanitized, had_null

    def parse_raw_http_request(self, raw_request: str) -> Dict[str, Any]:
        """
        Parses raw HTTP stream or URI string into structured components:
        - method: GET, POST, etc.
        - uri: Full requested path and query
        - path: Clean path
        - query_string: Raw query string
        - query_params: Parsed dictionary
        - headers: Dictionary of HTTP headers
        - body: Extracted payload body
        - anomaly_flags: Canonicalization flags (e.g. multiple_encoding, null_byte)
        """
        cleaned_raw = self.strip_dataset_artifacts(raw_request)
        anomaly_flags = []

        # Check for null bytes in raw text
        cleaned_raw, had_null = self.sanitize_control_characters(cleaned_raw)
        if had_null:
            anomaly_flags.append("NULL_BYTE_DETECTED")

        lines = cleaned_raw.splitlines()
        if not lines:
            return {
                "method": "UNKNOWN",
                "uri": "/",
                "path": "/",
                "query_string": "",
                "query_params": {},
                "headers": {},
                "body": "",
                "anomaly_flags": ["EMPTY_REQUEST"],
                "canonical_text": ""
            }

        first_line = lines[0].strip()
        parts = first_line.split()

        method = "GET"
        raw_uri = "/"
        http_version = "HTTP/1.1"

        if len(parts) >= 2 and parts[0].upper() in VALID_METHODS:
            method = parts[0].upper()
            if re.match(r"^HTTP/\d\.\d$", parts[-1], re.IGNORECASE):
                http_version = parts[-1].upper()
                raw_uri = " ".join(parts[1:-1])
            else:
                raw_uri = " ".join(parts[1:])
        else:
            raw_uri = first_line

        # Parse headers and body
        headers = {}
        body_lines = []
        reading_headers = True

        for line in lines[1:]:
            if reading_headers:
                if line.strip() == "":
                    reading_headers = False
                    continue
                if ":" in line:
                    h_name, h_val = line.split(":", 1)
                    headers[h_name.strip().lower()] = h_val.strip()
            else:
                body_lines.append(line)

        raw_body = "\n".join(body_lines)
        decoded_body, _ = self.safe_url_decode(raw_body)

        # Parse URI and Query
        parsed_url = urllib.parse.urlparse(raw_uri)
        path = parsed_url.path or "/"
        query_string = parsed_url.query

        # Canonicalize URI and query
        decoded_path, path_passes = self.safe_url_decode(path)
        canonical_path = self.normalize_path(decoded_path)
        if path_passes > 1:
            anomaly_flags.append(f"DOUBLE_URL_ENCODED_PATH_{path_passes}X")

        decoded_query, query_passes = self.safe_url_decode(query_string)
        if query_passes > 1:
            anomaly_flags.append(f"DOUBLE_URL_ENCODED_QUERY_{query_passes}X")

        # Parse query params
        query_params = urllib.parse.parse_qs(decoded_query, keep_blank_values=True)

        # Build clean representation for Transformer and Rules
        canonical_representation = f"{method} {canonical_path}"
        if decoded_query:
            canonical_representation += f"?{decoded_query}"
        if decoded_body.strip():
            canonical_representation += f"\nBody: {decoded_body.strip()}"

        return {
            "method": method,
            "raw_uri": raw_uri,
            "canonical_path": canonical_path,
            "query_string": decoded_query,
            "query_params": query_params,
            "headers": headers,
            "body": decoded_body.strip(),
            "http_version": http_version,
            "anomaly_flags": anomaly_flags,
            "canonical_text": canonical_representation[:self.max_payload_len]
        }
