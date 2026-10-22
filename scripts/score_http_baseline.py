#!/usr/bin/env python3
"""Replay a labeled HTTP-request CSV through a local reference WAF.

This script records only canonical request hashes, response status codes, and
binary block decisions. It never reads the label column. Keep it pointed at a
local WAF instance you control; do not use it against third-party services.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from waf.normalization.canonicalizer import Canonicalizer


def local_origin(value: str, allow_remote: bool) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("--base-url must be an http(s) origin without credentials.")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("--base-url must be an origin; paths and queries belong in the request CSV.")
    host = parsed.hostname.lower()
    is_local = host == "localhost"
    try:
        is_local = is_local or ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    if not is_local and not allow_remote:
        raise ValueError("Remote baseline targets are disabled by default. Use a local test WAF, or pass --allow-remote only for infrastructure you control.")
    return f"{parsed.scheme}://{parsed.netloc}"


def request_parts(raw: str) -> tuple[str, str, dict[str, str], bytes]:
    text = raw.replace("\r\n", "\n")
    head, separator, body = text.partition("\n\n")
    lines = head.splitlines()
    if not lines:
        raise ValueError("Empty HTTP request.")
    start = lines[0].split()
    if len(start) < 2:
        raise ValueError(f"Invalid HTTP request line: {lines[0]!r}")
    method, target = start[0].upper(), start[1]
    if target.startswith(("http://", "https://")):
        absolute = urllib.parse.urlsplit(target)
        target = absolute.path or "/"
        if absolute.query:
            target += "?" + absolute.query
    if not target.startswith("/") or target.startswith("//") or "\\" in target:
        raise ValueError("Only origin-form HTTP request targets are accepted.")
    headers: dict[str, str] = {}
    excluded = {"host", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "content-length", "forwarded"}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        if key not in excluded and not key.startswith("x-forwarded-"):
            headers[name.strip()] = value.strip()
    return method, target, headers, body.encode("utf-8") if separator else b""


def replay(url: str, method: str, target: str, headers: dict[str, str], body: bytes, timeout: float) -> int:
    request_target = urllib.parse.quote(target, safe="/%?=&;:+,@!$'()*[]-._~%")
    request = urllib.request.Request(url + request_target, data=body or None, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path, help="Labeled dataset CSV; labels are ignored by this scorer")
    parser.add_argument("--base-url", required=True, help="Local reference WAF origin, e.g. http://127.0.0.1:8081")
    parser.add_argument("--request-column", default="request")
    parser.add_argument("--block-statuses", default="403", help="Comma-separated HTTP statuses counted as blocks")
    parser.add_argument("--engine-id", default="external-http-waf", help="Exact WAF image tag/version used for this run")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--delay-seconds", type=float, default=0.0)
    parser.add_argument("--allow-remote", action="store_true", help="Permit sending requests to a non-loopback WAF you control")
    parser.add_argument("--output", type=Path, required=True, help="Output sidecar CSV path")
    args = parser.parse_args()
    if args.timeout <= 0 or args.delay_seconds < 0:
        parser.error("timeout must be positive and delay-seconds nonnegative")
    try:
        origin = local_origin(args.base_url, args.allow_remote)
        blocked_statuses = {int(value.strip()) for value in args.block_statuses.split(",") if value.strip()}
        if not blocked_statuses or any(code < 100 or code > 599 for code in blocked_statuses):
            raise ValueError("--block-statuses must contain HTTP codes from 100 through 599.")
    except ValueError as error:
        parser.error(str(error))

    canonicalizer = Canonicalizer()
    source_hash = hashlib.sha256(args.csv.read_bytes()).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with args.csv.open("r", encoding="utf-8-sig", newline="") as source, args.output.open("w", encoding="utf-8", newline="") as output:
        reader = csv.DictReader(source)
        if args.request_column not in (reader.fieldnames or []):
            parser.error(f"Request column {args.request_column!r} not found in CSV.")
        writer = csv.DictWriter(output, fieldnames=["request_sha256", "prediction", "http_status"])
        writer.writeheader()
        seen: set[str] = set()
        for row_number, row in enumerate(reader, start=2):
            raw = (row.get(args.request_column) or "").strip()
            if not raw:
                raise ValueError(f"Empty request on CSV row {row_number}.")
            parsed = canonicalizer.parse_raw_http_request(raw)
            digest = hashlib.sha256(parsed["canonical_text"].encode("utf-8")).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            method, target, headers, body = request_parts(raw)
            status = replay(origin, method, target, headers, body, args.timeout)
            writer.writerow({"request_sha256": digest, "prediction": int(status in blocked_statuses), "http_status": status})
            count += 1
            if args.delay_seconds:
                time.sleep(args.delay_seconds)

    metadata: dict[str, Any] = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_sha256": source_hash,
        "sidecar_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
        "base_origin": origin,
        "engine_id": args.engine_id,
        "block_statuses": sorted(blocked_statuses),
        "unique_requests_scored": count,
        "note": "Labels were not read. Baseline decisions use HTTP status codes only; validate block statuses for the selected WAF and upstream.",
    }
    args.output.with_suffix(args.output.suffix + ".metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
