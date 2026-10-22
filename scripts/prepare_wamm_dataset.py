#!/usr/bin/env python3
"""Convert the WAMM DS-Augmented-v2 SQLite release into the project CSV schema.

The output includes only request text, a binary label, the source attack class,
    and a host-aware canonical-request hash used as a duplicate-safe random
    split group. It does not claim application/source-held-out generalization.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import lzma
import re
import sqlite3
import tempfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from waf.normalization.canonicalizer import Canonicalizer


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="DS_Augmented_v2.db.xz from the upstream repository")
    parser.add_argument("output", type=Path, help="Normalized CSV output path")
    args = parser.parse_args()

    canonicalizer = Canonicalizer()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="wamm-", dir=args.output.parent) as temporary_dir:
        database_path = Path(temporary_dir) / "dataset.sqlite"
        with lzma.open(args.source, "rb") as compressed, database_path.open("wb") as database:
            while chunk := compressed.read(1024 * 1024):
                database.write(chunk)

        connection = sqlite3.connect(database_path)
        try:
            tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            if len(tables) != 1:
                raise ValueError(f"Expected one SQLite table, found {len(tables)}")
            table = tables[0][0]
            columns = {row[1] for row in connection.execute(f'PRAGMA table_info("{table}")')}
            if not {"col1", "col2"}.issubset(columns):
                raise ValueError(f"Unexpected WAMM table schema: {sorted(columns)}")

            label_by_request: dict[str, int] = {}
            conflicting_requests: set[str] = set()
            for request, source_label in connection.execute(f'SELECT col1, col2 FROM "{table}"'):
                match = re.match(r"\s*(\d+)\s*-\s*(.+?)\s*$", source_label or "")
                if not match:
                    raise ValueError(f"Unrecognized WAMM label: {source_label!r}")
                class_id = match.group(1)
                parsed = canonicalizer.parse_raw_http_request(request or "")
                host = parsed["headers"].get("host", "").strip().lower()
                fingerprint_text = f"{host}\n{parsed['canonical_text']}"
                request_group = hashlib.sha256(fingerprint_text.encode("utf-8")).hexdigest()
                label = 0 if class_id == "000" else 1
                prior_label = label_by_request.setdefault(request_group, label)
                if prior_label != label:
                    conflicting_requests.add(request_group)

            with args.output.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=["request", "is_attack", "group", "request_sha256", "category"])
                writer.writeheader()
                rows = connection.execute(f'SELECT col1, col2 FROM "{table}"')
                written = 0
                for request, source_label in rows:
                    match = re.match(r"\s*(\d+)\s*-\s*(.+?)\s*$", source_label or "")
                    class_id, category = match.groups()
                    parsed = canonicalizer.parse_raw_http_request(request or "")
                    host = parsed["headers"].get("host", "").strip().lower()
                    fingerprint_text = f"{host}\n{parsed['canonical_text']}"
                    request_group = hashlib.sha256(fingerprint_text.encode("utf-8")).hexdigest()
                    if request_group in conflicting_requests:
                        continue
                    label = 0 if class_id == "000" else 1
                    writer.writerow({
                        "request": request or "",
                        "is_attack": label,
                        "group": request_group,
                        "request_sha256": request_group,
                        "category": category.strip(),
                    })
                    written += 1
        finally:
            connection.close()

    print(f"Wrote {written} normalized WAMM records to {args.output}; excluded {len(conflicting_requests)} canonical request fingerprints with conflicting binary labels.")


if __name__ == "__main__":
    main()
