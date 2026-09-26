#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
SOURCE = ROOT / "specs" / "v2" / "source"
SEMANTIC_REVIEWS = SOURCE / "semantic_reviews.json"
STABLE_IDS = SOURCE / "stable_ids.json"

Json = dict[str, Any]


def _load(path: Path) -> Json:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"expected JSON object: {path}")
    return value


def _write(path: Path, value: Json) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _stable_failure_id(canonical_key: str) -> str:
    digest = hashlib.sha256(canonical_key.encode("utf-8")).hexdigest()[:16].upper()
    return f"FAIL-{digest}"


def _utc_timestamp(value: str | None) -> str:
    if value:
        try:
            parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise SystemExit("--reviewed-at must use YYYY-MM-DDTHH:MM:SSZ") from exc
        return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _register_failures(keys: list[str]) -> list[tuple[str, str]]:
    if not keys:
        return []
    payload = _load(STABLE_IDS)
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise SystemExit("stable_ids.json entries must be a list")

    by_kind_key = {
        (str(row.get("kind") or ""), str(row.get("canonical_key") or "")): row
        for row in entries
        if isinstance(row, dict)
    }
    ids = {str(row.get("stable_id") or "") for row in entries if isinstance(row, dict)}
    added: list[tuple[str, str]] = []

    for canonical_key in sorted(set(keys)):
        if ":" not in canonical_key:
            raise SystemExit(f"failure key must be canonical code:reason form: {canonical_key!r}")
        existing = by_kind_key.get(("failure", canonical_key))
        expected = _stable_failure_id(canonical_key)
        if existing is not None:
            actual = str(existing.get("stable_id") or "")
            if actual != expected:
                raise SystemExit(
                    f"existing failure stable ID mismatch for {canonical_key}: "
                    f"expected {expected}, found {actual}"
                )
            continue
        if expected in ids:
            raise SystemExit(f"stable ID collision while registering {canonical_key}: {expected}")
        row = {
            "aliases": [],
            "canonical_key": canonical_key,
            "kind": "failure",
            "stable_id": expected,
            "status": "active",
        }
        entries.append(row)
        by_kind_key[("failure", canonical_key)] = row
        ids.add(expected)
        added.append((canonical_key, expected))

    if added:
        entries.sort(key=lambda row: str(row.get("stable_id") or ""))
        _write(STABLE_IDS, payload)
    return added


def _derive_transaction_rows() -> tuple[object, object, list[Json]]:
    sys.path.insert(0, str(SCRIPTS))
    compiler = importlib.import_module("compile_v2_spec")
    validation = importlib.import_module("v2_spec_validation")

    captured: list[Json] = []
    original = compiler.apply_semantic_reviews

    def capture(tx_rows: list[Json], route_rows: list[Json], reviews: Json) -> Json:
        # Deliberately do not bless or mutate any persisted review here. The
        # compiler requires review-shaped fields later in the pipeline, so the
        # discovery pass supplies explicit non-authoritative placeholders only
        # after preserving the exact pre-review transaction material.
        captured.extend(dict(row) for row in tx_rows)
        for row in tx_rows:
            row["semantic_derivation"] = row.get("semantic_precision")
            row["semantic_review"] = {
                "review_digest": "REFRESH_DISCOVERY_ONLY",
                "reviewer": "REFRESH_DISCOVERY_ONLY",
                "reviewed_at": "1970-01-01T00:00:00Z",
                "review_method": "REFRESH_DISCOVERY_ONLY",
                "independent_review": False,
                "authority_effect": "REFRESH_DISCOVERY_ONLY",
            }
        for row in route_rows:
            row["semantic_derivation"] = row.get("semantic_precision")
            row["semantic_review"] = {
                "review_digest": "REFRESH_DISCOVERY_ONLY",
                "reviewer": "REFRESH_DISCOVERY_ONLY",
                "reviewed_at": "1970-01-01T00:00:00Z",
                "review_method": "REFRESH_DISCOVERY_ONLY",
                "independent_review": False,
                "authority_effect": "REFRESH_DISCOVERY_ONLY",
            }
        return {
            "transaction_review_count": 0,
            "route_review_count": 0,
            "independent_transaction_reviews": 0,
            "independent_route_reviews": 0,
            "validation_result": "REFRESH_DISCOVERY_ONLY",
        }

    compiler.apply_semantic_reviews = capture
    try:
        compiler.compile_artifacts()
    finally:
        compiler.apply_semantic_reviews = original
    return compiler, validation, captured


def _refresh_reviews(
    tx_types: list[str],
    *,
    reviewed_at: str,
    reviewer: str,
    review_method: str,
    authority_effect: str | None,
) -> list[tuple[str, str, str]]:
    requested = set(tx_types)
    if not requested:
        raise SystemExit("at least one --tx-type is required")

    compiler, validation, tx_rows = _derive_transaction_rows()
    by_type = {str(row.get("tx_type") or ""): row for row in tx_rows}
    missing = sorted(requested - set(by_type))
    if missing:
        raise SystemExit(f"unknown transaction type(s): {missing}")

    reviews = _load(SEMANTIC_REVIEWS)
    rows = reviews.get("transactions")
    if not isinstance(rows, list):
        raise SystemExit("semantic_reviews.json transactions must be a list")
    review_by_type = {str(row.get("tx_type") or ""): row for row in rows if isinstance(row, dict)}
    missing_reviews = sorted(requested - set(review_by_type))
    if missing_reviews:
        raise SystemExit(f"missing semantic-review row(s): {missing_reviews}")

    changed: list[tuple[str, str, str]] = []
    for tx_type in sorted(requested):
        material = validation.tx_review_material(by_type[tx_type])
        digest = validation.compact_digest(material)
        review = review_by_type[tx_type]
        old = str(review.get("review_digest") or "")
        review["review_digest"] = digest
        review["reviewed_at"] = reviewed_at
        review["reviewer"] = reviewer
        review["review_method"] = review_method
        if authority_effect is not None:
            review["authority_effect"] = authority_effect
        changed.append((tx_type, old, digest))

    _write(SEMANTIC_REVIEWS, reviews)

    # Full compile must now pass semantic review for the entire repository.
    artifacts, _manifest = compiler.compile_artifacts()
    compiler._write_artifacts(artifacts)
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Refresh explicitly reviewed V2 transaction semantic bindings and "
            "their generated derivatives. This command never auto-accepts all "
            "stale contracts."
        )
    )
    parser.add_argument(
        "--tx-type",
        action="append",
        default=[],
        help="Canonical transaction type explicitly reviewed for this change; repeatable.",
    )
    parser.add_argument(
        "--register-failure",
        action="append",
        default=[],
        metavar="CODE:REASON",
        help="New canonical failure identity to register; repeatable.",
    )
    parser.add_argument("--reviewed-at", default=None)
    parser.add_argument(
        "--reviewer",
        required=True,
        help="Human-readable maintainer/review authority recorded in semantic_reviews.json.",
    )
    parser.add_argument(
        "--review-method",
        default="maintainer_reviewed_semantic_change_with_regression_evidence",
    )
    parser.add_argument(
        "--authority-effect",
        default=None,
        help="Optional replacement authority-effect statement for all named transactions.",
    )
    args = parser.parse_args(argv)

    reviewed_at = _utc_timestamp(args.reviewed_at)
    added = _register_failures(list(args.register_failure))
    changed = _refresh_reviews(
        list(args.tx_type),
        reviewed_at=reviewed_at,
        reviewer=str(args.reviewer),
        review_method=str(args.review_method),
        authority_effect=args.authority_effect,
    )

    print("semantic review refresh complete")
    for key, stable_id in added:
        print(f"registered failure: {key} -> {stable_id}")
    for tx_type, old, new in changed:
        print(f"refreshed transaction: {tx_type}")
        print(f"  old: {old}")
        print(f"  new: {new}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
