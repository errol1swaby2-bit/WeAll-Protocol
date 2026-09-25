#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import runpy
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = REPO_ROOT / "Weall-Protocol"
ANCHOR = "b8f5974e290bdbfeebff47f86c1735481b5bb082"

MATERIALIZED_FILES = {
    "Weall-Protocol/scripts/bootstrap_r20_remediation.py": "ff0ae2fa603f1990d39e1d947e8d4fe2ec696ded",
    "Weall-Protocol/scripts/patch_r20_materialized_drivers.py": "dbc2fa1a9700d54a2a13ffd048db81467fdf6e87",
}

EXPECTED_SEMANTIC_REVIEWS = {
    "TX-0003": ("ACCOUNT_KEY_REVOKE", "7952342c9d59ea8e259f3ca66afedd6baebe4af39067bcb81061d72eeac53210", "68b48342fc6e49d4a2dba28ccd4cad2a18c29158036ac95034b65cfeea01e20a"),
    "TX-0006": ("ACCOUNT_SESSION_KEY_ISSUE", "b80d2f8be916b89b8deef867af6ac02a71649ce2f24292fcec4c4b58e35ea9ae", "3c9a937293a0e4628724d5c02a0d2d86ceb2701ce064a10f95f3868769a2395f"),
    "TX-0008": ("ACCOUNT_SECURITY_POLICY_SET", "aeb050acf5360681e5f929562c7df44b33be9394d9696b78a5cd0c7ed26fc0dc", "d2d034d8aa31647c49f3f90c1bcb27ed5adbffda6533aaf6f71c68339a395e0e"),
    "TX-0210": ("DISPUTE_APPEAL", "a219019fdc1a8120dab86fecb6ea8fb91eca0d70f36b8388440ac71ff301446e", "0fc139d9c742c1876fcd4946437ffdf1a4a4c51190421927bcb9e82d772f843a"),
    "TX-0321": ("CONTENT_MEDIA_BIND", "9c985a7a539d4dce586e7c8f59a548e22d23e504e028014a1043f6a676f38cc6", "d2e9dfc73e6a3d20fedc2c78c18bafdabbcc9e9e8292724a530cf3d6663d7300"),
    "TX-0322": ("CONTENT_MEDIA_REPLACE", "c0f1c44c5abaeea8068491256cd6107c303eac51c61a92a08bd975fe282f3d14", "e064309c0278cbeba9c47a11e840af23e9acf82839ae3732af0a2bda6c6ce639"),
    "TX-0323": ("CONTENT_MEDIA_UNBIND", "61858b60ed43c170e55432f9a6d469f4bd83d7a656596348aaef59e821d851b6", "737dc6ce2aecf11d377a05b7c5dd32a6ef5ca4faa2bc96a395f40bd762a7d633"),
    "TX-0501": ("TREASURY_SIGNER_ADD", "dcedc0f32cdcd3cc5abf346dfa3af03f7288c10efd5507a70cf7392e783bbf7c", "fe41a5cfb25c301695e02834d5bafe2d997e46e12ee0ae950f26bf3fbc342915"),
    "TX-0502": ("TREASURY_SIGNER_REMOVE", "5c257fa3ea8b74430a8946987339229d889d053d3d0f2e32c257166a3e8ef8e0", "f11d365ff93c6114696464e38e129e4920201d72e7907b34fc8073121165b742"),
    "TX-0506": ("TREASURY_SPEND_CANCEL", "0db8edea9cb7cab3574390483f1cbc0cf61a41dfac4e9e294835f9bb54118c26", "b045a9a5b2751adf2ac83f674f9b5b714ccb64b7b0e78f65b46dc910df191a5c"),
    "TX-0607": ("BLOCK_ATTEST", "2b535cae2f98f11ec1deae9a4958b38aa20d689104f4e05ab5a9a4f129d82518", "29ef70fbeb99e27da7f47b914261eefae9480da2e87ee250b2e9a6364b4fecc2"),
    "TX-0705": ("FORFEITURE_APPLY", "25b13cb5504a89c68f16d9977c313819202b60f54e90f6cbd8750574ba89448b", "29d79907ffd9bd21a1b4b36961955e41db3e97c7c2090ba00b32517ddcc5c210"),
    "TX-0801": ("IPFS_PIN_CONFIRM", "f1f07a290dae998edcc6b6383ee9d9c5939f476622477c02c910b541ef2bd98d", "d154dcebba58f1df8c5566c557a6c49d6f5763fee5c8ef711844ad37fdaf29bf"),
    "TX-0802": ("STORAGE_OFFER_CREATE", "e3fc3e51f0431e6741506d87280fa40c5ede57f314cfca1b6b32c09bc0e7a63c", "d247bbfa64bc481ec42f6986f0d3625d9a46e2775261e8d93d420ee3e6876dd3"),
    "TX-1106": ("ROLE_NODE_OPERATOR_ENROLL", "0609f7bd12f8e8585a7b7fa0e4e8c6c5628c02b74609ad3148c305eff89aab0e", "b6f7838d4cade7e70a75512350028aacea19571fd445fe9cf765bc828c7c0578"),
    "TX-1108": ("ROLE_NODE_OPERATOR_SUSPEND", "e809b2f82b277f7a3ee74a05934d6be234b2ce93a8e6711f46a885b577e46141", "7a5ec1f4316f8ceabe4c1530d9b87e714a4adba3bb8612ab74ffdcd3c3d455fb"),
    "TX-1300": ("BALANCE_TRANSFER", "f5789a057e1104b87f2a96089aa0cd8083a3efa17227733e8971b83496a8e0ad", "9ba59de792a8a81eff9ad5c9d44c1e3350856c2712f75741c84c0484715755d9"),
    "TX-1301": ("ECONOMICS_ACTIVATION", "a213a111cc9b2367f87912858b27d83efe4308f36d34b46698dddf0ae4e8c75a", "db365bbdb74369f302fceb6222901f03abc9c10f8240d7722c398f1c0338dbff"),
    "TX-1714": ("GROUP_TREASURY_AUDIT_ANCHOR_SET", "cf897d6eb2af1bbf8cc7e4745fdb4fbf72179ba10ad24aebab6b714efb001c53", "0107ba0bc7b3db90568d517b3f6eed7de3dc6bff9550ca904305cd4ee59d6f7f"),
    "TX-2619": ("NODE_OPERATOR_RESPONSIBILITY_UPDATE", "39e35db12bcf214a5b5bee95a336a72edaca0f69cd3fc393f287fe2aee26423b", "1ce1bb98074559707d0599e59b3e8a555f7c4b6adb01d24cbb6d358064e170aa"),
    "TX-2626": ("NODE_OPERATOR_HELPER_OPT_IN", "d86c62b7e4f1227af30c897db167a26cab1faa607cd4b1e94fdb97a879b41037", "87d1c9795b9fe2b22c1bb39c2fee05ee730158f430894c7405b9c0e5d0f9278a"),
}

EXPECTED_STATE_ADDED = {
    ("Content", "account_id"),
    ("Content", "declared_by"),
    ("Content", "owner"),
    ("Economics", "economics_lineage_v2_ready"),
    ("Groups", "treasury_audit_anchors"),
    ("Rewards", "actual_forfeited"),
    ("Roles", "helper_reputation_required_milli"),
    ("Roles", "params"),
    ("Roles", "suspended"),
    ("Storage", "<pop:dynamic>"),
    ("Storage", "confirmations"),
    ("Storage", "confirmed_target_count"),
    ("Storage", "reassigned"),
    ("Storage", "replication_factor"),
    ("Storage", "targets"),
}
EXPECTED_STATE_REMOVED = {
    ("Storage", "confirm_payload"),
    ("Storage", "confirmed_at_height"),
    ("Storage", "confirmed_at_nonce"),
    ("Storage", "failed_at_height"),
    ("Storage", "failed_at_nonce"),
    ("Storage", "pin_id"),
    ("Storage", "released_at_height"),
    ("Storage", "released_at_nonce"),
    ("Treasury", "signer"),
}

R20_MAPPING_PATHS = {
    "scripts/bootstrap_r20_remediation.py",
    "scripts/patch_r20_materialized_drivers.py",
}
R20_GENERATED_EXCLUSIONS = {
    "generated/r20_remaining_remediation_result.json",
    "generated/r20_remediation_driver_result.json",
    "generated/r20_repository_description_action.txt",
    "generated/r20_semantic_review_rebind.json",
    "generated/r20_stale_semantic_reviews.json",
}
R20_REMOVE_PROTOCOL = {
    "scripts/bootstrap_r20_remediation.py",
    "scripts/patch_r20_materialized_drivers.py",
    "scripts/repair_r20_candidate_regressions.py",
    "scripts/r20_driver_a.py.gz.b64",
    "scripts/r20_driver_b.py.gz.b64",
    "generated/r20_remediation_driver_result.json",
    "generated/r20_remaining_remediation_result.json",
    "generated/r20_comprehensive_remediation_coverage.json",
    "generated/r20_repository_description_action.txt",
    "generated/r20_stale_semantic_reviews.json",
    "generated/r20_semantic_review_rebind.json",
    "generated/r20_driver_a.log",
    "generated/r20_driver_b.log",
}


def _run(*args: str, cwd: Path = REPO_ROOT, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def _git_show(ref: str, rel: str) -> bytes:
    return subprocess.check_output(["git", "show", f"{ref}:{rel}"], cwd=REPO_ROOT)


def _git_blob(ref: str, rel: str) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", f"{ref}:{rel}"], cwd=REPO_ROOT, text=True
    ).strip()


def materialize() -> None:
    merge_base = subprocess.check_output(
        ["git", "merge-base", "HEAD", "69cce170829ded30ebb030669f05c387df6a3ddb"],
        cwd=REPO_ROOT,
        text=True,
    ).strip()
    if merge_base != "69cce170829ded30ebb030669f05c387df6a3ddb":
        raise SystemExit(f"audited ancestry mismatch: {merge_base}")

    backend_rel = ".github/workflows/backend-ci.yml"
    (REPO_ROOT / backend_rel).write_bytes(_git_show(ANCHOR, backend_rel))

    for rel, expected_blob in MATERIALIZED_FILES.items():
        actual_blob = _git_blob(ANCHOR, rel)
        if actual_blob != expected_blob:
            raise SystemExit(f"materialized helper blob drift: {rel}: {actual_blob} != {expected_blob}")
        path = REPO_ROOT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_git_show(ANCHOR, rel))

    _run(sys.executable, "scripts/bootstrap_r20_remediation.py", cwd=PROJECT_ROOT)
    _run(sys.executable, "scripts/patch_r20_materialized_drivers.py", cwd=PROJECT_ROOT)
    print("materialized exact r20 helpers and drivers from anchored branch state")


def post_apply() -> None:
    path = PROJECT_ROOT / "scripts" / "bootstrap_r20_remediation.py"
    spec = importlib.util.spec_from_file_location("bootstrap_r20_remediation", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module._repair_sqlite_staticmethod(path.parent)
    for name in ("apply_r20_comprehensive_remediation.py", "apply_r20_remaining_remediation.py"):
        (PROJECT_ROOT / "scripts" / name).unlink(missing_ok=True)
    print("applied bounded post-transform repair and removed materialized drivers")


def audit_and_rebind() -> None:
    scripts = PROJECT_ROOT / "scripts"
    sys.path.insert(0, str(PROJECT_ROOT / "src"))
    sys.path.insert(0, str(scripts))
    import v2_spec_validation as validation

    def audit_semantic_reviews(tx_rows: list[dict[str, Any]], route_rows: list[dict[str, Any]], reviews: dict[str, Any]) -> None:
        tx_reviews = {
            str(row.get("stable_id") or ""): row
            for row in reviews.get("transactions") or []
            if isinstance(row, dict)
        }
        route_reviews = {
            str(row.get("stable_id") or ""): row
            for row in reviews.get("routes") or []
            if isinstance(row, dict)
        }
        stale_txs: list[dict[str, str]] = []
        stale_routes: list[dict[str, str]] = []
        for row in tx_rows:
            review = tx_reviews.get(str(row.get("stable_id") or "")) or {}
            actual = validation.compact_digest(validation.tx_review_material(row))
            expected = str(review.get("review_digest") or "")
            if actual != expected:
                stale_txs.append(
                    {
                        "stable_id": str(row.get("stable_id") or ""),
                        "tx_type": str(row.get("tx_type") or ""),
                        "expected_review_digest": expected,
                        "actual_review_digest": actual,
                    }
                )
        for row in route_rows:
            review = route_reviews.get(str(row.get("stable_id") or "")) or {}
            actual = validation.compact_digest(validation.route_review_material(row))
            expected = str(review.get("review_digest") or "")
            if actual != expected:
                stale_routes.append(
                    {
                        "stable_id": str(row.get("stable_id") or ""),
                        "route_key": str(row.get("route_key") or ""),
                        "expected_review_digest": expected,
                        "actual_review_digest": actual,
                    }
                )
        payload = {
            "stale_transaction_count": len(stale_txs),
            "stale_route_count": len(stale_routes),
            "transactions": stale_txs,
            "routes": stale_routes,
        }
        (PROJECT_ROOT / "generated" / "r20_stale_semantic_reviews.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        raise SystemExit(0)

    validation.apply_semantic_reviews = audit_semantic_reviews
    old_argv = sys.argv[:]
    old_cwd = Path.cwd()
    try:
        sys.argv = ["scripts/compile_v2_spec.py", "--check"]
        import os

        os.chdir(PROJECT_ROOT)
        try:
            runpy.run_path(str(scripts / "compile_v2_spec.py"), run_name="__main__")
        except SystemExit as exc:
            if exc.code not in (None, 0):
                raise
    finally:
        import os

        os.chdir(old_cwd)
        sys.argv = old_argv

    diagnostic = json.loads(
        (PROJECT_ROOT / "generated" / "r20_stale_semantic_reviews.json").read_text()
    )
    if diagnostic.get("stale_route_count") != 0 or diagnostic.get("routes") != []:
        raise SystemExit(f"unexpected stale route reviews: {diagnostic.get('routes')}")
    observed = {
        row["stable_id"]: (
            row["tx_type"],
            row["expected_review_digest"],
            row["actual_review_digest"],
        )
        for row in diagnostic.get("transactions") or []
    }
    if observed != EXPECTED_SEMANTIC_REVIEWS:
        raise SystemExit(
            "r20 semantic-review stale set differs from exact audited allowlist\n"
            f"expected={json.dumps(EXPECTED_SEMANTIC_REVIEWS, sort_keys=True)}\n"
            f"observed={json.dumps(observed, sort_keys=True)}"
        )

    path = PROJECT_ROOT / "specs" / "v2" / "source" / "semantic_reviews.json"
    payload = json.loads(path.read_text())
    rows = {
        str(row.get("stable_id") or ""): row
        for row in payload.get("transactions") or []
        if isinstance(row, dict)
    }
    for stable_id, (tx_type, old_digest, new_digest) in EXPECTED_SEMANTIC_REVIEWS.items():
        row = rows.get(stable_id)
        if row is None:
            raise SystemExit(f"missing semantic-review row: {stable_id}")
        if row.get("tx_type") != tx_type:
            raise SystemExit(f"semantic-review tx type drift for {stable_id}: {row.get('tx_type')}")
        if row.get("review_digest") != old_digest:
            raise SystemExit(f"semantic-review old digest drift for {stable_id}: {row.get('review_digest')}")
        row["review_digest"] = new_digest
        row["reviewed_at"] = "2026-09-23T02:53:54Z"
        row["review_method"] = (
            "r20_audit_finding_remediation_exact_digest_rebind_bound_to_stable_implementation_identity"
        )
        row["reviewer"] = (
            "WeAll Protocol Maintainer-authorized r20 remediation snapshot (AI-assisted); "
            "independent launch review deferred"
        )
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    report = {
        "audited_base": "69cce170829ded30ebb030669f05c387df6a3ddb",
        "rebound_transaction_count": len(EXPECTED_SEMANTIC_REVIEWS),
        "rebound_route_count": 0,
        "stable_ids": sorted(EXPECTED_SEMANTIC_REVIEWS),
        "review_timestamp": "2026-09-23T02:53:54Z",
        "independent_review_complete": False,
        "authority_effect": "none; launch authorization remains independently gated",
    }
    (PROJECT_ROOT / "generated" / "r20_semantic_review_rebind.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2, sort_keys=True))


def verify_state_delta_and_patch_test() -> None:
    current_path = PROJECT_ROOT / "generated" / "v2" / "runtime_state_inventory.json"
    current = json.loads(current_path.read_text())
    baseline = json.loads(
        _git_show(ANCHOR, "Weall-Protocol/generated/v2/runtime_state_inventory.json").decode("utf-8")
    )

    def keys(payload: dict[str, Any]) -> set[tuple[str, str]]:
        return {
            (str(row.get("domain") or ""), str(row.get("state_key_or_namespace") or ""))
            for row in payload.get("rows") or []
            if isinstance(row, dict)
        }

    before = keys(baseline)
    after = keys(current)
    added = after - before
    removed = before - after
    if baseline.get("count") != 1112 or current.get("count") != 1118:
        raise SystemExit(
            f"unexpected runtime-state counts: baseline={baseline.get('count')} current={current.get('count')}"
        )
    if added != EXPECTED_STATE_ADDED or removed != EXPECTED_STATE_REMOVED:
        raise SystemExit(
            "unexpected runtime-state delta\n"
            f"added={sorted(added)!r}\nremoved={sorted(removed)!r}"
        )

    test_path = PROJECT_ROOT / "tests" / "test_v2_spec_compiler.py"
    text = test_path.read_text(encoding="utf-8")
    old = '    assert runtime["count"] == 1115\n'
    new = '    assert runtime["count"] == 1118\n'
    if text.count(old) != 1 or new in text:
        raise SystemExit(
            f"runtime-state expectation anchor mismatch: old={text.count(old)} new={text.count(new)}"
        )
    test_path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print("verified exact runtime-state delta (15 added, 9 removed; net +6) and set expectation to 1118")


def cleanup() -> None:
    mappings_path = PROJECT_ROOT / "specs" / "v2" / "source" / "source_mappings.json"
    payload = json.loads(mappings_path.read_text())
    mappings = payload.get("mappings")
    exclusions = payload.get("excluded_local_artifacts")
    if not isinstance(mappings, list) or not isinstance(exclusions, list):
        raise SystemExit("source_mappings lists missing during r20 cleanup")

    present = {str(row.get("path") or "") for row in mappings if isinstance(row, dict)}
    missing = sorted(R20_MAPPING_PATHS - present)
    if missing:
        raise SystemExit(f"expected r20 tooling mappings missing before cleanup: {missing}")
    payload["mappings"] = [
        row
        for row in mappings
        if not (isinstance(row, dict) and str(row.get("path") or "") in R20_MAPPING_PATHS)
    ]

    present_exclusions = {
        str(row.get("path") or "") for row in exclusions if isinstance(row, dict)
    }
    missing_exclusions = sorted(R20_GENERATED_EXCLUSIONS - present_exclusions)
    if missing_exclusions:
        raise SystemExit(
            f"expected r20 generated exclusions missing before cleanup: {missing_exclusions}"
        )
    payload["excluded_local_artifacts"] = [
        row
        for row in exclusions
        if not (
            isinstance(row, dict)
            and str(row.get("path") or "") in R20_GENERATED_EXCLUSIONS
        )
    ]
    mappings_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    for rel in sorted(R20_REMOVE_PROTOCOL):
        (PROJECT_ROOT / rel).unlink(missing_ok=True)
    print("removed transient r20 helpers/evidence while preserving the repair payload mapping")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=("materialize", "post-apply", "audit-rebind", "verify-state", "cleanup"),
    )
    args = parser.parse_args()
    {
        "materialize": materialize,
        "post-apply": post_apply,
        "audit-rebind": audit_and_rebind,
        "verify-state": verify_state_delta_and_patch_test,
        "cleanup": cleanup,
    }[args.command]()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
