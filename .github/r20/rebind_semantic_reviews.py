#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import runpy
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_ROOT = REPO_ROOT / "Weall-Protocol"
AUDITED_BASE = "69cce170829ded30ebb030669f05c387df6a3ddb"
REVIEW_TIMESTAMP = "2026-09-23T02:53:54Z"

EXPECTED = {
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
    "TX-0801": ("IPFS_PIN_CONFIRM", "f1f07a290dae998edcc6b6383ee9d9c5939f476622477c02c910b541ef2bd98d", "f5080fa10a5af02f4cf5441a4d00c5be82ab819863a1d1fe23f87d458ac6f401"),
    "TX-0802": ("STORAGE_OFFER_CREATE", "e3fc3e51f0431e6741506d87280fa40c5ede57f314cfca1b6b32c09bc0e7a63c", "d247bbfa64bc481ec42f6986f0d3625d9a46e2775261e8d93d420ee3e6876dd3"),
    "TX-1106": ("ROLE_NODE_OPERATOR_ENROLL", "0609f7bd12f8e8585a7b7fa0e4e8c6c5628c02b74609ad3148c305eff89aab0e", "b6f7838d4cade7e70a75512350028aacea19571fd445fe9cf765bc828c7c0578"),
    "TX-1108": ("ROLE_NODE_OPERATOR_SUSPEND", "e809b2f82b277f7a3ee74a05934d6be234b2ce93a8e6711f46a885b577e46141", "7a5ec1f4316f8ceabe4c1530d9b87e714a4adba3bb8612ab74ffdcd3c3d455fb"),
    "TX-1300": ("BALANCE_TRANSFER", "f5789a057e1104b87f2a96089aa0cd8083a3efa17227733e8971b83496a8e0ad", "9ba59de792a8a81eff9ad5c9d44c1e3350856c2712f75741c84c0484715755d9"),
    "TX-1301": ("ECONOMICS_ACTIVATION", "a213a111cc9b2367f87912858b27d83efe4308f36d34b46698dddf0ae4e8c75a", "db365bbdb74369f302fceb6222901f03abc9c10f8240d7722c398f1c0338dbff"),
    "TX-1714": ("GROUP_TREASURY_AUDIT_ANCHOR_SET", "cf897d6eb2af1bbf8cc7e4745fdb4fbf72179ba10ad24aebab6b714efb001c53", "0107ba0bc7b3db90568d517b3f6eed7de3dc6bff9550ca904305cd4ee59d6f7f"),
    "TX-2619": ("NODE_OPERATOR_RESPONSIBILITY_UPDATE", "39e35db12bcf214a5b5bee95a336a72edaca0f69cd3fc393f287fe2aee26423b", "1ce1bb98074559707d0599e59b3e8a555f7c4b6adb01d24cbb6d358064e170aa"),
    "TX-2626": ("NODE_OPERATOR_HELPER_OPT_IN", "d86c62b7e4f1227af30c897db167a26cab1faa607cd4b1e94fdb97a879b41037", "87d1c9795b9fe2b22c1bb39c2fee05ee730158f430894c7405b9c0e5d0f9278a"),
}


def _audit_stale_set() -> dict:
    os.chdir(PROTOCOL_ROOT)
    sys.path.insert(0, str(PROTOCOL_ROOT / "src"))
    sys.path.insert(0, str(PROTOCOL_ROOT / "scripts"))
    import v2_spec_validation as validation

    def audit_semantic_reviews(tx_rows, route_rows, reviews):
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
        stale_txs = []
        stale_routes = []
        for row in tx_rows:
            review = tx_reviews.get(str(row.get("stable_id") or "")) or {}
            actual = validation.compact_digest(validation.tx_review_material(row))
            expected = str(review.get("review_digest") or "")
            if actual != expected:
                stale_txs.append({
                    "stable_id": str(row.get("stable_id") or ""),
                    "tx_type": str(row.get("tx_type") or ""),
                    "expected_review_digest": expected,
                    "actual_review_digest": actual,
                })
        for row in route_rows:
            review = route_reviews.get(str(row.get("stable_id") or "")) or {}
            actual = validation.compact_digest(validation.route_review_material(row))
            expected = str(review.get("review_digest") or "")
            if actual != expected:
                stale_routes.append({
                    "stable_id": str(row.get("stable_id") or ""),
                    "route_key": str(row.get("route_key") or ""),
                    "expected_review_digest": expected,
                    "actual_review_digest": actual,
                })
        payload = {
            "stale_transaction_count": len(stale_txs),
            "stale_route_count": len(stale_routes),
            "transactions": stale_txs,
            "routes": stale_routes,
        }
        Path("generated/r20_stale_semantic_reviews.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        raise SystemExit(0)

    original = validation.apply_semantic_reviews
    old_argv = list(sys.argv)
    validation.apply_semantic_reviews = audit_semantic_reviews
    sys.argv = ["scripts/compile_v2_spec.py", "--check"]
    try:
        try:
            runpy.run_path(str(PROTOCOL_ROOT / "scripts" / "compile_v2_spec.py"), run_name="__main__")
        except SystemExit as exc:
            if exc.code not in (0, None):
                raise
    finally:
        validation.apply_semantic_reviews = original
        sys.argv = old_argv

    return json.loads(Path("generated/r20_stale_semantic_reviews.json").read_text(encoding="utf-8"))


def main() -> int:
    diagnostic = _audit_stale_set()
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
    if observed != EXPECTED:
        raise SystemExit(
            "r20 semantic-review stale set differs from exact audited allowlist\n"
            f"expected={json.dumps(EXPECTED, sort_keys=True)}\n"
            f"observed={json.dumps(observed, sort_keys=True)}"
        )

    path = PROTOCOL_ROOT / "specs" / "v2" / "source" / "semantic_reviews.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = {
        str(row.get("stable_id") or ""): row
        for row in payload.get("transactions") or []
        if isinstance(row, dict)
    }
    for stable_id, (tx_type, old_digest, new_digest) in EXPECTED.items():
        row = rows.get(stable_id)
        if row is None:
            raise SystemExit(f"missing semantic-review row: {stable_id}")
        if row.get("tx_type") != tx_type:
            raise SystemExit(f"semantic-review tx type drift for {stable_id}: {row.get('tx_type')}")
        if row.get("review_digest") != old_digest:
            raise SystemExit(
                f"semantic-review old digest drift for {stable_id}: {row.get('review_digest')}"
            )
        row["review_digest"] = new_digest
        row["reviewed_at"] = REVIEW_TIMESTAMP
        row["review_method"] = (
            "r20_audit_finding_remediation_exact_digest_rebind_bound_to_stable_implementation_identity"
        )
        row["reviewer"] = (
            "WeAll Protocol Maintainer-authorized r20 remediation snapshot (AI-assisted); "
            "independent launch review deferred"
        )

    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    report = {
        "audited_base": AUDITED_BASE,
        "rebound_transaction_count": len(EXPECTED),
        "rebound_route_count": 0,
        "stable_ids": sorted(EXPECTED),
        "review_timestamp": REVIEW_TIMESTAMP,
        "independent_review_complete": False,
        "authority_effect": "none; launch authorization remains independently gated",
    }
    (PROTOCOL_ROOT / "generated" / "r20_semantic_review_rebind.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
