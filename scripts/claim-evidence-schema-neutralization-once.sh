#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

python - <<'PY'
from pathlib import Path

replacements = {
    Path("Weall-Protocol/scripts/gen_public_beta_blocker_report_v1_5.py"): [
        ("safe_before_first_round", "safe_with_current_evidence"),
        ("nlnet_first_round_disposition", "release_disposition"),
        (
            "safe_to_close_before_nlnet_first_round_with_current_repo_evidence",
            "safe_to_close_with_current_repository_evidence",
        ),
        (
            "safe_to_reduce_before_nlnet_first_round",
            "safe_to_reduce_with_current_evidence",
        ),
        (
            "keep_open_and_frame_as_mainnet_readiness_hardening",
            "keep_open_as_mainnet_readiness_hardening",
        ),
    ],
    Path("Weall-Protocol/tests/prod/test_public_observer_open_download_transcript_capture.py"): [
        (
            "safe_to_close_before_nlnet_first_round_with_current_repo_evidence",
            "safe_to_close_with_current_repository_evidence",
        ),
    ],
    Path("Weall-Protocol/scripts/gen_current_verified_claims.py"): [
        (
            "The current reviewer framing is pre-public-testnet / active hardening, not public beta or mainnet.",
            "The current repository posture is pre-public-testnet / active hardening, not public beta or mainnet.",
        ),
        (
            "clean-checkout audit after the review-prep changes are committed.",
            "clean-checkout audit after the relevant repository changes are committed.",
        ),
    ],
    Path("Weall-Protocol/docs/TRUTH_BOUNDARY.md"): [
        ("## reviewer framing", "## Current repository posture"),
        ("The correct reviewer framing is:", "The current repository posture is:"),
    ],
    Path("Weall-Protocol/docs/reviewer/DIRECT_MESSAGE_TRANSACTION_QUARANTINE.md"): [
        (
            "The NLnet/public-testnet reviewer claim is public-only civic protocol infrastructure",
            "The current protocol-scope claim is public-only civic protocol infrastructure",
        ),
    ],
}

for path, pairs in replacements.items():
    text = path.read_text(encoding="utf-8")
    original = text
    for old, new in pairs:
        if old not in text:
            raise SystemExit(f"expected text not found in {path}: {old!r}")
        text = text.replace(old, new)
    if text == original:
        raise SystemExit(f"no change made to {path}")
    path.write_text(text, encoding="utf-8")
PY

# Remove the one-shot machinery before generating source-sensitive derivatives so
# the generated tree describes the actual proposed repository state.
git rm -f .github/workflows/claim-evidence-schema-neutralization-once.yml scripts/claim-evidence-schema-neutralization-once.sh

cd Weall-Protocol

python -m ruff format scripts/gen_public_beta_blocker_report_v1_5.py scripts/gen_current_verified_claims.py tests/prod/test_public_observer_open_download_transcript_capture.py
python -m ruff check scripts/gen_public_beta_blocker_report_v1_5.py scripts/gen_current_verified_claims.py tests/prod/test_public_observer_open_download_transcript_capture.py

PYTHONPATH=src:scripts python scripts/gen_public_only_protocol_audit_v1_5.py
PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py
python scripts/gen_release_evidence_manifest_v1_5.py
python scripts/gen_current_verified_claims.py
python scripts/compile_v2_spec.py

PYTHONPATH=src:scripts python scripts/gen_public_only_protocol_audit_v1_5.py --check
PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check
python scripts/gen_release_evidence_manifest_v1_5.py --check
python scripts/gen_current_verified_claims.py --check
python scripts/compile_v2_spec.py --check
python scripts/check_generated.py
# The clean-checkout V2 checker must run on the committed final tree. Normal PR
# Backend CI performs that check after this one-shot has committed and pushed.
PYTHONDONTWRITEBYTECODE=1 python scripts/check_v15_public_readiness_artifacts.py
python scripts/check_public_claim_freshness.py
python scripts/check_reviewer_truth_boundaries.py
pytest -q tests/prod/test_public_observer_open_download_transcript_capture.py

cd "$ROOT"

if git grep -n -E 'nlnet_first_round_disposition|safe_to_close_before_nlnet_first_round_with_current_repo_evidence|safe_to_reduce_before_nlnet_first_round|keep_open_and_frame_as_mainnet_readiness_hardening' -- \
  Weall-Protocol/scripts \
  Weall-Protocol/tests \
  Weall-Protocol/generated \
  Weall-Protocol/docs/CURRENT_VERIFIED_CLAIMS.md \
  Weall-Protocol/docs/TRUTH_BOUNDARY.md \
  Weall-Protocol/docs/reviewer/DIRECT_MESSAGE_TRANSACTION_QUARANTINE.md
then
  echo "legacy funding-review schema wording remains in active surfaces" >&2
  exit 1
fi

# Historical audit metadata is intentionally preserved.
git status --short
git diff --check

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git add -A
git commit -m "Neutralize current claim evidence schema terminology"
git push origin HEAD:claim-evidence-schema-neutralization
