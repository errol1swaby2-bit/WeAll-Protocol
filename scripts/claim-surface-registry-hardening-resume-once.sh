#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

cd "${GITHUB_WORKSPACE}"

# Self-delete this resume helper before source-sensitive generation.
git rm -f scripts/claim-surface-registry-hardening-resume-once.sh

python - <<'PY'
from pathlib import Path

path = Path("scripts/claim-surface-registry-hardening-once.sh")
text = path.read_text(encoding="utf-8")
text = text.replace(
    '    "reviewer-facing test references": "verification-facing test references",',
    '    "reviewer-facing batch test references": "verification-facing batch test references",\n'
    '    "reviewer-facing test references": "verification-facing test references",',
)
old = '''python scripts/check_generated.py
PYTHONPATH=src python scripts/compile_v2_spec.py --check
python scripts/check_v2_spec_clean_checkout.py
PYTHONDONTWRITEBYTECODE=1 python scripts/check_v15_public_readiness_artifacts.py
python scripts/check_public_claim_freshness.py
python scripts/gen_current_verified_claims.py --check
pytest -q tests/test_current_document_registry.py tests/test_release_docs_truth_sync.py tests/test_reviewer_language_cleanup.py

git diff --check

git add -A
git status --short

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git commit -m "Harden current claim surface registry"
git push origin HEAD:claim-surface-registry-hardening
'''
new = '''python scripts/check_generated.py
PYTHONPATH=src python scripts/compile_v2_spec.py --check
PYTHONDONTWRITEBYTECODE=1 python scripts/check_v15_public_readiness_artifacts.py
python scripts/check_public_claim_freshness.py
python scripts/gen_current_verified_claims.py --check
pytest -q tests/test_current_document_registry.py tests/test_release_docs_truth_sync.py tests/test_reviewer_language_cleanup.py

git diff --check

git add -A
git status --short

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git commit -m "Harden current claim surface registry"

# The clean-checkout validator compares generated derivatives to committed source.
# Commit locally first, validate that exact tree, then publish it.
python scripts/check_v2_spec_clean_checkout.py

git push origin HEAD:claim-surface-registry-hardening
'''
if old not in text:
    raise SystemExit("expected validation tail not found in one-shot helper")
path.write_text(text.replace(old, new), encoding="utf-8")
PY

bash scripts/claim-surface-registry-hardening-once.sh
