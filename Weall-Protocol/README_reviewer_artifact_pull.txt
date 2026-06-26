Batch 490: observer pulls reviewer artifacts from Genesis

Files:
- batch490_reviewer_artifact_pull.patch: git patch to apply at Weall-Protocol backend repo root.
- apply_batch490_reviewer_artifact_pull.sh: helper script that checks and applies the patch.

Usage from repo root:
  bash apply_batch490_reviewer_artifact_pull.sh /path/to/batch490_reviewer_artifact_pull.patch

Validation:
  PYTHONPATH=src pytest -q \
    tests/test_reviewer_disposable_genesis.py \
    tests/test_reviewer_artifact_pull.py \
    tests/test_reviewer_rehearsal_wrappers.py \
    tests/test_external_observer_bundle.py \
    tests/test_reviewer_public_tx_ingress_security.py
