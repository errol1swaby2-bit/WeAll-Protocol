# External Cross-Machine Replay Transcript

This runbook prepares `AUD-618-P1-003`. It does not close the blocker by itself.

The blocker closes only after a real external transcript package proves the same
commit and generated vectors replay to identical state roots and tx-index hashes
on two external or physical machines. A founder-local run, a single-machine run,
or a copied local artifact must remain classified as local rehearsal evidence.

## Evidence required

Capture the following from each external machine:

1. Machine/operator metadata and whether the machine is independent, external, or physically separate.
2. Repository URL, branch, commit, and clean `git status --short` before local evidence files are written.
3. Python version and operating system.
4. `generated/state_root_vectors_v1_5.json` SHA-256.
5. `generated/tx_index.json` SHA-256.
6. `scripts/replay_consistency_audit.py --json` output.
7. `scripts/rehearse_fresh_node_replay_sync_v1_5.py --json` output.
8. `scripts/check_tx_canon_artifacts.py` output.
9. `generated/tx_lifecycle_assurance_v1_5.json` SHA-256, covering all 236 canonical transaction lifecycle vectors.
10. `scripts/a04_cross_machine_determinism_probe_v1_5.py --json` output proving lifecycle-render equality under `PYTHONHASHSEED=0,1,7,42` and insertion-order-invariant canonical projection.
11. Seeded determinism regressions under `PYTHONHASHSEED=1,7,31337`, including scheduler/order permutation, helper serial equivalence, failed-receipt replay, and the all-236 lifecycle matrix.
12. DB-backed and ordinary fresh-node replay/state-sync evidence.
13. A local `LOCAL_MACHINE_REPLAY_EVIDENCE.json` packet and manifest.
14. Operator signature or controlled external attestation.

The final aggregate transcript must include at least two machine packets and must
prove:

- same commit;
- same generated vectors;
- identical replay state roots;
- identical fresh-node replay roots;
- identical tx-index hash;
- explicit public beta/mainnet/public validator non-claims;
- identical all-236 lifecycle manifest and live lifecycle digests;
- identical broad lifecycle projection digest, including reversed mapping-insertion projection;
- identical seeded lifecycle regeneration across the required hash seeds;
- passing scheduler/order-permutation, helper-equivalence, failed-receipt, DB-backed replay, and fresh-node state-sync gates.

## Local packet capture command

Run this command separately on each external machine from a clean checkout:

```bash
cd WeAll-Protocol
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock
pip install -e .

bash scripts/capture_external_cross_machine_replay_transcript_v1_5.sh \
  --machine-id <external-machine-id> \
  --operator-id <external-operator-id> \
  --out-dir docs/proofs/external-cross-machine-replay/<yyyy-mm-dd>/<operator-or-host>/<machine-id>/
```

The script writes one machine packet only. It does not close `AUD-618-P1-003`.

## Aggregate transcript construction and validation

After at least two packets are collected, build the aggregate transcript with:

```bash
python scripts/build_external_cross_machine_replay_transcript_v1_5.py \
  --packet <machine-a>/LOCAL_MACHINE_REPLAY_EVIDENCE.json \
  --packet <machine-b>/LOCAL_MACHINE_REPLAY_EVIDENCE.json \
  --machine-isolation two_physical_machines \
  --operator-attestation external_replay_operator_signed \
  --operator-signature '<controlled external signature/reference>' \
  --out docs/proofs/external-cross-machine-replay/<yyyy-mm-dd>/<operator-or-host>/TRANSCRIPT.json
```

The builder independently rejects mismatched commit/tree, lifecycle/vector hashes,
per-block replay digests, DB-backed replay digests, fresh-node replay digests,
hash-seed matrices, or missing broad determinism gates.

Then run:

```bash
cd WeAll-Protocol
source .venv/bin/activate

PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py \
  --kind external_cross_machine_replay_transcript \
  --path docs/proofs/external-cross-machine-replay/<yyyy-mm-dd>/<operator-or-host>/TRANSCRIPT.json
```

Strict release validation is stronger and must be used before public beta:

```bash
PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py \
  --kind external_cross_machine_replay_transcript \
  --strict-release \
  --path docs/proofs/external-cross-machine-replay/<yyyy-mm-dd>/<operator-or-host>/TRANSCRIPT.json
```

## Closure rule

Keep `AUD-618-P1-003` open until the completed aggregate transcript exists,
passes validation, and is reviewed as external evidence. Do not set
`public_beta_ready=true` from this script, this template, or a founder-local run.
