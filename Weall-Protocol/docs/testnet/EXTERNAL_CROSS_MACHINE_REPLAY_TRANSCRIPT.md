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
9. A local `LOCAL_MACHINE_REPLAY_EVIDENCE.json` packet and manifest.
10. Operator signature or controlled external attestation.

The final aggregate transcript must include at least two machine packets and must
prove:

- same commit;
- same generated vectors;
- identical replay state roots;
- identical fresh-node replay roots;
- identical tx-index hash;
- explicit public beta/mainnet/public validator non-claims.

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

## Aggregate transcript validation

After at least two packets are collected, combine them into the aggregate
`TRANSCRIPT.json` template and run:

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
