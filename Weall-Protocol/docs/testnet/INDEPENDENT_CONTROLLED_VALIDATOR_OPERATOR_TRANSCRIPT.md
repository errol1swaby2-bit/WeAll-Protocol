# Independent controlled validator/operator transcript for AUD-618-P0-001

`AUD-618-P0-001` remains open until an invited or independent operator attaches a
strict-release validated controlled validator/operator transcript. Local founder
rehearsals, source tests, and capture scaffolds can improve the runbook, but they
cannot close the blocker.

This is a **controlled validator rehearsal** evidence path. It is not public
validator admission, public multi-validator BFT readiness, public beta readiness,
mainnet readiness, or live economics readiness.

## Per-machine capture

Run from a fresh checkout on each invited operator machine:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

bash scripts/capture_independent_controlled_validator_operator_transcript_v1_5.sh \
  --operator-id <operator-id> \
  --machine-id <machine-id> \
  --node-id <node-id> \
  --out-dir ~/weall-validator-operator-aud-618-p0-001/<machine-id>
```

Optional local rehearsal execution may be captured with `--run-local-rehearsal`,
but that still does not close the blocker unless the operator transcript is
external, complete, signed, and strict-release validated.

## Evidence required in the aggregate transcript

The aggregate `TRANSCRIPT.json` must prove:

- exact branch and commit;
- fresh clone and dependency installation;
- node registration;
- node-operator readiness;
- validator-candidate path;
- readiness receipt;
- controlled activation rehearsal;
- observer vote/bypass rejection;
- restart remains fail-closed unless chain state permits signing;
- matching state roots across validator nodes;
- partition/rejoin and minority partition non-finalization;
- equivocation rejection;
- fresh-node catchup;
- restart replay;
- operator signatures or controlled external attestation;
- public beta, mainnet, public validator, public multi-validator BFT, live
  economics, automatic upgrade, helper execution, and legal/compliance claims
  remain false.

Use the template at
`docs/proofs/independent-controlled-validator-operator/2026-07-05/TRANSCRIPT_TEMPLATE.json`.

## Strict validation

```bash
PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py \
  --kind public_validator_operator_transcript \
  --strict-release \
  --path <TRANSCRIPT.json>
```

Strict release mode rejects placeholder identities, sample signatures,
`sample_transcript_only=true`, missing external attestation, missing operator
attestation, and missing controlled-validator safety evidence.

## Required non-claims

Do not claim:

- public beta readiness;
- mainnet readiness;
- public validator safety;
- public multi-validator BFT readiness;
- live economics;
- automatic protocol upgrades;
- production helper execution;
- legal/compliance approval.

Allowed statement before real external evidence is attached:

```text
Independent controlled validator/operator transcript capture is prepared, but AUD-618-P0-001 remains open until external operator evidence is attached, signed, and strict-release validated.
```
