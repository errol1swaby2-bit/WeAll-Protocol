# Independent controlled validator/operator transcript — AUD-618-P0-001

Status: TEMPLATE ONLY. This directory prepares the evidence package for
`AUD-618-P0-001`; it does not close the blocker and does not claim public beta,
public validator, public multi-validator BFT, or mainnet readiness.

The blocker closes only when an invited or independent operator runs a fresh
checkout from the documented commit and attaches a strict-release validated
aggregate transcript proving:

- exact branch and commit;
- fresh clone and dependency install;
- node registration;
- node-operator readiness;
- validator-candidate path;
- readiness receipt;
- controlled activation rehearsal;
- observer vote/bypass rejection;
- restart remains fail-closed unless chain state permits signing;
- matching state roots across the controlled validator rehearsal;
- partition/rejoin, minority partition, equivocation rejection, fresh-node
  catchup, and restart replay evidence;
- operator signatures or controlled external attestation;
- all public beta/mainnet/public-BFT/live-economics/automatic-upgrade/helper
  claims remain false.

## Per-machine packet

On each invited operator machine:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

bash scripts/capture_independent_controlled_validator_operator_transcript_v1_5.sh \
  --operator-id <operator-id> \
  --machine-id <machine-id> \
  --node-id <node-id> \
  --out-dir ~/weall-validator-operator-aud-618-p0-001/<machine-id>
```

The script records a local packet. A packet is not closure. It creates:

- `LOCAL_VALIDATOR_OPERATOR_EVIDENCE.json`;
- `commands.txt`;
- `CLAIM_BOUNDARIES.md`;
- `manifest.json`.

## Aggregate transcript

After enough external/operator packets exist, create `TRANSCRIPT.json` from
`TRANSCRIPT_TEMPLATE.json` and validate:

```bash
PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py \
  --kind public_validator_operator_transcript \
  --strict-release \
  --path docs/proofs/independent-controlled-validator-operator/2026-07-05/<operator>/TRANSCRIPT.json
```

Strict-release validation rejects placeholder identities/signatures, scaffold
runs, missing external attestation, and missing controlled-validator safety proof.
