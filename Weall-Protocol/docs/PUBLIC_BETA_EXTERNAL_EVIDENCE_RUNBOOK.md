# WeAll v1.5 Public-Beta External Evidence Runbook

This runbook is a release-gate document. It does **not** claim public beta,
mainnet, public validator, live economics, public storage market, automatic
protocol upgrades, or production helper execution readiness.

The current repository may claim only:

> controlled multi-node private testnet candidate, with public-beta blocker
> evidence gates present.

## Required transcripts before any public-beta claim

### 1. Public validator operator transcript

Run at least four independently configured validator nodes operated as separate
operators or isolated machines. The transcript must include:

- `operator_ids`, `node_ids`, and `machine_ids` with at least four unique values.
- Chain identity and manifest evidence.
- At least six proposal/vote/commit rounds.
- Threshold evidence.
- Matching state roots across validators.
- Partition/rejoin evidence.
- Proof that a minority partition cannot finalize.
- Equivocation rejection.
- Observer vote rejection.
- Fresh node catch-up.
- Restart/replay recovery.
- Operator signatures or controlled references.
- A stable transcript digest.

Validate it with:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate
PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py \
  --kind public_validator_operator_transcript \
  --path /path/to/public-validator-transcript.json
```

### 2. Storage/IPFS external operator transcript

Run a real IPFS daemon/operator topology with at least three operators and peer
IDs. The transcript must include:

- operator/machine/IPFS peer identities.
- CID and replication factor.
- origin failure and retrieval from a non-origin machine.
- fresh node retrieval.
- wrong-CID rejection.
- corrupt-content rejection by hash.
- revalidation evidence.
- operator signatures or controlled references.
- a stable transcript digest.

Validate it with:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate
PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py \
  --kind storage_ipfs_operator_transcript \
  --path /path/to/storage-ipfs-transcript.json
```

### 3. Legal/compliance attestation

Before public token, economics, governance, or public launch claims, attach a
controlled counsel/compliance attestation that identifies the review scope,
approved claims, restricted claims, and launch-matrix boundaries.

Validate it with:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate
PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py \
  --kind legal_compliance_attestation \
  --path /path/to/legal-compliance-attestation.json
```

## Required release checks

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate
PYTHONPATH=src:scripts python scripts/gen_external_operator_transcript_requirements_v1_5.py --check
PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check
PYTHONPATH=src:scripts python scripts/check_v15_public_readiness_artifacts.py --require-git-tracked
PYTHONPATH=src:scripts python scripts/run_controlled_testnet_go_gate_v1_5.py --run-gates --require-git-tracked
```

Then run the root clean-clone gate:

```bash
cd ~/WeAll-Protocol
scripts/run_clean_clone_go_gate_v1_5.sh
```

## Forbidden claims until evidence is attached and release-reviewed

- Public beta ready.
- Mainnet ready.
- Public validators enabled.
- Public multi-validator BFT readiness is not claimed; only externally attested transcript evidence may be attached for later release review.
- Public storage provider market ready.
- Public decentralized media durability ready.
- Live economics or transfer readiness.
- Production helper execution ready.
- Legal/compliance ready.
