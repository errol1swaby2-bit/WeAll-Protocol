# Real storage/IPFS operator transcript for AUD-618-P1-004

`AUD-618-P1-004` remains open until a real IPFS/storage operator transcript is
attached and reviewed. Local simulations, deterministic storage scaffolds, and a
single founder-run daemon are not enough to close the blocker.

This transcript exists to prove the storage durability claims that are still
forbidden before public beta:

- a real payload is published to a real IPFS/Kubo daemon;
- the payload is pinned or retrievable across at least three distinct operator
  machines;
- retrieval works from a non-origin machine;
- a fresh node can retrieve the payload;
- wrong-CID retrieval fails cleanly;
- corrupt content is rejected by content-addressed verification;
- revalidation is exercised;
- origin failure or origin-unavailable retrieval is captured;
- operator signatures or controlled external attestation are attached.

## Local packet capture per operator

Run on each storage operator machine with a live IPFS/Kubo API:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

bash scripts/capture_real_storage_ipfs_operator_transcript_v1_5.sh \
  --operator-id <operator-id> \
  --machine-id <machine-id> \
  --api-base http://127.0.0.1:5001 \
  --out-dir ~/weall-storage-ipfs-aud-618-p1-004/<machine-id>
```

The script records a **local packet** only. A local packet is not a blocker
closure. It produces:

- `LOCAL_STORAGE_IPFS_EVIDENCE.json`;
- IPFS version/id/add/pin proof API outputs;
- original, retrieved, and corrupt negative-control payload files;
- wrong-CID rejection logs;
- `manifest.json`;
- `CLAIM_BOUNDARIES.md`.

## Aggregate transcript

After at least three real operator/machine packets exist, create an aggregate
`TRANSCRIPT.json` from
`docs/proofs/real-storage-ipfs-operator/2026-07-05/TRANSCRIPT_TEMPLATE.json`.
Then validate:

```bash
PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py \
  --kind storage_ipfs_operator_transcript \
  --strict-release \
  --path docs/proofs/real-storage-ipfs-operator/2026-07-05/<operator>/TRANSCRIPT.json
```

Strict-release validation rejects placeholder identities, sample signatures,
`sample_transcript_only=true`, missing external attestation, and missing real
`real_daemon_topology=true` evidence.

## Required non-claims

Even after the capture tooling exists, do not claim:

- public beta readiness;
- mainnet readiness;
- public storage-market readiness;
- public decentralized media durability;
- live economics;
- automatic protocol upgrades;
- production helper execution;
- legal/compliance approval.

Allowed statement before real external evidence is attached:

```text
Storage/IPFS transcript capture is prepared, but AUD-618-P1-004 remains open until real daemon/operator evidence is attached and reviewed.
```
