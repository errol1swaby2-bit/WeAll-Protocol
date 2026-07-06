# Real storage/IPFS operator transcript — 2026-07-05 template

Status: TEMPLATE ONLY — not completed external evidence. This directory prepares the evidence package for
`AUD-618-P1-004`; it does not close the blocker and does not claim public beta,
mainnet, public storage-market, or public decentralized media durability
readiness.

A valid blocker-closing package must come from real IPFS/Kubo daemons and real
operator machines, not local simulations or deterministic scaffolds. Prefer an
independent storage operator. At minimum, the aggregate transcript must include:

- exact branch and commit;
- three distinct operator IDs;
- three distinct machine IDs;
- three distinct IPFS peer IDs;
- daemon versions from the live `/api/v0/version` endpoint;
- the payload SHA-256 and resulting CID;
- publish/add proof from the origin machine;
- pin proof for every operator machine;
- retrieval proof from non-origin machines;
- fresh-node retrieval proof;
- wrong-CID rejection proof;
- corrupt-content rejection proof;
- revalidation evidence;
- origin failure or origin-unavailable retrieval evidence;
- operator signatures or controlled external attestation;
- claim boundaries showing public beta/storage-market/durability remain false
  until release review accepts the evidence.

Recommended capture command per storage operator machine:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

bash scripts/capture_real_storage_ipfs_operator_transcript_v1_5.sh \
  --operator-id <operator-id> \
  --machine-id <machine-id> \
  --api-base http://127.0.0.1:5001 \
  --out-dir ~/weall-storage-ipfs-aud-618-p1-004/<machine-id>
```

After at least three local packets are captured, combine them into
`TRANSCRIPT.json` using `TRANSCRIPT_TEMPLATE.json` as the aggregate shape and
validate with:

```bash
PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py \
  --kind storage_ipfs_operator_transcript \
  --strict-release \
  --path docs/proofs/real-storage-ipfs-operator/2026-07-05/<operator>/TRANSCRIPT.json
```
