# Operator incident response runbook

This runbook is for bounded public observer / controlled testnet operators. It is evidence-first and fail-closed.

It does not authorize public beta, public validator, mainnet, live economics, automatic software upgrades, production helper execution, public storage-market operation, or legal/compliance approval.

## Incident classes

| Class | Examples | First action |
| --- | --- | --- |
| Chain identity | wrong `chain_id`, genesis hash mismatch, tx index mismatch, protocol profile mismatch | stop mutation tests and capture identity outputs |
| Sync/finality | height stuck, finalized height unknown/stale, state root mismatch | capture chain head and replay evidence |
| Peer/seed | no peers, seed registry missing, no direct P2P URI, stale validator endpoints | capture seed/validator/NAT outputs |
| Mempool/tx | backlog, observer queue stuck, upstream accepted but local sync missing | capture mempool, observer-edge, and tx status outputs |
| Authority | validator-candidate but not effective, helper gated, storage opted-in but not proven | capture operator status; do not flip local flags |
| Blocker boundary | economics, helper production, protocol upgrade, storage market, legal gates visible | keep blocked; link to blocker report evidence |

## Evidence commands

From the backend machine:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
source .venv/bin/activate

curl -fsS http://127.0.0.1:8000/v1/status | python -m json.tool
curl -fsS http://127.0.0.1:8000/readyz | python -m json.tool
curl -fsS http://127.0.0.1:8000/v1/chain/head | python -m json.tool
curl -fsS http://127.0.0.1:8000/v1/status/mempool | python -m json.tool
curl -fsS http://127.0.0.1:8000/v1/nodes/seeds | python -m json.tool
curl -fsS http://127.0.0.1:8000/v1/nodes/validators | python -m json.tool
curl -fsS http://127.0.0.1:8000/v1/status/operator | python -m json.tool
PYTHONPATH=src python scripts/build_operator_incident_report.py --help
```

If `build_operator_incident_report.py` supports a configured output path in the current branch, use it to package the evidence. If it only prints help or lacks the required arguments, paste the command outputs into the incident packet manually.

## Stop rules

Stop immediately if any UI, script, or operator note implies that:

- a local script grants validator authority;
- an environment flag bypasses protocol state;
- node switching fixes chain identity mismatch;
- mempool acceptance means final confirmation;
- local storage preference grants storage-market authority;
- helper production execution is enabled;
- protocol upgrades are automatically applied;
- public beta/mainnet/public BFT/legal approval has been reached.

## Recovery order

1. Capture evidence first.
2. Classify the incident.
3. Check whether it is local environment, protocol state, external transcript, or future hardening.
4. Run only documented read-only diagnostics until classification is clear.
5. Use recovery runbooks only when they do not bypass authority boundaries.
6. Re-run release and readiness checks after any patch.

## External evidence still required

This runbook helps collect evidence, but it does not close external gates by itself. The remaining public-beta blockers still require independent validator/operator, legal/compliance, executable upgrade hardening, external replay, real IPFS/storage, helper topology, and external public observer transcript evidence.
