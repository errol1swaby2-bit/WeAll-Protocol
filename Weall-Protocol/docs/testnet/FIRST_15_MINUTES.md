# First 15 minutes on the bounded public observer / controlled testnet

This guide is for a normal tester opening WeAll for the first time after a clean clone or a fresh browser session.

The goal is not to prove public beta, mainnet, public multi-validator BFT, live economics, automatic upgrade, production helper, legal, public validator, or public storage-market readiness. The goal is to help a tester safely boot, connect, understand their role, use public civic flows, and report evidence without founder explanation.

## What you should see first

Open the frontend and start on **Home**. The first screen should show:

- the current node / API target;
- `chain_id`;
- block height;
- finalized height when the node exposes it;
- current authority level;
- active account or clear "no account selected" state;
- safe next-step cards for account, verification, public civic browsing, and transaction status.

If any of these are missing, capture a screenshot and file it as a first-run UX issue.

## Role boundaries

| Role | What it can do during this bounded testnet | What it cannot claim |
| --- | --- | --- |
| Observer | Read, sync, inspect, and forward where configured. | Cannot validate or finalize blocks. |
| User | Submit signed account actions permitted by account standing and protocol rules. | Local keys or UI state do not create protocol authority. |
| Node operator | Run local infrastructure and read diagnostics. | Scripts do not grant authority by themselves. |
| Validator candidate | Record controlled rehearsal readiness. | Signing remains fail-closed until protocol state authorizes it. |
| Validator | Only active in bounded controlled rehearsal when protocol state permits it. | Public multi-validator BFT readiness remains unclaimed. |

Frontend buttons, browser state, seed hints, local scripts, node switching, and environment flags must never be treated as protocol authority.

## Clean clone and boot

From a fresh checkout:

```bash
cd ~/WeAll-Protocol/Weall-Protocol
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh
```

Expected posture:

```text
v1.5 public-readiness artifacts are present, fresh, and release-safe
observer/node boot starts without enabling live economics, public validator signing, automatic upgrades, or production helper execution
```

If the backend does not start, capture the terminal output and do not continue to frontend mutation tests until the node failure is understood.

## Frontend first-run path

From the frontend:

1. Open **Home**.
2. Confirm the status cards show current node, `chain_id`, height, finalized height or "unknown", account state, and authority level.
3. Open **Personal Node** and inspect node, seed, peer, chain identity, safe command guidance, operator mode matrix, and incident-response packet guidance. Compare it against [Node/operator journey and incident response readiness](NODE_OPERATOR_JOURNEY_AND_INCIDENT_RESPONSE.md).
4. Create or restore an account from **Login** only if you intend to submit signed test actions.
5. Open **Account Verification** and confirm the UI explains eligibility without claiming real-world identity certainty.
6. Open **Account** and compare the account/profile surface against [Account and public profile readiness](ACCOUNT_PROFILE_READINESS.md).
7. Browse **Feed**, **Groups**, **Decisions**, **Reports**, and **Review Center**. Compare Feed/Create Post/Thread behavior against [Public social flow readiness](PUBLIC_SOCIAL_FLOW_READINESS.md).
8. Open **Decisions** and compare the queue/detail/create/vote flow against [Governance rendered journey readiness](GOVERNANCE_RENDERED_JOURNEY.md).
9. Open a public group and compare the directory/detail/create flow against [Group flow readiness](GROUP_FLOW_READINESS.md).
10. Open **Reports** and **Review Center** and compare dispute queue/detail/review behavior against [Dispute and review rendered journey readiness](DISPUTE_REVIEW_RENDERED_JOURNEY.md).
11. Submit only a low-risk test action if the account state permits it.
12. Open **Transactions** and compare the rendered timeline against [Transaction lifecycle rendered evidence](TRANSACTION_LIFECYCLE_RENDERED_EVIDENCE.md). Verify the action is not called finalized until backend status shows inclusion/finality or a terminal rejected state.

The user journey should be understandable without opening advanced developer tools.

## Transaction wording rules

Do not treat any of these as final confirmation:

- browser button clicked;
- local validation started;
- local request returned;
- mempool accepted;
- queued or pending status;
- forwarded or gossiped status.

A transaction is only final when the backend reports inclusion/finalization or a specific rejected terminal state. If the UI says "posted", "confirmed", "final", or "complete" before that point, file a blocker against transaction lifecycle wording.

## Public-only civic loop

During this bounded testnet, protocol-native social, group, governance, moderation, dispute, reputation, and operator activity is public-readable. Group membership may gate posting, commenting, voting, moderation, invitation, or administration, but it must not gate read visibility. Social actions should be treated as signed submissions until the transaction lifecycle shows confirmation/rejection or the affected read model visibly reconciles.

The first-run reviewer loop is:

```text
Home → Account → Verification → Feed → Groups → Decisions → Reports → Review Center → Activity → Transactions → Personal Node
```

## Evidence to capture

For an external observer transcript, capture:

- machine and OS;
- branch and commit;
- dependency install output;
- trust root / seed registry verification output;
- observer boot command and result;
- chain identity check;
- state sync check;
- frontend load screenshot;
- Home status cards screenshot;
- Personal Node screenshot, including mode matrix, safe next action, seed/peer status, validator endpoint freshness, mempool/backlog status, and incident timeline;
- Decisions queue/detail/timeline screenshot;
- Reports queue/detail/review-timeline screenshot;
- Review Center lane and consent-boundary screenshot;
- Transactions page screenshot after any submitted action or honest fail-closed result, including the lifecycle timeline and tx id when available;
- any errors with exact command/output.

## Stop conditions

Stop and file a bug rather than continuing if:

- the frontend implies public beta, mainnet, public BFT, live economics, automatic upgrade, production helper, legal approval, or public storage readiness;
- the Home or Personal Node page hides node/chain/authority status from a normal tester;
- Personal Node implies that local commands, node switching, or environment flags grant validator/operator authority;
- chain mismatch, stale validator endpoint, missing readyz, or mempool backlog warnings are hidden instead of surfaced as incident evidence;
- a mutation reports final success without transaction lifecycle evidence;
- private protocol-native messaging or private group read visibility appears;
- browser state or a copied command appears to grant validator/operator/protocol authority.


## Upgrade execution boundary

If you see protocol or constitution upgrade records during the first-run journey, treat them as public governance records only. They may show declaration, scheduled activation height, target version, or ignored execution fields, but they do not fetch artifacts, apply software, execute migrations, roll back migrations, restart nodes, or activate economics. See `docs/testnet/UPGRADE_EXECUTION_HARDENING_PLAN.md` for the future hardening plan that keeps `AUD-618-P0-003` open.

## Allowed readiness statement after this journey

If the first-run path works locally but external transcripts are still missing, the strongest allowed claim is:

```text
Ready for controlled internal/public-observer rehearsal candidate, with public beta readiness still blocked by explicit external evidence gates.
```


## 4. Try one public social action

Open the Feed or Create Post page and submit a small public test post.

Expected behavior:

- the action uses public-only wording;
- submission is not labeled final immediately;
- Transactions/backend tx status is the place to inspect confirmation;
- rejected/error states explain what to do next.

See `docs/testnet/PUBLIC_SOCIAL_FLOW_READINESS.md` for the social-flow checklist.

## 6. Inspect the governance rendered journey

Open **Decisions**, a decision detail page, and the create-decision page. Expected behavior:

- the canonical ladder is visible: `draft → poll → revision → validation → voting → closed → tallied → executed → finalized`;
- block height, deadline height, and blocks remaining are labeled as protocol/backend state;
- wall-clock time appears only as an estimate;
- vote choices for multi-option proposals use canonical option IDs;
- protocol/constitution upgrade records are described as record-only and non-activating;
- latest action output points the tester back to Transactions rather than claiming finality.

See `docs/testnet/GOVERNANCE_RENDERED_JOURNEY.md` for the governance-flow checklist.

## 7. Inspect the dispute and review rendered journey

Open **Reports**, a report detail page, **Review Center**, and a report review action route if one is assigned. Expected behavior:

- report records, tallies, appeals, and outcomes are described as public civic state;
- raw PoH/video/government identity evidence is not exposed through broad report pages;
- the lifecycle is understandable: `submission → assignment → acceptance/decline → attendance/check-in → review vote → tally/outcome → appeal window → appeal review if filed → finalization`;
- review, withdrawal, timeout, appeal, and finalization windows are based on backend block height, not browser timers;
- accept, decline, withdraw, Keep Post, Remove Post, and Need More Review are signed transactions;
- no submitted review action is called final until Transactions/read-model reconciliation shows it.

See `docs/testnet/DISPUTE_REVIEW_RENDERED_JOURNEY.md` for the dispute/review checklist.

## 8. Inspect transaction lifecycle rendered evidence

Open **Transactions** after any signed action or honest fail-closed result. Expected behavior:

- submitted, locally accepted, queued/pending, forwarded/gossiped, included in block, finalized/confirmed, rejected, removed from mempool, and unknown/unavailable are visibly distinct;
- mempool acceptance, queueing, and gossip are not labeled final;
- `/v1/tx/status/{tx_id}` is treated as read-only status evidence;
- observer-edge upstream accepted/confirmed is separate from local observer state synced;
- clearing browser history is not described as deleting protocol records.

See `docs/testnet/TRANSACTION_LIFECYCLE_RENDERED_EVIDENCE.md` for the transaction lifecycle checklist.

## 9. Inspect node/operator journey and incident response

Open **Personal Node** after checking Transactions. Expected behavior:

- current mode is separated into observer, node operator, validator-candidate, and validator authority;
- the dashboard shows current backend URL, chain identity, height/finalized height if available, readyz, seed/peer state, validator endpoint freshness, NAT/firewall posture, mempool/backlog symptoms, and blocked helper/economics/storage/upgrade gates;
- safe commands are labeled diagnostic-only, local-only, observer-only, evidence capture, external transcript, or requires protocol state;
- node switching blocks incompatible chain identity, genesis hash, tx index hash, or protocol profile hash;
- incident response guidance tells the tester to capture evidence before recovery;
- no frontend state, copied command, seed hint, or environment flag is described as granting protocol authority.

See `docs/testnet/NODE_OPERATOR_JOURNEY_AND_INCIDENT_RESPONSE.md` and `docs/operators/INCIDENT_RESPONSE.md` for the operator journey checklist.

## External transcript capture

When this journey is run by an external public-observer tester, capture the evidence package described in `docs/testnet/PUBLIC_OBSERVER_OPEN_DOWNLOAD_TRANSCRIPT.md`. The capture package prepares `AUD-628-P1-001`, but it does not close the blocker until the transcript is external, complete, and reviewed.

For the separate external cross-machine replay gate, use `docs/testnet/EXTERNAL_CROSS_MACHINE_REPLAY_TRANSCRIPT.md`. That package prepares `AUD-618-P1-003`, but it does not close the blocker until at least two external/physical machine packets are combined, validated, and reviewed.

## Storage/IPFS external evidence note

Public storage-market and decentralized media durability claims remain forbidden
until `AUD-618-P1-004` is closed by a real daemon/operator transcript. See
[Real storage/IPFS operator transcript](REAL_STORAGE_IPFS_OPERATOR_TRANSCRIPT.md)
for the capture checklist. A first-run tester should not treat local browser
media state, one local IPFS daemon, or a simulated durability rehearsal as public
storage readiness.

## Controlled validator/operator external evidence note

Public validator safety and public multi-validator BFT claims remain forbidden
until `AUD-618-P0-001` is closed by an independent controlled
validator/operator transcript. See
[Independent controlled validator/operator transcript](INDEPENDENT_CONTROLLED_VALIDATOR_OPERATOR_TRANSCRIPT.md)
for the capture checklist. A copied command, environment flag, seed registry hint,
local browser state, or founder-run rehearsal does not grant validator authority
and does not close the blocker.

## Legal/compliance evidence boundary

Before any tester, reviewer, or public update interprets this repository as a
public beta, mainnet, live-economics, public-validator, public-storage, or legal
approval package, read:

```text
docs/testnet/LEGAL_COMPLIANCE_EVIDENCE_PACK.md
docs/legal/COUNSEL_REVIEW_EVIDENCE_PACK.md
```

`AUD-618-P0-002` remains open until a real counsel or controlled external
attestation is attached and passes strict-release validation. Local draft docs and
checked-in templates are preparation only.

## Optional reviewer add-on: production helper topology hardening boundary

For Pass 26 evidence capture, reviewers can open `docs/testnet/PRODUCTION_HELPER_TOPOLOGY_HARDENING_PLAN.md` and confirm that `AUD-618-P1-005` is a future hardening gate, not a current readiness claim. The expected first-run observation is:

- helper production execution remains disabled;
- helper readiness is diagnostic only;
- missing helpers cannot halt block production;
- local scripts and frontend state cannot grant helper authority;
- the future closure package requires serial equivalence, Byzantine rejection, deterministic merge, crash/restart replay, multi-node helper topology, operator policy, and governance/release evidence.

Capture the generated artifact check output:

```bash
PYTHONPATH=src:scripts python scripts/gen_production_helper_topology_hardening_plan_v1_5.py --check
```

## Final go-gate package

Before a tester transcript is treated as release evidence, check `docs/testnet/FINAL_PUBLIC_OBSERVER_CONTROLLED_TESTNET_GO_GATE.md` and run:

```bash
PYTHONPATH=src:scripts python scripts/gen_final_public_observer_controlled_testnet_go_gate_v1_5.py --check
```

A local first-run journey can support controlled rehearsal readiness. It cannot close `AUD-628-P1-001` unless the documented external open-download/state-sync/rendered journey transcript is attached.
