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
3. Open **Personal Node** and inspect node, seed, peer, chain identity, and safe command guidance.
4. Create or restore an account from **Login** only if you intend to submit signed test actions.
5. Open **Account Verification** and confirm the UI explains eligibility without claiming real-world identity certainty.
6. Open **Account** and compare the account/profile surface against [Account and public profile readiness](ACCOUNT_PROFILE_READINESS.md).
7. Browse **Feed**, **Groups**, **Decisions**, **Reports**, and **Review Center**. Compare Feed/Create Post/Thread behavior against [Public social flow readiness](PUBLIC_SOCIAL_FLOW_READINESS.md).
8. Open **Decisions** and compare the queue/detail/create/vote flow against [Governance rendered journey readiness](GOVERNANCE_RENDERED_JOURNEY.md).
9. Open a public group and compare the directory/detail/create flow against [Group flow readiness](GROUP_FLOW_READINESS.md).
10. Submit only a low-risk test action if the account state permits it.
11. Open **Transactions** and verify the action is not called finalized until backend status shows inclusion/finality.

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
- Personal Node screenshot;
- Decisions queue/detail/timeline screenshot;
- Transactions page screenshot after any submitted action or honest fail-closed result;
- any errors with exact command/output.

## Stop conditions

Stop and file a bug rather than continuing if:

- the frontend implies public beta, mainnet, public BFT, live economics, automatic upgrade, production helper, legal approval, or public storage readiness;
- the Home page hides node/chain/authority status from a normal tester;
- a mutation reports final success without transaction lifecycle evidence;
- private protocol-native messaging or private group read visibility appears;
- browser state or a copied command appears to grant validator/operator/protocol authority.

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
