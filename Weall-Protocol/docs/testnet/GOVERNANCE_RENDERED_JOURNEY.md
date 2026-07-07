# Governance rendered journey readiness

This checklist is for bounded public observer / controlled testnet testers reviewing the **Decisions** flow in the frontend.

The goal is not to claim public beta, mainnet, public multi-validator BFT, live economics, automatic software upgrade, production helper execution, legal approval, public validator safety, public storage-market readiness, or complete identity infrastructure. The goal is to make governance understandable and safe to inspect.

## Pages in scope

- `web/src/pages/Proposals.tsx` — decision queue / proposal list.
- `web/src/pages/Proposal.tsx` — proposal detail, voting, timeline, execution state, and latest action evidence.
- `web/src/pages/ProposalCreate.tsx` — proposal creation / signed governance submission.
- `web/src/components/ProcedureTimeline.tsx` — block-height deadline and wall-clock estimate display.
- `web/src/lib/governance.ts` — frontend normalizers for proposal/vote/read-model shape.

## Required rendered story

A normal tester should be able to follow this path without founder explanation:

```text
Home → Decisions → Create decision → Decision detail → Vote / inspect votes → Transactions → Decision detail refresh
```

The UI must make the canonical governance stage ladder visible:

```text
draft → poll → revision → validation → voting → closed → tallied → executed → finalized
```

Stage movement is controlled by backend/protocol state. Browser state, local timers, copied commands, node switching, seed hints, and frontend buttons must not imply protocol authority.

## Proposal list expectations

The decision queue should show:

- total/open/result counts;
- clear empty state;
- stage filters;
- search over id/title/body/creator/stage;
- stage summary by backend state;
- a reminder that block-height deadlines are protocol truth;
- a reminder that transaction lifecycle evidence confirms submissions;
- a reminder that protocol/constitution upgrade records are non-activating.

## Proposal detail expectations

The proposal detail page should show:

- proposal id and creator;
- current stage;
- the canonical stage ladder;
- current procedure block;
- next deadline block;
- blocks remaining;
- wall-clock estimate labeled as display-only;
- why the proposal cannot execute yet, or what execution/finalization record is visible;
- voting window status;
- eligibility status;
- current account vote, if any;
- multi-option ballot choices using canonical option IDs, when present;
- public deliberation comments and version history;
- action transaction types, when the proposal declares actions;
- latest action response plus a link to Transactions.

## Multi-option voting expectations

Multi-option proposals must make clear that:

- option IDs are canonical;
- mutable labels are not the authority;
- abstain remains explicit;
- one signed account has one recorded vote in the displayed voting window;
- submission is not final until the transaction/read model confirms status.

## Execution and upgrade boundary

The UI may display governance action records, including protocol or constitution upgrade declaration/activation records. During this bounded testnet those records remain **record-only**.

The UI must not claim that a proposal or upgrade record:

- auto-applies software;
- fetches artifacts;
- executes migrations;
- rolls back migrations;
- restarts nodes;
- activates economics;
- enables live fees, transfers, staking, rewards, slashing, or markets;
- proves public mainnet or public multi-validator BFT readiness.

For upgrade-related records, the safe wording is:

```text
Protocol and constitution upgrade actions are public, governance-parent-bound records only. They do not fetch artifacts, execute migrations, restart nodes, auto-apply software, or activate economics in this bounded testnet.
```

## Transaction lifecycle expectations

Governance mutation buttons may submit transactions, but the UI must not treat these as final confirmation:

- button clicked;
- local payload constructed;
- HTTP request returned;
- mempool accepted;
- queued/pending;
- forwarded/gossiped;
- optimistic read-model wait started.

A governance action is only confirmed when Transactions or refreshed backend state shows inclusion/finality or a specific terminal rejection.

## Evidence to capture for AUD-628-P1-001

During the external observer rendered journey, capture:

- Decisions queue screenshot;
- Create Decision screenshot;
- proposal detail timeline screenshot;
- multi-option vote screenshot if a sample proposal exists;
- latest action response screenshot after a safe test action or honest fail-closed result;
- Transactions screenshot showing included/finalized/rejected/pending status;
- terminal logs for backend status if the UI fails closed.

## Allowed readiness statement

```text
Governance rendered journey is clearer for controlled internal/public-observer rehearsal. Public beta readiness remains blocked by explicit external evidence gates.
```
