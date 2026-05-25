# Batch 408 — Async PoH Reviewability Truth

## Problem

The observer/frontend path could make an async PoH case visible on both observer and genesis after only `POH_ASYNC_REQUEST_OPEN` committed. That state is useful, but it is not a submitted verification review. A reviewer queue has nothing to surface until evidence is declared, evidence is bound, and a juror assignment is scheduled/applied.

## Truth model

Async verification progress is now treated as separate states:

1. `POH_ASYNC_REQUEST_OPEN` — case shell opened.
2. `POH_ASYNC_EVIDENCE_DECLARE` — evidence commitment exists.
3. `POH_ASYNC_EVIDENCE_BIND` — evidence is bound to the case.
4. Reviewable case — evidence declared and bound.
5. Assigned case — one or more jurors are assigned.
6. Reviewed/finalized — reviews reach deterministic threshold and system finalization applies.

The UI must not report “evidence submitted” from request-open alone.

## API diagnostics

Async case responses expose:

- `evidence_declared`
- `evidence_bound`
- `reviewable`
- `assigned`
- `missing_steps`
- `reviewer_queue_reason`

Juror-case list responses expose diagnostics explaining an empty queue, including `cases_exist_but_not_reviewable` and `reviewable_cases_not_assigned`.

## Observer reconcile posture

The local reconcile loop backs off repeated probes for accepted but not yet confirmed rows. This prevents the operator helper from hammering the observer API into rate limits while genesis/observer state catches up.

## Acceptance

A local two-node run where only `POH_ASYNC_REQUEST_OPEN` committed should now be described as:

> Case opened, evidence not yet declared/bound, not reviewable, no assigned reviewer queue entry yet.

A complete async submission must commit at least request-open, evidence-declare, and evidence-bind before the frontend reports reviewable evidence submission.
