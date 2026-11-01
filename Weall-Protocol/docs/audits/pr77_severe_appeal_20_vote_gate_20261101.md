# PR77 severe-appeal 20/25 gate: authorization remains BLOCKED

The existing manual DISPUTE_APPEAL path selected a fresh 25+5 panel but
assigned ordinary BFT quorum (17/25) as the decision threshold.
For explicitly classified severe/critical/S4 account sanctions in
constitutional-clock mode this patch requires 20 approvals for a single
appeal decision. It checks a second-round 25+5 panel, original 25+5
panel, 60 distinct normalized juror identities, and exact assignment
before accepting a severe appeal vote. If fewer than 25 active appeal
jurors remain the result cannot be finalized.

This is a structural guard, not an authenticated automatic appeal.
The existing MANUAL appeal operation is used only as a test fixture.
DISPUTE_OPEN does not yet bind a canonical severe classification, the
source of ballot records is not independently verified, and no fresh
automatic appeal is created. Existing severe final receipt and
ACCOUNT_BAN execution guards remain fail-closed. Legacy-clock and
ordinary content-dispute quorum behavior are left unchanged.

This change needs V2 semantic, replay, and release reviews before
consensus activation. Do not merge or launch PR77 from these tests.

## Verified GitHub evidence — November 1, 2026

- Runtime/test implementation: `54b97d386b43198f3934e64ba3add19d28ce69f8`.
- New dedicated severe-appeal regression run `41327959034`: **PASS,
  64 focused tests**. Follow-up run `41327995131`: **PASS**.
- Exact V1.5 artifact/format refresh workflow run `41327989701`:
  **PASS — 99 focused tests**, Ruff lint/format, generated artifact
  currentness, release hygiene.
- Resulting bounded bot commit
  `57aeb1cb3140ba761cd50f1d747bb5ed8eb329e9` updated six
  source-bound V1.5 artifacts and formatted the scoped dispute source
  and new regression test. No semantic attestation was approved.
- V1.5 public-beta readiness still reports **8 open blockers**.

### Authorization and replay caveat

A second manual appeal panel being structurally disjoint is not evidence
that the constitutionally required **automatic** appeal was issued, and
stored votes/commitments alone are not independently authenticated proof.
This patch changes active severe-appeal quorum behavior and therefore
requires independent semantic and historical replay adjudication before
network activation. Neither `DISPUTE_OPEN` canonical classification nor
`ACCOUNT_BAN` producer authorization is implemented here.

PR #77 remains Draft. The known stale V2 semantic review is
deliberately unchanged; do not merge or launch based on focused tests.
