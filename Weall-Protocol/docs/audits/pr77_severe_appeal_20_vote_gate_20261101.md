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
