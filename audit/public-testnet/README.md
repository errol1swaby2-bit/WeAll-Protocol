# Public testnet audit workspace

Frozen implementation baseline: [6d3d692](https://github.com/errol1swaby2-bit/WeAll-Protocol/commit/6d3d69234415d294936d99e819367cff589ced3d).

- [Living full audit report](FULL_REPORT.md) — all recovered narratives, registers, source re-audit evidence and latest checkpoint.
- [Immutable master evidence ZIP](evidence/WeAll_Master_Audit_Reaudit_Through_R1A.zip) — exact prior archive, 71 files, SHA-256 56a4b7b322edceb7810dc7655a94a7f6487bf50b3cd72eb93f59ac25cb84c587.
- [R1B diagnostic probes](diagnostics/test_r1b_helper_hierarchy.py) — real runtime imports with explicit locally accepted fixtures.
- [Diagnostic GitHub Actions workflow](../../.github/workflows/public-testnet-audit-diagnostic.yml) — observation only; no required checks, deployment, protocol changes or enforcement.

## Working contract

Keep the pinned baseline and original evidence immutable. After each audit increment, update FULL_REPORT.md with exact tested SHA, source locations, commands, outcomes, artifact links, fixture limitations, remaining production reachability and finding status; retain prior results. Reconcile results before planning each remediation increment. A correction requires separate explicit authorization before it changes runtime or protocol files. Never interpret a successful diagnostic job as a passed security audit. Existing CI is unchanged. The R1A patch inside the archive is evidence only, not applied. No finding is closed by this setup.

## Combined backend + frontend audit (PR #97)

This PR now preserves **two distinct audit tracks** on the same frozen baseline. Start with the [combined audit index](COMBINED_AUDIT_INDEX.md).

- **Backend/protocol:** [existing living master report](FULL_REPORT.md) and immutable 71-member evidence archive remain in place; TN-001–TN-081 (21 provisional P0, 60 provisional P1), plus eight separately tracked candidates.
- **Frontend/product:** [full FE-001–FE-064 ledger](frontend/FRONTEND_MASTER_LEDGER_PHASES1-12.md), [64-item index](frontend/FINDINGS_INDEX_FE001-FE064.md), [233-case acceptance register](frontend/ACCEPTANCE_233_CASES.csv), [journey matrix](frontend/JOURNEY_COMPLETENESS_MATRIX.md), and [browser test handoff](frontend/PRIORITIZED_ACCEPTANCE_HANDOFF.md).

The original 82-member frontend ZIP is preserved externally and documented by SHA-256 in the combined index; the PR contains its full master ledger and test register as Git-reviewable text, **not the original ZIP binary**. Existing backend evidence and current production/runtime code were not changed by the documentation addition. Neither track has any formal finding closure or public-testnet authorization.
