# WeAll Protocol r20 Comprehensive Remediation

Exact audited base: `69cce170829ded30ebb030669f05c387df6a3ddb`  
Audited tree: `6badceb25a9d209ac54b6066a2e4a4844abe74ab`  
Remediation branch: `audit-r20-comprehensive-remediation`

This remediation is intentionally **not applied directly to `main`**. The branch is rooted at the exact audited commit and uses two fail-fast transformation drivers. Every replacement is AST- or exact-fragment-bound; unexpected source drift aborts the run.

## Safety rules

1. No source mutation is accepted unless the branch descends from the audited base.
2. Ambiguous authority/constitutional semantics fail closed rather than inventing new permissions.
3. Generated artifacts and the locked Python environment are revalidated after transformation.
4. Whole-tree Ruff and the full backend pytest suite must pass before the exact repaired candidate is pushed.
5. The workflow candidate commit uses `[r20-remediation-applied]` to prevent self-trigger loops.
6. `P2-CLAIM-001` includes an external GitHub repository-description metadata action, because repository description is not a source-tree file.

## Coverage

The two drivers cover all **44** confirmed findings recorded in `WeAll_Audit_Findings_Ledger_r20.md`:

- Driver A: 30 findings covering peer identity, account/security, persistence, consensus, governance, sync, SYSTEM lineage, economics, helper claims, docs/maintenance, and CI.
- Driver B: 14 remaining findings covering repository claims, Content, Dispute, Groups/Treasury, Roles, Storage, and Reputation.

The workflow refuses to publish a successful remediation result unless the union of the two driver manifests is exactly the 44-finding r20 set.

## External metadata action

After source validation succeeds, update the GitHub repository description so it no longer makes an unconditional canon-conformance claim:

```bash
gh repo edit errol1swaby2-bit/WeAll-Protocol \
  --description 'WeAll Protocol — implementation under independent technical review; canonical conformance is verified per exact release evidence.'
```

This action should be performed only after the branch validation is green and before claiming `P2-CLAIM-001` fully closed.

## Validation gate

The remediation workflow runs the locked dependency install, formats/checks the complete tree with Ruff, refreshes and validates canon/generated artifacts, writes a combined coverage manifest, creates an exact local candidate commit, revalidates that exact candidate including the complete backend pytest suite and clean-worktree checks, and only then pushes the repaired tree back to the remediation branch.
