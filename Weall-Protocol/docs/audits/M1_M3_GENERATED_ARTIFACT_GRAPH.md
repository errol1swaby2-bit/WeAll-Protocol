# Generated Artifact Dependency Graph

## Deterministic v2 compiler
- Generator: `Weall-Protocol/scripts/compile_v2_spec.py`.
- Check mode: `python scripts/compile_v2_spec.py --check --summary`.
- The current manifest binds 23 input registers and 42 outputs, including the retained PDF, transaction canon derivative, semantic-review bindings, traceability, schemas, runtime inventory, and frontend protocol status.

## Canonical transaction artifacts
- Authoritative source: `specs/tx_canon/tx_canon.yaml`.
- Runtime/schema dependencies: `src/weall/runtime/tx_schema.py`, domain registry, and appliers.
- Outputs: `generated/tx_index.json` and `generated/tx_contract_map.json`.
- Check gate: `python -S scripts/check_tx_canon_artifacts.py`.

## Required regeneration order
1. Review the semantic source change and record old/new digests outside the repository.
2. Update runtime schema, canonical transaction definition, admission, and apply behavior together.
3. Regenerate/check canonical transaction artifacts.
4. Update exactly the reviewed semantic-review entry.
5. Run the v2 compiler generation once, then check mode.
6. Regenerate affected v1.5 artifacts in declared generator order.
7. Run freshness, traceability, and closure checks without mutation.

## Baseline warning
The current artifacts are internally fresh for the current source snapshot, but the current source implements auto-accept membership. Applying the approval-required correction will intentionally invalidate the current `GROUP_CREATE` semantic digest and dependent artifacts.
