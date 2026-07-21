# WeAll v2 singular specification compiler

Milestone 1 is implemented as one versioned source tree under
`specs/v2/source/` and one deterministic compiler:

```bash
PYTHONPATH=src python scripts/compile_v2_spec.py
PYTHONPATH=src python scripts/compile_v2_spec.py --check
python scripts/check_v2_spec_clean_checkout.py
```

The compiler is hermetic static analysis. It does not import the WeAll runtime
or require runtime dependencies such as Pydantic to discover transaction
appliers. Exact transaction-to-applier bindings are declared in
`specs/v2/source/tx_appliers.json` and checked against source functions.

## Singular source and provenance

The source tree contains:

- the exact uploaded v2.0 First Draft PDF, its SHA-256, PDF structure, metadata identity, 390-page count, authority-status declaration, and register fingerprints;
- the separate 236-entry current compatibility transaction canon, 27-entry target TX canon, complete 150-entry target TX/MSG/SYS/RCP contract canon, and exact applier registry;
- append-only stable identifiers and tombstones;
- all 755 controlling requirements, 215 parameters, M-001 through M-078, 94 exact state-object contracts, 98 target failure contracts, activation profiles, divergences, vectors, evidence declarations, source mappings, and reviewed contract overrides.

Every generated register carries the exact uploaded First Draft PDF hash, repository URL,
specification snapshot, compiler identity/version, active profile set, and a
SHA-256 digest of the complete scanned source tree. The generated PDF is a
byte-identical derivative of the pinned source PDF.

## Generated registers

- `current_tx_canon.json` and `tx_contract_matrix.json`: all 236 current compatibility transactions.
- `target_tx_canon.json`: the 27 target TX contracts.
- `target_contract_canon.json` and `target_contract_schema_index.json`: all 150 exact target TX/MSG/SYS/RCP contracts and their schema fingerprints.
- `route_contract_map.json`: all 159 current route implementations.
- `state_contract_index.json`: the 94 exact PDF-defined state-object contracts.
- `runtime_state_inventory.json`: the separate 972-row AST-derived current runtime state inventory.
- `message_contract_index.json`: runtime and `src/weall/net` MSG candidates,
  authority, replay, idempotency, and failure rules.
- `scheduler_contract_index.json`: SYS/due-work functions, ordering,
  idempotency, retry, replay, and failure rules.
- `receipt_contract_index.json`: one RCP row for every canonical transaction.
- `failure_contract_index.json`: current runtime/API failure inventory.
- `target_failure_contract_index.json`: all 98 exact PDF-defined target failure contracts.
- `parameter_registry.json`: all 215 PDF-defined parameters with authority, activation, migration, requirement, field, and boundary-vector bindings.
- `requirement_traceability.json`: all 755 controlling requirements. Specification extraction never marks implementation verification as PASS.
- `mechanism_registry.json`: exact M-001 through M-078 current behavior, production target, authority boundary, repository paths, divergences, gates, and evidence.
- `divergence_registry.json`, `vector_registry.json`, and
  `evidence_index.json`.
- `source_coverage_map.json`: explicit mechanism/register mapping for every
  authoritative or launch-critical file and explicit utility classification
  for non-protocol surfaces.
- typed JSON Schemas with `additionalProperties: false`.
- `web/src/generated/protocolStatus.ts`, consumed by
  `ProtocolStatusSummary.tsx`.

## Fail-closed behavior

Compilation fails when any of the following occurs:

- a canonical transaction lacks an applier, schema/gate declaration, stable
  identifier, or mechanism mapping;
- a route, state token, MSG, SYS action, RCP, failure, or evidence artifact
  lacks a registered stable identifier;
- an authoritative or launch-critical source file lacks an explicit mapping;
- an evidence artifact appears without an entry in the explicit evidence
  manifest;
- the exact uploaded PDF hash, PDF structure, metadata title, page count, version label, or authority status changes;
- a human-machine register count, identifier fingerprint, or row fingerprint differs from the PDF extraction fingerprint;
- an uncontrolled status or verification-result enum is used;
- a requirement claims PASS without a 40-hex implementation commit, UTC timestamp, executed run ID, 64-hex evidence digest, independent reviewer, and activation gate;
- declared inputs/outputs, counts, schemas, or committed derivatives drift.

`check_v2_spec_clean_checkout.py` creates a clean `git archive` of `HEAD` and
runs the compiler freshness check inside it. This prevents ignored or untracked
files from influencing committed derivatives.

## Assurance boundary

Milestone 1 full-scope completion establishes specification compilation, typed register
shape, provenance, traceability, stable identifiers, mechanism coverage, and
clean-checkout reproducibility. It does not prove that every runtime mechanism
already implements the production target.

The compilation manifest therefore continues to disclose incomplete
transaction- and route-level semantic review, open implementation divergences,
and fail-closed public-testnet/Mainnet activation. Mechanism coverage is not a
runtime-correctness, external-review, capacity, interoperability, or launch
certificate.

## Change procedure

1. Update the applicable source registry and implementation in the same change.
2. Allocate stable IDs explicitly; never recompute or reuse an existing ID.
3. Add exact source, mechanism, requirement, vector, evidence, activation, and
   migration mappings.
4. Run the compiler without `--check` and review every generated diff.
5. Run the focused tests and the clean-checkout gate.
6. Commit source and derivatives together.
