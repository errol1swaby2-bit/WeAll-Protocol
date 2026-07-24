from __future__ import annotations

"""Shared immutable contract for Milestone 2 closure evidence.

The builder and the commit checker both use these constants, while the checker
still independently reloads every staged/committed blob and recomputes hashes,
sizes, success markers, state roots, and path-set equality.
"""

REQUIRED_PREFIXES: tuple[str, ...] = (
    "artifacts/m2-closure/backend/",
    "artifacts/m2-closure/frontend/",
    "artifacts/m2-closure/browser/account-custody/",
    "artifacts/m2-closure/browser/async/",
    "artifacts/m2-closure/browser/live/",
    "artifacts/m2-closure/media/",
    "artifacts/m2-closure/restart-replay/",
    "artifacts/m2-closure/two-node/",
    "artifacts/m2-closure/observer/",
)

COMMAND_LEDGER: tuple[dict[str, object], ...] = (
    {
        "id": "backend-full-pytest",
        "command": "cd Weall-Protocol && PYTHONPATH=src:scripts WEALL_API_BOOT_RUNTIME=0 python3 -m pytest -q",
        "evidence": "artifacts/m2-closure/backend/pytest.txt",
    },
    {
        "id": "tx-canon",
        "command": "cd Weall-Protocol && python3 -S scripts/check_tx_canon_artifacts.py",
        "evidence": "artifacts/m2-closure/backend/tx-canon.txt",
    },
    {
        "id": "production-genesis",
        "command": "cd Weall-Protocol && PYTHONPATH=src python3 scripts/assert_production_genesis_artifacts.py",
        "evidence": "artifacts/m2-closure/backend/production-genesis.txt",
    },
    {
        "id": "public-testnet-chain-identity",
        "command": "cd Weall-Protocol && PYTHONPATH=src python3 scripts/gen_public_testnet_v1_chain_identity.py --check",
        "evidence": "artifacts/m2-closure/backend/testnet-chain-identity.txt",
    },
    {
        "id": "seed-registry-rotation",
        "command": "cd Weall-Protocol && PYTHONPATH=src python3 scripts/check_public_testnet_seed_registry_rotation.py",
        "evidence": "artifacts/m2-closure/backend/seed-registry-rotation.txt",
    },
    {
        "id": "m2-traceability",
        "command": "cd Weall-Protocol && python3 scripts/check_m2_requirement_traceability.py",
        "evidence": "artifacts/m2-closure/backend/traceability.txt",
    },
    {
        "id": "frontend-typecheck",
        "command": "cd web && npm run typecheck",
        "evidence": "artifacts/m2-closure/frontend/typecheck.txt",
    },
    {
        "id": "frontend-build",
        "command": "cd web && npm run build",
        "evidence": "artifacts/m2-closure/frontend/build.txt",
    },
    {
        "id": "frontend-contract-real-stack",
        "command": "bash scripts/run_frontend_contract_check_real_stack.sh",
        "evidence": "artifacts/m2-closure/frontend/contract-check/contract-check.txt",
    },
    {
        "id": "frontend-production-safety",
        "command": "cd web && npm run production-safety-check",
        "evidence": "artifacts/m2-closure/frontend/production-safety.txt",
    },
    {
        "id": "account-custody-source",
        "command": "cd web && npm run test:account-custody-source",
        "evidence": "artifacts/m2-closure/frontend/account-custody-source.txt",
    },
    {
        "id": "account-custody-crypto-source",
        "command": "cd web && npm run test:account-custody-crypto-source",
        "evidence": "artifacts/m2-closure/frontend/account-custody-crypto-source.txt",
    },
    {
        "id": "account-custody-browser",
        "command": "bash scripts/run_account_custody_real_stack_e2e.sh",
        "evidence": "artifacts/m2-closure/browser/account-custody/runner.txt",
    },
    {
        "id": "async-tier1-browser",
        "command": "bash scripts/run_m2_async_browser_e2e.sh",
        "evidence": "artifacts/m2-closure/browser/async/playwright.txt",
    },
    {
        "id": "live-tier2-browser",
        "command": "bash scripts/run_m2_live_browser_e2e.sh",
        "evidence": "artifacts/m2-closure/browser/live/playwright.txt",
    },
    {
        "id": "media-interruption-replacement",
        "command": "bash scripts/run_m2_media_rehearsal.sh",
        "evidence": "artifacts/m2-closure/media/media-interruption-replacement.txt",
    },
    {
        "id": "restart-replay",
        "command": "bash scripts/run_m2_restart_replay_gate.sh",
        "evidence": "artifacts/m2-closure/restart-replay/restart-replay.txt",
    },
    {
        "id": "two-node-state-root",
        "command": "bash scripts/run_m2_two_node_state_root_gate.sh",
        "evidence": "artifacts/m2-closure/two-node/two-node-state-root.txt",
    },
    {
        "id": "observer-catchup",
        "command": "bash scripts/run_m2_observer_catchup_gate.sh",
        "evidence": "artifacts/m2-closure/observer/observer-catchup.txt",
    },
)

# Literal markers are intentionally conservative and tied to the closure runner's
# real outputs.  Regex markers are used only where the count is variable.
SUCCESS_MARKERS: tuple[dict[str, str], ...] = (
    {"path": "artifacts/m2-closure/backend/pytest.txt", "regex": r"\b\d+ passed\b"},
    {"path": "artifacts/m2-closure/backend/tx-canon.txt", "contains": "tx canon artifacts are synchronized"},
    {"path": "artifacts/m2-closure/backend/production-genesis.txt", "contains": "production genesis artifacts are pinned"},
    {"path": "artifacts/m2-closure/backend/testnet-chain-identity.txt", "contains": '"ok": true'},
    {"path": "artifacts/m2-closure/backend/seed-registry-rotation.txt", "contains": "OK: public-testnet seed registry commitments and pinned signature are current"},
    {"path": "artifacts/m2-closure/backend/traceability.txt", "contains": "OK: M2 traceability covers"},
    {"path": "artifacts/m2-closure/frontend/typecheck.txt", "contains": "tsc -b --pretty false"},
    {"path": "artifacts/m2-closure/frontend/build.txt", "contains": "built in"},
    {"path": "artifacts/m2-closure/frontend/contract-check/contract-check.txt", "contains": "Contract check PASSED."},
    {"path": "artifacts/m2-closure/frontend/production-safety.txt", "contains": "OK: frontend production UX safety guard passed"},
    {"path": "artifacts/m2-closure/frontend/account-custody-source.txt", "contains": "account custody source checks passed"},
    {"path": "artifacts/m2-closure/frontend/account-custody-crypto-source.txt", "contains": "account custody cryptographic source gate passed"},
    {"path": "artifacts/m2-closure/browser/account-custody/runner.txt", "regex": r"\b\d+ passed\b"},
    {"path": "artifacts/m2-closure/browser/async/playwright.txt", "regex": r"\b1 passed\b"},
    {"path": "artifacts/m2-closure/browser/live/playwright.txt", "regex": r"\b1 passed\b"},
    {"path": "artifacts/m2-closure/media/media-interruption-replacement.txt", "regex": r"\b\d+ passed\b"},
    {"path": "artifacts/m2-closure/restart-replay/restart-replay.txt", "contains": "OK: live controlled-devnet restart/catch-up probe passed"},
    {"path": "artifacts/m2-closure/two-node/two-node-state-root.txt", "contains": "OK: node identities, tips, and state roots match"},
    {"path": "artifacts/m2-closure/observer/observer-catchup.txt", "contains": "after-node2-restart-catchup"},
)

STATE_SUMMARY_PATHS: dict[str, str] = {
    "restart_replay": "artifacts/m2-closure/restart-replay/final-state.json",
    "two_node": "artifacts/m2-closure/two-node/final-state.json",
    "observer": "artifacts/m2-closure/observer/final-state.json",
}

TRANSCRIPT_PATHS: tuple[str, ...] = (
    "artifacts/m2-closure/browser/account-custody/runner.txt",
    "artifacts/m2-closure/browser/async/playwright.txt",
    "artifacts/m2-closure/browser/live/playwright.txt",
    "artifacts/m2-closure/media/media-interruption-replacement.txt",
    "artifacts/m2-closure/restart-replay/restart-replay.txt",
    "artifacts/m2-closure/restart-replay/final-state.json",
    "artifacts/m2-closure/two-node/two-node-state-root.txt",
    "artifacts/m2-closure/two-node/final-state.json",
    "artifacts/m2-closure/observer/observer-catchup.txt",
    "artifacts/m2-closure/observer/final-state.json",
)

PRIVATE_MARKERS: tuple[bytes, ...] = (
    b'"private_key"',
    b'"private_key_hex"',
    b'"secretKeyB64"',
    b'"secret_key"',
    b'"recoveryAuthoritySecretKeyB64"',
    b'"evidenceKemSecretKeyB64"',
    b"BEGIN PRIVATE KEY",
    b"BEGIN RSA PRIVATE KEY",
    b"BEGIN EC PRIVATE KEY",
    b"BEGIN OPENSSH PRIVATE KEY",
)

MILESTONE = "M2"
ARTIFACT_ROOT = "artifacts/m2-closure"
MANIFEST_TOP_LEVEL_KEYS: frozenset[str] = frozenset(
    {
        "schema_version",
        "milestone",
        "implementation_freeze_commit",
        "implementation_tree",
        "evidence_commit_parent_required",
        "artifact_root",
        "artifact_count",
        "commands",
        "transcript_hashes",
        "final_state_roots",
        "files",
        "truth_boundary",
    }
)
FILE_ENTRY_KEYS: frozenset[str] = frozenset({"path", "sha256", "size_bytes"})
TRUTH_BOUNDARY: dict[str, object] = {
    "claim": "local deterministic and controlled-devnet Milestone 2 closure evidence",
    "does_not_claim": [
        "independent third-party security audit",
        "public multi-validator mainnet readiness",
        "erasure from storage providers outside the attested provider set",
    ],
}
