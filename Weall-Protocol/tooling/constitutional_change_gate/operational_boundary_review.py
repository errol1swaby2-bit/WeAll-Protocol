#!/usr/bin/env python3
"""Read-only source-pinned operational boundary observations, not approvals."""

from __future__ import annotations

import hashlib
from collections import Counter

import repository_coverage as coverage

CASES = (
    {
        "id": "OPS-RESET-001",
        "path": "Weall-Protocol/scripts/devnet_reset_state.sh",
        "boundary": "devnet_recursive_reset_after_issue68",
        "anchors": (
            'DEVNET_DIR="${WEALL_DEVNET_DIR:-',
            'python3 "${REPO_ROOT}/scripts/devnet_safe_paths.py" reset "${DEVNET_DIR}"',
        ),
        "control": "reset_delegates_to_nofollow_fd_relative_path_helper",
        "finding": "Old basename-only rm -rf was replaced by a guarded helper; shell delegation alone does not prove all race, path, or caller safety.",
        "next_proofs": (
            "temp_fixture_negative_tests_exact_commit",
            "canonical_path_and_symlink_runtime_adjudication",
            "persisted_ledger_never_reset_in_rehearsal",
        ),
    },
    {
        "id": "OPS-IPFS-002",
        "path": "Weall-Protocol/scripts/devnet_local_two_frontend_rehearsal.sh",
        "boundary": "non_destructive_ipfs_partition_failure_after_issue68",
        "anchors": (
            'IPFS_PARTITION_PATH="${WEALL_IPFS_PARTITION_PATH:-',
            'python3 scripts/devnet_safe_paths.py check-ipfs "${DEVNET_DIR}" "${IPFS_PARTITION_PATH}"',
            'Preserving the repository; no automatic deletion.',
        ),
        "control": "reject_untrusted_partition_and_fail_without_automatic_recovery_deletion",
        "finding": "Automatic rm -rf was removed and checked-path refusal was introduced. Dynamic path races, other IPFS startup paths, and real Kubo behavior remain unproven.",
        "next_proofs": (
            "reserved_ipfs_path_and_symlink_negative_tests",
            "real_startup_fail_closed_without_destroying_existing_data",
            "independent_post_fix_control_flow_review",
        ),
    },
    {
        "id": "OPS-REHEARSAL-003",
        "path": "Weall-Protocol/scripts/devnet_local_two_frontend_rehearsal.sh",
        "boundary": "opt_in_full_devnet_reset",
        "anchors": (
            'RESET="${WEALL_LOCAL_REHEARSAL_RESET:-0}"',
            'if _bool_true "${RESET}"; then',
            'WEALL_DEVNET_DIR="${DEVNET_DIR}" bash scripts/devnet_reset_state.sh',
        ),
        "control": "full_devnet_reset_flag_defaults_off",
        "finding": "The explicit reset flag governs full devnet reset; separate IPFS error handling now fails without deleting partition contents, subject to runtime verification.",
        "next_proofs": ("default_preserves_ledger", "delegation_inherits_path_checks"),
    },
    {
        "id": "OPS-RESTART-004",
        "path": "Weall-Protocol/scripts/devnet_restart_catchup_live.sh",
        "boundary": "restart_catchup_reset",
        "anchors": (
            'if _bool_true "${WEALL_DEVNET_LIVE_RESET:-0}"; then',
            "bash scripts/devnet_reset_state.sh",
        ),
        "control": "restart_reset_flag_defaults_off",
        "finding": "Restart/catch-up reset is opt-in; persisted chain parity needs exact two-node evidence and explicit path checks.",
        "next_proofs": ("persisted_state_survives_restarts", "chain_identity_and_root_parity"),
    },
    {
        "id": "OPS-PROD-005",
        "path": "Weall-Protocol/scripts/boot_node_operator.sh",
        "boundary": "production_operator_preflight",
        "anchors": (
            'export WEALL_MODE="${WEALL_MODE:-prod}"',
            'bash "${SCRIPT_DIR}/prod_node_preflight.sh"',
            'exec "${SCRIPT_DIR}/run_node_prod.sh"',
        ),
        "control": "production_preflight_before_process_exec",
        "finding": "Preflight and nonempty account/node-key checks are not proof of runtime on-chain operator authorization.",
        "next_proofs": (
            "manifest_identity",
            "on_chain_operator_role",
            "invalid_key_role_negative_tests",
        ),
    },
    {
        "id": "OPS-PROD-006",
        "path": "Weall-Protocol/scripts/prod_node_preflight.sh",
        "boundary": "manifest_and_signing_preflight",
        "anchors": (
            'MANIFEST="${WEALL_CHAIN_MANIFEST_PATH:-',
            "WEALL_SIGVERIFY=0 is forbidden",
            "prod_chain_manifest_check.sh",
        ),
        "control": "manifest_and_signature_verification_preflight",
        "finding": "Shell checks are not proof that runtime consensus, replay, and authority enforcement cannot be bypassed.",
        "next_proofs": ("runtime_fail_closed_probes", "genesis_chain_manifest_parity"),
    },
    {
        "id": "OPS-SAFE-007",
        "path": "Weall-Protocol/scripts/devnet_safe_paths.py",
        "boundary": "fd_safe_custom_reset_and_reserved_ipfs_subpaths",
        "anchors": (
            'CONFIRMATION = "I_CONFIRM_DELETE_CUSTOM_DEVNET"',
            'NOFOLLOW = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW',
            'if target == repo_root / RESET_BASENAME:',
            'if not shutil.rmtree.avoids_symlink_attacks:',
            'shutil.rmtree(target.name, dir_fd=parent_fd)',
            'if ipfs.parent != devnet or ipfs.name not in ("ipfs_partition", "ipfs"):',
        ),
        "control": "disposable_target_path_and_fd_relative_delete_candidate",
        "finding": "The exact helper source includes explicit environment confirmation and fd-relative deletion; operational and TOCTOU safety still require adversarial review.",
        "next_proofs": (
            "exact_commit_disposable_directory_negative_tests",
            "symlink_race_and_mount_boundary_review",
            "no_unintended_delete_or_state_loss_in_live_rehearsal",
        ),
    },
)


def adjudicate(case: dict, source: str | None, sha256: str | None) -> dict:
    evidence = []
    for anchor in case["anchors"]:
        match = (
            next(
                (
                    {"line": index, "text": text.strip()}
                    for index, text in enumerate(source.splitlines(), start=1)
                    if anchor in text
                ),
                None,
            )
            if source is not None
            else None
        )
        evidence.append({"expected": anchor, "observed": match})
    status = (
        "OPEN_SOURCE_ANCHORS_REPRODUCED"
        if source is not None and all(x["observed"] for x in evidence)
        else "BLOCKED_SOURCE_ANCHOR_MISSING_OR_CHANGED"
    )
    return {
        "id": case["id"],
        "source_path": case["path"],
        "sha256": sha256,
        "boundary": case["boundary"],
        "observed_control": case["control"],
        "finding_for_review": case["finding"],
        "next_required_proofs": list(case["next_proofs"]),
        "evidence": evidence,
        "status": status,
        "semantic_authorization": "NOT_ESTABLISHED",
        "completeness": "STATIC_ANCHORS_ONLY_NOT_CONTROL_FLOW_PROOF",
    }


def inspect(repo, commit: str, tracked_paths: set[str]) -> dict:
    records = []
    for case in CASES:
        if case["path"] not in tracked_paths:
            records.append(adjudicate(case, None, None))
            continue
        raw = coverage.git(repo, "show", f"{commit}:{case['path']}")
        digest = hashlib.sha256(raw).hexdigest()
        try:
            content = raw.decode("utf-8")
        except UnicodeError:
            content = None
        records.append(adjudicate(case, content, digest))
    counts = Counter(x["status"] for x in records)
    return {
        "schema": "weall.operational_boundary_review.candidate.v0.1",
        "source_commit": commit,
        "status": "OPEN_INDEPENDENT_CONTROL_FLOW_AND_NEGATIVE_TEST_REVIEW",
        "shell_scripts_executed": False,
        "case_count": len(records),
        "cases": records,
        "source_anchor_status_counts": dict(sorted(counts.items())),
    }
