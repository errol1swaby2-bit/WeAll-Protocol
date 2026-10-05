from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]
ASSURANCE_VERSION = "weall.p0.assurance.v1"

# Deliberately fixed and reviewable. Property failures print the exact seed needed
# to reproduce the same generated representation/order corpus.
DETERMINISTIC_PROPERTY_SEEDS: tuple[int, ...] = (
    0x00000001,
    0x0000C0DE,
    0x0005EA1D,
    0x00A16F01,
    0x01020304,
    0x13579BDF,
    0x2468ACE0,
    0x5EED2026,
)


@dataclass(frozen=True)
class EditSpec:
    path: str
    find: str
    replace: str


@dataclass(frozen=True)
class MutationSpec:
    mutation_id: str
    track: str
    description: str
    edits: tuple[EditSpec, ...]
    tests: tuple[str, ...]
    equivalent: bool = False
    equivalent_reason: str = ""


def _edit(path: str, find: str, replace: str) -> EditSpec:
    return EditSpec(path=path, find=find, replace=replace)


MUTATIONS: tuple[MutationSpec, ...] = (
    MutationSpec(
        mutation_id="P0-01-INCLUDED-FAILURE-NONCE",
        track="P0-01",
        description="Re-enable nonce reuse after a canonically included failed user transaction.",
        edits=(
            _edit(
                "src/weall/runtime/runtime_context.py",
                "        return target(state, env, consume_nonce_on_fail=True)\n",
                "        return target(state, env, consume_nonce_on_fail=False)\n",
            ),
        ),
        tests=("tests/test_nonce_failure_block_progression.py",),
    ),
    MutationSpec(
        mutation_id="P0-02-LIVE-JUROR-ORDER",
        track="P0-02",
        description="Remove canonical ordering from the Live/async eligible reviewer baseline.",
        edits=(
            _edit(
                "src/weall/runtime/poh/juror_select.py",
                "    # deterministic ordering baseline (before seeded shuffle)\n"
                "    out.sort()\n"
                "    return out\n",
                "    # MUTANT: preserve attacker/representation insertion order.\n"
                "    return out\n",
            ),
        ),
        tests=("tests/test_p0_property_invariants.py",),
    ),
    MutationSpec(
        mutation_id="P0-03-HIGHQC-PARENT",
        track="P0-03",
        description="Build the next BFT proposal from committed state instead of the certified parent state.",
        edits=(
            _edit(
                "src/weall/runtime/bft_runtime_adapter.py",
                "        candidate_base_state = _bft_votecheck._speculative_parent_state(\n"
                "            self, str(verified_parent_qc.block_id)\n"
                "        )\n",
                "        candidate_base_state = dict(self.state)\n",
            ),
        ),
        tests=(
            "tests/test_p0_03_production_composition.py",
            "tests/test_p0_03_certified_branch_transition.py",
        ),
    ),
    MutationSpec(
        mutation_id="P0-05-MUTUAL-AUTH-ACK",
        track="P0-05",
        description="Stop signing identity-bound hello acknowledgements when identity is required.",
        edits=(
            _edit(
                "src/weall/net/handshake.py",
                "    identity: dict[str, Any] | None = None\n"
                "    if cfg.require_identity:\n"
                "        pubkey = str(cfg.identity_pubkey or \"\").strip()\n",
                "    identity: dict[str, Any] | None = None\n"
                "    if False and cfg.require_identity:\n"
                "        pubkey = str(cfg.identity_pubkey or \"\").strip()\n",
            ),
        ),
        tests=("tests/test_p0_05_f001_mutual_peer_auth.py",),
    ),
    MutationSpec(
        mutation_id="P0-05-WIRE-BUDGET",
        track="P0-05",
        description="Restore an undersized peer wire budget that rejects protocol-valid messages.",
        edits=(
            _edit(
                "src/weall/net/wire_limits.py",
                "MAX_WIRE_MESSAGE_BYTES = 1_000_000\n",
                "MAX_WIRE_MESSAGE_BYTES = 65_536\n",
            ),
        ),
        tests=("tests/test_p0_05_f002a_wire_budget.py",),
    ),
    MutationSpec(
        mutation_id="P0-06-ASYNC-CASEID-GRINDING",
        track="P0-06",
        description="Put applicant-controlled async case_id back into reviewer ranking.",
        edits=(
            _edit(
                "src/weall/runtime/poh/juror_select.py",
                "    scored = [(_score(entropy, \"pohasync-v2\", a), a) for a in pool]\n",
                "    scored = [(_score(entropy, \"pohasync-v2\", str(case_id), a), a) for a in pool]\n",
            ),
        ),
        tests=(
            "tests/test_poh_async_panel_grinding_regression.py",
            "tests/test_p0_property_invariants.py",
        ),
    ),
    MutationSpec(
        mutation_id="P0-07-PRODUCTION-CHAIN-MODE",
        track="P0-07",
        description="Stop recognizing the checked production chain ID as strict production governance.",
        edits=(
            _edit(
                "src/weall/runtime/ballot_policy.py",
                '_PRODUCTION_CHAIN_IDS = frozenset({"weall-prod"})\n',
                "_PRODUCTION_CHAIN_IDS = frozenset()\n",
            ),
        ),
        tests=(
            "tests/test_governance_no_creator_fallback_for_executable_prod.py",
            "tests/test_p0_governance_economics_closure.py",
        ),
    ),
    MutationSpec(
        mutation_id="P0-07-VOTING-PROPOSAL-FREEZE",
        track="P0-07",
        description="Permit production proposal edits after voting has opened.",
        edits=(
            _edit(
                "src/weall/runtime/apply/governance.py",
                '    if stg == "voting" and strict_civic_governance_enabled(state):\n',
                '    if False and stg == "voting" and strict_civic_governance_enabled(state):\n',
            ),
        ),
        tests=("tests/test_p0_governance_economics_closure.py",),
    ),
    MutationSpec(
        mutation_id="P0-08-ECON-ACTIVATION-PRECONDITIONS",
        track="P0-08",
        description="Allow economics activation even when mandatory readiness preconditions are missing.",
        edits=(
            _edit(
                "src/weall/runtime/apply/economics.py",
                '    if not bool(report.get("ready")):\n',
                '    if False and not bool(report.get("ready")):\n',
            ),
        ),
        tests=("tests/test_economics_activation_requires_hardened_governance_electorate.py",),
    ),
    MutationSpec(
        mutation_id="P0-09-POH-SCOPED-QUERY-AUTH",
        track="P0-09",
        description="Bypass session/principal binding for scoped PoH queue reads.",
        edits=(
            _edit(
                "src/weall/api/poh_route_auth.py",
                "    if selector is not None:\n",
                "    if False and selector is not None:\n",
            ),
        ),
        tests=(
            "tests/test_p0_a12_generated_vector_runtime_truth.py",
            "tests/test_p0_restart_and_poh_privacy_closure.py",
        ),
    ),
    MutationSpec(
        mutation_id="P0-10-HISTORY-FINALITY-BOUNDARY",
        track="P0-10",
        description="Allow compaction to prune the finalized anchor itself.",
        edits=(
            _edit(
                "src/weall/runtime/block_history.py",
                "    if any(int(height) >= int(finalized_height) for _block_id, _record, height in pruned):\n",
                "    if any(int(height) > int(finalized_height) for _block_id, _record, height in pruned):\n",
            ),
        ),
        tests=("tests/test_p0_10_a15_f001_bounded_block_history.py",),
    ),
    MutationSpec(
        mutation_id="P0-10-STATE-SYNC-TRUST-ANCHOR",
        track="P0-10",
        description="Permit production state sync to disable a required trusted-anchor boundary.",
        edits=(
            _edit(
                "src/weall/net/state_sync.py",
                '        if mode == "prod" and trusted_anchor_default and not self.require_trusted_anchor:\n',
                '        if False and mode == "prod" and trusted_anchor_default and not self.require_trusted_anchor:\n',
            ),
        ),
        tests=("tests/test_p0_10_a15_f002_state_sync_resource_bounds.py",),
    ),
    MutationSpec(
        mutation_id="P0-10-ACCOUNT-WORK-IDENTITY-BINDING",
        track="P0-10",
        description="Remove signer and transaction nonce from account-registration proof-of-work binding.",
        edits=(
            _edit(
                "src/weall/runtime/account_registration_work.py",
                '        str(env.signer or "").strip(),\n'
                "        int(env.nonce),\n",
                '        "",\n'
                "        0,\n",
            ),
        ),
        tests=("tests/test_a15_f003_account_registration_scarcity.py",),
    ),
)


def property_seed_rng(property_id: str, seed: int) -> random.Random:
    label = str(property_id or "").encode("utf-8")
    digest = hashlib.sha256(label + b"|" + str(int(seed)).encode("ascii")).digest()
    mixed = int.from_bytes(digest[:8], "big") ^ int(seed)
    return random.Random(mixed)


def property_cases(property_id: str) -> Iterable[tuple[int, random.Random]]:
    selected = os.environ.get("WEALL_P0_PROPERTY_SEED", "").strip()
    if selected:
        seeds = (int(selected, 0),)
    else:
        seeds = DETERMINISTIC_PROPERTY_SEEDS
    for seed in seeds:
        yield int(seed), property_seed_rng(property_id, int(seed))


def property_reproducer(property_id: str, seed: int) -> str:
    return (
        f"WEALL_P0_PROPERTY_SEED={int(seed)} "
        f"pytest -q tests/test_p0_property_invariants.py -k {property_id}"
    )


def minimize_sequence(
    items: Sequence[object], still_fails: Callable[[Sequence[object]], bool]
) -> list[object]:
    """Deterministically shrink a failing sequence by deletion.

    This is intentionally small and dependency-free. It is sufficient for the
    P0 property corpus: failures report the seed, and sequence-shaped generated
    cases can be reduced to a minimal deletion witness before being promoted to
    a permanent regression fixture.
    """

    current = list(items)
    changed = True
    while changed and len(current) > 1:
        changed = False
        for index in range(len(current)):
            candidate = current[:index] + current[index + 1 :]
            if candidate and still_fails(candidate):
                current = candidate
                changed = True
                break
    return current


def _apply_mutation(src_root: Path, mutation: MutationSpec) -> None:
    for edit in mutation.edits:
        target = src_root / edit.path
        text = target.read_text(encoding="utf-8")
        count = text.count(edit.find)
        if count != 1:
            raise RuntimeError(
                f"{mutation.mutation_id}: expected exactly one edit anchor in "
                f"{edit.path}, found {count}"
            )
        target.write_text(text.replace(edit.find, edit.replace, 1), encoding="utf-8")


def _run_pytest(
    test_paths: Sequence[str], *, src_overlay: Path | None, timeout_s: int
) -> dict:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if src_overlay is not None:
        existing = env.get("PYTHONPATH", "")
        parts = [str(src_overlay), str(ROOT)]
        if existing:
            parts.append(existing)
        env["PYTHONPATH"] = os.pathsep.join(parts)
    started = time.monotonic()
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", *test_paths],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=max(1, int(timeout_s)),
            check=False,
        )
        duration_s = time.monotonic() - started
        return {
            "returncode": int(proc.returncode),
            "duration_seconds": round(duration_s, 3),
            "output_tail": (proc.stdout or "")[-12000:],
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        duration_s = time.monotonic() - started
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return {
            "returncode": 124,
            "duration_seconds": round(duration_s, 3),
            "output_tail": str(output)[-12000:],
            "timed_out": True,
        }


def _run_mutation(mutation: MutationSpec, *, timeout_s: int) -> dict:
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="weall-p0-mutant-") as tmp:
        overlay_root = Path(tmp)
        overlay_src = overlay_root / "src"
        shutil.copytree(ROOT / "src", overlay_src, dirs_exist_ok=False)
        try:
            _apply_mutation(overlay_root, mutation)
        except Exception as exc:
            return {
                "mutation_id": mutation.mutation_id,
                "track": mutation.track,
                "description": mutation.description,
                "tests": list(mutation.tests),
                "equivalent": bool(mutation.equivalent),
                "equivalent_reason": mutation.equivalent_reason,
                "status": "invalid",
                "returncode": 125,
                "duration_seconds": round(time.monotonic() - started, 3),
                "output_tail": f"{type(exc).__name__}: {exc}",
                "timed_out": False,
            }

        result = _run_pytest(mutation.tests, src_overlay=overlay_src, timeout_s=timeout_s)

    # pytest's normal "tests failed" exit is 1. Collection/import/usage errors are
    # invalid mutation executions, not kills. A clean exit is a surviving mutant.
    if result["returncode"] == 1:
        status = "killed"
    elif result["returncode"] == 0:
        status = "equivalent_allowed" if mutation.equivalent else "survived"
    else:
        status = "invalid"

    return {
        "mutation_id": mutation.mutation_id,
        "track": mutation.track,
        "description": mutation.description,
        "tests": list(mutation.tests),
        "equivalent": bool(mutation.equivalent),
        "equivalent_reason": mutation.equivalent_reason,
        "status": status,
        **result,
    }


def _run_gate(*, report_path: Path, timeout_s: int) -> int:
    report_path.parent.mkdir(parents=True, exist_ok=True)

    property_result = _run_pytest(
        ("tests/test_p0_property_invariants.py",),
        src_overlay=None,
        timeout_s=max(timeout_s, 180),
    )

    mutation_results = [_run_mutation(m, timeout_s=timeout_s) for m in MUTATIONS]
    killed = sum(1 for row in mutation_results if row["status"] == "killed")
    survived = [
        row["mutation_id"] for row in mutation_results if row["status"] == "survived"
    ]
    invalid = [
        row["mutation_id"] for row in mutation_results if row["status"] == "invalid"
    ]
    allowed = [
        row["mutation_id"]
        for row in mutation_results
        if row["status"] == "equivalent_allowed"
    ]
    denominator = sum(1 for m in MUTATIONS if not m.equivalent)
    mutation_score = (killed / denominator) if denominator else 1.0

    report = {
        "schema": ASSURANCE_VERSION,
        "generated_at_unix": int(time.time()),
        "property_seed_corpus": list(DETERMINISTIC_PROPERTY_SEEDS),
        "property_suite": property_result,
        "mutation_summary": {
            "total": len(MUTATIONS),
            "non_equivalent_total": denominator,
            "killed": killed,
            "survived": survived,
            "invalid": invalid,
            "equivalent_allowed": allowed,
            "mutation_score": round(mutation_score, 6),
        },
        "mutations": mutation_results,
        "gate": {
            "property_suite_passed": property_result["returncode"] == 0,
            "no_non_equivalent_survivors": not survived,
            "no_invalid_mutations": not invalid,
            "passed": (
                property_result["returncode"] == 0
                and not survived
                and not invalid
                and killed == denominator
            ),
        },
    }
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(json.dumps(report["mutation_summary"], sort_keys=True))
    print(f"property_suite_returncode={property_result['returncode']}")
    print(f"report={report_path}")
    if report["gate"]["passed"]:
        print("P0 assurance gate: PASS")
        return 0
    print("P0 assurance gate: FAIL")
    return 1


def _manifest_json() -> dict:
    return {
        "schema": ASSURANCE_VERSION,
        "property_seed_corpus": list(DETERMINISTIC_PROPERTY_SEEDS),
        "mutations": [asdict(m) for m in MUTATIONS],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic WeAll P0 property/mutation assurance gate"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    manifest = sub.add_parser(
        "manifest", help="Print the locked mutation/property manifest"
    )
    manifest.add_argument("--json", action="store_true")

    gate = sub.add_parser(
        "gate", help="Run deterministic property and mutation assurance"
    )
    gate.add_argument(
        "--report",
        default="artifacts/p0-assurance/p0_assurance_report.json",
        help="Report path relative to Weall-Protocol/",
    )
    gate.add_argument("--timeout-seconds", type=int, default=120)

    args = parser.parse_args(argv)
    if args.command == "manifest":
        payload = _manifest_json()
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(
                f"{ASSURANCE_VERSION}: {len(MUTATIONS)} mutations, "
                f"{len(DETERMINISTIC_PROPERTY_SEEDS)} deterministic property seeds"
            )
        return 0

    report = Path(args.report)
    if not report.is_absolute():
        report = ROOT / report
    return _run_gate(report_path=report, timeout_s=max(30, int(args.timeout_seconds)))


if __name__ == "__main__":
    raise SystemExit(main())
