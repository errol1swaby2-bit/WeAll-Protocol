#!/usr/bin/env python3
from __future__ import annotations

import runpy
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
PROJECT_ROOT = REPO_ROOT / "Weall-Protocol"
PREVIOUS_COMMIT = "06ca382577241cd0fbc0acfb5910fa0faa9c8f66"
PREVIOUS_REL = ".github/r20/r20_candidate_control.py"
PREVIOUS_BLOB = "a7f174d6a2b3268e220bfd63490123dd391d8b56"
TEMP_PREVIOUS = HERE / ".r20_candidate_control_b564.py"


def _load_previous_main():
    actual_blob = subprocess.check_output(
        ["git", "rev-parse", f"{PREVIOUS_COMMIT}:{PREVIOUS_REL}"],
        cwd=REPO_ROOT,
        text=True,
    ).strip()
    if actual_blob != PREVIOUS_BLOB:
        raise SystemExit(f"known B564 controller blob drift: {actual_blob} != {PREVIOUS_BLOB}")
    source = subprocess.check_output(
        ["git", "show", f"{PREVIOUS_COMMIT}:{PREVIOUS_REL}"],
        cwd=REPO_ROOT,
    )
    TEMP_PREVIOUS.write_bytes(source)
    namespace = runpy.run_path(str(TEMP_PREVIOUS), run_name="r20_candidate_control_b564")
    previous_main = namespace.get("main")
    if not callable(previous_main):
        raise SystemExit("known B564 controller has no callable main()")
    return previous_main


def _instrument_b562_generator() -> None:
    path = PROJECT_ROOT / "scripts" / "gen_b562_b566_mechanics_hardening_proof_v1_5.py"
    text = path.read_text(encoding="utf-8")
    if "def _run_component(" in text:
        raise SystemExit("B562 diagnostic helper unexpectedly already present")

    old_import = "import json\nfrom pathlib import Path\n"
    new_import = "import json\nimport sys\nfrom pathlib import Path\n"
    if text.count(old_import) != 1:
        raise SystemExit(f"B562 import anchor count: {text.count(old_import)}")
    text = text.replace(old_import, new_import, 1)

    build_anchor = "\ndef build() -> dict[str, Any]:\n"
    helper = '''\ndef _run_component(name: str, fn):\n    print(f"B562 component start: {name}", file=sys.stderr, flush=True)\n    try:\n        result = fn()\n    except BaseException as exc:\n        print(\n            f"B562 component raised: {name}: {type(exc).__name__}: {exc}",\n            file=sys.stderr,\n            flush=True,\n        )\n        raise\n    if not isinstance(result, dict):\n        print(\n            f"B562 component returned non-dict: {name}: {type(result).__name__}",\n            file=sys.stderr,\n            flush=True,\n        )\n    else:\n        print(\n            f"B562 component result: {name}: ok={bool(result.get('ok'))}",\n            file=sys.stderr,\n            flush=True,\n        )\n        if not bool(result.get("ok")):\n            print(\n                json.dumps({"component": name, "result": result}, sort_keys=True, indent=2),\n                file=sys.stderr,\n                flush=True,\n            )\n    return result\n\n\ndef build() -> dict[str, Any]:\n'''
    if text.count(build_anchor) != 1:
        raise SystemExit(f"B562 build anchor count: {text.count(build_anchor)}")
    text = text.replace(build_anchor, helper, 1)

    replacements = {
        "    validator = run_validator_apply()\n": "    validator = _run_component(\"validator_follower_apply_hardening\", run_validator_apply)\n",
        "    follower_sync = run_follower_sync()\n": "    follower_sync = _run_component(\"live_peer_catchup_from_follower_state\", run_follower_sync)\n",
        "    storage_retry = run_storage_retry()\n": "    storage_retry = _run_component(\"storage_worker_failure_retry_loop\", run_storage_retry)\n",
        "    anti_sybil = run_anti_sybil_windows()\n": "    anti_sybil = _run_component(\"anti_sybil_escalation_recovery_windows\", run_anti_sybil_windows)\n",
        "    economics = run_economics_farming()\n": "    economics = _run_component(\"economics_farming_simulation_locked\", run_economics_farming)\n",
    }
    for old, new in replacements.items():
        if text.count(old) != 1:
            raise SystemExit(f"B562 component anchor count for {old.strip()!r}: {text.count(old)}")
        text = text.replace(old, new, 1)

    path.write_text(text, encoding="utf-8")
    print("instrumented B562 component diagnostics without changing acceptance criteria")


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        previous_main = _load_previous_main()
        rc = previous_main()
        if rc not in (None, 0):
            raise SystemExit(f"known B564 controller failed: {rc}")
        if command == "post-apply":
            _instrument_b562_generator()
        return 0
    finally:
        TEMP_PREVIOUS.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
