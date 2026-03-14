#!/usr/bin/env python3
"""
Patch WeAll domain_apply.py:
- Enforce signers_required + threshold<=len(signers) for TREASURY_SIGNERS_SET and GROUP_SIGNERS_SET
- Fix GROUP_SIGNERS_SET error details variable (treasury_id -> group_id)

Run from repo root:
  python3 scripts/patch_roles_thresholds.py
"""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET = REPO_ROOT / "src" / "weall" / "runtime" / "domain_apply.py"


def die(msg: str) -> None:
    raise SystemExit(msg)


def main() -> None:
    if not TARGET.exists():
        die(f"ERROR: target not found: {TARGET}")

    txt = TARGET.read_text()

    # 1) Fix GROUP_SIGNERS_SET error details (treasury_id -> group_id)
    txt2 = txt.replace(
        '{"tx_type": env.tx_type, "treasury_id": treasury_id}',
        '{"tx_type": env.tx_type, "group_id": group_id}',
    )

    # 2) Strengthen threshold enforcement for BOTH group + treasury signers blocks.
    # We replace the older conditional:
    #     if len(signers) > 0 and threshold > len(signers): raise ...
    # with:
    #     if len(signers)==0: raise signers_required
    #     if threshold>len(signers): raise threshold_exceeds_signers
    #
    # Your current file may already have one or both edits, so we do a couple of safe transformations.

    # Pattern A: older guard "len(signers) > 0 and threshold > len(signers)"
    old_guard = (
        "    # threshold cannot exceed number of signers\n"
        "    if len(signers) > 0 and threshold > len(signers):\n"
        "        raise ApplyError(\n"
        '            "bad_payload",\n'
        '            "threshold_exceeds_signers",\n'
        '            {"threshold": int(threshold), "n_signers": len(signers)},\n'
        "        )\n"
    )

    strengthened_guard = (
        "    # signers list must be non-empty, and threshold must not exceed signers\n"
        "    if len(signers) == 0:\n"
        "        raise ApplyError(\n"
        '            "invalid_payload",\n'
        '            "signers_required",\n'
        '            {"tx_type": env.tx_type, "treasury_id": treasury_id},\n'
        "        )\n"
        "\n"
        "    if threshold > len(signers):\n"
        "        raise ApplyError(\n"
        '            "bad_payload",\n'
        '            "threshold_exceeds_signers",\n'
        '            {"threshold": int(threshold), "n_signers": len(signers)},\n'
        "        )\n"
    )

    if old_guard in txt2:
        txt2 = txt2.replace(old_guard, strengthened_guard)

    # Pattern B: already-strengthened block but treasury_id details present in GROUP_SIGNERS_SET.
    # If the strengthened guard exists but still has treasury_id, our earlier replace fixes it.

    if txt2 == txt:
        # Nothing changed — but that's okay if you already manually applied the fixes.
        print("No changes needed (file already patched).")
        return

    TARGET.write_text(txt2)
    print(f"Patched: {TARGET}")


if __name__ == "__main__":
    main()
