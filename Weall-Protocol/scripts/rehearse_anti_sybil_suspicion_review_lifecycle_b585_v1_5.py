#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from rehearse_anti_sybil_adjudication_deletion_v1_5 import run_harness as run_adjudication
from rehearse_anti_sybil_escalation_recovery_windows_v1_5 import run_harness as run_windows
from rehearse_anti_sybil_panel_signal_aggregation_v1_5 import run_harness as run_panel

Json = dict[str, Any]


def run_harness() -> Json:
    windows = run_windows()
    panel = run_panel()
    adjudication = run_adjudication()
    ok = bool(
        windows.get("ok")
        and panel.get("ok")
        and adjudication.get("ok")
        and windows.get("suspicion_id")
        and panel.get("panel_selection", {}).get("selected_count", 0) >= 3
        and adjudication.get("dismissed_adjudication", {}).get("status") == "adjudicated_dismissed"
        and adjudication.get("evidence_deletion", {}).get("deleted") is True
    )
    return {
        "ok": ok,
        "batch": "585",
        "lifecycle_model": "anti_sybil_suspicion_to_review_to_appeal_recovery_without_auto_deletion",
        "suspicion_record": {
            "recorded": bool(windows.get("suspicion_id")),
            "suspicion_id": windows.get("suspicion_id"),
            "escalation_level": windows.get("escalation_level"),
            "review_window_open_height": windows.get("review_window_open_height"),
            "review_window_close_height": windows.get("review_window_close_height"),
        },
        "follow_up_panel_assignment": panel.get("panel_selection", {}),
        "evidence_retention_policy": {
            "before_recovery": windows.get("retention_before_recovery"),
            "after_recovery": windows.get("retention_after_recovery"),
            "final_retention_record": adjudication.get("final_retention_record"),
        },
        "false_positive_appeal_recovery_path": {
            "dismissed_adjudication": adjudication.get("dismissed_adjudication"),
            "false_positive_compensation_policy": adjudication.get("false_positive_compensation_policy"),
            "evidence_deletion": adjudication.get("evidence_deletion"),
        },
        "reviewer_accountability_record": {
            "scores_after_confirm": adjudication.get("scores_after_confirm"),
            "scores_after_dismiss": adjudication.get("scores_after_dismiss"),
        },
        "no_automatic_duplicate_human_deletion": True,
        "duplicate_human_detection_claimed": False,
        "collusion_adjudication_claimed": True,
        "complete_anti_sybil_solved": False,
        "automatic_collusion_detection_claimed": False,
        "source_rehearsals": {
            "escalation_recovery_windows": windows,
            "panel_signal_aggregation": panel,
            "adjudication_deletion": adjudication,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
