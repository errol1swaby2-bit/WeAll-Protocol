from pathlib import Path

from weall.runtime.tx_schema import PAYLOAD_MODELS

ROOT = Path(__file__).resolve().parents[3]


def test_batch624_reviewer_lane_payload_schema_accepts_lane_for_opt_in_and_out() -> None:
    for tx_type in ("REVIEWER_LANE_OPT_IN", "REVIEWER_LANE_OPT_OUT"):
        model = PAYLOAD_MODELS[tx_type]
        payload = model.model_validate({"account_id": "@reviewer", "lane": "dispute_review"})
        assert payload.account_id == "@reviewer"
        assert payload.lane == "dispute_review"


def test_batch624_frontend_source_guards_are_wired_into_clean_gate() -> None:
    script = ROOT / "web/scripts/test_batch624_responsibility_exit_and_route_truth_source.mjs"
    gate = ROOT / "scripts/run_clean_clone_go_gate_v1_5.sh"
    assert script.exists()
    assert "test_batch624_responsibility_exit_and_route_truth_source.mjs" in gate.read_text(encoding="utf-8")
