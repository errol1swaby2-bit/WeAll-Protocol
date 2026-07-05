from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("PYTEST_CURRENT_TEST", None)
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    return subprocess.run(
        [*args],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=45,
    )


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_public_observer_open_download_capture_script_is_helpful_and_non_authoritative() -> None:
    script = ROOT / "scripts" / "capture_public_observer_open_download_transcript_v1_5.sh"
    assert script.is_file()
    assert os.access(script, os.X_OK)
    text = script.read_text(encoding="utf-8")
    for required in [
        "AUD-628-P1-001",
        "does not close the blocker",
        "WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY",
        "public_observer_launch_runtime_transcript_v1_5.json",
        "RENDERED_JOURNEY_CHECKLIST.md",
        "public_beta_ready",
        "public_observer_launch_ready",
        "external_review_required_before_closure",
    ]:
        assert required in text

    proc = _run("bash", "scripts/capture_public_observer_open_download_transcript_v1_5.sh", "--help")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Captures the external public-observer open-download transcript package" in proc.stdout
    assert "does not close the blocker" in proc.stdout


def test_public_observer_open_download_template_keeps_aud_628_open() -> None:
    readme = _read("docs/proofs/public-observer-open-download/2026-07-05/README.md")
    template = _read("docs/proofs/public-observer-open-download/2026-07-05/TRANSCRIPT_TEMPLATE.md")
    runbook = _read("docs/testnet/PUBLIC_OBSERVER_OPEN_DOWNLOAD_TRANSCRIPT.md")
    first_15 = _read("docs/testnet/FIRST_15_MINUTES.md")
    launch_transcripts = _read("docs/PUBLIC_OBSERVER_LAUNCH_TRANSCRIPTS.md")

    for text in [readme, template, runbook, first_15, launch_transcripts]:
        assert "AUD-628-P1-001" in text
    assert "template" in readme.lower()
    assert "Status: TEMPLATE ONLY" in template
    assert "does not close the blocker" in runbook
    assert "must not close `AUD-628-P1-001`" in launch_transcripts
    assert "public beta readiness" in readme
    assert "public beta/mainnet/public validator/live economics/automatic upgrade/helper/legal/storage overclaim" in readme


def test_public_observer_launch_evidence_requirements_reference_capture_package() -> None:
    proc = _run(sys.executable, "scripts/gen_public_observer_launch_evidence_requirements_v1_5.py", "--check")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads((ROOT / "generated" / "public_observer_launch_evidence_requirements_v1_5.json").read_text(encoding="utf-8"))
    assert payload["public_observer_launch_ready"] is False
    assert payload["public_beta_ready"] is False
    gate_text = json.dumps(payload, sort_keys=True)
    assert "scripts/capture_public_observer_open_download_transcript_v1_5.sh" in gate_text
    assert "docs/proofs/public-observer-open-download/2026-07-05/TRANSCRIPT_TEMPLATE.md" in gate_text
    assert "docs/proofs/public-observer-open-download/<date>/<external-operator>/manifest.json" in gate_text


def test_public_beta_blocker_report_still_requires_external_observer_transcript() -> None:
    proc = _run(sys.executable, "scripts/gen_public_beta_blocker_report_v1_5.py", "--check")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads((ROOT / "generated" / "public_beta_blocker_report_v1_5.json").read_text(encoding="utf-8"))
    assert payload["public_beta_ready"] is False
    blockers = {item["id"]: item for item in payload["blockers"]}
    blocker = blockers["AUD-628-P1-001"]
    assert blocker["safe_to_close_before_nlnet_first_round_with_current_repo_evidence"] is False
    assert blocker["gate_status"] == "gate_present_external_transcript_required"
    assert "external clean-clone observer transcript" in blocker["remaining_external_evidence"]
