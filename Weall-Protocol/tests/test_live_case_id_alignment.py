from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_devnet_live_cli_case_id_matches_runtime_apply_prefix() -> None:
    cli = _read("scripts/devnet_tx.py")
    apply = _read("src/weall/runtime/apply/poh.py")
    assert 'return f"poh_live:{str(account or \'\').strip()}:{max(0, int(nonce))}"' in cli
    assert 'return f"poh3:{str(account or \'\').strip()}:{max(0, int(nonce))}"' not in cli
    assert 'case_id = _case_id("poh_live", account_id=account_id, nonce=_as_int(_get_env(env, "nonce", 0)))' in apply


def test_devnet_live_request_polls_submitted_case_id_not_legacy_poh3() -> None:
    full = _read("scripts/devnet_full_onboarding_e2e.sh")
    cli = _read("scripts/devnet_tx.py")
    assert "devnet_request_live.sh" in full
    assert "case_id=\"$(_json_file_field \"${t3_out}\" case_id)\"" in full
    assert "last_poh_live_case_id" in cli
    assert 'return f"poh3:{str(account or \'\').strip()}:{max(0, int(nonce))}"' not in cli
