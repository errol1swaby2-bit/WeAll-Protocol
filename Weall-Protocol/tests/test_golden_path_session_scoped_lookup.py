from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "golden_path_full_stack.py"


def test_golden_path_account_state_supports_owner_authenticated_lookup() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert "def _account_state(cfg: Cfg, account: str, *, session_key: str | None = None)" in text
    assert '"X-WeAll-Account": account' in text
    assert '"X-WeAll-Session-Key": session_key' in text


def test_golden_path_does_not_expect_session_keys_from_public_account_lookup() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert "Public account lookups intentionally redact bearer session keys" in text
    assert "state = _account_state(cfg, account, session_key=session_key)" in text
    assert "session key was not written on-chain" not in text
    assert "session key was not visible through owner-authenticated account lookup" in text
