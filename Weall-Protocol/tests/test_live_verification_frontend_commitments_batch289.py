from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ACCOUNT_VERIFICATION = ROOT / "web" / "src" / "pages" / "AccountVerificationPage.tsx"
LIVE_HELPER = ROOT / "web" / "src" / "lib" / "liveVerification.ts"
DEVNET_REQUEST_LIVE = ROOT / "Weall-Protocol" / "scripts" / "devnet_request_live.sh"
DEVNET_ONBOARDING = ROOT / "Weall-Protocol" / "scripts" / "devnet_full_onboarding_e2e.sh"


def test_live_verification_commitment_helper_exists_batch289() -> None:
    text = LIVE_HELPER.read_text(encoding="utf-8")
    assert "LiveVerificationCommitments" in text
    assert "createLiveVerificationCommitments" in text
    assert "hasRequiredLiveVerificationCommitments" in text
    assert "session_commitment" in text
    assert "room_commitment" in text
    assert "prompt_commitment" in text
    assert "device_pairing_commitment" in text
    assert "sha256HexText" in text


def test_account_verification_submits_live_commitments_batch289() -> None:
    text = ACCOUNT_VERIFICATION.read_text(encoding="utf-8")
    assert "createLiveVerificationCommitments" in text
    assert "hasRequiredLiveVerificationCommitments" in text
    assert "weall.pohLiveTxRequest({ account_id: acct, ...commitments }" in text
    assert "The backend live verification skeleton is missing required session commitments." in text
    assert "Advanced: prepared live request commitments" in text
    assert "session, room, and prompt commitments" in text


def test_devnet_live_request_generates_default_commitments_batch289() -> None:
    text = DEVNET_REQUEST_LIVE.read_text(encoding="utf-8")
    assert "_default_live_commitment" in text
    assert "WEALL_POH_LIVE_SESSION_COMMITMENT" in text
    assert "WEALL_POH_LIVE_ROOM_COMMITMENT" in text
    assert "WEALL_POH_LIVE_PROMPT_COMMITMENT" in text
    assert "WEALL_POH_LIVE_DEVICE_PAIRING_COMMITMENT" in text
    assert "weall-controlled-devnet-live|v1" in text


def test_full_onboarding_can_run_optional_live_flow_batch289() -> None:
    text = DEVNET_ONBOARDING.read_text(encoding="utf-8")
    assert "WEALL_DEVNET_RUN_LIVE" in text
    assert "_run_live_devnet_flow \"${ACCOUNT}\"" in text
    assert "could not resolve onboarding account after account creation" in text
    assert "Completing optional native live Tier-2 verification" in text
