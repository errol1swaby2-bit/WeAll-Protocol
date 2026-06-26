from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOGIN = ROOT / "web" / "src" / "pages" / "LoginPage.tsx"
SESSION_PAGE = ROOT / "web" / "src" / "pages" / "SessionDevicesPage.tsx"
RECOVERY = ROOT / "web" / "src" / "auth" / "recoveryFile.ts"
PASSKEYS = ROOT / "web" / "src" / "auth" / "passkeys.ts"
KEYS = ROOT / "web" / "src" / "auth" / "keys.ts"


def test_login_page_uses_recovery_key_language() -> None:
    text = LOGIN.read_text(encoding="utf-8")
    assert "Create account key" in text
    assert "Download recovery file" in text
    assert "Copy recovery key" in text
    assert "I saved my recovery key somewhere private" in text
    assert "Sign in with recovery key" in text
    assert "Upload your saved recovery file" in text
    assert "Add easy sign-in" in text
    assert "Advanced connection settings" in text
    assert "Private key" not in text
    assert "Backend and current browser state" not in text
    assert "Access contract" not in text
    assert "Local signer" not in text
    assert "Environment targeting" not in text


def test_recovery_file_helpers_are_explicit_and_validate_keypair() -> None:
    text = RECOVERY.read_text(encoding="utf-8")
    assert 'type: "weall_recovery_key"' in text
    assert "downloadRecoveryKeyFile" in text
    assert "parseRecoveryKeyFileText" in text
    assert "readRecoveryKeyFile" in text
    assert "validateKeypair" in text
    assert "Anyone with this file can restore this WeAll account key" in text


def test_passkey_easy_signin_is_device_convenience_not_protocol_authority() -> None:
    text = PASSKEYS.read_text(encoding="utf-8")
    assert "navigator.credentials.create" in text
    assert "navigator.credentials.get" in text
    assert "PublicKeyCredential" in text
    assert "weall_easy_signin" in text
    assert "registerEasySignIn" in text
    assert "confirmEasySignIn" in text
    # The frontend passkey helper must not submit protocol txs or mutate chain state.
    assert "txSubmit" not in text
    assert "ACCOUNT_SESSION_KEY_ISSUE" not in text
    assert "ACCOUNT_DEVICE_REGISTER" not in text


def test_session_page_has_plain_logout_and_easy_signin_management() -> None:
    text = SESSION_PAGE.read_text(encoding="utf-8")
    assert "Log out of this device" in text
    assert "Clear this browser only" in text
    assert "Advanced local-only option" in text
    assert "Passkey-style access on this device" in text
    assert "It does not replace your recovery key" in text
    assert "Add easy sign-in" in text
    assert "Forget" in text


def test_raw_recovery_secret_still_not_persisted_to_localstorage() -> None:
    text = KEYS.read_text(encoding="utf-8")
    assert "never persist raw account private keys" in text
    assert "sessionStorage.setItem(secretStorageKey" in text
    assert 'KEYRING_PREFIX' not in text
    assert 'localStorage.setItem(`${KEYRING_PREFIX}${normalized}`' not in text
    assert "secretKeyB64" not in text.split("const secureMeta", 1)[1].split("sessionStorage.setItem", 1)[0]
