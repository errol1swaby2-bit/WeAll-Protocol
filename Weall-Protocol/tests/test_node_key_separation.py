from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ACCOUNT_PAGE = ROOT / "web" / "src" / "pages" / "Account.tsx"
NODE_KEYS = ROOT / "web" / "src" / "auth" / "nodeKeys.ts"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_operator_config_uses_separate_node_key_file() -> None:
    account_page = read(ACCOUNT_PAGE)

    assert "WEALL_NODE_PRIVKEY_FILE=" in account_page
    assert "WEALL_NODE_PRIVKEY=${" not in account_page
    assert "localSecretKey" not in account_page
    assert "<PASTE_NODE_PRIVKEY>" not in account_page
    assert "not from your account recovery key" in account_page


def test_operator_registration_uses_generated_node_pubkey() -> None:
    account_page = read(ACCOUNT_PAGE)

    assert "const nodePubkey" in account_page
    assert "pubkey: nodePubkey" in account_page
    assert "String(rec.pubkey || \"\") === nodePubkey" in account_page
    assert "Generate and download node key" in account_page
    assert "Separate node key" in account_page
    assert "Node device registered with node public key" in account_page
    assert "Node device registered with same pubkey" not in account_page


def test_node_key_file_helper_is_explicitly_not_recovery_key() -> None:
    helper = read(NODE_KEYS)

    assert 'type: "weall_node_key"' in helper
    assert "createNodeKeyFile" in helper
    assert "downloadNodeKeyFile" in helper
    assert "secretKeyB64" in helper
    assert "not your WeAll account recovery key" in helper
    assert "weall-node-key-" in helper
