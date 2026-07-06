from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = [ROOT / "README.md", ROOT.parent / "README.md", ROOT / "SECURITY.md", ROOT / "docs" / "security" / "CRYPTO_AGILITY_AND_QUANTUM_POSTURE.md"]


def test_docs_do_not_claim_quantum_proof_or_completed_crypto_audit():
    combined = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in DOCS if p.exists()).lower()
    assert "quantum-proof" not in combined
    positive_claims = (
        "has completed a production cryptographic audit",
        "completed production cryptographic audit complete",
        "production cryptographic audit is complete",
    )
    for claim in positive_claims:
        assert claim not in combined
    assert "production post-quantum security" not in combined


def test_docs_preserve_pre_public_testnet_hardening_frame():
    text = (ROOT / "docs" / "security" / "CRYPTO_AGILITY_AND_QUANTUM_POSTURE.md").read_text(encoding="utf-8")
    assert "WeAll is a pre-public-testnet protocol implementation under active hardening." in text
    assert "public-only" in text
    assert "pq-mldsa-v1" in text
    assert "classical signature profiles removed" in text.lower()
