from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT.parent / "web"


def test_wallet_and_tipping_components_exist_batch482() -> None:
    wallet = (WEB / "src" / "components" / "WalletPanel.tsx").read_text(encoding="utf-8")
    tip = (WEB / "src" / "components" / "ContentTipButton.tsx").read_text(encoding="utf-8")

    assert "WeCoin balance" in wallet
    assert "BALANCE_TRANSFER" in wallet
    assert "Genesis economics are locked" in wallet
    assert "balance_transfer_enabled" in wallet

    assert "Tip WCN" in tip
    assert "BALANCE_TRANSFER" in tip
    assert "content_tip" in tip
    assert "Tips are locked until Genesis economics activation" in tip


def test_profile_and_feed_mount_wallet_tipping_batch482() -> None:
    account = (WEB / "src" / "pages" / "Account.tsx").read_text(encoding="utf-8")
    feed = (WEB / "src" / "components" / "FeedView.tsx").read_text(encoding="utf-8")

    assert 'import WalletPanel from "../components/WalletPanel";' in account
    assert "<WalletPanel account={acct} base={base}" in account
    assert 'import ContentTipButton from "./ContentTipButton";' in feed
    assert "<ContentTipButton base={base}" in feed
