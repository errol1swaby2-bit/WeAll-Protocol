from __future__ import annotations

from pathlib import Path


def test_production_node_scripts_do_not_require_poh_email_or_cloudflare_secrets() -> None:
    root = Path(__file__).resolve().parents[1]
    targets = [
        root / "scripts" / "run_node.sh",
        root / "scripts" / "run_node_prod.sh",
        root / "configs" / "production.env.example",
    ]
    forbidden = [
        "CLOUDFLARE_",
        "CF_",
        "TURNSTILE_",
        "CLOUDFLARE_WORKER",
        "WEALL_POH_EMAIL_SECRET",
        "WEALL_SMTP_PASSWORD",
    ]

    for path in targets:
        body = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in body, f"{token} should not be required by normal-node file {path}"
