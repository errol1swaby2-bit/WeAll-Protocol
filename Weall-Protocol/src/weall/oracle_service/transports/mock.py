from __future__ import annotations

import json
from pathlib import Path

from weall.oracle_service.transports.base import EmailMessage, EmailSendResult


class MockDevTransport:
    provider = "mock"

    def __init__(self, *, outbox_path: str | Path) -> None:
        self.outbox_path = Path(outbox_path)

    def validate_config(self) -> None:
        self.outbox_path.parent.mkdir(parents=True, exist_ok=True)

    def send(self, message: EmailMessage) -> EmailSendResult:
        self.validate_config()
        rec = {
            "to_email_masked": _mask_email(message.to_email),
            "from": message.from_email,
            "subject": message.subject,
            "body_text": message.body_text,
        }
        with self.outbox_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
        return EmailSendResult(provider=self.provider, diagnostic=str(self.outbox_path))


def _mask_email(email: str) -> str:
    try:
        local, domain = str(email or "").split("@", 1)
    except ValueError:
        return "***"
    if not local:
        masked = "***"
    elif len(local) == 1:
        masked = f"{local}***"
    else:
        masked = f"{local[0]}***{local[-1]}"
    return f"{masked}@{domain}"
