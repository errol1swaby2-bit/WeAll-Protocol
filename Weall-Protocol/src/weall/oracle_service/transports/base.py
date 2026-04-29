from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class EmailMessage:
    to_email: str
    from_email: str
    subject: str
    body_text: str


@dataclass(frozen=True)
class EmailSendResult:
    provider: str
    message_id: str = ""
    diagnostic: str = ""


class EmailTransport(Protocol):
    provider: str

    def validate_config(self) -> None:
        ...

    def send(self, message: EmailMessage) -> EmailSendResult:
        ...
