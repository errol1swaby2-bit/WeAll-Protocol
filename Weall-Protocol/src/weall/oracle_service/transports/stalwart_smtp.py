from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage as SmtpEmailMessage

from weall.oracle_service.transports.base import EmailMessage, EmailSendResult


@dataclass(frozen=True)
class StalwartSMTPConfig:
    host: str
    port: int = 587
    username: str = ""
    password: str = ""
    starttls: bool = True
    timeout_seconds: float = 10.0


class StalwartSMTPTransport:
    provider = "stalwart_smtp"

    def __init__(self, config: StalwartSMTPConfig) -> None:
        self.config = config

    def validate_config(self) -> None:
        if not str(self.config.host or "").strip():
            raise ValueError("missing_smtp_host")
        if int(self.config.port) <= 0:
            raise ValueError("invalid_smtp_port")

    def send(self, message: EmailMessage) -> EmailSendResult:
        self.validate_config()
        msg = SmtpEmailMessage()
        msg["From"] = message.from_email
        msg["To"] = message.to_email
        msg["Subject"] = message.subject
        msg.set_content(message.body_text)

        with smtplib.SMTP(self.config.host, int(self.config.port), timeout=float(self.config.timeout_seconds)) as smtp:
            if self.config.starttls:
                smtp.starttls(context=ssl.create_default_context())
            if self.config.username:
                smtp.login(self.config.username, self.config.password)
            refused = smtp.send_message(msg)
        if refused:
            raise RuntimeError(f"smtp_refused:{sorted(refused.keys())}")
        return EmailSendResult(provider=self.provider)
