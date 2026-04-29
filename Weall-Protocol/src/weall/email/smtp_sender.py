# src/weall/email/smtp_sender.py
from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage


def _env(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return v.strip() if isinstance(v, str) and v.strip() else default


def send_email(*, to_email: str, subject: str, body_text: str) -> None:
    """
    Minimal SMTP sender (stdlib only).

    Required env vars:
      WEALL_EMAIL_HOST
      WEALL_EMAIL_PORT
      WEALL_EMAIL_USER
      WEALL_EMAIL_PASS
      WEALL_EMAIL_FROM

    Notes:
      - For Gmail: host=smtp.gmail.com, port=587, use an App Password.
      - Port 587 uses STARTTLS; port 465 uses implicit TLS.
    """
    host = _env("WEALL_EMAIL_HOST")
    port = int(_env("WEALL_EMAIL_PORT", "587"))
    user = _env("WEALL_EMAIL_USER")
    password = _env("WEALL_EMAIL_PASS")
    sender = _env("WEALL_EMAIL_FROM", user)

    if not host or not user or not password or not sender:
        raise RuntimeError("email not configured: set WEALL_EMAIL_HOST/PORT/USER/PASS/FROM")

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body_text)

    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=20) as s:
            s.login(user, password)
            s.send_message(msg)
        return

    with smtplib.SMTP(host, port, timeout=20) as s:
        s.ehlo()
        s.starttls()
        s.ehlo()
        s.login(user, password)
        s.send_message(msg)
