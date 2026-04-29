from __future__ import annotations

from weall.oracle_service.transports.stalwart_smtp import StalwartSMTPConfig, StalwartSMTPTransport


class ExternalSMTPTransport(StalwartSMTPTransport):
    provider = "external_smtp"

    def __init__(self, config: StalwartSMTPConfig) -> None:
        super().__init__(config)
