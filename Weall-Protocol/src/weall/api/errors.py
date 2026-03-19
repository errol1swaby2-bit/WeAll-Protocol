from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ApiError(Exception):
    status_code: int
    code: str
    message: str
    details: dict[str, Any]

    @staticmethod
    def bad_request(code: str, message: str, details: dict[str, Any] | None = None) -> ApiError:
        return ApiError(400, code, message, details or {})

    @staticmethod
    def forbidden(code: str, message: str, details: dict[str, Any] | None = None) -> ApiError:
        return ApiError(403, code, message, details or {})

    @staticmethod
    def not_found(code: str, message: str, details: dict[str, Any] | None = None) -> ApiError:
        return ApiError(404, code, message, details or {})

    @staticmethod
    def too_many(code: str, message: str, details: dict[str, Any] | None = None) -> ApiError:
        return ApiError(429, code, message, details or {})

    @staticmethod
    def payload_too_large(
        code: str, message: str, details: dict[str, Any] | None = None
    ) -> ApiError:
        return ApiError(413, code, message, details or {})

    @staticmethod
    def internal(code: str, message: str, details: dict[str, Any] | None = None) -> ApiError:
        return ApiError(500, code, message, details or {})
