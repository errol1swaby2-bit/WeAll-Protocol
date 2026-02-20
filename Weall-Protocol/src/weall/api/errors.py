from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True, slots=True)
class ApiError(Exception):
    status_code: int
    code: str
    message: str
    details: Dict[str, Any]

    @staticmethod
    def bad_request(code: str, message: str, details: Optional[Dict[str, Any]] = None) -> "ApiError":
        return ApiError(400, code, message, details or {})

    @staticmethod
    def forbidden(code: str, message: str, details: Optional[Dict[str, Any]] = None) -> "ApiError":
        return ApiError(403, code, message, details or {})

    @staticmethod
    def not_found(code: str, message: str, details: Optional[Dict[str, Any]] = None) -> "ApiError":
        return ApiError(404, code, message, details or {})

    @staticmethod
    def too_many(code: str, message: str, details: Optional[Dict[str, Any]] = None) -> "ApiError":
        return ApiError(429, code, message, details or {})

    @staticmethod
    def internal(code: str, message: str, details: Optional[Dict[str, Any]] = None) -> "ApiError":
        return ApiError(500, code, message, details or {})
