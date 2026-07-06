from __future__ import annotations

"""Production-safe outbound relay envelopes for NAT/CGNAT nodes.

The relay layer is intentionally transport-only:
  * it does not grant peer, node, validator, PoH, or consensus authority;
  * every envelope is chain/schema/tx-index bound;
  * every envelope is sender-signed;
  * relayed wire messages still face normal tx/BFT admission when consumed;
  * the relay store is a bounded durable mailbox, not consensus state.
"""

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from weall.crypto.sig import sign_signature_for_profile, verify_signature_for_profile
from weall.crypto.signature_profiles import LEGACY_ED25519_V1, PQ_MLDSA_V1, default_signature_profile_for_mode
from weall.net.codec import decode_message, dumps_json, encode_message, loads_json
from weall.net.messages import MsgType, WireMessage

Json = dict[str, Any]

_RELAY_DOMAIN = "WEALL_NET_RELAY_V1"
_RELAY_ACCESS_DOMAIN = "WEALL_NET_RELAY_ACCESS_V1"
_ALLOWED_RELAY_TYPES = {
    MsgType.TX_ENVELOPE.value,
    MsgType.BFT_PROPOSAL.value,
    MsgType.BFT_VOTE.value,
    MsgType.BFT_QC.value,
    MsgType.BFT_TIMEOUT.value,
    MsgType.STATE_SYNC_REQUEST.value,
    MsgType.STATE_SYNC_RESPONSE.value,
    MsgType.PEER_GETADDR.value,
    MsgType.PEER_ADDR.value,
    MsgType.PING.value,
    MsgType.PONG.value,
}


class RelayEnvelopeError(ValueError):
    """Raised when a relay envelope is malformed or unsafe."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = str(code)


@dataclass(frozen=True, slots=True)
class RelayConfig:
    chain_id: str
    schema_version: str
    tx_index_hash: str
    max_payload_bytes: int = 512 * 1024
    max_ttl_ms: int = 10 * 60 * 1000
    max_fetch_limit: int = 100
    allow_broadcast_recipient: bool = False
    max_access_ttl_ms: int = 60_000
    allow_unbound_recipient_fetch: bool = False
    require_recipient_pubkey: bool = False


def _now_ms() -> int:
    return int(time.time() * 1000)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _clean_peer_id(value: Any) -> str:
    return str(value or "").strip()


def _wire_payload_to_json(message: WireMessage | Json | bytes | str) -> Json:
    if isinstance(message, bytes):
        obj = loads_json(message)
    elif isinstance(message, str):
        obj = loads_json(message)
    elif isinstance(message, dict):
        obj = dict(message)
    else:
        obj = loads_json(encode_message(message))
    if not isinstance(obj, dict):
        raise RelayEnvelopeError("relay_payload_not_object")
    return obj


def _msg_type_from_payload(payload: Json) -> str:
    header = payload.get("header")
    if not isinstance(header, dict):
        raise RelayEnvelopeError("relay_payload_missing_header")
    mtype = str(header.get("type") or "").strip()
    if not mtype:
        raise RelayEnvelopeError("relay_payload_missing_type")
    return mtype


def _payload_hash(payload: Json) -> str:
    return _sha256_hex(_canonical_json_bytes(payload))


def _relay_signing_material(envelope: Json) -> bytes:
    payload_hash = str(envelope.get("payload_hash") or "").strip()
    if not payload_hash and isinstance(envelope.get("payload"), dict):
        payload_hash = _payload_hash(envelope["payload"])
    material = {
        "domain": _RELAY_DOMAIN,
        "version": int(envelope.get("version") or 1),
        "chain_id": str(envelope.get("chain_id") or ""),
        "schema_version": str(envelope.get("schema_version") or ""),
        "tx_index_hash": str(envelope.get("tx_index_hash") or ""),
        "sender_peer_id": str(envelope.get("sender_peer_id") or ""),
        "recipient_peer_id": str(envelope.get("recipient_peer_id") or ""),
        "recipient_pubkey": str(envelope.get("recipient_pubkey") or ""),
        "msg_type": str(envelope.get("msg_type") or ""),
        "nonce": str(envelope.get("nonce") or ""),
        "created_ms": int(envelope.get("created_ms") or 0),
        "expires_at_ms": int(envelope.get("expires_at_ms") or 0),
        "payload_hash": payload_hash,
        "sig_profile": str(envelope.get("sig_profile") or LEGACY_ED25519_V1).strip(),
    }
    return _canonical_json_bytes(material)


def compute_relay_id(envelope: Json) -> str:
    pubkey = str(envelope.get("pubkey") or "").strip()
    return _sha256_hex(_relay_signing_material(envelope) + b"|" + pubkey.encode("utf-8"))




def _clean_relay_ids(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        return ()
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        rid = str(raw or "").strip()
        if not rid or rid in seen:
            continue
        seen.add(rid)
        out.append(rid)
    return tuple(out)


def _relay_access_signing_material(request: Json) -> bytes:
    req_type = str(request.get("request_type") or "").strip().lower()
    relay_ids = _clean_relay_ids(request.get("relay_ids")) if req_type == "ack" else ()
    material = {
        "domain": _RELAY_ACCESS_DOMAIN,
        "version": int(request.get("version") or 1),
        "request_type": req_type,
        "chain_id": str(request.get("chain_id") or ""),
        "schema_version": str(request.get("schema_version") or ""),
        "tx_index_hash": str(request.get("tx_index_hash") or ""),
        "recipient_peer_id": str(request.get("recipient_peer_id") or ""),
        "nonce": str(request.get("nonce") or ""),
        "created_ms": int(request.get("created_ms") or 0),
        "expires_at_ms": int(request.get("expires_at_ms") or 0),
        "limit": int(request.get("limit") or 0) if req_type == "fetch" else 0,
        "relay_ids": list(relay_ids),
        "sig_profile": str(request.get("sig_profile") or LEGACY_ED25519_V1).strip(),
    }
    return _canonical_json_bytes(material)


def compute_relay_access_request_id(request: Json) -> str:
    pubkey = str(request.get("pubkey") or "").strip()
    return _sha256_hex(_relay_access_signing_material(request) + b"|" + pubkey.encode("utf-8"))


def make_relay_access_request(
    *,
    request_type: str,
    chain_id: str,
    schema_version: str,
    tx_index_hash: str,
    recipient_peer_id: str,
    pubkey: str,
    privkey: str,
    nonce: str,
    relay_ids: list[str] | tuple[str, ...] | None = None,
    limit: int = 0,
    now_ms: int | None = None,
    ttl_ms: int = 60_000,
    sig_profile: str | None = None,
) -> Json:
    created = int(now_ms if now_ms is not None else _now_ms())
    req_type = str(request_type or "").strip().lower()
    req: Json = {
        "version": 1,
        "request_type": req_type,
        "chain_id": str(chain_id or "").strip(),
        "schema_version": str(schema_version or "").strip(),
        "tx_index_hash": str(tx_index_hash or "").strip(),
        "recipient_peer_id": _clean_peer_id(recipient_peer_id),
        "nonce": str(nonce or "").strip(),
        "created_ms": created,
        "expires_at_ms": created + max(1, int(ttl_ms)),
        "pubkey": str(pubkey or "").strip(),
        "sig_profile": str(sig_profile or default_signature_profile_for_mode()).strip() or PQ_MLDSA_V1,
    }
    if req_type == "fetch":
        req["limit"] = max(1, int(limit or 1))
    elif req_type == "ack":
        req["relay_ids"] = list(_clean_relay_ids(relay_ids or ()))
    else:
        req["request_type"] = req_type
    req["sig_alg"] = "ML-DSA" if req["sig_profile"] == PQ_MLDSA_V1 else "Ed25519"
    req["sig"] = sign_signature_for_profile(
        sig_profile=str(req["sig_profile"]),
        message=_relay_access_signing_material(req),
        privkey=str(privkey),
        encoding="hex",
    )
    req["request_id"] = compute_relay_access_request_id(req)
    return req


def validate_relay_access_request(
    request: Any,
    *,
    cfg: RelayConfig,
    request_type: str,
    now_ms: int | None = None,
) -> Json:
    if not isinstance(request, dict):
        raise RelayEnvelopeError("relay_access_not_object")
    req = dict(request)
    try:
        version = int(req.get("version") or 0)
    except Exception as exc:
        raise RelayEnvelopeError("relay_access_bad_version") from exc
    if version != 1:
        raise RelayEnvelopeError("relay_access_bad_version")
    expected_type = str(request_type or "").strip().lower()
    req_type = str(req.get("request_type") or "").strip().lower()
    if req_type != expected_type or req_type not in {"fetch", "ack"}:
        raise RelayEnvelopeError("relay_access_bad_type")
    if str(req.get("chain_id") or "") != str(cfg.chain_id):
        raise RelayEnvelopeError("relay_access_chain_mismatch")
    if str(req.get("schema_version") or "") != str(cfg.schema_version):
        raise RelayEnvelopeError("relay_access_schema_mismatch")
    if str(req.get("tx_index_hash") or "") != str(cfg.tx_index_hash):
        raise RelayEnvelopeError("relay_access_tx_index_mismatch")
    recipient = _clean_peer_id(req.get("recipient_peer_id"))
    if not recipient:
        raise RelayEnvelopeError("relay_access_missing_recipient")
    nonce = str(req.get("nonce") or "").strip()
    if not nonce:
        raise RelayEnvelopeError("relay_access_missing_nonce")
    now = int(now_ms if now_ms is not None else _now_ms())
    try:
        created_ms = int(req.get("created_ms") or 0)
        expires_at_ms = int(req.get("expires_at_ms") or 0)
    except Exception as exc:
        raise RelayEnvelopeError("relay_access_bad_time") from exc
    if created_ms <= 0 or expires_at_ms <= 0 or expires_at_ms <= created_ms:
        raise RelayEnvelopeError("relay_access_bad_time")
    if expires_at_ms <= now:
        raise RelayEnvelopeError("relay_access_expired")
    if created_ms > now + 5 * 60 * 1000:
        raise RelayEnvelopeError("relay_access_created_in_future")
    if int(cfg.max_access_ttl_ms) > 0 and (expires_at_ms - created_ms) > int(cfg.max_access_ttl_ms):
        raise RelayEnvelopeError("relay_access_ttl_too_large")
    pubkey = str(req.get("pubkey") or "").strip()
    sig = str(req.get("sig") or "").strip()
    if not pubkey or not sig:
        raise RelayEnvelopeError("relay_access_missing_signature")
    sig_profile = str(req.get("sig_profile") or "").strip()
    if not sig_profile:
        sig_profile = LEGACY_ED25519_V1 if str(req.get("sig_alg") or "ed25519").lower() == "ed25519" else ""
    if not sig_profile:
        raise RelayEnvelopeError("relay_access_bad_sig_alg")
    req["sig_profile"] = sig_profile
    try:
        if not verify_signature_for_profile(
            sig_profile=sig_profile,
            message=_relay_access_signing_material(req),
            sig=sig,
            pubkey=pubkey,
        ):
            raise RelayEnvelopeError("relay_access_bad_signature")
    except RelayEnvelopeError:
        raise
    except Exception as exc:
        raise RelayEnvelopeError("relay_access_bad_signature") from exc
    if req_type == "fetch":
        try:
            req["limit"] = max(1, int(req.get("limit") or 1))
        except Exception as exc:
            raise RelayEnvelopeError("relay_access_bad_limit") from exc
    if req_type == "ack":
        ids = _clean_relay_ids(req.get("relay_ids"))
        if not ids:
            raise RelayEnvelopeError("relay_access_missing_relay_ids")
        req["relay_ids"] = list(ids)
    request_id = str(req.get("request_id") or "").strip()
    expected_request_id = compute_relay_access_request_id(req)
    if request_id and request_id != expected_request_id:
        raise RelayEnvelopeError("relay_access_id_mismatch")
    req["request_id"] = expected_request_id
    return req

def make_relay_envelope(
    *,
    message: WireMessage | Json | bytes | str,
    chain_id: str,
    schema_version: str,
    tx_index_hash: str,
    sender_peer_id: str,
    recipient_peer_id: str,
    recipient_pubkey: str | None = None,
    pubkey: str,
    privkey: str,
    nonce: str,
    now_ms: int | None = None,
    ttl_ms: int = 60_000,
    sig_profile: str | None = None,
) -> Json:
    payload = _wire_payload_to_json(message)
    msg_type = _msg_type_from_payload(payload)
    created = int(now_ms if now_ms is not None else _now_ms())
    ttl = max(1, int(ttl_ms))
    envelope: Json = {
        "version": 1,
        "chain_id": str(chain_id or "").strip(),
        "schema_version": str(schema_version or "").strip(),
        "tx_index_hash": str(tx_index_hash or "").strip(),
        "sender_peer_id": _clean_peer_id(sender_peer_id),
        "recipient_peer_id": _clean_peer_id(recipient_peer_id),
        "recipient_pubkey": str(recipient_pubkey or "").strip(),
        "msg_type": msg_type,
        "nonce": str(nonce or "").strip(),
        "created_ms": created,
        "expires_at_ms": created + ttl,
        "payload": payload,
        "payload_hash": _payload_hash(payload),
        "pubkey": str(pubkey or "").strip(),
        "sig_profile": str(sig_profile or default_signature_profile_for_mode()).strip() or PQ_MLDSA_V1,
    }
    envelope["sig_alg"] = "ML-DSA" if envelope["sig_profile"] == PQ_MLDSA_V1 else "Ed25519"
    envelope["sig"] = sign_signature_for_profile(
        sig_profile=str(envelope["sig_profile"]),
        message=_relay_signing_material(envelope),
        privkey=str(privkey),
        encoding="hex",
    )
    envelope["relay_id"] = compute_relay_id(envelope)
    return envelope


def validate_relay_envelope(envelope: Any, *, cfg: RelayConfig, now_ms: int | None = None) -> Json:
    if not isinstance(envelope, dict):
        raise RelayEnvelopeError("relay_envelope_not_object")
    env = dict(envelope)
    try:
        version = int(env.get("version") or 0)
    except Exception as exc:
        raise RelayEnvelopeError("relay_bad_version") from exc
    if version != 1:
        raise RelayEnvelopeError("relay_bad_version")

    if str(env.get("chain_id") or "") != str(cfg.chain_id):
        raise RelayEnvelopeError("relay_chain_mismatch")
    if str(env.get("schema_version") or "") != str(cfg.schema_version):
        raise RelayEnvelopeError("relay_schema_mismatch")
    if str(env.get("tx_index_hash") or "") != str(cfg.tx_index_hash):
        raise RelayEnvelopeError("relay_tx_index_mismatch")

    sender = _clean_peer_id(env.get("sender_peer_id"))
    recipient = _clean_peer_id(env.get("recipient_peer_id"))
    if not sender:
        raise RelayEnvelopeError("relay_missing_sender")
    if not recipient:
        raise RelayEnvelopeError("relay_missing_recipient")
    if recipient == "*" and not bool(cfg.allow_broadcast_recipient):
        raise RelayEnvelopeError("relay_broadcast_disabled")
    recipient_pubkey = str(env.get("recipient_pubkey") or "").strip()
    if recipient_pubkey and len(recipient_pubkey) < 16:
        raise RelayEnvelopeError("relay_bad_recipient_pubkey")
    if bool(cfg.require_recipient_pubkey) and recipient != "*" and not recipient_pubkey:
        raise RelayEnvelopeError("relay_missing_recipient_pubkey")

    payload = env.get("payload")
    if not isinstance(payload, dict):
        raise RelayEnvelopeError("relay_payload_not_object")
    try:
        # Ensure the nested message is a valid known WeAll wire message.
        decode_message(dumps_json(payload))
    except Exception as exc:
        raise RelayEnvelopeError("relay_payload_decode_failed") from exc
    msg_type = _msg_type_from_payload(payload)
    if msg_type not in _ALLOWED_RELAY_TYPES:
        raise RelayEnvelopeError("relay_msg_type_not_allowed")
    if str(env.get("msg_type") or "") != msg_type:
        raise RelayEnvelopeError("relay_msg_type_mismatch")

    header = payload.get("header") if isinstance(payload.get("header"), dict) else {}
    if str(header.get("chain_id") or "") != str(cfg.chain_id):
        raise RelayEnvelopeError("relay_payload_chain_mismatch")
    if str(header.get("schema_version") or "") != str(cfg.schema_version):
        raise RelayEnvelopeError("relay_payload_schema_mismatch")
    if str(header.get("tx_index_hash") or "") != str(cfg.tx_index_hash):
        raise RelayEnvelopeError("relay_payload_tx_index_mismatch")

    size = len(_canonical_json_bytes(payload))
    if int(cfg.max_payload_bytes) > 0 and size > int(cfg.max_payload_bytes):
        raise RelayEnvelopeError("relay_payload_too_large")

    now = int(now_ms if now_ms is not None else _now_ms())
    try:
        created_ms = int(env.get("created_ms") or 0)
        expires_at_ms = int(env.get("expires_at_ms") or 0)
    except Exception as exc:
        raise RelayEnvelopeError("relay_bad_time") from exc
    if created_ms <= 0 or expires_at_ms <= 0 or expires_at_ms <= created_ms:
        raise RelayEnvelopeError("relay_bad_time")
    if expires_at_ms <= now:
        raise RelayEnvelopeError("relay_expired")
    if created_ms > now + 5 * 60 * 1000:
        raise RelayEnvelopeError("relay_created_in_future")
    if int(cfg.max_ttl_ms) > 0 and (expires_at_ms - created_ms) > int(cfg.max_ttl_ms):
        raise RelayEnvelopeError("relay_ttl_too_large")

    expected_payload_hash = _payload_hash(payload)
    if str(env.get("payload_hash") or "") != expected_payload_hash:
        raise RelayEnvelopeError("relay_payload_hash_mismatch")

    pubkey = str(env.get("pubkey") or "").strip()
    sig = str(env.get("sig") or "").strip()
    if not pubkey or not sig:
        raise RelayEnvelopeError("relay_missing_signature")
    sig_profile = str(env.get("sig_profile") or "").strip()
    if not sig_profile:
        sig_profile = LEGACY_ED25519_V1 if str(env.get("sig_alg") or "ed25519").lower() == "ed25519" else ""
    if not sig_profile:
        raise RelayEnvelopeError("relay_bad_sig_alg")
    env["sig_profile"] = sig_profile
    try:
        if not verify_signature_for_profile(
            sig_profile=sig_profile,
            message=_relay_signing_material(env),
            sig=sig,
            pubkey=pubkey,
        ):
            raise RelayEnvelopeError("relay_bad_signature")
    except RelayEnvelopeError:
        raise
    except Exception as exc:
        raise RelayEnvelopeError("relay_bad_signature") from exc

    relay_id = str(env.get("relay_id") or "").strip()
    expected_relay_id = compute_relay_id(env)
    if relay_id and relay_id != expected_relay_id:
        raise RelayEnvelopeError("relay_id_mismatch")
    env["relay_id"] = expected_relay_id
    env["payload_hash"] = expected_payload_hash
    return env


class RelaySpool:
    """SQLite-backed durable relay mailbox.

    Fetch is at-least-once and explicit ack removes delivered messages. The
    consumer side must still dedupe messages by their native tx/BFT identity.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        p = Path(self.path)
        if p.parent and str(p.parent) != ".":
            p.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        return con

    def _init_db(self) -> None:
        with self._connect() as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS relay_messages (
                    relay_id TEXT PRIMARY KEY,
                    recipient_peer_id TEXT NOT NULL,
                    sender_peer_id TEXT NOT NULL,
                    chain_id TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    tx_index_hash TEXT NOT NULL,
                    recipient_pubkey TEXT NOT NULL DEFAULT '',
                    msg_type TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    created_ms INTEGER NOT NULL,
                    expires_at_ms INTEGER NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_fetch_ms INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            try:
                con.execute("ALTER TABLE relay_messages ADD COLUMN recipient_pubkey TEXT NOT NULL DEFAULT ''")
            except sqlite3.OperationalError:
                pass
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_relay_recipient_expiry ON relay_messages(recipient_peer_id, expires_at_ms, created_ms)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_relay_recipient_pubkey ON relay_messages(recipient_peer_id, recipient_pubkey)"
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS relay_access_nonces (
                    request_id TEXT PRIMARY KEY,
                    recipient_peer_id TEXT NOT NULL,
                    request_type TEXT NOT NULL,
                    created_ms INTEGER NOT NULL,
                    expires_at_ms INTEGER NOT NULL
                )
                """
            )

    def prune(self, *, now_ms: int | None = None) -> int:
        now = int(now_ms if now_ms is not None else _now_ms())
        with self._connect() as con:
            cur = con.execute("DELETE FROM relay_messages WHERE expires_at_ms <= ?", (now,))
            deleted = int(cur.rowcount or 0)
            con.execute("DELETE FROM relay_access_nonces WHERE expires_at_ms <= ?", (now,))
            return deleted

    def submit(self, envelope: Any, *, cfg: RelayConfig, now_ms: int | None = None) -> Json:
        now = int(now_ms if now_ms is not None else _now_ms())
        env = validate_relay_envelope(envelope, cfg=cfg, now_ms=now)
        self.prune(now_ms=now)
        raw = json.dumps(env, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with self._connect() as con:
            con.execute(
                """
                INSERT OR IGNORE INTO relay_messages(
                    relay_id, recipient_peer_id, sender_peer_id, chain_id, schema_version,
                    tx_index_hash, recipient_pubkey, msg_type, envelope_json, created_ms, expires_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(env["relay_id"]),
                    str(env["recipient_peer_id"]),
                    str(env["sender_peer_id"]),
                    str(env["chain_id"]),
                    str(env["schema_version"]),
                    str(env["tx_index_hash"]),
                    str(env.get("recipient_pubkey") or ""),
                    str(env["msg_type"]),
                    raw,
                    int(env["created_ms"]),
                    int(env["expires_at_ms"]),
                ),
            )
        return {"relay_id": str(env["relay_id"]), "msg_type": str(env["msg_type"])}


    def _consume_access_request(self, req: Json) -> None:
        rid = str(req.get("request_id") or "").strip()
        if not rid:
            raise RelayEnvelopeError("relay_access_missing_request_id")
        with self._connect() as con:
            try:
                con.execute(
                    """
                    INSERT INTO relay_access_nonces(
                        request_id, recipient_peer_id, request_type, created_ms, expires_at_ms
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        rid,
                        str(req.get("recipient_peer_id") or ""),
                        str(req.get("request_type") or ""),
                        int(req.get("created_ms") or 0),
                        int(req.get("expires_at_ms") or 0),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise RelayEnvelopeError("relay_access_replay") from exc

    def fetch(
        self,
        *,
        recipient_peer_id: str,
        cfg: RelayConfig,
        limit: int = 100,
        now_ms: int | None = None,
    ) -> tuple[Json, ...]:
        now = int(now_ms if now_ms is not None else _now_ms())
        recipient = _clean_peer_id(recipient_peer_id)
        if not recipient:
            raise RelayEnvelopeError("relay_missing_recipient")
        self.prune(now_ms=now)
        cap = min(max(1, int(limit or 1)), max(1, int(cfg.max_fetch_limit)))
        with self._connect() as con:
            rows = con.execute(
                """
                SELECT relay_id, envelope_json FROM relay_messages
                WHERE recipient_peer_id = ? AND expires_at_ms > ?
                ORDER BY created_ms ASC, relay_id ASC
                LIMIT ?
                """,
                (recipient, now, cap),
            ).fetchall()
            relay_ids = [str(r["relay_id"]) for r in rows]
            if relay_ids:
                con.executemany(
                    "UPDATE relay_messages SET attempts = attempts + 1, last_fetch_ms = ? WHERE relay_id = ?",
                    [(now, rid) for rid in relay_ids],
                )
        out: list[Json] = []
        for row in rows:
            try:
                env = json.loads(str(row["envelope_json"] or "{}"))
                out.append(validate_relay_envelope(env, cfg=cfg, now_ms=now))
            except Exception:
                # Bad stored rows should not poison fetch; prune them by ID.
                try:
                    self.ack(recipient_peer_id=recipient, relay_ids=(str(row["relay_id"]),))
                except Exception:
                    pass
        return tuple(out)


    def fetch_authorized(
        self,
        *,
        access_request: Any,
        cfg: RelayConfig,
        limit: int | None = None,
        now_ms: int | None = None,
    ) -> tuple[Json, ...]:
        now = int(now_ms if now_ms is not None else _now_ms())
        req = validate_relay_access_request(access_request, cfg=cfg, request_type="fetch", now_ms=now)
        self._consume_access_request(req)
        requested_limit = int(limit or req.get("limit") or 1)
        recipient = _clean_peer_id(req.get("recipient_peer_id"))
        pubkey = str(req.get("pubkey") or "").strip()
        if not pubkey:
            raise RelayEnvelopeError("relay_access_missing_signature")
        self.prune(now_ms=now)
        cap = min(max(1, requested_limit), max(1, int(cfg.max_fetch_limit)))
        with self._connect() as con:
            if bool(cfg.allow_unbound_recipient_fetch):
                rows = con.execute(
                    """
                    SELECT relay_id, envelope_json FROM relay_messages
                    WHERE recipient_peer_id = ? AND expires_at_ms > ?
                      AND (recipient_pubkey = ? OR recipient_pubkey = '')
                    ORDER BY created_ms ASC, relay_id ASC
                    LIMIT ?
                    """,
                    (recipient, now, pubkey, cap),
                ).fetchall()
            else:
                rows = con.execute(
                    """
                    SELECT relay_id, envelope_json FROM relay_messages
                    WHERE recipient_peer_id = ? AND expires_at_ms > ? AND recipient_pubkey = ?
                    ORDER BY created_ms ASC, relay_id ASC
                    LIMIT ?
                    """,
                    (recipient, now, pubkey, cap),
                ).fetchall()
            relay_ids = [str(r["relay_id"]) for r in rows]
            if relay_ids:
                con.executemany(
                    "UPDATE relay_messages SET attempts = attempts + 1, last_fetch_ms = ? WHERE relay_id = ?",
                    [(now, rid) for rid in relay_ids],
                )
        out: list[Json] = []
        for row in rows:
            try:
                env = json.loads(str(row["envelope_json"] or "{}"))
                out.append(validate_relay_envelope(env, cfg=cfg, now_ms=now))
            except Exception:
                try:
                    self.ack(recipient_peer_id=recipient, relay_ids=(str(row["relay_id"]),))
                except Exception:
                    pass
        return tuple(out)

    def ack_authorized(self, *, access_request: Any, cfg: RelayConfig, now_ms: int | None = None) -> int:
        now = int(now_ms if now_ms is not None else _now_ms())
        req = validate_relay_access_request(access_request, cfg=cfg, request_type="ack", now_ms=now)
        self._consume_access_request(req)
        recipient = _clean_peer_id(req.get("recipient_peer_id"))
        pubkey = str(req.get("pubkey") or "").strip()
        ids = _clean_relay_ids(req.get("relay_ids"))
        if not ids:
            return 0
        with self._connect() as con:
            deleted = 0
            for rid in ids:
                if bool(cfg.allow_unbound_recipient_fetch):
                    cur = con.execute(
                        "DELETE FROM relay_messages WHERE recipient_peer_id = ? AND relay_id = ? AND (recipient_pubkey = ? OR recipient_pubkey = '')",
                        (recipient, rid, pubkey),
                    )
                else:
                    cur = con.execute(
                        "DELETE FROM relay_messages WHERE recipient_peer_id = ? AND relay_id = ? AND recipient_pubkey = ?",
                        (recipient, rid, pubkey),
                    )
                deleted += int(cur.rowcount or 0)
            return int(deleted)

    def ack(self, *, recipient_peer_id: str, relay_ids: tuple[str, ...] | list[str]) -> int:
        recipient = _clean_peer_id(recipient_peer_id)
        if not recipient:
            raise RelayEnvelopeError("relay_missing_recipient")
        ids = tuple(str(x or "").strip() for x in relay_ids if str(x or "").strip())
        if not ids:
            return 0
        with self._connect() as con:
            cur = con.executemany(
                "DELETE FROM relay_messages WHERE recipient_peer_id = ? AND relay_id = ?",
                [(recipient, rid) for rid in ids],
            )
            return int(cur.rowcount or 0)

    def status(self, *, now_ms: int | None = None, include_recipients: bool = True) -> Json:
        now = int(now_ms if now_ms is not None else _now_ms())
        self.prune(now_ms=now)
        with self._connect() as con:
            total = int(con.execute("SELECT COUNT(*) FROM relay_messages").fetchone()[0])
            by_type = [
                {"msg_type": str(row[0]), "count": int(row[1])}
                for row in con.execute(
                    "SELECT msg_type, COUNT(*) FROM relay_messages GROUP BY msg_type ORDER BY msg_type"
                ).fetchall()
            ]
            by_recipient = [
                {"recipient_peer_id": str(row[0]), "count": int(row[1])}
                for row in con.execute(
                    "SELECT recipient_peer_id, COUNT(*) FROM relay_messages GROUP BY recipient_peer_id ORDER BY recipient_peer_id LIMIT 50"
                ).fetchall()
            ]
        out = {"messages_total": total, "by_type": by_type}
        if bool(include_recipients):
            out["by_recipient"] = by_recipient
        return out


def decode_relay_payload(envelope: Json) -> WireMessage:
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise RelayEnvelopeError("relay_payload_not_object")
    return decode_message(dumps_json(payload))
