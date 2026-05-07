from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

Json = dict[str, Any]

_CHALLENGE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DEFAULT_MAX_PROBE_BYTES = 64 * 1024 * 1024


class StorageProbeRunnerError(ValueError):
    """Raised when local storage probe preparation or verification fails closed."""


@dataclass(frozen=True, slots=True)
class ProbePaths:
    root: Path
    challenge_dir: Path
    segments_dir: Path
    manifest_path: Path


def _as_dict(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _as_str(value: Any) -> str:
    try:
        return str(value or "").strip()
    except Exception:
        return ""


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + _sha256_hex(encoded)


def _require_safe_challenge_id(challenge_id: str) -> str:
    challenge_id = _as_str(challenge_id)
    if not challenge_id:
        raise StorageProbeRunnerError("challenge_id_required")
    if not _CHALLENGE_ID_RE.match(challenge_id):
        raise StorageProbeRunnerError("unsafe_challenge_id")
    if ".." in challenge_id or "/" in challenge_id or "\\" in challenge_id:
        raise StorageProbeRunnerError("unsafe_challenge_id")
    return challenge_id


def _resolve_root(storage_root: str | os.PathLike[str], *, create: bool = False) -> Path:
    root = Path(storage_root).expanduser()
    if create:
        root.mkdir(parents=True, exist_ok=True)
    resolved = root.resolve()
    if not resolved.exists() or not resolved.is_dir():
        raise StorageProbeRunnerError("storage_root_must_be_existing_directory")
    return resolved


def _ensure_within_root(root: Path, path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise StorageProbeRunnerError("path_escape_rejected") from exc
    return resolved


def probe_paths(storage_root: str | os.PathLike[str], challenge_id: str, *, create_root: bool = False) -> ProbePaths:
    root = _resolve_root(storage_root, create=create_root)
    cid = _require_safe_challenge_id(challenge_id)
    challenge_dir = _ensure_within_root(root, root / "probes" / cid)
    segments_dir = _ensure_within_root(root, challenge_dir / "segments")
    manifest_path = _ensure_within_root(root, challenge_dir / "manifest.json")
    return ProbePaths(root=root, challenge_dir=challenge_dir, segments_dir=segments_dir, manifest_path=manifest_path)


def available_bytes(storage_root: str | os.PathLike[str]) -> int:
    root = _resolve_root(storage_root, create=False)
    return int(shutil.disk_usage(root).free)


def _probe_offsets(challenge: Mapping[str, Any]) -> list[int]:
    raw = challenge.get("probe_offsets")
    if not isinstance(raw, list):
        raise StorageProbeRunnerError("probe_offsets_required")
    offsets: list[int] = []
    seen: set[int] = set()
    for item in raw:
        offset = _as_int(item, -1)
        if offset < 0:
            raise StorageProbeRunnerError("probe_offset_must_be_non_negative")
        if offset not in seen:
            offsets.append(offset)
            seen.add(offset)
    if not offsets:
        raise StorageProbeRunnerError("probe_offsets_required")
    return offsets


def normalize_capacity_probe_challenge(challenge: Mapping[str, Any]) -> Json:
    src = _as_dict(challenge)
    challenge_id = _require_safe_challenge_id(_as_str(src.get("challenge_id") or src.get("id")))
    reserved = _as_int(src.get("reserved_capacity_bytes") or src.get("challenged_capacity_bytes") or src.get("capacity_bytes"), 0)
    declared = _as_int(src.get("declared_capacity_bytes"), reserved)
    sample_size = _as_int(src.get("sample_size_bytes") or src.get("sample_bytes"), 0)
    offsets = _probe_offsets(src)
    sample_count = _as_int(src.get("sample_count") or src.get("challenge_count"), len(offsets))
    expires_height = _as_int(src.get("expires_height") or src.get("expiry_height"), 0)
    seed = _as_str(src.get("challenge_seed") or src.get("challenge_seed_commitment") or src.get("seed") or challenge_id)
    if declared <= 0:
        raise StorageProbeRunnerError("declared_capacity_required")
    if reserved <= 0:
        raise StorageProbeRunnerError("reserved_capacity_required")
    if reserved > declared:
        raise StorageProbeRunnerError("reserved_capacity_exceeds_declared_capacity")
    if sample_size <= 0:
        raise StorageProbeRunnerError("sample_size_required")
    if sample_size > reserved:
        raise StorageProbeRunnerError("sample_size_exceeds_reserved_capacity")
    if sample_count <= 0:
        raise StorageProbeRunnerError("sample_count_required")
    if len(offsets) < sample_count:
        raise StorageProbeRunnerError("insufficient_probe_offsets")
    max_offset = max(0, int(reserved) - int(sample_size))
    for offset in offsets[:sample_count]:
        if offset < 0 or offset > max_offset:
            raise StorageProbeRunnerError("probe_offset_out_of_reserved_range")
    return {
        "proof_scope": "capacity_probe",
        "challenge_id": challenge_id,
        "account_id": _as_str(src.get("account_id") or src.get("operator_id") or src.get("operator")),
        "node_pubkey": _as_str(src.get("node_pubkey") or src.get("node_public_key")),
        "declared_capacity_bytes": int(declared),
        "reserved_capacity_bytes": int(reserved),
        "sample_count": int(sample_count),
        "sample_size_bytes": int(sample_size),
        "probe_offsets": [int(v) for v in offsets[:sample_count]],
        "challenge_seed": seed,
        "expires_height": int(expires_height),
    }


def _segment_name(offset: int, sample_size: int) -> str:
    return f"offset-{int(offset):020d}-size-{int(sample_size):020d}.probe"


def _segment_bytes(challenge: Mapping[str, Any], offset: int, sample_size: int) -> bytes:
    seed = _as_str(challenge.get("challenge_seed") or challenge.get("challenge_id"))
    challenge_id = _as_str(challenge.get("challenge_id"))
    header = f"weall-storage-probe-v1|{challenge_id}|{seed}|{int(offset)}|{int(sample_size)}|".encode("utf-8")
    out = bytearray()
    counter = 0
    while len(out) < sample_size:
        out.extend(hashlib.sha256(header + str(counter).encode("ascii")).digest())
        counter += 1
    return bytes(out[:sample_size])


def _segment_hash(challenge: Mapping[str, Any], offset: int, sample_size: int) -> str:
    return "sha256:" + _sha256_hex(_segment_bytes(challenge, offset, sample_size))


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)


def _write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    encoded = json.dumps(value, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    _write_atomic(path, encoded)


def prepare_capacity_probe(
    storage_root: str | os.PathLike[str],
    challenge: Mapping[str, Any],
    *,
    available_capacity_bytes: int | None = None,
    max_probe_bytes: int = _DEFAULT_MAX_PROBE_BYTES,
) -> Json:
    normalized = normalize_capacity_probe_challenge(challenge)
    paths = probe_paths(storage_root, normalized["challenge_id"], create_root=True)
    reserved = int(normalized["reserved_capacity_bytes"])
    sample_size = int(normalized["sample_size_bytes"])
    offsets = [int(v) for v in normalized["probe_offsets"]]
    total_probe_bytes = int(sample_size) * len(offsets)
    if max_probe_bytes > 0 and total_probe_bytes > int(max_probe_bytes):
        raise StorageProbeRunnerError("probe_material_exceeds_local_limit")
    available = int(available_capacity_bytes) if available_capacity_bytes is not None else available_bytes(paths.root)
    if available < reserved:
        raise StorageProbeRunnerError("insufficient_available_disk_for_declared_capacity")
    paths.segments_dir.mkdir(parents=True, exist_ok=True)
    segment_records: list[Json] = []
    for offset in offsets:
        segment_path = _ensure_within_root(paths.root, paths.segments_dir / _segment_name(offset, sample_size))
        data = _segment_bytes(normalized, offset, sample_size)
        _write_atomic(segment_path, data)
        segment_records.append({"offset": int(offset), "size": int(sample_size), "path": str(segment_path.relative_to(paths.root)), "response_hash": "sha256:" + _sha256_hex(data)})
    manifest: Json = {
        "version": 1,
        "kind": "weall.storage.capacity_probe.local_manifest",
        "challenge": normalized,
        "storage_root": str(paths.root),
        "challenge_dir": str(paths.challenge_dir.relative_to(paths.root)),
        "segments": segment_records,
        "total_probe_bytes": int(total_probe_bytes),
        "reserved_capacity_bytes": int(reserved),
        "available_capacity_bytes_at_prepare": int(available),
        "manifest_hash": "",
    }
    manifest["manifest_hash"] = _hash_json({k: v for k, v in manifest.items() if k != "manifest_hash"})
    paths.challenge_dir.mkdir(parents=True, exist_ok=True)
    _write_json_atomic(paths.manifest_path, manifest)
    return manifest


def load_probe_manifest(storage_root: str | os.PathLike[str], challenge_id: str) -> Json:
    paths = probe_paths(storage_root, challenge_id, create_root=False)
    if not paths.manifest_path.exists():
        raise StorageProbeRunnerError("probe_manifest_not_found")
    try:
        return _as_dict(json.loads(paths.manifest_path.read_text(encoding="utf-8")))
    except json.JSONDecodeError as exc:
        raise StorageProbeRunnerError("probe_manifest_invalid_json") from exc


def generate_probe_response(storage_root: str | os.PathLike[str], challenge_id: str) -> Json:
    manifest = load_probe_manifest(storage_root, challenge_id)
    challenge = normalize_capacity_probe_challenge(_as_dict(manifest.get("challenge")))
    paths = probe_paths(storage_root, challenge["challenge_id"], create_root=False)
    sample_size = int(challenge["sample_size_bytes"])
    responses: list[Json] = []
    for offset in [int(v) for v in challenge["probe_offsets"]]:
        segment_path = _ensure_within_root(paths.root, paths.segments_dir / _segment_name(offset, sample_size))
        if not segment_path.exists():
            raise StorageProbeRunnerError("probe_segment_missing")
        data = segment_path.read_bytes()
        expected = _segment_bytes(challenge, offset, sample_size)
        if data != expected:
            raise StorageProbeRunnerError("probe_segment_corrupt")
        responses.append({"offset": int(offset), "size": int(sample_size), "response_hash": "sha256:" + _sha256_hex(data)})
    response: Json = {"challenge_id": challenge["challenge_id"], "node_pubkey": challenge.get("node_pubkey") or None, "probe_responses": responses, "response_commitment": ""}
    response["response_commitment"] = _hash_json(responses)
    return response


def verify_probe_response(challenge: Mapping[str, Any], response: Mapping[str, Any]) -> Json:
    normalized = normalize_capacity_probe_challenge(challenge)
    resp = _as_dict(response)
    if _as_str(resp.get("challenge_id")) != normalized["challenge_id"]:
        raise StorageProbeRunnerError("challenge_id_mismatch")
    raw_responses = resp.get("probe_responses")
    if not isinstance(raw_responses, list):
        raise StorageProbeRunnerError("probe_responses_required")
    expected_offsets = [int(v) for v in normalized["probe_offsets"]]
    sample_size = int(normalized["sample_size_bytes"])
    by_offset: dict[int, Mapping[str, Any]] = {}
    for item in raw_responses:
        rec = _as_dict(item)
        offset = _as_int(rec.get("offset"), -1)
        if offset in by_offset:
            raise StorageProbeRunnerError("duplicate_probe_response_offset")
        by_offset[offset] = rec
    verified: list[Json] = []
    for offset in expected_offsets:
        rec = by_offset.get(offset)
        if not isinstance(rec, Mapping):
            raise StorageProbeRunnerError("missing_probe_response_offset")
        size = _as_int(rec.get("size"), 0)
        if size != sample_size:
            raise StorageProbeRunnerError("probe_response_size_mismatch")
        expected_hash = _segment_hash(normalized, offset, sample_size)
        if _as_str(rec.get("response_hash")) != expected_hash:
            raise StorageProbeRunnerError("probe_response_hash_mismatch")
        verified.append({"offset": int(offset), "size": int(sample_size), "response_hash": expected_hash})
    expected_commitment = _hash_json(verified)
    supplied_commitment = _as_str(resp.get("response_commitment"))
    if supplied_commitment and supplied_commitment != expected_commitment:
        raise StorageProbeRunnerError("response_commitment_mismatch")
    return {"challenge_id": normalized["challenge_id"], "verification_status": "verified", "verified_capacity_bytes": int(normalized["reserved_capacity_bytes"]), "probed_capacity_bytes": int(normalized["reserved_capacity_bytes"]), "sample_count": len(verified), "sample_size_bytes": int(sample_size), "response_commitment": expected_commitment, "verification_receipt_hash": _hash_json({"challenge": normalized, "responses": verified})}


def cleanup_expired_probes(storage_root: str | os.PathLike[str], *, current_height: int) -> Json:
    root = _resolve_root(storage_root, create=False)
    probes_dir = _ensure_within_root(root, root / "probes")
    removed: list[str] = []
    kept: list[str] = []
    if not probes_dir.exists():
        return {"removed": removed, "kept": kept}
    for child in probes_dir.iterdir():
        if not child.is_dir():
            continue
        try:
            cid = _require_safe_challenge_id(child.name)
            manifest_path = _ensure_within_root(root, child / "manifest.json")
            if not manifest_path.exists():
                kept.append(cid)
                continue
            manifest = _as_dict(json.loads(manifest_path.read_text(encoding="utf-8")))
            challenge = normalize_capacity_probe_challenge(_as_dict(manifest.get("challenge")))
            expires_height = int(challenge.get("expires_height") or 0)
            if expires_height > 0 and int(current_height) > expires_height:
                shutil.rmtree(child)
                removed.append(cid)
            else:
                kept.append(cid)
        except Exception:
            kept.append(child.name)
    return {"removed": sorted(removed), "kept": sorted(kept)}


def probe_metrics(storage_root: str | os.PathLike[str]) -> Json:
    root = _resolve_root(storage_root, create=False)
    probes_dir = _ensure_within_root(root, root / "probes")
    active = 0
    total_bytes = 0
    if probes_dir.exists():
        for child in probes_dir.iterdir():
            if not child.is_dir():
                continue
            active += 1
            for file in child.rglob("*"):
                if file.is_file():
                    total_bytes += int(file.stat().st_size)
    return {"active_probe_count": int(active), "probe_bytes_on_disk": int(total_bytes), "storage_root": str(root)}


def _load_json_arg(value: str) -> Json:
    path = Path(value)
    if path.exists():
        return _as_dict(json.loads(path.read_text(encoding="utf-8")))
    return _as_dict(json.loads(value))


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="WeAll local storage capacity probe runner")
    sub = parser.add_subparsers(dest="command", required=True)
    p_prepare = sub.add_parser("prepare")
    p_prepare.add_argument("--storage-root", required=True)
    p_prepare.add_argument("--challenge", required=True)
    p_prepare.add_argument("--available-capacity-bytes", type=int, default=None)
    p_prepare.add_argument("--max-probe-bytes", type=int, default=_DEFAULT_MAX_PROBE_BYTES)
    p_respond = sub.add_parser("respond")
    p_respond.add_argument("--storage-root", required=True)
    p_respond.add_argument("--challenge-id", required=True)
    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--challenge", required=True)
    p_verify.add_argument("--response", required=True)
    p_cleanup = sub.add_parser("cleanup")
    p_cleanup.add_argument("--storage-root", required=True)
    p_cleanup.add_argument("--current-height", type=int, required=True)
    p_metrics = sub.add_parser("metrics")
    p_metrics.add_argument("--storage-root", required=True)
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command == "prepare":
        result = prepare_capacity_probe(args.storage_root, _load_json_arg(args.challenge), available_capacity_bytes=args.available_capacity_bytes, max_probe_bytes=args.max_probe_bytes)
    elif args.command == "respond":
        result = generate_probe_response(args.storage_root, args.challenge_id)
    elif args.command == "verify":
        result = verify_probe_response(_load_json_arg(args.challenge), _load_json_arg(args.response))
    elif args.command == "cleanup":
        result = cleanup_expired_probes(args.storage_root, current_height=args.current_height)
    elif args.command == "metrics":
        result = probe_metrics(args.storage_root)
    else:  # pragma: no cover
        raise StorageProbeRunnerError("unknown_command")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
