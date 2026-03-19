from __future__ import annotations

import os
import time
from collections.abc import Iterable
from dataclasses import dataclass


def _now_ms() -> int:
    return int(time.time() * 1000)


def _norm_uri(uri: str) -> str:
    return str(uri or "").strip()


def _is_supported_uri(uri: str) -> bool:
    return uri.startswith("tcp://") or uri.startswith("tls://")


def _atomic_write_text(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


@dataclass
class PeerListStore:
    """A tiny persistent peer list store.

    File format:
      - One URI per line
      - Lines starting with '#' are comments
      - Empty/whitespace lines are ignored

    This store is intentionally simple: it is meant for bootstrapping a mesh.
    Security decisions live elsewhere (strikes/bans/scores).
    """

    path: str
    max_peers: int = 1000

    # Debounce writes in hot loops.
    min_write_interval_ms: int = 2_000

    _last_write_ms: int = 0

    def load(self) -> list[str]:
        p = str(self.path or "").strip()
        if not p:
            return []
        try:
            with open(p, encoding="utf-8") as f:
                raw = f.read().splitlines()
        except FileNotFoundError:
            return []
        except Exception:
            return []

        out: list[str] = []
        seen: set[str] = set()
        for line in raw:
            s = (line or "").strip()
            if not s or s.startswith("#"):
                continue
            s = _norm_uri(s)
            if not s or not _is_supported_uri(s):
                continue
            if s in seen:
                continue
            seen.add(s)
            out.append(s)
            if len(out) >= int(self.max_peers):
                break
        return out

    # Backwards-compatible alias for older callsites.
    def read_list(self) -> list[str]:
        return self.load()

    def save(self, peers: Iterable[str], *, force: bool = False) -> None:
        p = str(self.path or "").strip()
        if not p:
            return

        now = _now_ms()
        if not force and (now - int(self._last_write_ms or 0)) < int(self.min_write_interval_ms):
            return

        cleaned: list[str] = []
        seen: set[str] = set()
        for uri in peers:
            s = _norm_uri(str(uri))
            if not s or not _is_supported_uri(s):
                continue
            if s in seen:
                continue
            seen.add(s)
            cleaned.append(s)
            if len(cleaned) >= int(self.max_peers):
                break

        header = "# WeAll peer list (auto-managed)\n# One peer URI per line.\n"
        body = "\n".join(cleaned) + ("\n" if cleaned else "")
        try:
            _atomic_write_text(p, header + body)
            self._last_write_ms = now
        except Exception:
            return

    # Backwards-compatible alias for older callsites.
    def write_list(self, peers: Iterable[str], *, force: bool = False) -> None:
        self.save(peers, force=force)

    def merge(self, peers: Iterable[str], *, force: bool = False) -> list[str]:
        """Merge peers into the persisted list and return the merged list.

        This is intended for bootstrapping: the node can merge env/seed peers
        into the local peer list file without duplications.
        """

        existing = self.load()
        merged: list[str] = []
        seen: set[str] = set()

        for uri in list(existing) + [str(p) for p in peers]:
            s = _norm_uri(uri)
            if not s or not _is_supported_uri(s):
                continue
            if s in seen:
                continue
            seen.add(s)
            merged.append(s)
            if len(merged) >= int(self.max_peers):
                break

        self.save(merged, force=force)
        return merged
