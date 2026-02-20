# src/weall/net/net_loop.py
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from weall.ledger.state import LedgerView
from weall.net.node import NetConfig, NetNode
from weall.net.state_sync import StateSyncService
from weall.net.messages import (
    MsgType,
    WireHeader,
    TxEnvelopeMsg,
    BftProposalMsg,
    BftVoteMsg,
    BftQcMsg,
    BftTimeoutMsg,
)
from weall.runtime.bft_hotstuff import leader_for_view, normalize_validators
from weall.runtime.tx_admission import admit_tx
from weall.tx.canon import TxIndex

Json = Dict[str, Any]


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return bool(default)
    return (v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return int(default)


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


@dataclass
class NetLoopConfig:
    enabled: bool
    bind_host: str
    bind_port: int
    tick_ms: int
    lock_path: str
    schema_version: str


def net_loop_config_from_env() -> NetLoopConfig:
    enabled = _env_bool("WEALL_NET_ENABLED", True)
    bind_host = os.environ.get("WEALL_NET_BIND_HOST", "0.0.0.0")
    bind_port = _env_int("WEALL_NET_BIND_PORT", 30303)
    tick_ms = max(5, _env_int("WEALL_NET_TICK_MS", 25))
    lock_path = os.environ.get("WEALL_NET_LOCK_PATH", "./data/net_loop.lock")
    schema_version = (os.environ.get("WEALL_NET_SCHEMA_VERSION") or "1").strip() or "1"
    return NetLoopConfig(
        enabled=bool(enabled),
        bind_host=str(bind_host),
        bind_port=int(bind_port),
        tick_ms=int(tick_ms),
        lock_path=str(lock_path),
        schema_version=str(schema_version),
    )


class _FileLock:
    def __init__(self, path: str) -> None:
        self._path = path
        self._fh = None

    def acquire(self) -> bool:
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        try:
            fh = open(self._path, "a+", encoding="utf-8")
        except Exception:
            return False
        try:
            import fcntl  # type: ignore
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:
            try:
                fh.close()
            except Exception:
                pass
            return False
        self._fh = fh
        return True

    def release(self) -> None:
        fh = self._fh
        self._fh = None
        if fh is None:
            return
        try:
            import fcntl  # type: ignore
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        try:
            fh.close()
        except Exception:
            pass


class NetMeshLoop:
    def __init__(self, *, executor, mempool, cfg: Optional[NetLoopConfig] = None) -> None:
        self._executor = executor
        self._mempool = mempool
        self._cfg = cfg or net_loop_config_from_env()

        self._lock = _FileLock(self._cfg.lock_path)
        self._stop = threading.Event()
        self._t: Optional[threading.Thread] = None
        self._started = False

        self.node: Optional[NetNode] = None

        try:
            tx_index_path = getattr(self._executor, "tx_index_path", None) or os.environ.get("WEALL_TX_INDEX_PATH", "./generated/tx_index.json")
            self._canon = TxIndex.load_from_file(str(tx_index_path))
        except Exception:
            self._canon = None

    @property
    def started(self) -> bool:
        return self._started

    def _state_provider(self) -> Json:
        ex = self._executor
        if hasattr(ex, "read_state") and callable(getattr(ex, "read_state")):
            st = ex.read_state()
            return st if isinstance(st, dict) else dict(st)
        if hasattr(ex, "snapshot") and callable(getattr(ex, "snapshot")):
            snap = ex.snapshot()
            if hasattr(snap, "to_dict") and callable(getattr(snap, "to_dict")):
                return snap.to_dict()
            return snap if isinstance(snap, dict) else dict(snap)
        return {}

    def start(self) -> bool:
        if self._started:
            return True
        if not self._cfg.enabled:
            return False
        if not self._lock.acquire():
            return False

        tx_index_hash_val = ""
        try:
            tx_index_hash = getattr(self._executor, "tx_index_hash", None)
            if callable(tx_index_hash):
                tx_index_hash_val = str(tx_index_hash())
        except Exception:
            pass

        chain_id = str(getattr(self._executor, "chain_id", os.environ.get("WEALL_CHAIN_ID", "weall")))
        peer_id = str(getattr(self._executor, "node_id", os.environ.get("WEALL_NODE_ID", "node")))

        sync = StateSyncService(
            chain_id=chain_id,
            schema_version=self._cfg.schema_version,
            tx_index_hash=tx_index_hash_val,
            state_provider=self._state_provider,
            enable_delta=True,
        )

        nc = NetConfig(
            chain_id=chain_id,
            schema_version=self._cfg.schema_version,
            tx_index_hash=tx_index_hash_val,
            peer_id=peer_id,
            agent="weall-node",
            caps=("tx_gossip", "state_sync", "bft"),
            identity_pubkey=(os.environ.get("WEALL_NODE_PUBKEY") or "").strip() or None,
            identity_privkey=(os.environ.get("WEALL_NODE_PRIVKEY") or "").strip() or None,
        )

        self.node = NetNode(
            cfg=nc,
            on_tx=self._on_tx,
            on_bft_proposal=self._on_bft_proposal,
            on_bft_vote=self._on_bft_vote,
            on_bft_qc=self._on_bft_qc,
            on_bft_timeout=self._on_bft_timeout,
            sync_service=sync,
            ledger_provider=self._state_provider,
        )
        self.node.bind(self._cfg.bind_host, self._cfg.bind_port)

        self._t = threading.Thread(target=self._run, name="weall-net-mesh", daemon=True)
        self._t.start()
        self._started = True
        return True

    def stop(self) -> None:
        self._stop.set()
        t = self._t
        if t is not None:
            try:
                t.join(timeout=2.0)
            except Exception:
                pass
        if self.node is not None:
            try:
                self.node.stop()
            except Exception:
                pass
        self._lock.release()

    def _run(self) -> None:
        assert self.node is not None
        tick_s = float(self._cfg.tick_ms) / 1000.0

        # Leader proposal tick
        bft_tick_ms = max(250, _env_int("WEALL_BFT_TICK_MS", 1000))
        last_bft = int(time.time() * 1000)

        while not self._stop.is_set():
            try:
                self.node.tick()
            except Exception:
                pass

            if _env_bool("WEALL_BFT_ENABLED", False):
                # timeouts are lightweight — we can check every loop
                self._bft_timeout_drive()

                now = int(time.time() * 1000)
                if now - last_bft >= bft_tick_ms:
                    last_bft = now
                    self._bft_drive()

            time.sleep(tick_s)

    # -------------------------
    # TX handler
    # -------------------------

    def _on_tx(self, peer_id: str, msg: TxEnvelopeMsg) -> None:
        try:
            tx = getattr(msg, "tx", None) or {}
            if not isinstance(tx, dict):
                return
            if self._canon is None:
                return
            st = self._state_provider()
            ledger = LedgerView.from_ledger(st)
            verdict = admit_tx(tx=tx, ledger=ledger, canon=self._canon, context="mempool")
            if not verdict.ok:
                return
            ex = self._executor
            if hasattr(ex, "submit_tx") and callable(getattr(ex, "submit_tx")):
                meta = ex.submit_tx(tx)
            else:
                meta = self._mempool.add(tx)
            if not isinstance(meta, dict) or not meta.get("ok"):
                return
        except Exception:
            return

    # -------------------------
    # BFT driving (leader proposals)
    # -------------------------

    def _extract_validators_and_view(self) -> tuple[list[str], int]:
        st = self._state_provider()
        validators: list[str] = []
        roles = st.get("roles")
        if isinstance(roles, dict):
            v = roles.get("validators")
            if isinstance(v, dict) and isinstance(v.get("active_set"), list):
                validators = [str(x).strip() for x in v.get("active_set") or [] if str(x).strip()]
        validators = normalize_validators(validators)

        view = 0
        bft = st.get("bft")
        if isinstance(bft, dict):
            view = int(bft.get("view") or 0)
        return validators, int(view)

    def _bft_drive(self) -> None:
        if self.node is None:
            return

        ex = self._executor
        if not hasattr(ex, "bft_leader_propose"):
            return

        try:
            validators, view = self._extract_validators_and_view()
            leader = leader_for_view(validators, view)
            local = (os.environ.get("WEALL_VALIDATOR_ACCOUNT") or getattr(ex, "node_id", "") or "").strip()
            if not local or not leader or local != leader:
                return
        except Exception:
            return

        try:
            blk = ex.bft_leader_propose(max_txs=max(1, _env_int("WEALL_BLOCK_MAX_TXS", 1000)))
            if not isinstance(blk, dict):
                return
            hdr = WireHeader(
                type=MsgType.BFT_PROPOSAL,
                chain_id=str(getattr(ex, "chain_id", "weall")),
                schema_version=self._cfg.schema_version,
                tx_index_hash=str(getattr(getattr(self, "_canon", None), "source_sha256", "")),
            )
            msg = BftProposalMsg(header=hdr, view=int(view), proposer=local, block=blk, justify_qc=_as_dict(blk.get("justify_qc")))
            self.node.broadcast_message(msg)
        except Exception:
            return

    def _bft_timeout_drive(self) -> None:
        if self.node is None:
            return
        ex = self._executor
        if not hasattr(ex, "bft_timeout_check"):
            return
        try:
            tmo = ex.bft_timeout_check()
            if not isinstance(tmo, dict):
                return
            hdr = WireHeader(
                type=MsgType.BFT_TIMEOUT,
                chain_id=str(getattr(ex, "chain_id", "weall")),
                schema_version=self._cfg.schema_version,
                tx_index_hash=str(getattr(getattr(self, "_canon", None), "source_sha256", "")),
            )
            msg = BftTimeoutMsg(header=hdr, view=int(tmo.get("view") or 0), timeout=tmo)
            self.node.broadcast_message(msg)
        except Exception:
            return

    # -------------------------
    # BFT handlers
    # -------------------------

    def _on_bft_proposal(self, peer_id: str, msg: BftProposalMsg) -> None:
        if not _env_bool("WEALL_BFT_ENABLED", False):
            return
        if self.node is None:
            return
        ex = self._executor
        if not hasattr(ex, "bft_make_vote_for_block"):
            return

        try:
            view = int(getattr(msg, "view"))
            blk = _as_dict(getattr(msg, "block"))
            bid = str(blk.get("block_id") or "").strip()
            parent = str(blk.get("prev_block_id") or blk.get("prev") or "").strip()
            if not bid:
                return

            # Safety: only vote if local executor says it's on the locked chain
            st = self._state_provider()
            blocks_map = st.get("blocks")
            if not isinstance(blocks_map, dict):
                blocks_map = {}
            can_vote = True
            try:
                bft = st.get("bft")
                if isinstance(bft, dict):
                    locked_qc = bft.get("locked_qc")
                    if isinstance(locked_qc, dict):
                        locked_bid = str(locked_qc.get("block_id") or "").strip()
                        if locked_bid and locked_bid in blocks_map:
                            cur = parent
                            ok = False
                            hops = 0
                            while cur and hops < 50000:
                                hops += 1
                                if cur == locked_bid:
                                    ok = True
                                    break
                                rec = blocks_map.get(cur)
                                if not isinstance(rec, dict):
                                    break
                                cur = str(rec.get("prev_block_id") or rec.get("prev") or "").strip()
                            can_vote = ok
            except Exception:
                can_vote = True

            if not can_vote:
                return

            vote = ex.bft_make_vote_for_block(view=view, block_id=bid, parent_id=parent)
            if not isinstance(vote, dict):
                return

            hdr = WireHeader(
                type=MsgType.BFT_VOTE,
                chain_id=str(getattr(ex, "chain_id", "weall")),
                schema_version=self._cfg.schema_version,
                tx_index_hash=str(getattr(getattr(self, "_canon", None), "source_sha256", "")),
            )
            vmsg = BftVoteMsg(header=hdr, view=int(view), vote=vote)

            # Vote goes back to proposer/leader (peer_id of sender)
            self.node.send_message(peer_id, vmsg)
        except Exception:
            return

    def _on_bft_vote(self, peer_id: str, msg: BftVoteMsg) -> None:
        if not _env_bool("WEALL_BFT_ENABLED", False):
            return
        if self.node is None:
            return
        ex = self._executor
        if not hasattr(ex, "bft_handle_vote"):
            return

        try:
            vote = _as_dict(getattr(msg, "vote"))
            qc = ex.bft_handle_vote(vote)
            if qc is None:
                return

            hdr = WireHeader(
                type=MsgType.BFT_QC,
                chain_id=str(getattr(ex, "chain_id", "weall")),
                schema_version=self._cfg.schema_version,
                tx_index_hash=str(getattr(getattr(self, "_canon", None), "source_sha256", "")),
            )
            qc_msg = BftQcMsg(header=hdr, qc=qc.to_json())  # type: ignore[attr-defined]
            self.node.broadcast_message(qc_msg)

            if hasattr(ex, "bft_commit_if_ready"):
                ex.bft_commit_if_ready(qc)
        except Exception:
            return

    def _on_bft_qc(self, peer_id: str, msg: BftQcMsg) -> None:
        if not _env_bool("WEALL_BFT_ENABLED", False):
            return
        ex = self._executor
        try:
            qcj = _as_dict(getattr(msg, "qc"))
            if not qcj:
                return
            if hasattr(ex, "bft_handle_qc"):
                ex.bft_handle_qc(qcj)
                return

            # fallback (legacy best-effort)
            st = self._state_provider()
            bft = st.get("bft")
            if not isinstance(bft, dict):
                st["bft"] = {}
            st["bft"]["high_qc"] = qcj
            if hasattr(ex, "_ledger_store"):
                ex.state = st
                ex._ledger_store.write(st)  # type: ignore[attr-defined]
        except Exception:
            return

    def _on_bft_timeout(self, peer_id: str, msg: BftTimeoutMsg) -> None:
        if not _env_bool("WEALL_BFT_ENABLED", False):
            return
        ex = self._executor
        try:
            tmo = _as_dict(getattr(msg, "timeout"))
            if not tmo:
                return
            if hasattr(ex, "bft_handle_timeout"):
                ex.bft_handle_timeout(tmo)
        except Exception:
            return


def start_net_mesh_loop_if_enabled(*, executor: Any, mempool: Any) -> Optional[NetMeshLoop]:
    loop = NetMeshLoop(executor=executor, mempool=mempool)
    ok = loop.start()
    return loop if ok else None
