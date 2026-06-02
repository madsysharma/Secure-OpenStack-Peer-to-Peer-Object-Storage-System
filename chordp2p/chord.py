"""Core Chord node logic with Sechord-secured routing.

This module owns a node's *routing* state (id, successor, predecessor, finger
table, blacklist) and drives lookups.  It is deliberately separate from the
socket server (``server.py``) and from storage (``storage.py``).

Key fixes vs. the original implementation
-----------------------------------------
* Lookups are **iterative and origin-driven**.  The origin asks each peer, over
  RPC, for its closest preceding finger, verifies that suggestion locally with
  Sechord, and only then advances.  The original instead pickled whole remote
  nodes and ran their methods on a stale local copy.
* The **blacklist is consistently keyed by node id** (the original mixed ids and
  ip strings, so verification and dead-node handling disagreed).
* All shared state is guarded by a re-entrant lock; network I/O is performed on
  snapshots taken under the lock to avoid holding it across blocking calls.
* A hard ``MAX_HOPS`` ceiling guarantees termination.
"""
from __future__ import annotations

import threading
from typing import Callable, Optional

from . import config, routing
from .logutil import get_logger
from .node_ref import NodeRef
from .rpc import MsgType, RpcError, call

log = get_logger("chord")


class ChordNode:
    def __init__(self, ip: str, port: int, settings: config.Settings = config.DEFAULTS,
                 node_id: Optional[int] = None):
        self.settings = settings
        self.m = settings.m
        self.ip = ip
        self.port = port
        # Id is normally derived by hashing ip:port.  An explicit id can be
        # supplied to reproduce specific report scenarios (e.g. the trap node
        # with id 64 in Figure 12) or for deterministic tests.
        self.id = node_id if node_id is not None else routing.hash_key(
            f"{ip}:{port}", self.m)

        self._lock = threading.RLock()
        self.successor: NodeRef = self.ref()
        self.predecessor: Optional[NodeRef] = None
        # finger_table[i] is the successor of (self.id + 2^i)
        self.finger_table: list[NodeRef] = [self.ref()] * self.m
        self.blacklist: set[int] = set()

        # malicious-node simulation (see report's "be-evil"/trap mechanism)
        self.evil: bool = False
        self.trap: Optional[NodeRef] = None

        log.info("node %s created (id=%d)", self.ref(), self.id)

    # ------------------------------------------------------------------ #
    # Identity helpers
    # ------------------------------------------------------------------ #
    def ref(self) -> NodeRef:
        return NodeRef(self.id, self.ip, self.port)

    def _is_self(self, ref: Optional[NodeRef]) -> bool:
        return ref is not None and ref.ip == self.ip and ref.port == self.port

    # ------------------------------------------------------------------ #
    # Remote helpers (transparently local when the ref is us)
    # ------------------------------------------------------------------ #
    def _alive(self, ref: NodeRef) -> bool:
        if self._is_self(ref):
            return True
        try:
            call(ref.addr, MsgType.PING, timeout=2.0)
            return True
        except RpcError:
            return False

    def _successor_of(self, ref: NodeRef) -> Optional[NodeRef]:
        if self._is_self(ref):
            with self._lock:
                return self.successor
        try:
            header, _ = call(ref.addr, MsgType.GET_SUCCESSOR)
            return NodeRef.from_dict(header.get("node"))
        except RpcError:
            return None

    def _predecessor_of(self, ref: NodeRef) -> Optional[NodeRef]:
        if self._is_self(ref):
            with self._lock:
                return self.predecessor
        try:
            header, _ = call(ref.addr, MsgType.GET_PREDECESSOR)
            return NodeRef.from_dict(header.get("node"))
        except RpcError:
            return None

    def _closest_preceding_of(self, ref: NodeRef, key: int,
                              blacklist: set[int]) -> Optional[NodeRef]:
        if self._is_self(ref):
            return self.closest_preceding_finger(key, blacklist)
        try:
            header, _ = call(ref.addr, MsgType.CLOSEST_PRECEDING,
                             {"key": key, "blacklist": sorted(blacklist)})
            return NodeRef.from_dict(header.get("node"))
        except RpcError:
            return None

    # ------------------------------------------------------------------ #
    # Local routing primitives
    # ------------------------------------------------------------------ #
    def closest_preceding_finger(self, key: int,
                                 blacklist: Optional[set[int]] = None) -> NodeRef:
        """The local finger most immediately preceding ``key``.

        If this node is *evil*, it misroutes by returning the trap node instead
        -- exactly the attack the report simulates.
        """
        with self._lock:
            if self.evil and self.trap is not None:
                log.warning("EVIL node %d misrouting lookup of %d to trap %s",
                            self.id, key, self.trap)
                return self.trap
            blocked = set(self.blacklist)
            if blacklist:
                blocked |= blacklist
            for finger in reversed(self.finger_table):
                if finger is None or finger.id in blocked or finger.id == self.id:
                    continue
                if routing.in_interval(finger.id, self.id, key, m=self.m):
                    return finger
            return self.ref()

    # ------------------------------------------------------------------ #
    # The secured lookup
    # ------------------------------------------------------------------ #
    def find_successor(self, key: int) -> NodeRef:
        """Locate the node responsible for ``key`` using Sechord verification.

        Returns the responsible :class:`NodeRef`.  Detects and routes around
        malicious hops, blacklisting offenders, and never exceeds MAX_HOPS.
        """
        key %= self.settings.id_space
        current = self.ref()
        backtrack: list[NodeRef] = []
        with self._lock:
            local_bl = set(self.blacklist)

        for hop in range(self.settings.max_hops):
            successor = self._successor_of(current)
            if successor is None:                       # current is dead
                local_bl.add(current.id)
                self._record_blacklist(current.id, reason="unreachable")
                if backtrack:
                    current = backtrack.pop()
                    continue
                break

            # key falls in (current, successor] -> successor owns it
            if current.id == successor.id or routing.in_interval(
                    key, current.id, successor.id, inclusive_end=True, m=self.m):
                return successor

            candidate = self._closest_preceding_of(current, key, local_bl)
            if candidate is None or candidate.id == current.id:
                return successor

            # ---- SECHORD VERIFICATION ---------------------------------- #
            if not routing.is_valid_hop(current.id, candidate.id, key,
                                        m=self.m, alpha=self.settings.alpha):
                log.warning(
                    "Malicious hop detected! node %d proposed an illegal hop "
                    "to %d while seeking %d -- A TRAITOR!",
                    current.id, candidate.id, key)
                # Isolate the bad target and the lying proposer so the lookup
                # routes around them on retry.
                local_bl.add(candidate.id)
                self._record_blacklist(candidate.id, reason="illegal hop target")
                if not self._is_self(current):
                    local_bl.add(current.id)
                    self._record_blacklist(current.id,
                                           reason="proposed illegal hop (traitor)")
                if backtrack:
                    current = backtrack.pop()          # retreat one step
                continue

            if not self._alive(candidate):
                local_bl.add(candidate.id)
                self._record_blacklist(candidate.id, reason="dead during routing")
                continue

            backtrack.append(current)
            current = candidate

        # Best-effort fallback if we ran out of hops.
        fallback = self._successor_of(current)
        return fallback or current

    # ------------------------------------------------------------------ #
    # Membership: join / stabilize / notify / fix_fingers
    # ------------------------------------------------------------------ #
    def create(self) -> None:
        """Start a brand-new ring with this node alone."""
        with self._lock:
            self.predecessor = None
            self.successor = self.ref()
            self.finger_table = [self.ref()] * self.m
        log.info("node %d created a new ring", self.id)

    def join(self, bootstrap: NodeRef) -> None:
        """Join an existing ring via a known bootstrap node."""
        try:
            header, _ = call(bootstrap.addr, MsgType.FIND_SUCCESSOR,
                             {"key": self.id})
            successor = NodeRef.from_dict(header["node"])
        except (RpcError, KeyError) as exc:
            raise RpcError(f"join failed via {bootstrap}: {exc}") from exc
        with self._lock:
            self.predecessor = None
            self.successor = successor
        log.info("node %d joined; successor=%s", self.id, successor)

    def notify(self, candidate: NodeRef) -> None:
        """``candidate`` thinks it might be our predecessor."""
        with self._lock:
            pred = self.predecessor
            if pred is None or routing.in_interval(
                    candidate.id, pred.id, self.id, m=self.m):
                if not self._is_self(candidate):
                    self.predecessor = candidate
                    log.debug("node %d predecessor set to %s", self.id, candidate)

    def stabilize(self) -> None:
        """Verify/repair the successor pointer (standard Chord stabilization)."""
        with self._lock:
            successor = self.successor
        x = self._predecessor_of(successor)
        with self._lock:
            if x and not self._is_self(x) and routing.in_interval(
                    x.id, self.id, self.successor.id, m=self.m):
                self.successor = x
            target = self.successor
        if not self._is_self(target):
            try:
                call(target.addr, MsgType.NOTIFY, {"node": self.ref().to_dict()})
            except RpcError:
                pass

    def fix_fingers(self) -> None:
        """Refresh one finger entry per call (cheap, spread over time)."""
        for i in range(self.m):
            start = (self.id + 2 ** i) % self.settings.id_space
            node = self.find_successor(start)
            with self._lock:
                self.finger_table[i] = node

    def check_predecessor(self) -> None:
        with self._lock:
            pred = self.predecessor
        if pred and not self._alive(pred):
            with self._lock:
                if self.predecessor and self.predecessor.id == pred.id:
                    self.predecessor = None
                    log.info("node %d dropped dead predecessor %s", self.id, pred)

    # ------------------------------------------------------------------ #
    # Blacklist & malicious toggles
    # ------------------------------------------------------------------ #
    def _record_blacklist(self, node_id: int, reason: str = "") -> None:
        with self._lock:
            if node_id not in self.blacklist:
                self.blacklist.add(node_id)
                log.info("node %d blacklisted %d (%s)", self.id, node_id, reason)

    def be_evil(self, trap: NodeRef) -> None:
        with self._lock:
            self.evil = True
            self.trap = trap
        log.warning("node %d is now EVIL (trap=%s)", self.id, trap)

    def be_good(self) -> None:
        with self._lock:
            self.evil = False
            self.trap = None
        log.info("node %d is honest again", self.id)

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #
    def info(self) -> dict:
        with self._lock:
            return {
                "self": self.ref().to_dict(),
                "successor": self.successor.to_dict(),
                "predecessor": self.predecessor.to_dict() if self.predecessor else None,
                "blacklist": sorted(self.blacklist),
                "evil": self.evil,
            }

    def fingers(self) -> list[dict]:
        with self._lock:
            return [f.to_dict() for f in self.finger_table]
