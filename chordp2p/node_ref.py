"""A lightweight, serialisable reference to a node.

This is the single most important change from the original design.  The
original code shipped *entire* ``ChordNode`` objects across the wire with
``pickle`` and then invoked methods on the local copy -- which is both a
remote-code-execution hazard (``pickle.loads`` on network data) and logically
broken (you operate on a stale snapshot).  Here, nodes only ever exchange a
small ``(id, ip, port)`` tuple and talk to each other through explicit RPCs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class NodeRef:
    id: int
    ip: str
    port: int

    @property
    def addr(self) -> tuple[str, int]:
        return (self.ip, self.port)

    def to_dict(self) -> dict:
        return {"id": self.id, "ip": self.ip, "port": self.port}

    @staticmethod
    def from_dict(d: Optional[dict]) -> "Optional[NodeRef]":
        if not d:
            return None
        return NodeRef(int(d["id"]), str(d["ip"]), int(d["port"]))

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"Node({self.id}@{self.ip}:{self.port})"
