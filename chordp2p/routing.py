"""Pure routing / Sechord-verification logic.

Everything here is a *pure function* of its arguments -- no sockets, no shared
state -- which makes the security-critical logic unit-testable in isolation
(see ``tests/test_routing.py``).

The Sechord idea (from Needels & Kwon, "Secure Routing in P2P DHTs") is: don't
blindly trust the next hop a peer hands you.  A correct Chord hop must (a) make
forward progress toward the key and (b) land near one of the *expected* finger
positions of the node that proposed it.  A malicious node that misroutes you to
an arbitrary peer (e.g. the trap node) violates (b), and we detect it.
"""
from __future__ import annotations

import hashlib
import statistics
from typing import Iterable

from . import config


# --------------------------------------------------------------------------- #
# Identifier hashing
# --------------------------------------------------------------------------- #
def hash_key(key: str, m: int = config.M) -> int:
    """Map an arbitrary string (ip:port or filename) into the id ring."""
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()
    return int(digest, 16) % (2 ** m)


# --------------------------------------------------------------------------- #
# Ring interval arithmetic
# --------------------------------------------------------------------------- #
def in_interval(x: int, start: int, end: int, inclusive_end: bool = False,
                m: int = config.M) -> bool:
    """True if ``x`` lies on the arc going clockwise from ``start`` to ``end``.

    ``start`` is always exclusive.  ``end`` is inclusive iff ``inclusive_end``.
    When ``start == end`` the arc is the whole ring (single-node case).
    """
    size = 2 ** m
    x %= size
    start %= size
    end %= size
    if start == end:
        return True  # full circle
    if start < end:
        return (start < x < end) or (inclusive_end and x == end)
    # wrap-around arc
    return (x > start) or (x < end) or (inclusive_end and x == end)


# --------------------------------------------------------------------------- #
# Sechord hop verification
# --------------------------------------------------------------------------- #
def ideal_finger_ids(node_id: int, m: int = config.M) -> list[int]:
    """The textbook finger targets of ``node_id``: node_id + 2^i (mod 2^m)."""
    size = 2 ** m
    return [(node_id + 2 ** i) % size for i in range(m)]


def hop_threshold(node_id: int, m: int = config.M,
                  alpha: float = config.ALPHA) -> float:
    """Acceptance threshold = mean + alpha * stddev of finger spacing.

    For M=8 this is exactly mean=32.0, threshold~=94.55, matching the report's
    Figure 12 trace.
    """
    fingers = ideal_finger_ids(node_id, m)
    size = 2 ** m
    spacing = [(fingers[i] - fingers[i - 1]) % size for i in range(m)]
    return statistics.mean(spacing) + alpha * statistics.pstdev(spacing)


def is_plausible_hop(from_id: int, candidate_id: int, m: int = config.M,
                     alpha: float = config.ALPHA) -> bool:
    """Sechord check: is ``candidate_id`` close enough to *some* ideal finger
    of ``from_id`` to be a believable next hop?
    """
    size = 2 ** m
    threshold = hop_threshold(from_id, m, alpha)
    for finger in ideal_finger_ids(from_id, m):
        forward_distance = (candidate_id - finger) % size
        if 0 < forward_distance <= threshold:
            return True
    return False


def is_valid_hop(from_id: int, candidate_id: int, key: int,
                 m: int = config.M, alpha: float = config.ALPHA) -> bool:
    """Full hop validation combining progress + Sechord plausibility.

    A hop is valid only if the candidate (1) lies strictly between the current
    node and the key (forward progress) and (2) is statistically plausible as a
    finger of the current node.  Failing either marks the proposer as
    potentially malicious.
    """
    if candidate_id == from_id:
        return False
    if not in_interval(candidate_id, from_id, key, m=m):
        return False
    return is_plausible_hop(from_id, candidate_id, m, alpha)


def closest_preceding(node_id: int, key: int, finger_ids: Iterable[int],
                      blacklist: Iterable[int] = (),
                      m: int = config.M) -> int:
    """Return the id of the finger most immediately preceding ``key``.

    Mirrors Chord's ``closest_preceding_node`` but as a pure helper over a list
    of finger ids.  Returns ``node_id`` itself if none qualifies.
    """
    blocked = set(blacklist)
    fingers = list(finger_ids)
    for fid in reversed(fingers):
        if fid in blocked or fid == node_id:
            continue
        if in_interval(fid, node_id, key, m=m):
            return fid
    return node_id
