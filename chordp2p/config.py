"""Central configuration for the Secure Chord P2P object store.

All tunables live here so the rest of the codebase never hard-codes magic
numbers.  The defaults (M=8, ALPHA=1.5) match the COEN 241 report so the
behaviour of the Sechord verification step is identical to Figure 12.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

# --- Identifier space ------------------------------------------------------
# Chord uses an m-bit identifier ring.  M=8 -> ids in [0, 256), matching the
# report (ids 58/97/148, threshold ~94.55, etc.).
M: int = 8
ID_SPACE: int = 2 ** M

# --- Sechord security ------------------------------------------------------
# Multiplier on the standard deviation of the ideal finger spacing used to
# build the "is this hop plausible?" threshold.  Higher -> more permissive.
ALPHA: float = 1.5

# Hard ceiling on the number of hops a single lookup may take.  Prevents the
# infinite routing loops the report warns about and bounds worst-case latency.
MAX_HOPS: int = 4 * M

# --- Storage / replication -------------------------------------------------
# Each object is stored on its owner node and replicated to this many
# successors for fault tolerance (the report backs files up to the successor).
REPLICATION: int = 1

# --- Networking ------------------------------------------------------------
DEFAULT_PORT: int = 5000
RPC_TIMEOUT: float = 5.0          # seconds per remote call
CHUNK_SIZE: int = 64 * 1024       # streaming chunk size for file transfer

# --- Background maintenance ------------------------------------------------
# Standard Chord runs these continuously.  The original project required them
# to be triggered by hand; here they run automatically unless disabled.
STABILIZE_INTERVAL: float = 1.0
FIX_FINGERS_INTERVAL: float = 1.0
CHECK_PRED_INTERVAL: float = 2.0

# --- Filesystem ------------------------------------------------------------
# Per-node data lives under STORAGE_ROOT/<node-id>/.  Defaults to a temp dir
# so the demo works on any machine without SCU-specific paths.
STORAGE_ROOT: str = os.environ.get("CHORD_STORAGE_ROOT", "/tmp/chordp2p")


@dataclass(frozen=True)
class Settings:
    """Immutable snapshot of the knobs above; handy for tests/simulations."""

    m: int = M
    alpha: float = ALPHA
    max_hops: int = MAX_HOPS
    replication: int = REPLICATION
    rpc_timeout: float = RPC_TIMEOUT

    @property
    def id_space(self) -> int:
        return 2 ** self.m


DEFAULTS = Settings()
