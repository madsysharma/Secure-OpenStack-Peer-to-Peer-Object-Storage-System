"""Secure Chord P2P object storage (COEN 241 revamp).

A clean, modular re-implementation of the secure peer-to-peer object store
described in the project report: a Chord DHT hardened with the Sechord
hop-verification scheme to detect and route around malicious (misrouting)
nodes.
"""
from .chord import ChordNode
from .config import DEFAULTS, Settings
from .node_ref import NodeRef
from .server import ChordServer

__all__ = ["ChordNode", "ChordServer", "NodeRef", "Settings", "DEFAULTS"]
__version__ = "1.0.0"
