"""Tiny logging wrapper so every module logs consistently.

Replaces the scattered ``print(...)`` debugging calls in the original code with
a real logger that includes the node identity and can be silenced or
redirected (e.g. to a file) without touching call sites.
"""
from __future__ import annotations

import logging
import sys

_CONFIGURED = False


def configure(level: int = logging.INFO) -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-5s [%(name)s] %(message)s",
                          datefmt="%H:%M:%S")
    )
    root = logging.getLogger("chordp2p")
    root.setLevel(level)
    root.addHandler(handler)
    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    configure()
    return logging.getLogger(f"chordp2p.{name}")
