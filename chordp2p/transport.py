"""Length-prefixed wire framing.

Every message on the network is a single *frame*::

    [4-byte header length][JSON header][4-byte payload length][raw payload]

The JSON header carries the request/response metadata; the raw payload carries
file bytes (so large objects stream as binary instead of being base64-bloated
inside JSON).  A payload of length 0 means "no body".

This replaces the original ad-hoc ``struct.pack`` sequences that were
duplicated and subtly different in every handler, and removes ``pickle``
entirely.
"""
from __future__ import annotations

import json
import socket
import struct
from typing import Tuple

_HEADER = struct.Struct("!I")


class ProtocolError(Exception):
    """Raised when a frame cannot be read or is malformed."""


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly ``n`` bytes or raise (handles short reads)."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProtocolError(
                f"connection closed after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def send_frame(sock: socket.socket, header: dict, payload: bytes = b"") -> None:
    header_bytes = json.dumps(header).encode("utf-8")
    sock.sendall(
        _HEADER.pack(len(header_bytes))
        + header_bytes
        + _HEADER.pack(len(payload))
        + payload
    )


def recv_frame(sock: socket.socket) -> Tuple[dict, bytes]:
    header_len = _HEADER.unpack(_recv_exact(sock, _HEADER.size))[0]
    header = json.loads(_recv_exact(sock, header_len).decode("utf-8"))
    payload_len = _HEADER.unpack(_recv_exact(sock, _HEADER.size))[0]
    payload = _recv_exact(sock, payload_len) if payload_len else b""
    return header, payload
