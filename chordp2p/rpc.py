"""RPC layer: message-type constants and a single ``call`` helper.

All remote interactions go through :func:`call`.  It opens a short-lived
connection, sends one request frame, and reads one response frame.  Errors
(timeouts, refused connections, protocol errors) are normalised into
:class:`RpcError` so callers can treat "node unreachable" uniformly.
"""
from __future__ import annotations

import socket
from typing import Optional, Tuple

from . import config
from .transport import ProtocolError, recv_frame, send_frame


class MsgType:
    """Every supported request type (kept as a namespace of constants)."""

    PING = "PING"
    GET_INFO = "GET_INFO"
    GET_SUCCESSOR = "GET_SUCCESSOR"
    GET_PREDECESSOR = "GET_PREDECESSOR"
    CLOSEST_PRECEDING = "CLOSEST_PRECEDING"
    FIND_SUCCESSOR = "FIND_SUCCESSOR"
    NOTIFY = "NOTIFY"
    GET_FINGERS = "GET_FINGERS"
    # storage
    STORE = "STORE"
    RETRIEVE = "RETRIEVE"
    BACKUP = "BACKUP"
    LIST_FILES = "LIST_FILES"
    HANDOFF = "HANDOFF"  # graceful-departure file handoff


class RpcError(Exception):
    """Any failure talking to a remote node."""


def call(
    addr: Tuple[str, int],
    mtype: str,
    params: Optional[dict] = None,
    payload: bytes = b"",
    timeout: float = config.RPC_TIMEOUT,
) -> Tuple[dict, bytes]:
    """Send one request to ``addr`` and return ``(header, payload)``.

    Raises :class:`RpcError` on any transport/connection problem, and on a
    server-reported error (``header["ok"] is False``).
    """
    header = {"type": mtype}
    if params:
        header.update(params)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(addr)
        send_frame(sock, header, payload)
        resp_header, resp_payload = recv_frame(sock)
    except (OSError, ProtocolError) as exc:
        raise RpcError(f"{mtype} -> {addr[0]}:{addr[1]} failed: {exc}") from exc
    finally:
        sock.close()

    if not resp_header.get("ok", True):
        raise RpcError(resp_header.get("error", "remote error"))
    return resp_header, resp_payload
