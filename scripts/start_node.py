#!/usr/bin/env python3
"""Start the FIRST node of a new Chord ring (no bootstrap).

Usage:
    python3 scripts/start_node.py <ip> [port]

Example:
    python3 scripts/start_node.py 127.0.0.1 5000
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from chordp2p.config import DEFAULT_PORT
from chordp2p.server import ChordServer


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    server = ChordServer(ip, port)
    server.start()
    print(f"Started ring at {ip}:{port} (node id {server.node.id})")
    try:
        server.run_cli()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
