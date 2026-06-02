#!/usr/bin/env python3
"""Join an EXISTING Chord ring via a bootstrap node.

Usage:
    python3 scripts/join_node.py <ip> <port> <bootstrap_ip> <bootstrap_port>

Example:
    python3 scripts/join_node.py 127.0.0.1 5001 127.0.0.1 5000
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from chordp2p.node_ref import NodeRef
from chordp2p.routing import hash_key
from chordp2p.server import ChordServer


def main() -> int:
    if len(sys.argv) < 5:
        print(__doc__)
        return 1
    ip, port = sys.argv[1], int(sys.argv[2])
    b_ip, b_port = sys.argv[3], int(sys.argv[4])
    bootstrap = NodeRef(hash_key(f"{b_ip}:{b_port}"), b_ip, b_port)
    server = ChordServer(ip, port, bootstrap=bootstrap)
    server.start()
    print(f"Joined ring via {b_ip}:{b_port}; this node id {server.node.id}")
    try:
        server.run_cli()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
