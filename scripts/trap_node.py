#!/usr/bin/env python3
"""Start a malicious "trap" node that misroutes every lookup to itself.

This is the modern equivalent of the report's ``trap.py``: it joins the ring
and immediately turns evil so you can watch honest nodes detect, blacklist, and
route around it.

Usage:
    python3 scripts/trap_node.py <ip> <port> <bootstrap_ip> <bootstrap_port>
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
    # Misroute toward our own predecessor (a dead-zone target), the classic
    # illegal-hop attack Sechord is designed to catch.
    import time
    time.sleep(2.0)  # let stabilization find a predecessor
    trap = server.node.predecessor or server.node.ref()
    server.node.be_evil(trap)
    print(f"TRAP node running at {ip}:{port} (id {server.node.id}); "
          f"misrouting to {trap.id}")
    try:
        server.run_cli()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
