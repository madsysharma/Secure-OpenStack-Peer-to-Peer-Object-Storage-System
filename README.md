# Secure OpenStack Peer-to-Peer Object Storage System

## Overview

This project implements a **Secure Peer-to-Peer (P2P) Object Storage System** for OpenStack, enhancing the scalability, fault tolerance, and security of OpenStack's object storage component. By transitioning from a traditional client-server architecture to a decentralized P2P model, the project addresses key limitations in performance, security, and scalability. The P2P architecture employs the **Sechord** algorithm, which is designed to defend against routing attacks while maintaining efficient data distribution and retrieval across nodes.

## Authors

- Kyle Felip Mondina
- Madhuri Sharma
- Chen Zhang

This project was completed as part of the course COEN 241 (Cloud Computing) at Santa Clara University under the guidance of Professor Ming-Hwa Wang, with refactoring done by myself later on.

## Table of Contents

- [Introduction](#introduction)
- [Objective](#objective)
- [Problem Description](#problem-description)
- [Our Solution](#our-solution)
- [Architecture](#architecture)
- [Project Layout](#project-layout)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Updates](#updates)
- [Limitations](#limitations)
- [Future Work](#future-work)

## Introduction

In modern cloud systems, scalability, fault tolerance, and security are critical for efficient resource distribution and reliable data storage. OpenStack, a prominent cloud platform, offers object storage solutions, but its current architecture has vulnerabilities to routing attacks. This project reimagines OpenStack's object storage using a secure P2P architecture to enhance performance and provide resilience against malicious activities.

## Objective

The primary goal of this project is to design and implement a **Secure P2P Object Storage System** for OpenStack that:

- Improves scalability and fault tolerance through decentralized data storage and retrieval.
- Protects against **routing attacks** by employing robust security measures within a P2P architecture.
- Ensures efficient load distribution and high performance, even under malicious attacks.

## Problem Description

OpenStack’s existing object storage system, while functional, faces several challenges:
- Vulnerability to routing attacks that compromise data integrity and availability.
- Performance issues such as high latency and inconsistent scaling under heavy load.
- Complexity in deployment and management.
  
## Our Solution

We propose a secure P2P system using the **Sechord routing algorithm**, which improves upon traditional Chord-based systems by introducing security checks at each routing step. Key features of our solution include:
- **Hop Verification**: Mitigates the risk of routing attacks by verifying the validity of each routing hop.
- **Decentralized Object Storage**: Reduces the load on central servers, distributing the data across the network for better scalability.
- **Malicious Node Detection**: Identifies and isolates malicious nodes to maintain the integrity of the system.

## Architecture

The architecture is based on a **modified Chord** distributed hash table (DHT) structure with added security features to defend against common routing attacks. The key architectural components are:
1. **Sechord Algorithm**: Secure routing protocol for mitigating malicious attacks.
   A correct Chord hop must do two things, and a misrouting attacker violates at least one:
   a. **Make forward progress** - the suggested next node must lie strictly between the current node and the key on the ring.
   b. **Be plausible** - the suggested node must sit near one of the *expected* finger positions of the node that proposed it. The acceptance threshold is `mean + ALPHA·stddev` of the ideal finger spacing.
   For `M = 8` this reproduces the report's Figure 12 exactly: `mean = 32.0`, `threshold ≈ 94.55`, and a misrouting suggestion toward a dead-zone trap (e.g. id 64 from node 97) is flagged as an *illegal hop*. The offending node is blacklisted and the lookup backtracks and routes around it.
2. **P2P Object Storage**: Decentralized system where each node is responsible for storing, retrieving, and replicating data.

## Project layout

```
secure-chord-p2p/
├── chordp2p/                 # the package
│   ├── config.py             # all tunables (M=8, ALPHA=1.5, timeouts, ...)
│   ├── logutil.py            # structured logging (replaces scattered prints)
│   ├── node_ref.py           # NodeRef value object (replaces pickled nodes)
│   ├── transport.py          # length-prefixed JSON-header + binary-payload framing
│   ├── rpc.py                # message types + the single `call` client helper
│   ├── routing.py            # PURE Sechord logic (interval math, hop checks)
│   ├── storage.py            # per-node object store + replica tracking
│   ├── chord.py              # ChordNode: state, secured find_successor, join/stabilize
│   └── server.py             # socket server, RPC dispatch, upload/download, CLI
├── scripts/
│   ├── start_node.py         # start the first node of a new ring
│   ├── join_node.py          # join an existing ring
│   └── trap_node.py          # start a malicious "trap" node
├── tests/
│   ├── test_routing.py       # unit tests (incl. the report's Figure-12 numbers)
│   └── simulate.py           # end-to-end multi-node simulation
├── requirements.txt          # (none - stdlib only)
└── README.md
```

Design principle: the security-critical logic in `routing.py` is **pure** (no sockets, no shared state), so it can be unit-tested in isolation. Networking (`transport`/`rpc`/`server`), routing state (`chord`), and storage (`storage`) are cleanly separated.

## Requirements

* Python 3.9 or newer. No third-party packages.

## Installation

To run this project, you'll need:

- **Python** (version 3.x)
- **OpenStack Swift** for object storage
- **NSL-KDD dataset** (for simulating network attacks)

Clone the repository and install necessary dependencies:

```bash
git clone https://github.com/your-repository/secure-openstack-p2p-storage.git
cd secure-openstack-p2p-storage
pip install -r requirements.txt
```

## Usage

### Run the test suite

```bash
# Pure-logic unit tests (fast)
python3 -m tests.test_routing

# Full multi-node simulation: ring formation, upload/download benchmark,
# and a live routing-attack detection + recovery demo
python3 -m tests.simulate
```

### Run a real multi-node ring (separate terminals / hosts)

```bash
# Terminal 1 - start the ring
python3 scripts/start_node.py 127.0.0.1 5000

# Terminal 2 - join it
python3 scripts/join_node.py 127.0.0.1 5001 127.0.0.1 5000

# Terminal 3 - join a malicious node and watch it get isolated
python3 scripts/trap_node.py 127.0.0.1 5002 127.0.0.1 5000
```

By default each node keeps its data under `/tmp/chordp2p/<node-id>/`. Override
with the `CHORD_STORAGE_ROOT` environment variable.

### Interactive CLI commands

```
info               show id, successor, predecessor, blacklist
fingers            print the finger table
find <id>          run a secured lookup for an id
upload <path>      store a file in the network (routed to its owner + replica)
download <name>    fetch a file by name into this node's downloads/
files              list objects and backups held locally
stabilize | fix    run a maintenance step manually
be-evil <ip:port>  turn this node malicious (misroute to the given trap)
be-good            return to honest behaviour
exit               shut the node down
```

## Updates

The original implementation worked only in a very specific demo setup and contained a number of correctness and design problems. The most important ones, and how they are addressed here, are as follows:

| # | Original problem | Fix in this version |
|---|------------------|---------------------|
| 1 | Entire `ChordNode` objects were shipped across the network with `pickle` and methods were invoked on the *local copy* - a remote-code-execution hazard and logically broken (stale snapshots). | A small `NodeRef(id, ip, port)` is the only thing exchanged; nodes talk through explicit JSON RPCs. No `pickle` anywhere. |
| 2 | `grab_chord_node` returned `None` on any error (no `return` in the `except`), so failures silently propagated everywhere. | A single `rpc.call` raises `RpcError`; callers handle "node unreachable" uniformly. |
| 3 | The blacklist mixed node **ids** and **ip strings**, so verification and dead-node handling disagreed. | The blacklist is consistently keyed by node **id**. |
| 4 | File transfer used `scp` / `os.system`, required pre-shared SSH, and one branch was hard-coded to `/tmp/czhang7/...`; other files used the literal string `/tmp/$USER/` (never shell-expanded). | Objects are transferred **in-band** over the protocol; each node owns an isolated directory under a configurable root. Runs anywhere. |
| 5 | Stabilization / finger-fixing had to be triggered by hand in the demo. | A background maintenance thread runs stabilize / fix-fingers / check-predecessor automatically. |
| 6 | Shared state (successor, predecessor, finger table, blacklist) was mutated from multiple threads with no synchronization. | All shared state is guarded by a re-entrant lock; blocking I/O is done on snapshots taken under the lock. |
| 7 | Constants (`PORT`, `M`) were re-declared and overrode the `globals.py` values inconsistently. | A single `config.py` is the source of truth. |
| 8 | `numpy` was pulled in for one mean / std-dev calculation. | Replaced with the stdlib `statistics` module - **zero third-party dependencies**. |
| 9 | The download path could loop the ring with no termination. | Lookups and retrieval are bounded (owner + replica), with a hard `MAX_HOPS` ceiling. |
| 10 | `find_successor` mixed recursion and iteration with several edge-case bugs; `misroute()` dereferenced `.ip` on a string; `TrapServer` used `grab_chord_node` without importing it. | A single, documented, iterative Sechord lookup; the malicious behaviour is a clean toggle on any node. |
| 11 | No tests; not runnable outside the SCU lab. | Pure-logic unit tests **and** an in-process multi-node simulation that runs anywhere. |

## Limitations

Sechord guarantees *detection and isolation* of the malicious node. *Recovery* of the lookup additionally requires an alternate forward path. When the traitor is the only forward bridge to the owner, a pure forward-Chord ring cannot route around it - this is precisely what RChord's **reverse edges** (cited as related work in the report) are for, and is the natural next extension.

## Future Work

Extended from the original report's conclusions:

1. **Add RChord-style reverse edges** so lookups can recover even when the malicious node is the sole forward bridge.
2. **Tune ALPHA against false positives** - the statistical threshold can reject legitimate distant hops; an adaptive threshold per ring density would help.
3. **Persisted-vs-transient blacklisting policy** - currently confirmed traitors are isolated for the node's lifetime; a decay/quarantine policy would let a genuinely-recovered node rejoin routing.
4. **Authentication layer** (e.g. the report's Risk-Based Authentication) on top of the secure routing, plus message signing to harden RPCs.
