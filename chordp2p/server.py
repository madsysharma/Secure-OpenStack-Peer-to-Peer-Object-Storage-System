"""Network server + orchestration for a single node.

Responsibilities:
* Accept connections and dispatch request frames to the right handler.
* Run background maintenance (stabilize / fix_fingers / check_predecessor)
  automatically -- the original required these to be typed by hand.
* Orchestrate object upload/download with successor replication, transferring
  bytes *in-band* (no scp/ssh).
* Provide an interactive CLI for demos.
"""
from __future__ import annotations

import os
import socket
import threading
import time
from typing import Optional

from . import config, routing
from .chord import ChordNode
from .logutil import get_logger
from .node_ref import NodeRef
from .rpc import MsgType, RpcError, call
from .storage import Storage
from .transport import ProtocolError, recv_frame, send_frame

log = get_logger("server")


class ChordServer:
    def __init__(self, ip: str, port: int = config.DEFAULT_PORT,
                 bootstrap: Optional[NodeRef] = None,
                 settings: config.Settings = config.DEFAULTS,
                 storage_root: str = config.STORAGE_ROOT,
                 auto_maintain: bool = True,
                 node_id: Optional[int] = None,
                 node_factory=ChordNode):
        self.ip = ip
        self.port = port
        self.node: ChordNode = node_factory(ip, port, settings, node_id=node_id)
        self.storage = Storage(self.node.id, storage_root)
        self.download_dir = os.path.join(storage_root, str(self.node.id), "downloads")
        os.makedirs(self.download_dir, exist_ok=True)

        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._auto_maintain = auto_maintain
        self._bootstrap = bootstrap

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        self._server_sock.bind((self.ip, self.port))
        self._server_sock.listen(16)
        log.info("listening on %s:%d", self.ip, self.port)

        if self._bootstrap:
            self.node.join(self._bootstrap)
        else:
            self.node.create()

        self._spawn(self._accept_loop, name="accept")
        if self._auto_maintain:
            self._spawn(self._maintenance_loop, name="maintenance")

    def stop(self) -> None:
        self._stop.set()
        try:
            self._server_sock.close()
        except OSError:
            pass

    def _spawn(self, target, name: str) -> None:
        t = threading.Thread(target=target, name=name, daemon=True)
        t.start()
        self._threads.append(t)

    # ------------------------------------------------------------------ #
    # Accept loop & dispatch
    # ------------------------------------------------------------------ #
    def _accept_loop(self) -> None:
        self._server_sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                client, _ = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,),
                             daemon=True).start()

    def _handle(self, client: socket.socket) -> None:
        try:
            header, payload = recv_frame(client)
            response, body = self._dispatch(header, payload)
            send_frame(client, response, body)
        except ProtocolError as exc:
            log.debug("dropped malformed frame: %s", exc)
        except Exception as exc:  # noqa: BLE001 - never let a handler kill the thread
            log.exception("handler error: %s", exc)
            try:
                send_frame(client, {"ok": False, "error": str(exc)})
            except OSError:
                pass
        finally:
            client.close()

    def _dispatch(self, header: dict, payload: bytes):
        mtype = header.get("type")
        node = self.node

        if mtype == MsgType.PING:
            return {"ok": True}, b""

        if mtype == MsgType.GET_INFO:
            return {"ok": True, **node.info()}, b""

        if mtype == MsgType.GET_SUCCESSOR:
            return {"ok": True, "node": node.successor.to_dict()}, b""

        if mtype == MsgType.GET_PREDECESSOR:
            pred = node.predecessor
            return {"ok": True, "node": pred.to_dict() if pred else None}, b""

        if mtype == MsgType.GET_FINGERS:
            return {"ok": True, "fingers": node.fingers()}, b""

        if mtype == MsgType.CLOSEST_PRECEDING:
            key = int(header["key"])
            blacklist = set(header.get("blacklist", []))
            ref = node.closest_preceding_finger(key, blacklist)
            return {"ok": True, "node": ref.to_dict()}, b""

        if mtype == MsgType.FIND_SUCCESSOR:
            ref = node.find_successor(int(header["key"]))
            return {"ok": True, "node": ref.to_dict()}, b""

        if mtype == MsgType.NOTIFY:
            node.notify(NodeRef.from_dict(header["node"]))
            return {"ok": True}, b""

        if mtype == MsgType.STORE:
            return self._handle_store(header, payload)

        if mtype == MsgType.BACKUP:
            self.storage.put_backup(header["name"], payload)
            return {"ok": True}, b""

        if mtype == MsgType.RETRIEVE:
            return self._handle_retrieve(header)

        if mtype == MsgType.LIST_FILES:
            return {"ok": True,
                    "objects": self.storage.list_objects(),
                    "backups": self.storage.list_backups()}, b""

        if mtype == MsgType.HANDOFF:
            # Receiving objects handed off by a departing predecessor.
            self.storage.put_object(header["name"], payload)
            return {"ok": True}, b""

        return {"ok": False, "error": f"unknown type {mtype!r}"}, b""

    # ------------------------------------------------------------------ #
    # Storage handlers
    # ------------------------------------------------------------------ #
    def _handle_store(self, header: dict, payload: bytes):
        name = header["name"]
        self.storage.put_object(name, payload)
        log.info("stored %r (%d bytes)", name, len(payload))
        # Replicate to successor(s) for fault tolerance.
        replicate = header.get("replicate", True)
        if replicate:
            self._replicate(name, payload)
        return {"ok": True, "node": self.node.ref().to_dict()}, b""

    def _replicate(self, name: str, data: bytes) -> None:
        succ = self.node.successor
        if succ.id == self.node.id:
            return
        try:
            call(succ.addr, MsgType.BACKUP, {"name": name}, payload=data)
            log.debug("replicated %r to successor %s", name, succ)
        except RpcError as exc:
            log.warning("replication of %r failed: %s", name, exc)

    def _handle_retrieve(self, header: dict):
        name = header["name"]
        data = self.storage.get_object(name)
        if data is not None:
            return {"ok": True, "found": True}, data
        return {"ok": True, "found": False}, b""

    # ------------------------------------------------------------------ #
    # Client-facing object operations (run by the node initiating them)
    # ------------------------------------------------------------------ #
    def upload(self, path: str) -> NodeRef:
        with open(path, "rb") as fh:
            data = fh.read()
        name = os.path.basename(path)
        key = routing.hash_key(name, self.node.m)
        owner = self.node.find_successor(key)
        if owner.id == self.node.id:
            self.storage.put_object(name, data)
            self._replicate(name, data)
        else:
            call(owner.addr, MsgType.STORE, {"name": name}, payload=data)
        log.info("uploaded %r -> owner %s", name, owner)
        return owner

    def download(self, name: str) -> Optional[str]:
        key = routing.hash_key(name, self.node.m)
        owner = self.node.find_successor(key)
        data: Optional[bytes] = None
        if owner.id == self.node.id:
            data = self.storage.get_object(name)
        else:
            try:
                header, body = call(owner.addr, MsgType.RETRIEVE, {"name": name})
                if header.get("found"):
                    data = body
            except RpcError as exc:
                log.warning("retrieve from owner failed: %s", exc)
        # Fall back to the owner's successor (where the replica lives).
        if data is None:
            replica = self.node.successor if owner.id == self.node.id else \
                self.node._successor_of(owner)
            if replica and replica.id != owner.id:
                try:
                    header, body = call(replica.addr, MsgType.RETRIEVE, {"name": name})
                    if header.get("found"):
                        data = body
                        log.info("recovered %r from replica %s", name, replica)
                except RpcError:
                    pass
        if data is None:
            log.warning("file %r not found in network", name)
            return None
        out = os.path.join(self.download_dir, name)
        with open(out, "wb") as fh:
            fh.write(data)
        log.info("downloaded %r -> %s", name, out)
        return out

    # ------------------------------------------------------------------ #
    # Background maintenance
    # ------------------------------------------------------------------ #
    def _maintenance_loop(self) -> None:
        last_stab = last_fix = last_pred = 0.0
        while not self._stop.is_set():
            now = time.monotonic()
            try:
                if now - last_stab >= config.STABILIZE_INTERVAL:
                    self.node.stabilize()
                    last_stab = now
                if now - last_fix >= config.FIX_FINGERS_INTERVAL:
                    self.node.fix_fingers()
                    last_fix = now
                if now - last_pred >= config.CHECK_PRED_INTERVAL:
                    self.node.check_predecessor()
                    last_pred = now
            except Exception as exc:  # noqa: BLE001
                log.debug("maintenance tick error: %s", exc)
            self._stop.wait(0.2)

    # ------------------------------------------------------------------ #
    # Interactive CLI
    # ------------------------------------------------------------------ #
    def run_cli(self) -> None:  # pragma: no cover - interactive
        help_text = (
            "commands: info | fingers | find <id> | upload <path> | "
            "download <name> | files | stabilize | fix | "
            "be-evil <ip:port> | be-good | exit")
        print(help_text)
        while not self._stop.is_set():
            try:
                raw = input("chord> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not raw:
                continue
            cmd, _, arg = raw.partition(" ")
            arg = arg.strip()
            try:
                self._cli_command(cmd.lower(), arg, help_text)
            except Exception as exc:  # noqa: BLE001
                print(f"error: {exc}")
            if cmd.lower() == "exit":
                break
        self.stop()

    def _cli_command(self, cmd: str, arg: str, help_text: str) -> None:  # pragma: no cover
        if cmd == "exit":
            print("shutting down...")
        elif cmd == "info":
            import json
            print(json.dumps(self.node.info(), indent=2))
        elif cmd == "fingers":
            for i, f in enumerate(self.node.fingers()):
                print(f"finger {i}: id={f['id']} {f['ip']}:{f['port']}")
        elif cmd == "find":
            ref = self.node.find_successor(int(arg))
            print(f"key {arg} -> {ref}")
        elif cmd == "upload":
            print(f"uploaded to {self.upload(arg)}")
        elif cmd == "download":
            out = self.download(arg)
            print(f"saved to {out}" if out else "not found")
        elif cmd == "files":
            print("objects:", self.storage.list_objects())
            print("backups:", self.storage.list_backups())
        elif cmd == "stabilize":
            self.node.stabilize()
            print("stabilized")
        elif cmd == "fix":
            self.node.fix_fingers()
            print("fingers fixed")
        elif cmd == "be-evil":
            ip, _, port = arg.partition(":")
            trap_id = routing.hash_key(f"{ip}:{port}", self.node.m)
            self.node.be_evil(NodeRef(trap_id, ip, int(port)))
            print("node is now evil")
        elif cmd == "be-good":
            self.node.be_good()
            print("node is honest again")
        else:
            print(help_text)
